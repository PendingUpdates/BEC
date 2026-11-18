"""Deterministic baseline, bounded entity expansion and chronological correlations."""
import ipaddress
import itertools
from collections import Counter, defaultdict, deque
from datetime import timedelta
from fnmatch import fnmatchcase

from .evidence import evidence_references
from .storage import DATA, digest, encode, iso, read, timestamp
from .messages import include_message_artifacts

WEIGHTS = dict(ip=25, country=20, region=10, asn=20, device=15, os=5, browser=5,
               user_agent=5, client_application=10, authentication_method=15, application=10, hour=5)
PHASES = {"authentication": "Authentication", "application": "Application activity",
          "mail.access": "Mailbox/data access", "mail.rule": "Persistence", "mail.delivery": "Mail delivery",
          "mail.trace": "Mail delivery", "mail.search": "Discovery", "mail.send": "Outbound mail",
          "mail.delete": "Mailbox changes", "mail.move": "Mailbox changes",
          "oauth.grant": "Persistence", "identity": "Identity changes", "email.click": "URL interaction",
          "email.postdelivery": "Post-delivery action", "email": "Email evidence", "xdr.alert": "XDR alert",
          "google.login": "Authentication", "google.oauth": "OAuth activity", "google.gmail": "Gmail activity"}


def traits(event):
    for name in WEIGHTS:
        val = event["traits"].get(name)
        for item in val if isinstance(val, list) else [val]:
            if item is not None and item != "":
                yield name, str(item)


def build_baseline(events, case):
    low = iso(timestamp(case.meta["start"]) - timedelta(days=case.options["baseline_days"]))
    known = defaultdict(lambda: defaultdict(set))
    count = Counter()
    for e in events:
        if (low <= e["timestamp_utc"] < case.meta["start"] and e["result"] != "failure"
                and e["event_type"] in ("authentication.success", "google.login.success")):
            user = e["actor"]["user"]
            if not user:
                continue
            count[user] += 1
            if e["dataset"] == "google_login":
                user = "workspace/" + user
            observed = known[user]
            for key, val in traits(e):
                observed[key].add(val)
    return known, count


def unusual(e, known):
    if not e["event_type"].startswith(("authentication.", "google.login.")):
        return []
    user = e["actor"]["user"] or ""
    past = known.get("workspace/" + user if e["dataset"] == "google_login" else user, {})
    return sorted({k for k, v in traits(e) if past.get(k) and v not in past[k]})


def index_scope(events, case):
    index = defaultdict(list)
    users_by_ip = defaultdict(set)
    for e in events:
        if case.meta["start"] <= e["timestamp_utc"] < case.meta["end"]:
            for kind, vals in e["entities"].items():
                for value in vals:
                    index[kind, value].append(e)
            if e["event_type"].startswith("authentication.") and e["network"]["src_ip"]:
                users_by_ip[e["network"]["src_ip"]].update(e["entities"]["user"])
    return index, users_by_ip


def scope(case, events, manual=None):
    """Breadth-first pivot with typed identifiers. Never pivot on an SMTP relay address."""
    cfg = case.options
    seed = ("user", case.meta["user"])
    networks = [ipaddress.ip_network(c) for c in cfg["trusted_networks"]]
    index, users_by_ip = index_scope(events, case)
    known, counts = build_baseline(events, case)
    historical_ids = defaultdict(dict)
    baseline_start = iso(timestamp(case.meta["start"]) - timedelta(days=cfg["baseline_days"]))
    for e in events:
        if baseline_start <= e["timestamp_utc"] < case.meta["start"] and e["event_type"] == "authentication.success":
            for uid in e["entities"].get("user_id", []):
                historical_ids[e["actor"]["user"]][uid] = e["event_id"]
    queue = deque([(seed, 0, None)])
    seen, accepted, selected, history = {seed}, [], {}, []
    for entity in manual or []:
        if entity not in seen:
            queue.append((entity, 0, None))
            seen.add(entity)
    limits = {"user": cfg["max_users"], "ip": cfg["max_ips"], "principal": cfg["max_users"],
              "user_id": cfg["max_users"]}
    used = Counter()
    while queue:
        entity, depth, cause = queue.popleft()
        kind, value = entity
        status = "searched"
        if kind == "ip":
            ip = ipaddress.ip_address(value)
            if any(ip in net for net in networks):
                status = "trusted network"
            elif len(users_by_ip[value]) >= cfg["shared_ip_users"]:
                status = "shared IP"
        if depth > cfg["max_depth"]:
            status = "depth limit"
        if used[kind] >= limits[kind]:
            status = "entity limit"
        row = dict(kind=kind, value=value, depth=depth, status=status, from_event=cause)
        history.append(row)
        if status != "searched":
            continue
        accepted.append(entity)
        used[kind] += 1
        if kind == "user":
            for uid, evidence_id in historical_ids[value].items():
                other = ("user_id", uid)
                if other not in seen:
                    seen.add(other)
                    queue.append((other, depth + 1, evidence_id))
        for event in index[entity]:
            selected[event["event_id"]] = event
            entities, typ = event["entities"], event["event_type"]
            next_entities = []
            if kind == "user" and typ.startswith("authentication."):
                next_entities.extend(("user_id", x) for x in entities.get("user_id", []))
                network_changes = {"ip", "country", "region", "asn"}.intersection(unusual(event, known))
                if network_changes or typ == "authentication.failure":
                    next_entities.extend(("ip", x) for x in entities["ip"])
            if kind == "user" and typ.startswith("mail.rule."):
                next_entities.extend(("ip", x) for x in entities["ip"])
            if kind == "ip" and typ.startswith("authentication."):
                next_entities.extend(("user", x) for x in entities["user"] if "@" in x)
            if typ == "oauth.grant":
                next_entities.extend(("principal", x) for x in entities["principal"])
            for other in next_entities:
                if other not in seen:
                    seen.add(other)
                    queue.append((other, depth + 1, event["event_id"]))
    include_message_artifacts(selected, index)
    ordered = sorted(selected.values(), key=lambda e: (e["timestamp_utc"], e["event_id"]))
    return ordered, accepted, history, known, counts


def points(e, value, reason):
    e["relevance_score"] += value
    e["reasons"].append(dict(points=value, reason=reason))


def score(events, known):
    for e in events:
        typ = e["event_type"]
        e["phase"] = next((phase for prefix, phase in PHASES.items() if typ.startswith(prefix)), "Other activity")
        for feature in unusual(e, known):
            tag = "unusual_hour" if feature == "hour" else "new_" + feature
            e["anomalies"].append(tag)
            points(e, WEIGHTS[feature], tag.replace("_", " ") + " relative to this user's observed sign-in history")
        if typ.startswith("mail.rule.") or typ in ("oauth.grant", "identity.method_change"):
            points(e, 40, "Account or mailbox configuration activity")
        if typ in ("mail.access", "mail.delete", "mail.search", "mail.send"):
            points(e, 10, "Mailbox investigation context")
        if typ in ("email.click", "email.postdelivery", "xdr.alert"):
            points(e, 10, "Defender recorded " + e["operation"])
        if typ in ("google.oauth.grant", "google.oauth.revoke", "google.gmail.app_access",
                   "google.gmail.auto_forward", "google.login.failure", "google.login.suspicious"):
            points(e, 10, "Workspace audit activity relevant to account access")
        e["assessment"] = "Contextual" if e["reasons"] else "Unknown"


def correlate(events, excluded_ips=()):
    findings = []
    for rule in read(DATA / "rules.json"):
        # For each join key keep the most recent qualifying prefix. One representative
        # sequence per terminal event and key, rather than every overlapping permutation.
        states = defaultdict(dict)
        for e in events:
            if e["result"] in ("failed", "failure", "false") and e["event_type"] != "authentication.failure":
                continue
            join = []
            for field in rule["keys"]:
                if field == "mail_user" and e["event_type"] == "mail.delivery":
                    vals = [str(e["target"]["resource"] or "").casefold()]
                elif field in ("user", "mail_user"):
                    vals = [e["actor"]["user"]]
                else:
                    vals = e["entities"][field]
                join.append([v for v in vals if v])
            t = timestamp(e["timestamp_utc"])
            for key in itertools.product(*join):
                state = states[key]
                for j in reversed(range(len(rule["steps"]))):
                    if not fnmatchcase(e["event_type"], rule["steps"][j]):
                        continue
                    if j == 0:
                        if not rule.get("first_anomaly") or e["anomalies"]:
                            state[0] = [e]
                        continue
                    prefix = state.get(j - 1)
                    if not prefix or t - timestamp(prefix[0]["timestamp_utc"]) > timedelta(minutes=rule["minutes"]):
                        continue
                    if t <= timestamp(prefix[-1]["timestamp_utc"]):
                        continue
                    if rule.get("distinct_users"):
                        a, b = prefix[0]["actor"]["user"], e["actor"]["user"]
                        if (not a or not b or a == b or key[0] in excluded_ips or
                                any("new_ip" not in r["anomalies"] for r in (prefix[0], e))):
                            continue
                    if rule.get("same_client_after_delivery") and j >= 2:
                        ip = e["network"]["src_ip"]
                        if not ip or ip != prefix[1]["network"]["src_ip"]:
                            continue
                    if rule.get("country_change") and j == 1:
                        countries = [r["network"]["country"] for r in (prefix[0], e)]
                        if not all(countries) or countries[0] == countries[1]:
                            continue
                    chain = prefix + [e]
                    if j < len(rule["steps"]) - 1:
                        state[j] = chain
                        continue
                    ids = [v["event_id"] for v in chain]
                    fid = "F-" + digest(encode([rule["id"], ids, key]))[:16]
                    findings.append(dict(tenant=e["tenant_id"], id=fid, rule=rule["id"],
                        observation=rule["name"], join=dict(zip(rule["keys"], key)),
                        assessment="Strongly Supported", confidence="High", event_ids=ids,
                        evidence=[v["evidence"] for v in chain],
                        event_evidence=[dict(event_id=v["event_id"], references=evidence_references(v)) for v in chain]))
                    for v in chain:
                        v["finding_ids"].append(fid)
                        if v["assessment"] == "Unknown":
                            v["assessment"] = "Contextual"
                    points(e, rule["points"], rule["name"])
                    if rule["points"] >= 30:
                        e["assessment"], e["confidence"] = "Suspicious", "Medium"
    return findings


def graph(tenant, events):
    nodes, edges = set(), defaultdict(list)
    for e in events:
        # An event node preserves join evidence without making unsupported pairwise claims.
        event_node = ("event", e["event_id"])
        nodes.add(event_node)
        for kind, vals in e["entities"].items():
            for value in vals:
                node = (kind, value)
                nodes.add(node)
                edges[event_node, node].append(e["event_id"])
    return dict(tenant=tenant, nodes=[dict(type=k, value=v) for k, v in sorted(nodes)],
                edges=[dict(source=list(a), target=list(b), event_ids=ids) for (a, b), ids in edges.items()])
