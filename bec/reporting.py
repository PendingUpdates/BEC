"""Analyst exports and a standalone, searchable case timeline."""
import csv
import io
import json
from collections import Counter
from datetime import timedelta
from zoneinfo import ZoneInfo

from .analysis import correlate, graph, scope, score
from .collection import replay
from .evidence import evidence_references
from .messages import correlate_messages
from .google_events import correlations as workspace_correlations
from .storage import DATA, atomic, now, read, save, timestamp


def cluster(events):
    groups, last_for = [], {}
    for e in events:
        is_access = e["event_type"] == "mail.access"
        key = (e["actor"]["user"], e["target"]["resource"], e["network"]["src_ip"],
               e["session"]["id"], e["assessment"], e["result"], tuple(e.get("message_links", [])))
        group = last_for.get(key) if is_access and key[0] and (key[2] or key[3]) else None
        when = timestamp(e["timestamp_utc"])
        if not group or when - timestamp(group[-1]["timestamp_utc"]) > timedelta(minutes=5):
            group = []
            groups.append(group)
        group.append(e)
        if is_access:
            last_for[key] = group
    return groups


def timeline_row(group, zone):
    first, last = group[0], group[-1]
    unique = lambda seq: list(dict.fromkeys(seq))
    reasons = unique(r["reason"] for e in group for r in e["reasons"])
    refs = [dict(event_id=e["event_id"], **ref) for e in group for ref in evidence_references(e)]
    when = timestamp(first["timestamp_utc"]).astimezone(zone)
    return dict(tenant=first["tenant_id"], timestamp_utc=first["timestamp_utc"],
                timestamp_local=when.isoformat(timespec="seconds") + " " + when.tzname(),
                end_utc=last["timestamp_utc"], phase=first["phase"], source=first["dataset"],
                event=first["operation"], event_type=first["event_type"], actor=first["actor"]["user"] or "",
                target=first["target"]["resource"] or "", src_ip=first["network"]["src_ip"] or "",
                device=first["device"]["id"] or "", assessment=first["assessment"],
                confidence=first["confidence"], relevance_score=max(e["relevance_score"] for e in group),
                count=len(group), reason=reasons, findings=unique(fid for e in group for fid in e["finding_ids"]),
                folders=unique(f for e in group for f in e["traits"]["folders"]),
                messages=unique(m for e in group for m in e["entities"]["message"]), evidence_reference=refs,
                message_links=unique(m for e in group for m in e.get("message_links", [])),
                link_notes=unique(n for e in group for n in e.get("link_notes", [])),
                defender=first.get("defender", {}), workspace=first.get("workspace", {}))


def csv_out(rows, message_index):
    fields = ("tenant","timestamp_utc","timestamp_local","end_utc","phase","source","event","event_type",
              "actor","target","src_ip","device","assessment","confidence","relevance_score","count",
              "reason","findings","folders","messages","evidence_reference","message_links","link_notes","defender",
              "linked_email_artifacts","workspace")
    buf = io.StringIO(newline="")
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        safe = {}
        linked = [message_index[mid] for mid in row["message_links"]]
        safe["linked_email_artifacts"] = json.dumps([
            {k: m[k] for k in ("network_message_id", "recipient", "urls", "attachments")} for m in linked],
            ensure_ascii=False)
        for key, val in row.items():
            if isinstance(val, (dict, list)):
                val = json.dumps(val, ensure_ascii=False)
            if isinstance(val, str) and val.lstrip().startswith(("=", "+", "-", "@")):
                val = "'" + val
            safe[key] = val
        writer.writerow(safe)
    return buf.getvalue().encode("utf-8-sig")


def report(case, manual=None):
    all_events, gaps = replay(case)
    events, _, pivots, known, baseline = scope(case, all_events, manual)
    score(events, known)
    excluded_ips = {p["value"] for p in pivots if p["kind"] == "ip" and p["status"] in ("trusted network", "shared IP")}
    findings = correlate(events, excluded_ips)
    workspace_findings = workspace_correlations(events)
    findings.extend(workspace_findings)
    messages, mailbox_findings = correlate_messages(events)
    findings.extend(mailbox_findings)
    root = case.path
    zone = ZoneInfo(case.options["timezone"])
    summary = read(root / "collection_summary.json") if (root / "collection_summary.json").exists() else {}
    gaps = [*summary.get("gaps", []), *gaps]
    if not summary:
        gaps.append(dict(dataset="all", reason="No collection performed."))
    account_only = (case.meta.get("collection_scope") == "named_account" or
                    case.meta.get("microsoft_auth") == "delegated")
    if not account_only and not baseline.get(case.meta["user"]):
        gaps.append(dict(dataset="baseline", reason="No earlier successful sign-ins for the primary user."))
    elif (case.meta.get("google_workspace") and case.options["baseline_days"] and
          "workspace/" + case.meta["user"] not in known):
        gaps.append(dict(dataset="google_login", reason="No earlier Workspace login observed for the primary user."))
    for pivot in pivots:
        if pivot["status"].endswith("limit"):
            gaps.append(dict(dataset="pivots", reason=pivot["status"], kind=pivot["kind"], value=pivot["value"]))
    complete = [timeline_row([e], zone) for e in events]
    relevant = [timeline_row(g, zone) for g in cluster([e for e in events if e["reasons"] or e["finding_ids"]
                                                        or e.get("message_links") or e["event_type"] == "mail.delivery"])]
    graph_obj = graph(case.tenant, events)
    overview = dict(case_id=case.id, tenant=case.tenant, user=case.meta["user"], start=case.meta["start"],
                    end=case.meta["end"], mode=summary.get("mode"), generated=now(), timezone=case.options["timezone"],
                    event_count=len(events), indexed_count=len(all_events), findings=len(findings), gaps=len(gaps),
                    investigation_rows=len(relevant), mailbox_message_matches=len(mailbox_findings),
                    workspace_matches=len(workspace_findings),
                    source_counts=dict(Counter(e["dataset"] for e in events)),
                    baseline_successes=dict(baseline), output=str(root / "timeline" / "timeline.html"))
    if account_only:
        overview["collection_scope"] = "Named account and related email evidence. Historical baseline excluded."
    save(root / "analysis_summary.json", overview)
    save(root / "telemetry_gaps.json", gaps)
    save(root / "entities" / "graph.json", graph_obj)
    save(root / "entities.json", dict(tenant=case.tenant, entities=[n for n in graph_obj["nodes"] if n["type"] != "event"]))
    save(root / "pivots" / "queue.json", dict(tenant=case.tenant, pivots=pivots))
    save(root / "findings.json", findings)
    save(root / "baseline.json", dict(tenant=case.tenant, successful_signins=dict(baseline),
        observed={u: {k: sorted(v) for k, v in fields.items()} for u, fields in known.items()}))
    atomic(root / "normalized" / "events.jsonl", "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events).encode())
    tl = root / "timeline"
    message_index = {m["id"]: m for m in messages}
    atomic(tl / "complete.csv", csv_out(complete, message_index))
    atomic(tl / "timeline.csv", csv_out(relevant, message_index))
    payload = dict(summary=overview, complete=complete, relevant=relevant, findings=findings, gaps=gaps, messages=messages)
    save(tl / "timeline.json", payload)
    template = (DATA / "report.html").read_text(encoding="utf-8")
    serialized = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).replace("<", r"\u003c").replace("&", r"\u0026")
    atomic(tl / "timeline.html", template.replace("__CASE_DATA__", serialized).encode())
    case.log("analysis", events=len(events), correlations=len(findings), gaps=len(gaps), pivots=len(pivots))
    return overview


def timesketch(case):
    source = case.path / "normalized" / "events.jsonl"
    path = case.path / "timeline" / "timesketch.jsonl"
    with source.open(encoding="utf-8") as f:
        rows = []
        for line in f:
            e = json.loads(line)
            rows.append(json.dumps(dict(datetime=e["timestamp_utc"], message=e["operation"],
                timestamp_desc=e["dataset"], tenant=e["tenant_id"], event_id=e["event_id"],
                actor=e["actor"]["user"], source_ip=e["network"]["src_ip"], evidence=e["evidence"],
                evidence_references=evidence_references(e),
                message_links=e.get("message_links", []), defender=e.get("defender", {}), workspace=e.get("workspace", {}))))
    atomic(path, "".join(s + "\n" for s in rows).encode())
    return path
