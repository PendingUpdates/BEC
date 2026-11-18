"""Normalize individual Admin SDK activity children and correlate Workspace evidence."""
from collections import defaultdict
from dataclasses import asdict
from datetime import timedelta

from .evidence import evidence_references
from .normalize import Event, address, canonical_ip, values
from .storage import CaseError, digest, encode, iso, timestamp


def parameters(items, prefix=""):
    """Keep repeated and typed nested parameter values under their full dotted names."""
    out = defaultdict(list)
    for item in items:
        name = prefix + item["name"]
        for field in ("value", "intValue", "boolValue", "multiValue", "multiIntValue"):
            if field in item:
                v = item[field]
                out[name].extend(v if isinstance(v, list) else [v])
        nested = item.get("multiMessageValue", [])
        if "messageValue" in item:
            nested = [item["messageValue"], *nested]
        for message in nested:
            for key, vals in parameters(message.get("parameter", []), name + ".").items():
                out[key].extend(vals)
    return dict(out)


LOGIN = {"login_success": "success", "login_failure": "failure", "logout": "logout",
         "login_challenge": "challenge", "suspicious_login": "suspicious"}
OAUTH = {"authorize": "grant", "revoke": "revoke", "deny": "deny", "request": "request", "activity": "use"}
GMAIL = {
    "1": ("sent", "Message sent"), "2": ("received", "Message received"),
    "3": ("spam_classification", "User changed spam classification"), "4": ("spam", "Flagged as spam after delivery"),
    "5": ("quarantined", "Message quarantined"), "6": ("released", "Message released"),
    "7": ("open", "First message open"), "8": ("unread", "Marked as unread"), "9": ("reply", "First reply"),
    "10": ("forward", "First forward"), "11": ("auto_forward", "Automatic forward"),
    "12": ("inbox", "Moved to inbox"), "13": ("trash", "Moved to trash"), "14": ("untrash", "Removed from trash"),
    "15": ("click", "Message link clicked"),
    "16": ("attachment_click", "Link clicked in attachment preview"),
    "17": ("attachment_download", "Attachment download"), "18": ("save_attachment", "Attachment saved to Drive"),
    "19": ("save_drive_item", "Linked Drive item saved"),
    "20": ("label_apply", "Message classification label applied"), "21": ("label_change", "Message classification label changed"),
    "22": ("label_remove", "Message classification label removed"), "23": ("attachment_label_apply", "Attachment classification label applied"),
    "24": ("attachment_label_change", "Attachment classification label changed"), "25": ("attachment_label_remove", "Attachment classification label removed"),
    "26": ("archive", "Message archived"), "27": ("delete", "Message permanently deleted"),
    "28": ("attachment_preview", "Attachment preview"), "29": ("draft", "Draft saved"),
    "30": ("bounce", "Message bounced"), "31": ("view", "Message viewed"),
    "32": ("download", "Message downloaded"), "33": ("app_access", "Application accessed message"),
    "34": ("rate_limited", "Receive rate limited"), "35": ("send_requested", "Send initiated"),
}


def normalize_child(tenant, dataset, record, index, evidence):
    native = record["id"]
    child = record["events"][index]
    name = child["name"]
    if not isinstance(name, str) or not name:
        raise CaseError("Workspace event name is missing.")
    params = parameters(child.get("parameters", []))
    def first(key):
        vals = params.get(key, [])
        return str(vals[0]) if len(vals) == 1 else None

    account = record.get("actor") or {}
    user = address(account.get("email"))
    ip = canonical_ip(record.get("ipAddress"))
    caller = account.get("applicationInfo") or {}
    client, app = caller.get("oauthClientId"), caller.get("applicationName")
    data = dict(customer_id=native["customerId"], application=native["applicationName"], event_name=name)
    result = "observed"
    target = None
    if dataset == "google_login":
        verb = LOGIN.get(name, name)
        kind = "google.login." + verb
        operation = "Workspace " + name.replace("_", " ")
        if verb in ("failure", "success"):
            result = verb
    elif dataset == "google_oauth":
        verb = OAUTH.get(name, name)
        kind = "google.oauth." + verb
        client, app = first("client_id"), first("app_name")
        operation = "OAuth " + name
        if app:
            operation += " · " + app
        target = app or client
        if name == "deny":
            result = "denied"
    else:
        code = first("event_info.mail_event_type")
        verb, label = GMAIL.get(code, ("event", f"Audit event {code or name}"))
        kind = "google.gmail." + verb
        operation = "Gmail · " + label
        target = first("message_info.subject") or first("message_info.rfc2822_message_id")
        if code:
            data["mail_event_type"] = code
    messages = list(params.get("message_info.rfc2822_message_id", []))
    owners = []
    if dataset == "google_gmail":
        resource_ids = set(child.get("resourceIds", []))
        for resource in record.get("resourceDetails", []):
            if resource.get("type") != "EMAIL" or resource.get("id") not in resource_ids:
                continue
            messages.extend(values(resource.get("id")))
            target = target or resource.get("title")
            for identity in resource.get("ownerDetails", {}).get("ownerIdentity", []):
                owners.extend(values(address(identity.get("userIdentity", {}).get("userEmail"))))
        if owners:
            data["mailbox_owners"] = values(*owners)
    for key in ("client_id", "app_name", "scope", "scope_data.scope", "api_name", "method_name",
                "product_bucket", "login_type", "login_failure_type", "is_suspicious",
                "message_info.subject", "message_info.rfc2822_message_id"):
        if key in params:
            data[key] = params[key]
    if client:
        data["oauth_client_id"] = str(client)
    if app:
        data["application_name"] = str(app)
    if child.get("status"):
        data["status"] = child["status"]
        status_code = child["status"].get("httpStatusCode")
        if child["status"].get("eventStatus") in ("FAILED", "SKIPPED") or (status_code and int(status_code) >= 400):
            result = "failure"
    entities = dict(user=values(user, *owners), ip=values(ip), session=[], device=[], app=values(client),
                    principal=[], message=values(*messages), mailbox=values(*owners), domain=[], correlation=[],
                    google_profile=values(account.get("profileId")), google_client=values(client))
    uid = native.get("uniqueQualifier")
    identity = [tenant, native["customerId"], dataset, native["time"], uid, index]
    if not uid:
        identity.append(record)
    eid = "EVT-" + digest(encode(identity))[:24]
    event = Event(tenant, eid, native["time"], iso(timestamp(native["time"])), "google_workspace", dataset,
                  kind, operation, {"user": user}, {"resource": target}, {"src_ip": ip, "country": None,
                  "region": None, "asn": None}, {"id": None}, {"id": None}, result, entities,
                  {**evidence, "source_event_id": uid, "event_index": index}, {"folders": [], "ip": ip})
    return {**asdict(event), "workspace": data}


def correlations(events):
    """Join observed activity within one customer and user. Revocation ends grant attribution."""
    logins, grants, findings = {}, {}, []
    revocations = {(e["tenant_id"], e["workspace"]["customer_id"], e["actor"]["user"],
                    e["workspace"].get("oauth_client_id"), e["timestamp_utc"])
                   for e in events if e["event_type"] == "google.oauth.revoke" and e["result"] != "failure"}
    def emit(rule, label, chain, join):
        ids = [e["event_id"] for e in chain]
        fid = "F-" + digest(encode([rule, ids]))[:16]
        findings.append(dict(id=fid, rule=rule, tenant=chain[0]["tenant_id"], observation=label,
                             join=join, confidence="High", assessment="Contextual", event_ids=ids,
                             evidence=[e["evidence"] for e in chain],
                             event_evidence=[dict(event_id=e["event_id"], references=evidence_references(e)) for e in chain]))
        for e in chain:
            e["finding_ids"].append(fid)
            if e["assessment"] == "Unknown":
                e["assessment"] = "Contextual"

    for e in events:
        details = e.get("workspace")
        if not details or not e["actor"]["user"] or e["result"] in ("failure", "denied"):
            continue
        user, ip = e["actor"]["user"], e["network"]["src_ip"]
        customer, client = details["customer_id"], details.get("oauth_client_id")
        account = (e["tenant_id"], customer, user)
        login_key, app_key = (*account, ip), (*account, client)
        kind, at = e["event_type"], timestamp(e["timestamp_utc"])
        if kind == "google.login.success" and ip:
            logins[login_key] = (at, e)
        elif kind == "google.login.logout":
            for key in [k for k in logins if k[:3] == account and (not ip or k[-1] == ip)]:
                del logins[key]
        elif kind == "google.oauth.revoke":
            grants.pop(app_key, None)
        elif (*app_key, e["timestamp_utc"]) in revocations:
            continue  # Equal timestamps cannot establish whether this client still had access.
        elif kind == "google.oauth.grant" and client:
            chain = [e]
            login = logins.get(login_key)
            if login and timedelta(0) < at - login[0] <= timedelta(minutes=30):
                chain.insert(0, login[1])
                emit("workspace-login-grant", "Workspace login followed by OAuth authorization from the same IP",
                     chain, dict(user=user, ip=ip, client_id=client))
            grants[app_key] = (at, chain)
        elif client and (kind == "google.gmail.app_access" or
                kind == "google.oauth.use" and any(str(v).casefold() == "gmail"
                    for k in ("product_bucket", "api_name") for v in details.get(k, []))):
            grant = grants.get(app_key)
            if grant and timedelta(0) < at - grant[0] <= timedelta(hours=2):
                label = "Workspace OAuth grant followed by " + ("Gmail message access" if kind == "google.gmail.app_access" else "a Gmail API call")
                chain = grant[1] + [e]
                join = dict(user=user, client_id=client)
                if len(chain) == 3:
                    join["login_grant_ip"] = chain[0]["network"]["src_ip"]
                emit("workspace-grant-gmail", label, chain, join)
    return findings
