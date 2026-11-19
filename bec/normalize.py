"""Vendor-specific field mappings. All pointers identify zero-based raw records."""
import ipaddress
import json
from dataclasses import asdict, dataclass, field

from .hunting import TABLES
from .storage import CaseError, GOOGLE_APPS, digest, iso, timestamp


@dataclass
class Event:
    tenant_id: str
    event_id: str
    timestamp_original: str
    timestamp_utc: str
    source: str
    dataset: str
    event_type: str
    operation: str
    actor: dict
    target: dict
    network: dict
    device: dict
    session: dict
    result: str
    entities: dict
    evidence: dict
    traits: dict
    assessment: str = "Unknown"
    confidence: str = "Low"
    relevance_score: int = 0
    reasons: list = field(default_factory=list)
    anomalies: list = field(default_factory=list)
    finding_ids: list = field(default_factory=list)
    phase: str = "Other activity"


def records(data, dataset=None):
    text = data.decode("utf-8-sig")
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        if dataset is not None and dataset not in GOOGLE_APPS:
            raise
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if dataset in GOOGLE_APPS or (dataset is None and isinstance(obj, dict)
            and ("items" in obj or "activities" in obj or "events" in obj
                 or obj.get("kind") in ("admin#reports#activities", "audit#activities", "reports#activities"))):
        if isinstance(obj, dict):
            if "id" in obj and "events" in obj:
                return [obj]
            if "items" in obj or obj.get("kind") in ("admin#reports#activities", "audit#activities", "reports#activities"):
                obj = obj.get("items", [])
            elif "activities" in obj:
                obj = obj["activities"]
        if not isinstance(obj, list):
            raise CaseError("Expected a Reports items array or a native Workspace activity export.")
        return obj
    rows = obj.get("value", obj.get("results", obj.get("Results"))) if isinstance(obj, dict) else obj
    if not isinstance(rows, list):
        raise CaseError("Expected a JSON array, Graph value array, or hunting results array.")
    return rows


def object_value(val):
    if isinstance(val, str):
        val = json.loads(val)
    if not isinstance(val, dict):
        raise CaseError("Expected an object record.")
    return val


def ual_body(row):
    return object_value(row.get("auditData", row.get("AuditData", row)))


def original_time(dataset, row):
    if dataset in GOOGLE_APPS:
        return row["id"]["time"]
    if dataset in TABLES:
        return row.get("Timestamp") or row.get("timestamp")
    if dataset == "ual":
        return row.get("createdDateTime") or ual_body(row).get("CreationTime")
    if dataset == "trace":
        return row.get("receivedDateTime") or row.get("Received")
    return row.get("activityDateTime" if dataset == "directory" else "createdDateTime")


def event_time(dataset, row):
    native_utc = (dataset == "ual" and not row.get("createdDateTime") or
                  dataset == "trace" and "Received" in row and not row.get("receivedDateTime"))
    return timestamp(original_time(dataset, row), vendor_utc=native_utc)


def canonical_ip(value):
    if not value:
        return None
    text = str(value).strip()
    if text.startswith("["):
        text = text[1:].split("]")[0]
    elif "." in text and text.count(":") == 1:
        text = text.split(":")[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def values(*args):
    return list(dict.fromkeys(str(v) for v in args if v is not None and v != ""))


def address(value):
    return str(value).casefold() if value else None


def network_id(value):
    value = str(value or "").strip().lower()
    if not value or value in ("0", "unknown", "none", "n/a") or set(value.replace("-", "")) == {"0"}:
        return None
    return value


def defender_event(tenant, dataset, raw, evidence):
    # Graph can return either native column names or lower-camel-case properties.
    row = {key.casefold(): value for key, value in raw.items()}
    get = row.get
    sender, recipient = address(get("senderfromaddress")), address(get("recipientemailaddress"))
    account = address(get("accountupn"))
    nid = network_id(get("networkmessageid"))
    kind, label = {
        "EmailEvents": ("email.processed", "Email processed"),
        "EmailUrlInfo": ("email.url", "URL found in email"),
        "EmailAttachmentInfo": ("email.attachment", "Attachment found in email"),
        "EmailPostDeliveryEvents": ("email.postdelivery", "Post-delivery action"),
        "UrlClickEvents": ("email.click", "Safe Links click"),
        "AlertEvidence": ("xdr.alert", "XDR alert evidence"),
    }[dataset]
    status = get("deliveryaction") or get("actionresult") or get("actiontype") or "observed"
    subject = get("subject") or get("emailsubject")
    detail = {"EmailEvents": subject or status, "UrlClickEvents": get("actiontype"),
              "EmailAttachmentInfo": get("filename"), "EmailPostDeliveryEvents": get("actiontype"),
              "AlertEvidence": get("title")}.get(dataset)
    entities = dict(user=values(sender, recipient, account), ip=[], session=[], device=values(get("deviceid")),
                    app=[], principal=[], message=values(get("internetmessageid")), mailbox=values(recipient),
                    domain=values(get("urldomain")), correlation=[], network_message=values(nid),
                    url=values(get("url") or get("remoteurl")), filename=values(get("filename")),
                    sha256=values(get("sha256")), sha1=values(get("sha1")), alert=values(get("alertid")))
    ip = canonical_ip(get("ipaddress"))
    entities["ip"] = values(ip)
    fields = ("Subject", "EmailSubject", "DeliveryAction", "DeliveryLocation", "EmailDirection", "Url",
              "UrlDomain", "UrlLocation", "FileName", "SHA256", "SHA1", "FileSize", "FileType",
              "ThreatTypes", "ThreatNames", "Action", "ActionType", "ActionResult", "IsClickedThrough",
              "Workload", "AlertId", "Title", "Severity", "ServiceSource", "EntityType", "EvidenceRole",
              "RemoteUrl", "UrlChain", "AccountUpn", "RecipientEmailAddress", "SenderFromAddress")
    observed = {key: get(key.casefold()) for key in fields if get(key.casefold()) not in (None, "")}
    eid = "EVT-" + digest(json.dumps([tenant, dataset, row], sort_keys=True).encode())[:24]
    original = original_time(dataset, raw)
    event = Event(tenant, eid, original, iso(event_time(dataset, raw)), "defender", dataset, kind,
                  f"{label} ({detail})" if detail else label, {"user": account or sender},
                  {"resource": recipient or get("url") or get("emailsubject")}, {"src_ip": ip, "country": None,
                  "region": None, "asn": None}, {"id": get("deviceid"), "hostname": get("devicename")},
                  {"id": None, "correlation_id": None}, str(status), entities,
                  {**evidence, "source_event_id": get("reportid") or get("alertid")}, {"folders": []})
    return {**asdict(event), "defender": observed}


OPS = {
    "mailitemsaccessed": "mail.access", "new-inboxrule": "mail.rule.create",
    "set-inboxrule": "mail.rule.modify", "updateinboxrules": "mail.rule.modify",
    "remove-inboxrule": "mail.rule.remove", "send": "mail.send", "sendas": "mail.send",
    "sendonbehalf": "mail.send", "move": "mail.move", "movetodeleteditems": "mail.delete",
    "softdelete": "mail.delete", "harddelete": "mail.delete", "searchqueryinitiatedexchange": "mail.search",
}


def directory_type(operation):
    name = operation.casefold()
    if any(term in name for term in ("consent to application", "add delegated permission grant",
                                      "add oauth2permissiongrant", "add app role assignment to service principal")):
        return "oauth.grant"
    if any(term in name for term in ("authentication method", "security info", "strong authentication")):
        return "identity.method_change"
    if "service principal" in name:
        return "identity.service_principal"
    return "identity.audit"


def normalize(tenant, dataset, row, evidence):
    row = object_value(row)
    if dataset in TABLES:
        return defender_event(tenant, dataset, row, evidence)
    original = original_time(dataset, row)
    when = iso(event_time(dataset, row))
    actor = target = ip = country = region = asn = session = correlation = None
    app = service = agent = client = mailbox = None
    device = {}
    users, apps, principals, messages, folders, methods = [], [], [], [], [], []
    result = "unknown"
    source_id = row.get("id")
    if dataset in ("interactive", "noninteractive", "service_principal"):
        source = "entra"
        code = (row.get("status") or {}).get("errorCode")
        if code is not None:
            result = "success" if str(code) == "0" else "failure"
        family = "application" if dataset == "service_principal" else "authentication"
        kind = family + "." + result
        operation = kind
        actor = row.get("userPrincipalName")
        target = row.get("resourceDisplayName")
        ip = row.get("ipAddress")
        location = row.get("location") or {}
        country, region = location.get("countryOrRegion"), location.get("state")
        asn = row.get("autonomousSystemNumber")
        device = row.get("deviceDetail") or {}
        session, correlation = row.get("sessionId"), row.get("correlationId")
        app, service = row.get("appId"), row.get("servicePrincipalId")
        methods = row.get("authenticationMethodsUsed") or []
        agent, client = row.get("userAgent"), row.get("clientAppUsed")
    elif dataset == "ual":
        source = "exchange"
        body = ual_body(row)
        source_id = body.get("Id") or source_id
        operation = str(body.get("Operation") or row.get("operation") or "Unknown")
        kind = OPS.get(operation.casefold(), "audit.other")
        actor = body.get("UserId") or row.get("userPrincipalName") or row.get("userId")
        mailbox = body.get("MailboxOwnerUPN")
        target = mailbox or body.get("ObjectId") or row.get("objectId")
        ip = body.get("ClientIPAddress") or body.get("ClientIP") or row.get("clientIp")
        ctx = body.get("AppAccessContext") or {}
        session = ctx.get("AADSessionId") or body.get("SessionId")
        correlation = body.get("CorrelationId") or ctx.get("CorrelationId")
        agent, app = body.get("ClientInfoString"), ctx.get("ClientAppId") or body.get("AppId")
        for folder in body.get("Folders") or []:
            folders.extend(values(folder.get("Path")))
            for item in folder.get("FolderItems") or []:
                messages.extend(values(item.get("InternetMessageId")))
        for item in body.get("AffectedItems") or []:
            messages.extend(values(item.get("InternetMessageId")))
        messages.extend(values((body.get("Item") or {}).get("InternetMessageId"), body.get("InternetMessageId")))
        result = str(body.get("ResultStatus") or "unknown").lower()
        country = body.get("Country") or body.get("CountryOrRegion")
    elif dataset == "directory":
        source = "entra"
        operation = str(row.get("activityDisplayName") or "Directory activity")
        kind = directory_type(operation)
        init = row.get("initiatedBy") or {}
        usr, app_obj = init.get("user") or {}, init.get("app") or {}
        actor, ip = usr.get("userPrincipalName"), usr.get("ipAddress")
        app, service = app_obj.get("appId"), app_obj.get("servicePrincipalId")
        targets = row.get("targetResources") or []
        names = []
        for item in targets:
            users.extend(values(address(item.get("userPrincipalName"))))
            names.extend(values(item.get("displayName") or item.get("userPrincipalName") or item.get("id")))
            typ = str(item.get("type", "")).casefold()
            if typ == "serviceprincipal":
                principals.extend(values(item.get("id")))
            for prop in item.get("modifiedProperties") or []:
                if prop.get("displayName") in ("AppId", "ServicePrincipal.AppId"):
                    apps.extend(values(str(prop.get("newValue") or "").strip('"[] ')))
        target = ", ".join(names)
        correlation, result = row.get("correlationId"), str(row.get("result") or "unknown").lower()
    elif dataset == "trace":
        source = "exchange"
        source_id = source_id or row.get("MessageTraceId")
        result = str(row.get("status") or row.get("Status") or "unknown").lower()
        kind = "mail.delivery" if result == "delivered" else "mail.trace"
        operation = f"Message trace ({result})"
        actor = row.get("senderAddress") or row.get("SenderAddress")
        target = row.get("recipientAddress") or row.get("RecipientAddress")
        users.extend(values(address(target)))
        ip = row.get("fromIP") or row.get("FromIP")
        messages.extend(values(row.get("messageId") or row.get("MessageId")))
    else:
        raise CaseError("Unknown dataset.")
    actor = address(actor)
    ip = canonical_ip(ip)
    users = values(actor, *users, address(mailbox))
    entities = {
        "user": users, "ip": values(ip), "session": values(session), "device": values(device.get("deviceId")),
        "app": values(app, *apps), "principal": values(service, *principals), "message": values(*messages),
        "mailbox": values(address(mailbox)), "domain": values(*(u.rsplit("@", 1)[1] for u in users if "@" in u)),
        "correlation": values(correlation),
    }
    # Per-recipient Exchange traces can share an ID.
    identity = [tenant, dataset, str(source_id), address(target) if dataset == "trace" else None]
    if not source_id:
        identity.append(digest(json.dumps(row, sort_keys=True).encode()))
    event_id = "EVT-" + digest(json.dumps(identity).encode())[:24]
    if dataset == "directory":
        entities["user_id"] = values(*(t.get("id") for t in targets if str(t.get("type", "")).lower() == "user"))
    traits = dict(ip=ip, country=country, region=region, asn=asn, device=device.get("deviceId"),
                  os=device.get("operatingSystem"), browser=device.get("browser"), user_agent=agent,
                  client_application=client, authentication_method=methods, application=app,
                  hour=int(when[11:13]), folders=values(*folders))
    return asdict(Event(tenant, event_id, original, when, source, dataset, kind, operation,
                        {"user": actor}, {"resource": target}, {"src_ip": ip, "country": country,
                        "region": region, "asn": asn}, {"id": device.get("deviceId"),
                        "hostname": device.get("displayName"), "os": device.get("operatingSystem"),
                        "browser": device.get("browser")}, {"id": session, "correlation_id": correlation},
                        result, entities, {**evidence, "source_event_id": source_id}, traits))
