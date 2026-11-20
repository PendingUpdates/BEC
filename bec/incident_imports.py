"""Strict, write-free verification of approved incident metadata exports (v1).

The caller supplies IncidentScope independently of the file and obtains an
AcquisitionAttestation for the exact input SHA-256. That attestation means the
operator vouches for a tenant- and target-scoped acquisition; it is NOT a
signature, independent proof of provider origin, or evidence of completeness.
Never construct approval merely from claims found in the input file.

Formats are UTF-8 (optional BOM), with native field spelling and values intact.
Purview and Entra JSON inputs are arrays of projected native records. Defender
JSON retains the native streaming wrapper: {"records": [{"tenantId", "time",
"category", "properties"}]}. Only the two Entra user-sign-in sources accept
native CSV: one header, RFC-style quoted cells, no duplicate/unknown columns.
CSV IsInteractive is true/false; AuthenticationMethodsUsed is a JSON array of
method names or one documented method name. CSV locators count logical records
(csv:1 is the header). JSON locators are RFC 6901 pointers into unchanged bytes.

Required/optional columns are exported below. Unknown fields, even nested ones,
refuse the WHOLE input. Full exports containing bodies, URLs, secrets, method
details, modifiedProperties, policy/group data or unrelated rows are not this
format. Use an explicitly authorized metadata projection at acquisition; never
change tenant/target fields to make an existing export pass. The returned raw
bytes are the submitted export, not a claim of original service HTTP bytes.

All Entra rows need the independently pinned user_object_id. All Purview rows
need the independently pinned mailbox_guid, including shared mailboxes. The two
workload sources additionally require an explicitly approved service-principal
GUID and a previously validated target-user audit source. Every workload row
must match that native principal AND correlation GUID in an audit app actor;
this is related workload evidence, never the user's authentication. All matched
audit locators are retained. Actor-only mailbox audits, current MFA inventory,
device-only attribution, Azure/Intune and general Graph exports are unsupported.
Names, policy membership and temporal proximity cannot establish these links.
A caller must finish validation before writing.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import io
import ipaddress
import json
import re
import unicodedata
import uuid

from .component_types import BoundSource, SourceCoverage, SourceRow
from .storage import CaseError


CONTRACT = "bec.incident-import/v1"
MAX_BYTES = 16 * 1024 * 1024
MAX_ROWS = 10000
MAX_WORKLOAD_ROWS = 1000
MAX_LINKABLE_AUDIT_ROWS = 1000
MAX_LINKS_PER_ROW = 32
TICKS_PER_SECOND = 10_000_000
SOURCE_FORMATS = {
    "purview.mailbox-audit": ("json",),
    "entra.audit-logs": ("json",),
    "entra.user-signins.interactive": ("json", "csv"),
    "entra.user-signins.noninteractive": ("json", "csv"),
    "entra.workload-signins.service-principal": ("json",),
    "entra.workload-signins.managed-identity": ("json",),
    "defender.url-clicks": ("json",),
}
SUPPORTED_SOURCES = frozenset(SOURCE_FORMATS)
SOURCE_BASES = {
    "purview.mailbox-audit": "mailbox-targeted",
    "entra.audit-logs": "user-targeted",
    "entra.user-signins.interactive": "user-targeted",
    "entra.user-signins.noninteractive": "user-targeted",
    "entra.workload-signins.service-principal": "case-linked-workload",
    "entra.workload-signins.managed-identity": "case-linked-workload",
    "defender.url-clicks": "clicker-targeted",
}
SOURCE_DATASETS = {
    "purview.mailbox-audit": "purview_mailbox_audit",
    "entra.audit-logs": "entra_audit",
    "entra.user-signins.interactive": "entra_user_interactive",
    "entra.user-signins.noninteractive": "entra_user_noninteractive",
    "entra.workload-signins.service-principal": "entra_workload_service_principal",
    "entra.workload-signins.managed-identity": "entra_workload_managed_identity",
    "defender.url-clicks": "defender_url_clicks",
}
SCHEMA_REFERENCES = {
    "purview.mailbox-audit": "https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema",
    "purview.mailbox-actions": "https://learn.microsoft.com/microsoft-365/compliance/enable-mailbox-auditing",
    "entra.audit-logs": "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs",
    "entra.audit-activities": "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities",
    "entra.user-signins.interactive": "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs",
    "entra.user-signins.noninteractive": "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs",
    "entra.workload-signins.service-principal": "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs",
    "entra.workload-signins.managed-identity": "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs",
    "defender.url-clicks": "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table",
    "defender.streaming": "https://learn.microsoft.com/en-us/defender-xdr/streaming-api-event-hub",
}

PURVIEW_REQUIRED = frozenset({"Id", "OrganizationId", "MailboxOwnerUPN", "MailboxGuid", "CreationTime",
                              "Operation", "Workload", "ResultStatus"})
PURVIEW_OPTIONAL = frozenset({"UserId", "RecordType", "LogonType", "ExternalAccess", "CrossMailboxOperations"})
AUDIT_REQUIRED = frozenset({"Id", "AADTenantId", "ActivityDateTime", "ActivityDisplayName", "Result", "TargetResources", "Type"})
AUDIT_OPTIONAL = frozenset({"TenantId", "TimeGenerated", "OperationName", "ResultType", "CorrelationId", "InitiatedBy"})
SIGNIN_REQUIRED = frozenset({"Id", "AADTenantId", "UserId", "UserPrincipalName", "CreatedDateTime", "IsInteractive", "ResultType", "Type"})
SIGNIN_OPTIONAL = frozenset({"TenantId", "TimeGenerated", "IPAddress", "AppId", "AuthenticationMethodsUsed", "AuthenticationRequirement"})
WORKLOAD_REQUIRED = frozenset({"Id", "AADTenantId", "ServicePrincipalId", "CorrelationId", "CreatedDateTime", "ResultType", "Type"})
WORKLOAD_OPTIONAL = frozenset({"TenantId", "TimeGenerated", "IPAddress", "AppId"})
CLICK_REQUIRED = frozenset({"Timestamp", "AccountUpn", "ReportId", "ActionType", "IsClickedThrough", "Workload"})
CLICK_OPTIONAL = frozenset({"TimeGenerated", "TenantId", "NetworkMessageId", "IPAddress", "Type"})

PURVIEW_OPERATIONS = frozenset({"MailItemsAccessed", "Send", "SendAs", "SendOnBehalf", "Move", "MoveToDeletedItems", "SoftDelete", "HardDelete", "UpdateInboxRules"})
PASSWORD_COMPLETED = frozenset({"Change password", "Reset password", "Change password (self-service)",
                                "Reset password (by admin)", "Reset password (self-service)"})
PASSWORD_ATTEMPTS = frozenset({"Admin started password reset", "User started password change", "user started password reset",
                               "User started password reset", "Blocked from self-service password reset",
                               "Self-service password reset flow activity progress"})
MFA_OPERATIONS = frozenset({"Admin deleted security info", "Admin registered security info", "Admin updated security info",
                           "User canceled security info registration", "User changed default security info",
                           "User deleted security info", "User registered all required security info",
                           "User registered security info", "User reviewed security info",
                           "User started security info registration", "User updated security info",
                           "Security info saved for self-service password reset"})
MFA_METHOD_OPERATIONS = {
    "Add Passkey (device-bound)": "device-bound passkey", "Delete Passkey (device-bound)": "device-bound passkey",
    "Add Windows Hello for Business credential": "Windows Hello for Business",
    "Delete Windows Hello for Business credential": "Windows Hello for Business",
    "Add passwordless phone sign-in credential": "passwordless phone sign-in",
    "Delete passwordless phone sign-in credential": "passwordless phone sign-in",
    "Add platform credential": "platform credential", "Delete platform credential": "platform credential",
}
DEVICE_OPERATIONS = frozenset({"Register device", "Unregister device", "Add registered owner to device",
                              "Remove registered owner from device", "Add registered users to device", "Remove registered users from device"})
METHOD_TYPES = frozenset({"SMS", "Authenticator App", "App Verification code", "Password", "FIDO", "PTA", "PHS"})


@dataclass(frozen=True)
class IncidentScope:
    tenant_id: str
    account: str
    start: str
    end: str
    user_object_id: str | None = None
    mailbox_guid: str | None = None


@dataclass(frozen=True)
class AcquisitionAttestation:
    source: str
    tenant_id: str
    account: str
    start: str
    end: str
    acquired_at: str
    input_sha256: str
    scope_basis: str
    format: str
    attested_by: str


def _text(value, label, limit=320):
    if (not isinstance(value, str) or not value or len(value) > limit or value != value.strip()
            or any(unicodedata.category(c).startswith("C") for c in value)):
        raise CaseError(f"Invalid {label}; use the documented metadata projection.")
    return value


def _guid(value, label):
    _text(value, label, 36)
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise CaseError(f"Invalid native {label} GUID.") from None
    if not parsed.int:
        raise CaseError(f"Empty native {label} GUID.")
    return str(parsed)


def _account(value):
    value = _text(value, "account")
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
        raise CaseError("An exact account UPN is required.")
    if any(char in value for char in "*?[]") or ".." in value:
        raise CaseError("An exact account UPN is required.")
    return value.casefold()


def _identifier(value):
    value = _text(value, "native event identifier", 128)
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]+", value):
        raise CaseError("Invalid native event identifier.")
    return value


def _instant(value):
    """Compare all seven native fractional digits; never round an exclusive end inwards."""
    if not isinstance(value, str):
        raise CaseError("Use explicit ISO UTC timestamps.")
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(?:Z|\+00:00)", value)
    if not match:
        raise CaseError("Use explicit ISO UTC timestamps with at most seven fractional digits.")
    try:
        date = datetime.fromisoformat(match[1]).replace(tzinfo=UTC)
    except ValueError:
        raise CaseError("Invalid UTC timestamp.") from None
    fraction = (match[2] or "").ljust(7, "0")
    ticks = ((date.toordinal() * 86400 + date.hour * 3600 + date.minute * 60 + date.second)
             * TICKS_PER_SECOND + int(fraction))
    precision = fraction if fraction[-1] != "0" else fraction[:6]
    return f"{match[1]}.{precision}Z", ticks


def _strict_fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or set(value) - set(required) - set(optional):
        raise CaseError("Missing, unknown or prohibited fields in the incident metadata projection.")


def _unique_object(pairs):
    value, seen = {}, set()
    for key, child in pairs:
        if key.casefold() in seen:
            raise CaseError("Duplicate or case-ambiguous JSON fields in incident input.")
        seen.add(key.casefold())
        value[key] = child
    return value


def _json(text):
    def invalid_number(_):
        raise CaseError("Non-finite JSON numbers are not supported.")
    try:
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=invalid_number)
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, CaseError):
            raise
        raise CaseError("Invalid incident JSON.") from None


def _parse(raw, source, format):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise CaseError("Incident exports must be UTF-8.") from None
    if format == "json":
        parsed = _json(text)
        if source == "defender.url-clicks":
            _strict_fields(parsed, {"records"})
            parsed, prefix = parsed["records"], "/records"
        else:
            prefix = ""
        if not isinstance(parsed, list) or len(parsed) > MAX_ROWS:
            raise CaseError("Incident JSON must contain a bounded record array.")
        return [(row, f"{prefix}/{index}") for index, row in enumerate(parsed)]
    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(reader)
        if len(set(name.casefold() for name in header)) != len(header):
            raise CaseError("Duplicate or case-ambiguous CSV columns.")
        _strict_fields(dict.fromkeys(header), SIGNIN_REQUIRED, SIGNIN_OPTIONAL)
        rows = []
        for index, cells in enumerate(reader, start=2):
            if len(cells) != len(header) or len(rows) >= MAX_ROWS:
                raise CaseError("Incident CSV must contain bounded, rectangular logical records.")
            row = dict(zip(header, cells))
            rows.append(({key: value for key, value in row.items() if value or key in SIGNIN_REQUIRED}, f"csv:{index}"))
        return rows
    except (csv.Error, StopIteration):
        raise CaseError("Invalid incident CSV.") from None


def _row_time(value, start, end):
    utc, tick = _instant(value)
    if not start <= tick < end:
        raise CaseError("An incident row falls outside the authorized half-open UTC window.")
    return utc


def _tenant(row, key, expected):
    if _guid(row[key], "tenant") != expected:
        raise CaseError("An incident row has a different native customer tenant.")


def _workspace(row, fields):
    if "TenantId" in row:
        fields["log_analytics_workspace_id"] = _guid(row["TenantId"], "workspace")


def _recorded_time(row, fields, acquired_tick):
    if "TimeGenerated" in row:
        utc, tick = _instant(row["TimeGenerated"])
        if tick > acquired_tick:
            raise CaseError("A source record timestamp is later than its acquisition attestation.")
        fields["source_time_generated"] = utc


def _purview(row, pointer, scope, start, end):
    _strict_fields(row, PURVIEW_REQUIRED, PURVIEW_OPTIONAL)
    _tenant(row, "OrganizationId", scope.tenant_id)
    if _account(row["MailboxOwnerUPN"]) != scope.account or _guid(row["MailboxGuid"], "mailbox") != scope.mailbox_guid:
        raise CaseError("Purview must identify the authorized mailbox UPN and independently pinned mailbox GUID.")
    operation = _text(row["Operation"], "mailbox operation", 100)
    result_status = _text(row["ResultStatus"], "mailbox result", 32)
    if row["Workload"] != "Exchange" or operation not in PURVIEW_OPERATIONS:
        raise CaseError("This Purview operation is not an explicitly mapped mailbox event.")
    if result_status not in {"Succeeded", "PartiallySucceeded", "Failed"}:
        raise CaseError("Unsupported native mailbox audit result.")
    fields = {"event_type": "mailbox.audit", "mailbox_upn": scope.account, "mailbox_guid": scope.mailbox_guid,
              "native_result": row["ResultStatus"], "target_basis": "MailboxOwnerUPN and MailboxGuid"}
    if operation == "UpdateInboxRules":
        fields.update(event_type="mailbox.rule.event", interpretation="Historical mailbox rule operation only; no current rule state or rule details retained.")
    if "CrossMailboxOperations" in row and row["CrossMailboxOperations"] is not False:
        raise CaseError("Cross-mailbox or ambiguous mailbox operations are not supported.")
    for key, allowed in (("RecordType", {2, 3, 19, 50}), ("LogonType", set(range(7)))):
        if key in row:
            if type(row[key]) is not int or row[key] not in allowed:
                raise CaseError("Invalid native mailbox audit metadata.")
            fields[key] = str(row[key])
    if "ExternalAccess" in row:
        if type(row["ExternalAccess"]) is not bool:
            raise CaseError("ExternalAccess must be a native boolean.")
        fields["external_access"] = str(row["ExternalAccess"]).lower()
    if "UserId" in row:
        # The actor is metadata only; it never supplies the target binding.
        fields["actor_upn"] = _account(row["UserId"])
    return SourceRow("purview_mailbox_audit", "event", _row_time(row["CreationTime"], start, end),
                     row["Operation"], _guid(row["Id"], "audit event"), pointer, fields)


def _audit_actor(value, fields):
    fields["actor_type"] = "unknown"
    if value is None:
        return
    _strict_fields(value, set(), {"user", "app"})
    present = [(name, actor) for name, actor in value.items() if actor is not None]
    if not present:
        return
    if len(present) != 1:
        raise CaseError("An audit row must not contain ambiguous user/application actors.")
    name, actor = present[0]
    if name == "user":
        _strict_fields(actor, {"id"}, {"userPrincipalName"})
        fields.update(actor_type="user", actor_user_id=_guid(actor["id"], "audit actor"))
        if "userPrincipalName" in actor:
            fields["actor_upn"] = _account(actor["userPrincipalName"])
    else:
        _strict_fields(actor, {"servicePrincipalId"}, {"appId"})
        fields.update(actor_type="service_principal", actor_service_principal_id=_guid(actor["servicePrincipalId"], "audit actor service principal"))
        if "appId" in actor:
            fields["actor_app_id"] = _guid(actor["appId"], "audit actor application")


def _audit(row, pointer, scope, start, end, acquired):
    _strict_fields(row, AUDIT_REQUIRED, AUDIT_OPTIONAL)
    _tenant(row, "AADTenantId", scope.tenant_id)
    if row["Type"] != "AuditLogs":
        raise CaseError("Expected a native AuditLogs record.")
    operation = _text(row["ActivityDisplayName"], "audit operation", 100)
    if "OperationName" in row and row["OperationName"] != operation:
        raise CaseError("Native audit operation names disagree.")
    native_result = _text(row["Result"], "directory audit result", 32)
    if native_result not in {"success", "failure", "timeout", "unknownFutureValue"}:
        raise CaseError("Unsupported native directory audit result.")
    if "ResultType" in row and (not isinstance(row["ResultType"], str) or row["ResultType"] not in {"Success", "Failure"}
            or (row["ResultType"] == "Success") != (row["Result"] == "success")):
        raise CaseError("Native audit result fields disagree.")
    device = operation in DEVICE_OPERATIONS
    targets = row["TargetResources"]
    if not isinstance(targets, list) or len(targets) != (2 if device else 1):
        raise CaseError("Audit targets must identify only the authorized user and an explicitly linked device where required.")
    user_index, device_id = None, None
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            raise CaseError("Invalid audit target resource.")
        if target.get("type") == "User":
            _strict_fields(target, {"id", "type", "userPrincipalName"})
            if user_index is not None or _guid(target["id"], "user") != scope.user_object_id or _account(target["userPrincipalName"]) != scope.account:
                raise CaseError("Audit target differs from the independently authorized user.")
            user_index = index
        elif device and target.get("type") == "Device":
            _strict_fields(target, {"id", "type"})
            if device_id is not None:
                raise CaseError("Ambiguous audit device targets.")
            device_id = _guid(target["id"], "device")
        else:
            raise CaseError("Policy, group, application and unlinked target resources are outside this mapping.")
    if user_index is None or device and device_id is None:
        raise CaseError("A positive native user target is required; actor-only association is insufficient.")
    fields = {"user_object_id": scope.user_object_id, "target_upn": scope.account, "native_result": row["Result"],
              "target_locator": f"{pointer}/TargetResources/{user_index}"}
    if operation in PASSWORD_COMPLETED | PASSWORD_ATTEMPTS:
        confirmed = operation in PASSWORD_COMPLETED and row["Result"] == "success"
        kind, dataset = ("password.change.source_confirmed" if confirmed else "password.attempt"), "entra_password"
        fields.update(change_confirmed_by_source=str(confirmed).lower(),
                      interpretation="A started/progress operation never proves a changed password; source success is not independent state verification.")
    elif operation in MFA_OPERATIONS or operation in MFA_METHOD_OPERATIONS:
        kind, dataset = "authentication_method.event", "entra_mfa_events"
        fields["interpretation"] = "Historical security-info event only; no current method inventory or secret material."
        if operation in MFA_METHOD_OPERATIONS:
            fields["method_type"] = MFA_METHOD_OPERATIONS[operation]
    elif device:
        kind, dataset = "device.registration.event", "entra_device_registration"
        fields.update(device_id=device_id, interpretation="Native co-targeted registration event; not current device ownership, compliance or posture.")
    else:
        raise CaseError("The directory audit operation is not in this incident mapping.")
    fields["event_type"] = kind
    _audit_actor(row.get("InitiatedBy"), fields)
    if "CorrelationId" in row:
        fields["correlation_id"] = _guid(row["CorrelationId"], "correlation")
    _workspace(row, fields)
    _recorded_time(row, fields, acquired)
    return SourceRow(dataset, "event", _row_time(row["ActivityDateTime"], start, end), operation,
                     _guid(row["Id"], "audit event"), pointer, fields)


def _methods(value):
    if isinstance(value, str):
        values = _json(value) if value.startswith("[") else [value]
    else:
        values = value
    if (not isinstance(values, list) or len(values) > 10 or
            any(not isinstance(item, str) or item not in METHOD_TYPES for item in values)):
        raise CaseError("Only documented authentication method type names are supported; method details are prohibited.")
    return json.dumps(values, ensure_ascii=True, separators=(",", ":"))


def _signin(row, pointer, scope, start, end, acquired, source, format):
    _strict_fields(row, SIGNIN_REQUIRED, SIGNIN_OPTIONAL)
    _tenant(row, "AADTenantId", scope.tenant_id)
    if _guid(row["UserId"], "user") != scope.user_object_id or _account(row["UserPrincipalName"]) != scope.account:
        raise CaseError("Sign-in user differs from the independently authorized target.")
    interactive = source.endswith(".interactive")
    table = "SigninLogs" if interactive else "AADNonInteractiveUserSignInLogs"
    flag = row["IsInteractive"]
    if format == "csv" and isinstance(flag, str) and flag.casefold() in {"true", "false"}:
        flag = flag.casefold() == "true"
    if row["Type"] != table or type(flag) is not bool or flag != interactive:
        raise CaseError("Interactive, noninteractive and workload sign-in records must not be relabeled.")
    result = _text(row["ResultType"], "sign-in result", 16)
    if interactive:
        if not re.fullmatch(r"0|[1-9][0-9]{0,8}", result):
            raise CaseError("Expected the native SigninLogs error code.")
        outcome = "success" if result == "0" else "failure"
    else:
        if result not in {"Success", "Failure"} and not re.fullmatch(r"0|[1-9][0-9]{0,8}", result):
            raise CaseError("Unsupported noninteractive native result.")
        outcome = {"Success": "success", "Failure": "failure"}.get(result, "uninterpreted-native-code")
    fields = {"event_type": "user.signin", "user_object_id": scope.user_object_id, "user_principal_name": scope.account,
              "sign_in_class": "user-interactive" if interactive else "user-noninteractive",
              "native_result_type": result, "source_outcome": outcome}
    if "IPAddress" in row:
        try:
            fields["ip_address"] = str(ipaddress.ip_address(_text(row["IPAddress"], "IP address", 64)))
        except ValueError:
            raise CaseError("Invalid native sign-in IP address.") from None
    if "AppId" in row:
        fields["client_app_id"] = _guid(row["AppId"], "client application")
    if "AuthenticationMethodsUsed" in row:
        fields["authentication_method_types"] = _methods(row["AuthenticationMethodsUsed"])
        fields["method_interpretation"] = "Types reported for this sign-in; not enrollment history or current method inventory."
    if "AuthenticationRequirement" in row:
        if (not isinstance(row["AuthenticationRequirement"], str) or
                row["AuthenticationRequirement"] not in {"singleFactorAuthentication", "multiFactorAuthentication"}):
            raise CaseError("Unsupported authentication requirement.")
        fields["authentication_requirement"] = row["AuthenticationRequirement"]
    _workspace(row, fields)
    _recorded_time(row, fields, acquired)
    return SourceRow(SOURCE_DATASETS[source], "event", _row_time(row["CreatedDateTime"], start, end),
                     "Sign-in activity", _identifier(row["Id"]), pointer, fields)


def _click(row, pointer, scope, start, end, acquired):
    _strict_fields(row, {"tenantId", "time", "category", "properties"})
    _tenant(row, "tenantId", scope.tenant_id)
    if row["category"] != "AdvancedHunting-UrlClickEvents":
        raise CaseError("Expected the native Defender UrlClickEvents streaming category.")
    received, received_tick = _instant(row["time"])
    if received_tick > acquired:
        raise CaseError("Defender reception time is later than acquisition.")
    event = row["properties"]
    _strict_fields(event, CLICK_REQUIRED, CLICK_OPTIONAL)
    if _account(event["AccountUpn"]) != scope.account:
        raise CaseError("The Defender clicker is outside the authorized account scope.")
    action = _text(event["ActionType"], "click action", 32)
    workload = _text(event["Workload"], "click workload", 32)
    if action not in {"ClickAllowed", "ClickBlocked"} or type(event["IsClickedThrough"]) is not bool:
        raise CaseError("Unsupported Safe Links outcome or non-native click-through boolean.")
    if workload not in {"Email", "Office", "Teams"} or event.get("Type", "UrlClickEvents") != "UrlClickEvents":
        raise CaseError("Unsupported click workload or table.")
    event_utc = _row_time(event["Timestamp"], start, end)
    if "TimeGenerated" in event and _instant(event["TimeGenerated"])[1] != _instant(event["Timestamp"])[1]:
        raise CaseError("Defender click timestamps disagree.")
    fields = {"event_type": "safe_links.click", "clicker_upn": scope.account, "action_type": event["ActionType"],
              "is_clicked_through": str(event["IsClickedThrough"]).lower(), "workload": event["Workload"],
              "defender_received_at": received,
              "interpretation": "Source click outcome only; no credential submission, page-load, compromise or email-join inference."}
    _workspace(event, fields)
    if "NetworkMessageId" in event:
        fields["network_message_id"] = _guid(event["NetworkMessageId"], "network message")
    if "IPAddress" in event:
        try:
            fields["ip_address"] = str(ipaddress.ip_address(_text(event["IPAddress"], "IP address", 64)))
        except ValueError:
            raise CaseError("Invalid native click IP address.") from None
    # ReportId repeats across blocked/click-through observations: preserve every row and locator.
    return SourceRow("defender_url_clicks", "event", event_utc, event["ActionType"],
                     _identifier(event["ReportId"]), f"{pointer}/properties", fields)


def _workload_anchors(related, principal, scope):
    """Recheck original audit bytes rather than trusting mutable derived row fields."""
    principal = _guid(principal, "approved service principal")
    if not isinstance(related, BoundSource) or related.source != "entra.audit-logs" or related.extension != "json":
        raise CaseError("A separately validated target-user audit source is required for workload attribution.")
    if (_guid(related.tenant, "audit tenant") != scope.tenant_id or _account(related.account) != scope.account
            or _instant(related.start)[1] != _instant(scope.start)[1] or _instant(related.end)[1] != _instant(scope.end)[1]):
        raise CaseError("Related audit evidence belongs to a different incident scope.")
    fields = related.provenance
    required = {"mapping_contract", "attested_by", "acquisition_start", "acquisition_end", "scope_basis", "input_sha256"}
    if (not isinstance(fields, dict) or not required <= fields.keys() or
            any(not isinstance(fields[key], str) for key in required) or fields["mapping_contract"] != CONTRACT or
            fields["input_sha256"] != related.sha256):
        raise CaseError("Related audit evidence lacks its verified acquisition provenance.")
    approval = AcquisitionAttestation(related.source, related.tenant, related.account,
        fields["acquisition_start"], fields["acquisition_end"], related.acquired_at, related.sha256,
        fields["scope_basis"], related.extension, fields["attested_by"])
    verified = verify_incident_source(related.raw, source=related.source, scope=scope, acquisition=approval)
    if verified.rows != related.rows:
        raise CaseError("Related audit projections differ from the verified original bytes.")
    anchors, count = {}, 0
    for row in verified.rows:
        if row.fields.get("actor_service_principal_id") != principal or "correlation_id" not in row.fields:
            continue
        if row.fields.get("target_upn") != scope.account or row.fields.get("user_object_id") != scope.user_object_id:
            raise CaseError("Related audit has no positive target-user binding.")
        correlation = _guid(row.fields["correlation_id"], "audit correlation")
        anchors.setdefault(correlation, []).append(row.locator)
        count += 1
        if count > MAX_LINKABLE_AUDIT_ROWS or len(anchors[correlation]) > MAX_LINKS_PER_ROW:
            raise CaseError("Workload correlation exceeds the bounded audit-link budget; use a narrower authorized export.")
    if not anchors:
        raise CaseError("No validated target-user audit event contains the approved native principal and correlation GUID.")
    return principal, related.sha256, anchors


def _workload(row, pointer, scope, start, end, acquired, source, links):
    _strict_fields(row, WORKLOAD_REQUIRED, WORKLOAD_OPTIONAL)
    _tenant(row, "AADTenantId", scope.tenant_id)
    managed = source.endswith(".managed-identity")
    table = "AADManagedIdentitySignInLogs" if managed else "AADServicePrincipalSignInLogs"
    if row["Type"] != table:
        raise CaseError("Service-principal and managed-identity tables must not be swapped or relabeled.")
    principal, audit_sha, anchors = links
    if _guid(row["ServicePrincipalId"], "workload service principal") != principal:
        raise CaseError("Workload principal is outside the independently approved linkage.")
    correlation = _guid(row["CorrelationId"], "workload correlation")
    if correlation not in anchors:
        raise CaseError("Every workload sign-in needs its own native principal/correlation match in target-user audit evidence.")
    result = _text(row["ResultType"], "workload result", 16)
    if result not in {"Success", "Failure"} and not re.fullmatch(r"0|[1-9][0-9]{0,8}", result):
        raise CaseError("Unsupported native workload sign-in result.")
    fields = {"event_type": "workload.signin.related_audit", "service_principal_id": principal,
        "workload_identity_class": "managed-identity" if managed else "service-principal",
        "correlation_id": correlation, "native_result_type": result,
        "source_outcome": {"Success": "success", "Failure": "failure"}.get(result, "uninterpreted-native-code"),
        "related_audit_sha256": audit_sha,
        "related_audit_locators": json.dumps(anchors[correlation], ensure_ascii=True, separators=(",", ":")),
        "interpretation": "Related workload event matched to a targeted audit actor by native principal and correlation IDs; never the user's authentication or proof of compromise."}
    if "IPAddress" in row:
        try:
            fields["ip_address"] = str(ipaddress.ip_address(_text(row["IPAddress"], "IP address", 64)))
        except ValueError:
            raise CaseError("Invalid native workload IP address.") from None
    if "AppId" in row:
        fields["application_id"] = _guid(row["AppId"], "application")
    _workspace(row, fields)
    _recorded_time(row, fields, acquired)
    return SourceRow(SOURCE_DATASETS[source], "event", _row_time(row["CreatedDateTime"], start, end),
                     "Sign-in activity", _identifier(row["Id"]), pointer, fields)


def verify_incident_source(raw: bytes, *, source: str, scope: IncidentScope,
                           acquisition: AcquisitionAttestation, related_audit: BoundSource | None = None,
                           workload_principal_id: str | None = None) -> BoundSource:
    """Return unchanged approved bytes only after every record passes; perform no I/O."""
    if not isinstance(source, str) or source not in SOURCE_FORMATS:
        raise CaseError("Unsupported incident source; use an explicitly mapped native source.")
    if not isinstance(scope, IncidentScope) or not isinstance(acquisition, AcquisitionAttestation):
        raise CaseError("Independent incident scope and acquisition attestation are required.")
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise CaseError("Incident source must be nonempty bounded bytes.")
    sha = hashlib.sha256(raw).hexdigest()
    if not isinstance(acquisition.input_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", acquisition.input_sha256) or sha != acquisition.input_sha256:
        raise CaseError("Incident input bytes differ from the independently approved SHA-256.")
    if acquisition.source != source or acquisition.scope_basis != SOURCE_BASES[source] or acquisition.format not in SOURCE_FORMATS[source]:
        raise CaseError("Acquisition source, format or positive target scope attestation does not match.")
    tenant, account = _guid(scope.tenant_id, "tenant"), _account(scope.account)
    start, low = _instant(scope.start)
    end, high = _instant(scope.end)
    acquired_start, acquired_low = _instant(acquisition.start)
    acquired_end, acquired_high = _instant(acquisition.end)
    acquired_at, acquired_tick = _instant(acquisition.acquired_at)
    now_tick = _instant(datetime.now(UTC).isoformat(timespec="microseconds"))[1]
    if (not 0 < high - low <= 366 * 86400 * TICKS_PER_SECOND or high > now_tick or
            not low <= acquired_low < acquired_high <= high or acquired_high > acquired_tick or acquired_tick > now_tick):
        raise CaseError("Use a completed incident window up to 366 days and a valid later acquisition time.")
    if _guid(acquisition.tenant_id, "acquisition tenant") != tenant or _account(acquisition.account) != account:
        raise CaseError("Acquisition scope does not match the independent incident scope.")
    attested_by = _account(acquisition.attested_by)
    user_id = _guid(scope.user_object_id, "user") if scope.user_object_id is not None else None
    mailbox_id = _guid(scope.mailbox_guid, "mailbox") if scope.mailbox_guid is not None else None
    if source.startswith("entra.") and user_id is None:
        raise CaseError("An independently verified native user object GUID is required for Entra imports.")
    if source == "purview.mailbox-audit" and mailbox_id is None:
        raise CaseError("An independently verified mailbox GUID is required for Purview imports.")
    checked_scope = IncidentScope(tenant, account, start, end, user_id, mailbox_id)
    workload = source.startswith("entra.workload-signins.")
    if workload:
        links = _workload_anchors(related_audit, workload_principal_id, checked_scope)
    elif related_audit is not None or workload_principal_id is not None:
        raise CaseError("Workload linkage arguments are only valid for an approved workload source.")
    entries = _parse(raw, source, acquisition.format)
    if workload and len(entries) > MAX_WORKLOAD_ROWS:
        raise CaseError("Workload export exceeds its bounded row budget.")
    rows = []
    for row, locator in entries:
        if source == "purview.mailbox-audit":
            result = _purview(row, locator, checked_scope, acquired_low, acquired_high)
        elif source == "entra.audit-logs":
            result = _audit(row, locator, checked_scope, acquired_low, acquired_high, acquired_tick)
        elif source.startswith("entra.user-signins."):
            result = _signin(row, locator, checked_scope, acquired_low, acquired_high, acquired_tick, source, acquisition.format)
        elif workload:
            result = _workload(row, locator, checked_scope, acquired_low, acquired_high, acquired_tick, source, links)
        else:
            result = _click(row, locator, checked_scope, acquired_low, acquired_high, acquired_tick)
        rows.append(result)
    dataset = SOURCE_DATASETS[source]
    coverage = [SourceCoverage(dataset, "observed" if rows else "empty",
        "Approved metadata export only; completeness, licensing, retention and provider origin are not independently verified. Empty does not prove absence.", acquired_start, acquired_end)]
    if low < acquired_low:
        coverage.append(SourceCoverage(dataset, "not_collected", "This source acquisition did not cover the earlier case interval.", start, acquired_start))
    if acquired_high < high:
        coverage.append(SourceCoverage(dataset, "not_collected", "This source acquisition did not cover the later case interval.", acquired_end, end))
    if source.startswith("entra."):
        coverage.extend((SourceCoverage("mfa_current_inventory", "not_collected", "Historical events and sign-in method types do not establish current enrollment."),
                         SourceCoverage("unlinked_workload_identity_signins", "not_collected", "This source does not cover unlinked or unapproved workload sign-ins; names and proximity are insufficient."),
                         SourceCoverage("device_current_state", "not_collected", "Registration events do not establish current ownership or Intune posture.")))
    if source == "defender.url-clicks":
        coverage.append(SourceCoverage("url_values_and_page_content", "not_collected", "URL values/chains and page content are excluded; click outcomes do not establish credential submission."))
    native_tenant = "OrganizationId" if source.startswith("purview.") else "tenantId (native streaming wrapper)" if source.startswith("defender.") else "AADTenantId"
    provenance = {"mapping_contract": CONTRACT, "acquisition_authority": "operator-attested scope; not independently authenticated",
                  "attested_by": attested_by, "input_sha256": sha, "scope_basis": acquisition.scope_basis,
                  "acquisition_start": acquired_start, "acquisition_end": acquired_end,
                  "native_customer_field": native_tenant, "workspace_tenantid": "Log Analytics workspace only; never customer authority",
                  "native_row_binding": "checked every supplied row" if rows else "not observed; empty export",
                  "evidence_class": "native-field metadata projection; exact submitted bytes retained",
                  "provider_transport_bytes": "not claimed", "schema_reference": SCHEMA_REFERENCES[source],
                  "identity_policy": "Preserve every source row and locator, including repeated native IDs and differing outcomes."}
    return BoundSource(source, tenant, account, start, end, acquired_at, acquisition.format, raw, sha,
                       tuple(rows), tuple(coverage), provenance)
