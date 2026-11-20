"""Validate allowlisted current Exchange observations, separately from message history.

Target IDs come from returned native properties, never a trustee, display name or
the requested mailbox argument. These local receipts are not provider signatures.
"""
import argparse
import base64
import json
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .bundles import exchange_json, local_path
from .storage import CaseError, digest, iso, timestamp, user_address

SCHEMA = "bec.exchange-snapshot/v1"
FILENAME = "exchange-snapshot.json"
MAX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 1000
COMMANDS = {
    "inbox_rules": "Get-InboxRule", "forwarding": "Get-Mailbox",
    "full_access": "Get-MailboxPermission", "send_as": "Get-RecipientPermission",
    "send_on_behalf": "Get-Mailbox",
}
REASONS = {
    "empty", "result-limit", "hidden-unavailable", "field-unavailable",
    "unbound-result", "invalid-result", "unavailable", "denied", "failed",
    "throttled", "serialization-failed", "mailbox-identity-unavailable", "projection-limited",
}
MAILBOX_FIELDS = {"PrimarySmtpAddress", "ExternalDirectoryObjectId", "Guid", "ExchangeGuid"}
RULE_FIELDS = {
    "MailboxOwnerId", "RuleIdentity", "Name", "Enabled", "Priority", "InError",
    "SupportedByTask", "DeleteMessage", "MarkAsRead", "StopProcessingRules",
    "ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "From",
}
FIELDS = {
    "inbox_rules": RULE_FIELDS,
    "forwarding": MAILBOX_FIELDS | {"ForwardingAddress", "ForwardingSmtpAddress", "DeliverToMailboxAndForward"},
    "full_access": {"Identity", "User", "AccessRights", "Deny", "IsInherited"},
    "send_as": {"Identity", "Trustee", "AccessRights", "AccessControlType", "IsInherited"},
    "send_on_behalf": MAILBOX_FIELDS | {"GrantSendOnBehalfTo"},
}
REQUIRED = {
    "inbox_rules": {"MailboxOwnerId", "RuleIdentity", "Enabled", "Priority"},
    "forwarding": MAILBOX_FIELDS | {"ForwardingAddress", "ForwardingSmtpAddress", "DeliverToMailboxAndForward"},
    "full_access": FIELDS["full_access"],
    "send_as": FIELDS["send_as"],
    "send_on_behalf": FIELDS["send_on_behalf"],
}


class SnapshotTargetError(CaseError):
    """A projected row does not positively establish its native target."""


def _guid(value, *, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise CaseError("Snapshot native identifiers must be GUID strings.")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise CaseError("Snapshot native identifier is invalid.") from exc
    if not parsed.int or str(parsed) != value:
        raise CaseError("Snapshot native identifier must be a canonical nonempty GUID.")
    return value


def _text(value, *, empty=False):
    if (not isinstance(value, str) or len(value) > 1024 or (not empty and not value.strip())
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
        raise CaseError("Snapshot property is not bounded plain text.")
    return value


def _utc(value):
    if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
        raise CaseError("Snapshot observation time must be explicit UTC.")
    try:
        return iso(timestamp(value))
    except (ValueError, OverflowError) as exc:
        raise CaseError("Snapshot observation time is invalid.") from exc


def _mailbox(value, account):
    if not isinstance(value, dict) or set(value) != MAILBOX_FIELDS:
        raise CaseError("Snapshot requires the verified mailbox identifiers.")
    if value["PrimarySmtpAddress"] != account or user_address(account) != account:
        raise SnapshotTargetError("Snapshot primary mailbox differs from the authorized account.")
    _guid(value["ExternalDirectoryObjectId"])
    _guid(value["Guid"], optional=True)
    _guid(value["ExchangeGuid"], optional=True)
    return value


def _identity(value, expected=None):
    # ADObjectId.ObjectGuid is the directory object ID, not ExchangeGuid or trustee SID.
    if not isinstance(value, dict) or set(value) != {"ObjectGuid"}:
        raise SnapshotTargetError("Snapshot target requires a returned native ObjectGuid.")
    actual = _guid(value["ObjectGuid"])
    if expected is not None and actual != expected:
        raise SnapshotTargetError("Snapshot returned a different mailbox target.")
    return actual


def _recipient(value):
    if value is None:
        return
    if isinstance(value, dict):
        if set(value) == {"Address", "RoutingType"}:
            _text(value["Address"])
            _text(value["RoutingType"])
        else:
            _identity(value)
    else:
        _text(value)


def validate_rows(source, rows, mailbox):
    """Check the entire projected observation before any of its bytes are saved."""
    if source not in COMMANDS or not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise CaseError("Snapshot observation exceeds its bounded record contract.")
    for row in rows:
        if not isinstance(row, dict) or not REQUIRED[source] <= row.keys() or not row.keys() <= FIELDS[source]:
            raise CaseError("Snapshot observation has missing or unapproved properties.")
        if source in {"forwarding", "send_on_behalf"}:
            target = {name: row[name] for name in MAILBOX_FIELDS}
            _mailbox(target, mailbox["PrimarySmtpAddress"])
            if target != mailbox:
                raise SnapshotTargetError("Snapshot returned a different native mailbox.")
        else:
            if not mailbox["Guid"]:
                raise SnapshotTargetError("Cannot establish the snapshot row's immutable mailbox target.")
            field = "MailboxOwnerId" if source == "inbox_rules" else "Identity"
            _identity(row[field], mailbox["Guid"])
        if source == "inbox_rules":
            if not isinstance(row["RuleIdentity"], str) or not re.fullmatch(r"[0-9]{1,20}", row["RuleIdentity"]):
                raise CaseError("Snapshot rule identity must be a native numeric identifier.")
            if type(row["Priority"]) is not int or not 0 <= row["Priority"] <= 2147483647:
                raise CaseError("Snapshot rule priority is invalid.")
            for name in ("Enabled", "InError", "SupportedByTask", "DeleteMessage", "MarkAsRead", "StopProcessingRules"):
                if name in row and type(row[name]) is not bool:
                    raise CaseError("Snapshot rule flag must be a native Boolean.")
            if "Name" in row:
                _text(row["Name"], empty=True)
            for name in ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "From"):
                if name in row:
                    if not isinstance(row[name], list) or len(row[name]) > MAX_RECORDS:
                        raise CaseError("Snapshot rule recipient list is invalid.")
                    for recipient in row[name]:
                        _recipient(recipient)
        elif source == "forwarding":
            _recipient(row["ForwardingAddress"])
            if row["ForwardingSmtpAddress"] is not None:
                _text(row["ForwardingSmtpAddress"])
            if type(row["DeliverToMailboxAndForward"]) is not bool:
                raise CaseError("Snapshot forwarding flag must be a native Boolean.")
        elif source in {"full_access", "send_as"}:
            _text(row["User" if source == "full_access" else "Trustee"])
            rights = row["AccessRights"]
            allowed = {"FullAccess", "ReadPermission", "ChangePermission", "ChangeOwner", "DeleteItem", "ExternalAccount"}
            if source == "send_as":
                allowed = {"SendAs"}
            if (not isinstance(rights, list) or not rights or any(not isinstance(x, str) or x not in allowed for x in rights)
                    or len(set(rights)) != len(rights)
                    or ("FullAccess" if source == "full_access" else "SendAs") not in rights):
                raise CaseError("Snapshot permission has unsupported rights.")
            if type(row["IsInherited"]) is not bool:
                raise CaseError("Snapshot permission inheritance must be a native Boolean.")
            if source == "full_access" and type(row["Deny"]) is not bool:
                raise CaseError("Snapshot FullAccess deny flag must be a native Boolean.")
            if source == "send_as" and (not isinstance(row["AccessControlType"], str)
                                       or row["AccessControlType"] not in {"Allow", "Deny"}):
                raise CaseError("Snapshot SendAs access-control type is invalid.")
        else:
            delegates = row["GrantSendOnBehalfTo"]
            if not isinstance(delegates, list) or len(delegates) > MAX_RECORDS:
                raise CaseError("Snapshot SendOnBehalf list is invalid.")
            for recipient in delegates:
                _recipient(recipient)
    if source in {"forwarding", "send_on_behalf"} and len(rows) > 1:
        raise CaseError("A mailbox property observation must contain one mailbox.")
    return rows


def _checked(raw, *, tenant, account, start, end, operator, connection, trace_receipt_sha256):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise CaseError("Snapshot exceeds its 8 MiB byte limit.")
    obj = exchange_json(raw)
    top = {"schema", "tenant", "directory_id", "scope", "mailbox", "captured_at",
           "trace_receipt_sha256", "evidence_class", "observations"}
    if not isinstance(obj, dict) or set(obj) != top or obj["schema"] != SCHEMA:
        raise CaseError("Unsupported Exchange current-state snapshot receipt.")
    if obj["evidence_class"] != "allowlisted-source-properties":
        raise CaseError("Snapshot evidence class is invalid.")
    _guid(tenant)
    _guid(connection)
    if user_address(operator) != operator or user_address(account) != account:
        raise CaseError("Snapshot binding requires canonical account addresses.")
    scope = dict(account=account, start=_utc(start), end=_utc(end), operator=operator, connection=connection)
    if scope["start"] >= scope["end"] or obj["tenant"] != tenant or obj["directory_id"] != tenant or obj["scope"] != scope:
        raise CaseError("Snapshot differs from its independently verified trace scope.")
    if (not isinstance(trace_receipt_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", trace_receipt_sha256)
            or obj["trace_receipt_sha256"] != trace_receipt_sha256):
        raise CaseError("Snapshot is not paired with the verified trace receipt.")
    mailbox = _mailbox(obj["mailbox"], account)
    captured = _utc(obj["captured_at"])
    if captured > iso(datetime.now(UTC)):
        raise CaseError("Snapshot capture time is in the future.")
    if not isinstance(obj["observations"], dict) or obj["observations"].keys() != COMMANDS.keys():
        raise CaseError("Snapshot must account for all five current observations.")
    for source, obs in obj["observations"].items():
        if (not isinstance(obs, dict) or set(obs) != {"command", "observed_at", "status", "reason_codes", "records", "hidden_included"}
                or obs["command"] != COMMANDS[source] or not isinstance(obs["status"], str)
                or obs["status"] not in {"collected", "partial", "denied", "unavailable"}):
            raise CaseError("Snapshot observation metadata is invalid.")
        if _utc(obs["observed_at"]) > captured:
            raise CaseError("Snapshot observation follows its capture receipt.")
        reasons = obs["reason_codes"]
        if (not isinstance(reasons, list) or len(reasons) > len(REASONS)
                or any(not isinstance(x, str) or x not in REASONS for x in reasons) or len(set(reasons)) != len(reasons)):
            raise CaseError("Snapshot coverage reason is invalid.")
        if (source == "inbox_rules" and type(obs["hidden_included"]) is not bool
                or source != "inbox_rules" and obs["hidden_included"] is not None):
            raise CaseError("Snapshot hidden-rule coverage is invalid.")
        rows = validate_rows(source, obs["records"], mailbox)
        if obs["status"] == "collected" and (not rows or reasons or source == "inbox_rules" and not obs["hidden_included"]):
            raise CaseError("Snapshot collected status conflicts with its coverage.")
        if obs["status"] != "collected" and not reasons:
            raise CaseError("Snapshot gaps must have an explicit reason.")
        if obs["status"] in {"denied", "unavailable"} and rows:
            raise CaseError("Unavailable snapshot observations cannot contain rows.")
        if len(rows) == MAX_RECORDS and "result-limit" not in reasons:
            raise CaseError("A full snapshot result must retain its limit gap.")
        if source == "inbox_rules" and any(set(row) != RULE_FIELDS for row in rows) and "field-unavailable" not in reasons:
            raise CaseError("Missing selected rule properties require a visible coverage gap.")
        if source == "inbox_rules" and rows and "projection-limited" not in reasons:
            raise CaseError("Rule projection omissions require explicit partial coverage.")
        if source == "inbox_rules" and rows and not obs["hidden_included"] and "hidden-unavailable" not in reasons:
            raise CaseError("Missing hidden rules require an explicit coverage gap.")
    return obj


def prepare_capture(raw, **binding):
    """Drop an entire unqualified observation in memory, then verify before saving.

    Replay never repairs a saved receipt. This capture-only step records a gap
    instead of persisting unexpected or unbound provider properties.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise CaseError("Snapshot exceeds its 8 MiB byte limit.")
    obj = exchange_json(raw)
    if not isinstance(obj, dict) or not isinstance(obj.get("observations"), dict):
        raise CaseError("Snapshot observations are missing.")
    mailbox = _mailbox(obj.get("mailbox"), binding["account"])
    changed = False
    for source, obs in obj["observations"].items():
        if source not in COMMANDS or not isinstance(obs, dict):
            raise CaseError("Snapshot source is invalid.")
        try:
            validate_rows(source, obs.get("records"), mailbox)
        except CaseError as exc:
            reasons = obs.get("reason_codes")
            if not isinstance(reasons, list) or any(not isinstance(x, str) or x not in REASONS for x in reasons):
                raise CaseError("Snapshot coverage reason is invalid.") from exc
            reason = "unbound-result" if isinstance(exc, SnapshotTargetError) else "invalid-result"
            if isinstance(obs.get("records"), list) and len(obs["records"]) > MAX_RECORDS:
                reason = "result-limit"
            obs.update(records=[], status="partial", reason_codes=list(dict.fromkeys([*reasons, reason])))
            changed = True
    if changed:
        raw = (json.dumps(obj, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
    _checked(raw, **binding)
    return raw


def validate_snapshot(raw, *, tenant, account, start, end, operator, connection, trace_receipt_sha256):
    """Replay only against an independently checked saved trace receipt."""
    from .component_types import BoundSource, SourceCoverage, SourceRow

    obj = _checked(raw, tenant=tenant, account=account, start=start, end=end, operator=operator,
                   connection=connection, trace_receipt_sha256=trace_receipt_sha256)
    rows, coverage = [], []
    for source, obs in obj["observations"].items():
        detail = "Current observation of selected properties only; not historical or effective-access proof."
        if source == "inbox_rules":
            detail += " MoveToFolder/CopyToFolder, other unselected conditions and exceptions, and body/header/subject text are omitted."
        if obs["reason_codes"]:
            detail += " Gaps: " + ", ".join(obs["reason_codes"]) + "."
        coverage.append(SourceCoverage(source, obs["status"], detail))
        for index, row in enumerate(obs["records"]):
            fields = {name: value if isinstance(value, str) else json.dumps(value, ensure_ascii=True, sort_keys=True)
                      for name, value in row.items()}
            native = row.get("RuleIdentity", obj["mailbox"]["ExternalDirectoryObjectId"])
            rows.append(SourceRow(source, "snapshot", _utc(obs["observed_at"]), COMMANDS[source], native,
                                  f"/observations/{source}/records/{index}", fields))
    provenance = dict(schema=SCHEMA, evidence_class=obj["evidence_class"], operator=operator, connection=connection,
                      trace_receipt_sha256=trace_receipt_sha256,
                      user_object_id=obj["mailbox"]["ExternalDirectoryObjectId"],
                      rule_projection_omissions="MoveToFolder, CopyToFolder, unselected conditions/exceptions, body/header/subject text")
    for name, key in (("Guid", "directory_object_guid"), ("ExchangeGuid", "mailbox_guid")):
        if obj["mailbox"][name]:
            provenance[key] = obj["mailbox"][name]
    return BoundSource("exchange_current_state", tenant, account, _utc(start), _utc(end),
                       _utc(obj["captured_at"]), "json", raw, digest(raw), tuple(rows), tuple(coverage), provenance)


def load_snapshot(path, **binding):
    path = local_path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise CaseError("Snapshot must be a local regular file of at most 8 MiB.")
    return validate_snapshot(path.read_bytes(), **binding)


def main():
    parser = argparse.ArgumentParser(description="Validate and save a paired current Exchange observation.")
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    try:
        directory = local_path(args.directory)
        if directory.is_symlink() or not directory.is_dir():
            raise CaseError("The verified trace export directory is required.")
        encoded = sys.stdin.buffer.read(MAX_BYTES * 2 + 1)
        if len(encoded) > MAX_BYTES * 2:
            raise CaseError("Snapshot input exceeds its byte limit.")
        try:
            raw = base64.b64decode(encoded.strip(), validate=True)
        except ValueError as exc:
            raise CaseError("Invalid snapshot transport encoding.") from exc
        obj = exchange_json(raw)
        if not isinstance(obj, dict) or not isinstance(obj.get("scope"), dict):
            raise CaseError("Snapshot scope is missing.")
        from .bundles import ExportBundle
        from .exchange import ExchangeReceipt
        bundle = ExportBundle.load(directory / "bundle.json", offline=True)
        scope = bundle.manifest.get("scope", {})
        receipt = ExchangeReceipt.check(bundle, bundle.manifest["tenant"], bundle.manifest.get("directory_id"),
                                        scope.get("account"), scope.get("start"), scope.get("end"))
        if receipt is None:
            raise CaseError("Snapshot requires a verified trace capture receipt.")
        for _, name, path in bundle.files:
            receipt.check_file(name, path.read_bytes(), bundle.manifest["tenant"])
        raw = prepare_capture(raw, tenant=bundle.manifest["tenant"], account=scope["account"], start=scope["start"],
                              end=scope["end"], operator=scope["operator"], connection=scope["connection"],
                              trace_receipt_sha256=receipt.sha)
        output = directory / FILENAME
        with output.open("xb") as stream:
            stream.write(raw)
        print(json.dumps(dict(path=str(output), sha256=digest(raw))))
        return 0
    except (CaseError, ValueError, TypeError, KeyError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
