"""Plan a bounded operator-session read and validate its local evidence receipt."""
import argparse
import base64
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .bundles import EXCHANGE_SCHEMA, exchange_json, local_path
from .collection import check_record_binding
from .storage import CaseError, atomic, digest, iso, save, timestamp, user_address

ADAPTER = Path(__file__).resolve().parent / "data" / "Invoke-BEC.ps1"
LIMIT = 1000
READS = {"sent": ("trace", "Get-MessageTraceV2", "SenderAddress"),
         "received": ("trace", "Get-MessageTraceV2", "RecipientAddress")}
GAPS = {"unavailable": "The cmdlet was unavailable in the verified session.",
        "denied-or-failed": "The scoped read failed or access was denied.",
        "serialization-failed": "Could not preserve the returned objects as complete JSON.",
        "empty": "No rows returned. Access, ingestion and retention are unconfirmed.",
        "at-limit": "The read reached its result limit. More records may exist."}


def affected_accounts(values):
    addresses = []
    for value in values:
        for text in re.split(r"[,;\s]+", value.strip()):
            if not text:
                continue
            address = user_address(text)
            local, domain = address.split("@")
            if (any(c in local for c in "*?[]") or
                    not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                            for label in domain.split("."))):
                raise CaseError("Enter exact account addresses without wildcards.")
            if address not in addresses:
                addresses.append(address)
    if not addresses:
        raise CaseError("Enter at least one affected account address.")
    return addresses


def utc_window(start, end):
    bounds = []
    for value in (start, end):
        if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
            raise CaseError("Supply explicit UTC bounds ending in Z or +00:00.")
        bounds.append(timestamp(value))
    start_dt, end_dt = bounds
    if not timedelta() < end_dt - start_dt <= timedelta(hours=24) or end_dt > datetime.now(UTC):
        raise CaseError("Use a completed UTC window greater than zero and at most 24 hours.")
    return iso(start_dt), iso(end_dt)


def plan(args):
    tenant = str(uuid.UUID(args.tenant))
    operator = user_address(args.operator)
    connection = str(uuid.UUID(args.connection))
    end = datetime.now(UTC)
    if args.start is None and args.end is None:
        start, end = iso(end - timedelta(hours=24)), iso(end)
    else:
        start, end = utc_window(args.start, args.end)
    root = local_path(args.root or os.environ.get("BEC_CASES") or Path.home() / "BEC-Cases")
    print(f"Signed in as {operator}. Customer tenant {tenant}.\nUTC window {start} to {end}. "
          f"Local case store {root}.", file=sys.stderr, flush=True)
    accounts = args.accounts
    if not accounts:
        print("Accounts to investigate (separate addresses with commas): ", end="", file=sys.stderr, flush=True)
        accounts = [sys.stdin.readline()]
    return dict(tenant=tenant, operator=operator, connection=connection, start=start, end=end,
                accounts=affected_accounts(accounts), root=str(root), limit=LIMIT)


def trace_page_status(raw, direction, tenant, account, start, end):
    """Validate the bytes to be preserved. The case interval includes the start and excludes the end."""
    rows = exchange_json(raw)
    if direction not in READS or not isinstance(rows, list) or len(rows) > LIMIT:
        raise CaseError("Expected a bounded array of native message trace rows.")
    start, end = utc_window(start, end)
    tenant = str(uuid.UUID(tenant))
    if affected_accounts([account]) != [account]:
        raise CaseError("An exact canonical account is required for trace capture.")
    field = READS[direction][2]
    alternate = field[0].lower() + field[1:]
    for row in rows:
        if not isinstance(row, dict) or any(k.casefold() == "auditdata" for k in row):
            raise CaseError("Expected a native message trace row.")
        for address in (row.get(field), row.get(alternate, row.get(field))):
            if not isinstance(address, str) or address.casefold() != account:
                raise CaseError("Trace page contains a record outside the requested directional account scope.")
        try:
            received = timestamp(row.get("Received"), vendor_utc=True)
            replay_time = timestamp(row["receivedDateTime"]) if "receivedDateTime" in row else received
        except (ValueError, OverflowError) as exc:
            raise CaseError("Trace record has no usable timestamp.") from exc
        if received != replay_time:
            raise CaseError("Trace timestamps disagree.")
        if not start <= iso(received) < end:
            raise CaseError("Trace page contains a record outside the case UTC window.")
        for key in ("TenantId", "tenantId", "ExternalDirectoryOrganizationId"):
            if key in row and str(row[key]).casefold() != tenant:
                raise CaseError("Trace directory ID differs from the case.")
    check_record_binding("trace", rows, tenant, tenant, None)
    if not rows:
        return "empty"
    return "at-limit" if len(rows) == LIMIT else "returned"


def save_trace(args, raw):
    status = trace_page_status(raw, args.direction, args.tenant, args.account, args.start, args.end)
    path = local_path(Path(args.directory) / (args.direction + ".json"))
    with path.open("xb") as stream:
        stream.write(raw)
    return {"status": status, "sha256": digest(raw)}


@dataclass
class ExchangeReceipt:
    sha: str
    scope: dict
    reads: dict
    files: dict
    captured_at: str

    @classmethod
    def check(cls, bundle, tenant, directory, account, start, end):
        manifest = bundle.manifest
        if manifest.get("schema") != EXCHANGE_SCHEMA:
            return None
        scope = manifest.get("scope")
        if not isinstance(scope, dict) or set(scope) != {"account", "start", "end", "operator", "connection"}:
            raise CaseError("Exchange receipt is missing its operator or scope.")
        start, end = utc_window(start, end)
        if (not directory or tenant != directory or manifest.get("directory_id") != directory
                or (scope.get("account"), scope.get("start"), scope.get("end")) != (account, start, end)):
            raise CaseError("Exchange receipt differs from the authorized tenant, account or UTC window.")
        user_address(scope["operator"])
        uuid.UUID(str(scope.get("connection")))
        reads = manifest.get("reads")
        if not isinstance(reads, dict) or set(reads) != READS.keys():
            raise CaseError("Exchange receipt must account for every scoped read.")
        files = {}
        for key, (dataset, _, _) in READS.items():
            status = reads[key]
            if not isinstance(status, str):
                raise CaseError("Exchange read status must be a string.")
            if status in ("unavailable", "denied-or-failed", "serialization-failed"):
                continue
            if status not in {"returned", "empty", "at-limit"}:
                raise CaseError("Unknown Exchange read status.")
            name = key + ".json"
            entries = [e for e in manifest["files"] if e["path"] == name and e["dataset"] == dataset]
            if len(entries) != 1 or not re.fullmatch(r"[a-f0-9]{64}", str(entries[0].get("sha256"))):
                raise CaseError("An Exchange read must reference its hashed file.")
            files[name] = entries[0]["sha256"]
        if len(files) != len(bundle.files):
            raise CaseError("Exchange receipt contains an unaccounted source file.")
        captured_at = iso(timestamp(manifest.get("captured_at")))
        return cls(digest(bundle.raw_manifest), scope, reads, files, captured_at)

    def check_file(self, name, raw, tenant):
        direction = name.removesuffix(".json")
        if direction not in READS or digest(raw) != self.files.get(name):
            raise CaseError("Exchange trace file hash or direction differs from the receipt.")
        status = trace_page_status(raw, direction, tenant, self.scope["account"], self.scope["start"], self.scope["end"])
        if self.reads[direction] != status:
            raise CaseError("Exchange trace count and receipt outcome differ.")

    def preserve(self, case, raw):
        path = case.receipt_path(self.sha)
        if path.exists() and digest(path.read_bytes()) != self.sha:
            raise CaseError("Saved Exchange receipt hash mismatch.")
        if not path.exists():
            atomic(path, raw)
        manifest = case.manifest()
        receipts = manifest.setdefault("exchange_receipts", [])
        if self.sha not in receipts:
            receipts.append(self.sha)
            save(case.path / "evidence_manifest.json", manifest)

    def provenance(self, name):
        _, cmdlet, field = READS[name.removesuffix(".json")]
        return dict(endpoint=cmdlet, field=field, result_limit=LIMIT, captured_at=self.captured_at,
                    receipt_sha256=self.sha, **self.scope)

    def coverage(self):
        result = {}
        for key, status in self.reads.items():
            if status in GAPS:
                dataset, cmdlet, field = READS[key]
                result[f"exchange:{self.sha}:{key}"] = dict(dataset=dataset, status="gap",
                    reason=f"{cmdlet} ({field}): {GAPS[status]}", receipt_sha256=self.sha)
        result["coverage:ual"] = dict(dataset="ual", status="gap", receipt_sha256=self.sha,
            reason="Mailbox audit was not collected. The Exchange adapter captures scoped message traces only.")
        result["exchange:inbox_rules"] = dict(dataset="ual", status="gap", reason="Current inbox rules were not read.")
        return result


def main():
    parser = argparse.ArgumentParser(description="Plan or preserve scoped Exchange message traces.")
    actions = parser.add_subparsers(dest="action", required=True)
    scope = actions.add_parser("plan")
    for key in ("tenant", "operator", "connection"):
        scope.add_argument("--" + key, required=True)
    for key in ("start", "end", "root"):
        scope.add_argument("--" + key)
    scope.add_argument("--accounts", nargs="+")
    capture = actions.add_parser("save-trace")
    capture.add_argument("--direction", choices=READS, required=True)
    for key in ("directory", "tenant", "account", "start", "end"):
        capture.add_argument("--" + key, required=True)
    args = parser.parse_args()
    try:
        if args.action == "plan":
            result = plan(args)
        else:
            raw = base64.b64decode(sys.stdin.buffer.read().strip(), validate=True)
            result = save_trace(args, raw)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError) as exc:
        print(f"BEC: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
