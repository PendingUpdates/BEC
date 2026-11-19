"""Plan a bounded operator-session read and validate its local evidence receipt."""
import argparse
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .bundles import EXCHANGE_SCHEMA, local_path
from .normalize import event_time, object_value, ual_body
from .storage import CaseError, atomic, digest, iso, save, timestamp, user_address

ADAPTER = Path(__file__).resolve().parent / "data" / "Invoke-BEC.ps1"
LIMIT = 1000
READS = {"sent": ("trace", "Get-MessageTraceV2", "SenderAddress"),
         "received": ("trace", "Get-MessageTraceV2", "RecipientAddress"),
         "audit": ("ual", "Search-UnifiedAuditLog", "UserIds")}
OPERATIONS = ("MailItemsAccessed", "Send", "SendAs", "SendOnBehalf", "New-InboxRule", "Set-InboxRule",
              "Remove-InboxRule", "UpdateInboxRules", "Move", "MoveToDeletedItems", "SoftDelete",
              "HardDelete", "SearchQueryInitiatedExchange")
GAPS = {"unavailable": "The cmdlet was unavailable in the verified session.",
        "denied-or-failed": "The scoped read failed or access was denied.",
        "serialization-failed": "Could not preserve the returned objects as complete JSON.",
        "empty": "No rows returned. Access, ingestion and retention are unconfirmed.",
        "at-limit": "The read reached its result limit. More records may exist.",
        "bounded-audit": "One bounded audit read. Completeness and ingestion are unconfirmed."}


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
                accounts=affected_accounts(accounts), root=str(root), limit=LIMIT, operations=OPERATIONS)


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
            if status not in {"returned", "empty", "at-limit", "bounded-audit"}:
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

    def check_file(self, name, raw, rows):
        key = name.removesuffix(".json")
        dataset, _, field = READS[key]
        n = len(rows)
        status = "empty" if n == 0 else "at-limit" if n == LIMIT else "bounded-audit" if key == "audit" else "returned"
        if n > LIMIT or self.reads[key] != status or digest(raw) != self.files[name]:
            raise CaseError("Exchange file hash, row count or coverage status differs from the receipt.")
        for value in rows:
            row = object_value(value)
            when = iso(event_time(dataset, row))
            if dataset == "ual":
                body = ual_body(row)
                user = body.get("UserId")
                if body.get("Operation") not in OPERATIONS:
                    raise CaseError("Unexpected Exchange audit operation for this read.")
            else:
                user = row.get(field)
            if (not isinstance(user, str) or user.casefold() != self.scope["account"]
                    or not self.scope["start"] <= when <= self.scope["end"]):
                raise CaseError("Exchange record does not match the requested account and UTC interval.")

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
        result["exchange:inbox_rules"] = dict(dataset="ual", status="gap",
            reason="Current inbox rules were not read. Audit entries cover only returned historical changes.")
        return result


def main():
    parser = argparse.ArgumentParser(description="Prepare the local scope for the Exchange PowerShell adapter.")
    for key in ("tenant", "operator", "connection"):
        parser.add_argument("--" + key, required=True)
    for key in ("start", "end", "root"):
        parser.add_argument("--" + key)
    parser.add_argument("--accounts", nargs="+")
    try:
        print(json.dumps(plan(parser.parse_args())))
        return 0
    except (OSError, ValueError) as exc:
        print(f"BEC: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
