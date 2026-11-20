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
from .trace_windows import MAX_CHUNK, PRESETS, chunk_plan, preset_start, requested_window

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


def reply(prompt, *, blank=""):
    print(prompt, end=" ", file=sys.stderr, flush=True)
    line = sys.stdin.readline()
    if not line or line.strip().casefold() in {"q", "quit", "cancel"}:
        raise CaseError("Investigation cancelled before collection.")
    return line.strip() or blank


def plan(args):
    if not sys.stdin.isatty():
        raise CaseError("Confirm the investigation interactively in the connected PowerShell window.")
    tenant_id, connection_id = uuid.UUID(args.tenant), uuid.UUID(args.connection)
    if not tenant_id.int or not connection_id.int:
        raise CaseError("A verified tenant ID and connection ID are required.")
    tenant = str(tenant_id)
    operator = user_address(args.operator)
    root = local_path(args.root or os.environ.get("BEC_CASES") or Path.home() / "BEC-Cases")
    print(f"Connected Exchange tenant ID: {tenant}\nSigned-in operator: {operator}", file=sys.stderr, flush=True)
    accounts = affected_accounts(args.accounts or [reply("Accounts to investigate (comma-separated; q to cancel):")])
    if args.start is None and args.end is None:
        menu = "  ".join(f"{i}. {preset}" for i, preset in enumerate(PRESETS, 1))
        value = reply(f"{menu}\nTime window [1, 24 hours; q to cancel]:", blank="1").casefold()
        choices = {str(i): name for i, name in enumerate(PRESETS, 1)}
        preset = choices.get(value, value)
        if preset not in PRESETS:
            raise CaseError("Choose a listed time window. No collection started.")
        now = datetime.now(UTC)
        start, end = iso(preset_start(now, preset)), iso(now)
    else:
        now = datetime.now(UTC)
        start, end = requested_window(args.start, args.end)
    planned_at = iso(now)
    chunks = chunk_plan(start, end, planned_at)
    print(f"Accounts: {', '.join(accounts)}\nRequested UTC: {start} to {end} (end excluded).", file=sys.stderr)
    if not chunks:
        raise CaseError("The entire request is outside live trace retention. Use separately authorized offline exports.")
    first = chunks[0]["start"]
    print(f"Queryable UTC: {first} to {end}.\n"
          f"Up to {len(chunks)*2} directional trace queries per mailbox, {LIMIT} rows per query.\n"
          f"Local case store: {root}", file=sys.stderr)
    question = "Collect these scoped message traces?"
    if first != start:
        print(f"Unavailable live: {start} to {first}. Exchange retains up to 90 days. "
              "Older authorized exports require a separate offline case.", file=sys.stderr)
        question = "Collect only the displayed retained interval?"
    if reply(question + " Type yes to continue [no]:").casefold() != "yes":
        raise CaseError("Investigation cancelled before collection.")
    return dict(tenant=tenant, operator=operator, connection=str(connection_id), start=start, end=end,
                planned_at=planned_at, chunks=chunks, accounts=accounts, root=str(root), limit=LIMIT)


class TraceEndBoundary(CaseError):
    """The service included an exclusive endpoint. Do not preserve the page."""


def trace_page_status(raw, direction, tenant, account, start, end):
    """Validate the bytes to be preserved. The case interval includes the start and excludes the end."""
    rows = exchange_json(raw)
    if direction not in READS or not isinstance(rows, list) or len(rows) > LIMIT:
        raise CaseError("Expected a bounded array of native message trace rows.")
    start, end = requested_window(start, end)
    if timestamp(end) - timestamp(start) > MAX_CHUNK or timestamp(end) > datetime.now(UTC):
        raise CaseError("A trace page requires a completed window of at most ten days.")
    tenant = str(uuid.UUID(tenant))
    if affected_accounts([account]) != [account]:
        raise CaseError("An exact canonical account is required for trace capture.")
    field = READS[direction][2]
    alternate = field[0].lower() + field[1:]
    has_end_row = False
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
        when = iso(received)
        if when == end:
            has_end_row = True
        elif not start <= when < end:
            raise CaseError("Trace page contains a record outside the case UTC window.")
        for key in ("TenantId", "tenantId", "ExternalDirectoryOrganizationId"):
            if key in row and str(row[key]).casefold() != tenant:
                raise CaseError("Trace directory ID differs from the case.")
    check_record_binding("trace", rows, tenant, tenant, None)
    if has_end_row:
        raise TraceEndBoundary("The trace page includes the excluded range endpoint.")
    if not rows:
        return "empty"
    return "at-limit" if len(rows) == LIMIT else "returned"


def save_trace(args, raw):
    status = trace_page_status(raw, args.direction, args.tenant, args.account, args.start, args.end)
    key = args.direction
    chunk = getattr(args, "chunk", None)
    if chunk is not None:
        if not re.fullmatch("0[1-9]", chunk):
            raise CaseError("Invalid trace range number.")
        key += "-" + chunk
    path = local_path(Path(args.directory) / (key + ".json"))
    if getattr(args, "new_directory", False):
        path.parent.mkdir(parents=True)
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
    schema: str = EXCHANGE_SCHEMA
    planned_at: str | None = None
    counts: dict | None = None

    @classmethod
    def check(cls, bundle, tenant, directory, account, start, end):
        from .bundles import EXCHANGE_SCHEMAS, EXCHANGE_SCHEMA_V3
        from .trace_windows import chunk_plan, read_start, requested_window

        manifest = bundle.manifest
        schema = manifest.get("schema")
        if schema not in EXCHANGE_SCHEMAS:
            return None
        scope = manifest.get("scope")
        if not isinstance(scope, dict) or set(scope) != {"account", "start", "end", "operator", "connection"}:
            raise CaseError("Exchange receipt is missing its operator or scope.")
        start, end = requested_window(start, end) if schema == EXCHANGE_SCHEMA_V3 else utc_window(start, end)
        if (not directory or tenant != directory or manifest.get("directory_id") != directory
                or (scope.get("account"), scope.get("start"), scope.get("end")) != (account, start, end)):
            raise CaseError("Exchange receipt differs from the authorized tenant, account or UTC window.")
        user_address(scope["operator"])
        uuid.UUID(str(scope.get("connection")))
        captured_at = iso(timestamp(manifest.get("captured_at")))
        planned_at = None
        reads = manifest.get("reads")
        failures = {"unavailable", "denied-or-failed", "serialization-failed"}
        if schema == EXCHANGE_SCHEMA_V3:
            def dated_utc(value):
                if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
                    raise CaseError("Exchange read and capture times must be explicit UTC.")
                return iso(timestamp(value))

            planned_at = dated_utc(manifest.get("planned_at"))
            captured_at = dated_utc(manifest.get("captured_at"))
            if not end <= planned_at <= captured_at <= iso(datetime.now(UTC)):
                raise CaseError("Exchange planning and capture times are out of order.")
            chunks = chunk_plan(start, end, planned_at)
            if not 1 <= len(chunks) <= 9:
                raise CaseError("Exchange receipt must plan one to nine retained ranges.")
            slots = {f"{direction}-{chunk['id']}": chunk for chunk in chunks for direction in READS}
            if not isinstance(reads, dict) or set(reads) != set(slots):
                raise CaseError("Exchange receipt must account for every directional range.")
            failures |= {"access-denied", "throttled", "boundary-overlap", "retention", "budget-limited"}
            for key, chunk in slots.items():
                entry = reads[key]
                if not isinstance(entry, dict) or set(entry) != {"start", "end", "checked_at", "status"}:
                    raise CaseError("Exchange range must record its bounds, check time and outcome.")
                checked_at = dated_utc(entry["checked_at"])
                if not planned_at <= checked_at <= captured_at:
                    raise CaseError("Exchange read time is outside the planning and capture times.")
                effective_start = read_start(chunk["start"], chunk["end"], checked_at)
                if (entry["start"], entry["end"]) != (effective_start, chunk["end"]):
                    raise CaseError("Exchange read bounds differ from the retained planned range.")
                zero_width = effective_start == chunk["end"]
                if zero_width != (entry["status"] == "retention"):
                    raise CaseError("Only an aged-off zero-width range may have retention status.")
        elif not isinstance(reads, dict) or set(reads) != READS.keys():
            raise CaseError("Exchange receipt must account for every scoped read.")
        files = {}
        for key, entry in reads.items():
            status = entry["status"] if schema == EXCHANGE_SCHEMA_V3 else entry
            if not isinstance(status, str):
                raise CaseError("Exchange read status must be a string.")
            if status in failures:
                continue
            if status not in {"returned", "empty", "at-limit"}:
                raise CaseError("Unknown Exchange read status.")
            name = key + ".json"
            entries = [e for e in manifest["files"] if e["path"] == name and e["dataset"] == "trace"]
            if len(entries) != 1 or not re.fullmatch(r"[a-f0-9]{64}", str(entries[0].get("sha256"))):
                raise CaseError("An Exchange read must reference its hashed file.")
            files[name] = entries[0]["sha256"]
        if len(files) != len(bundle.files):
            raise CaseError("Exchange receipt contains an unaccounted source file.")
        return cls(digest(bundle.raw_manifest), scope, reads, files, captured_at, schema, planned_at, {})

    def check_file(self, name, raw, tenant):
        key = name.removesuffix(".json")
        direction = key.split("-", 1)[0]
        if key not in self.reads or direction not in READS or digest(raw) != self.files.get(name):
            raise CaseError("Exchange trace file hash or direction differs from the receipt.")
        entry = self.reads[key] if self.planned_at else self.scope
        status = trace_page_status(raw, direction, tenant, self.scope["account"], entry["start"], entry["end"])
        expected = entry["status"] if self.planned_at else self.reads[key]
        if expected != status:
            raise CaseError("Exchange trace count and receipt outcome differ.")
        if self.counts is None:
            self.counts = {}
        self.counts[key] = len(exchange_json(raw))

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
        key = name.removesuffix(".json")
        _, cmdlet, field = READS[key.split("-", 1)[0]]
        query = dict(endpoint=cmdlet, field=field, result_limit=LIMIT, captured_at=self.captured_at,
                     receipt_sha256=self.sha, **self.scope)
        if self.planned_at:
            entry = self.reads[key]
            query.update(requested_start=self.scope["start"], requested_end=self.scope["end"],
                         start=entry["start"], end=entry["end"], checked_at=entry["checked_at"],
                         planned_at=self.planned_at, read_id=key, outcome=entry["status"])
        return query

    def coverage_report(self):
        """Describe declared reads, including preserved pages; none establishes complete coverage."""
        from .trace_windows import chunk_plan

        chunks = chunk_plan(self.scope["start"], self.scope["end"], self.planned_at) if self.planned_at else []
        slots = {f"{direction}-{chunk['id']}": chunk for chunk in chunks for direction in READS}
        queryable = dict(start=chunks[0]["start"], end=chunks[-1]["end"]) if chunks else {
            "start": self.scope["start"], "end": self.scope["end"]}
        aged_off = (dict(start=self.scope["start"], end=queryable["start"])
                    if self.planned_at and self.scope["start"] < queryable["start"] else None)
        reasons = {**GAPS,
            "returned": "Rows returned. Access, ingestion and retention can still limit coverage.",
            "access-denied": "Exchange refused this trace read with an authorization error.",
            "throttled": "The service throttled this read. No page was preserved.",
            "boundary-overlap": "The page included the excluded range endpoint. No page was preserved.",
            "retention": "The rolling retention safety cutoff excluded the entire planned range before this read.",
            "budget-limited": "This range was skipped after a service throttle or because the run reached its five-minute request limit."}
        reads = []
        for key in sorted(self.reads, key=lambda value: (value.split("-")[-1], value.startswith("received"))):
            direction = key.split("-", 1)[0]
            entry = self.reads[key] if self.planned_at else dict(
                start=self.scope["start"], end=self.scope["end"], checked_at=None, status=self.reads[key])
            name = key + ".json"
            before = slots[key]["start"] if self.planned_at else entry["start"]
            reads.append(dict(id=key, direction=direction, start=entry["start"], end=entry["end"],
                checked_at=entry["checked_at"], outcome=entry["status"],
                records=(self.counts or {}).get(key) if name in self.files else 0,
                file=name if name in self.files else None, sha256=self.files.get(name), result_limit=LIMIT,
                planned_start=before, aged_off_prefix=(dict(start=before, end=entry["start"])
                    if before < entry["start"] else None), reason=reasons[entry["status"]]))
        return dict(receipt_sha256=self.sha, schema=self.schema, account=self.scope["account"],
            requested=dict(start=self.scope["start"], end=self.scope["end"]), queryable=queryable,
            planned_at=self.planned_at, captured_at=self.captured_at, aged_off_prefix=aged_off,
            older_than_retention=bool(aged_off), reads=reads, result_limit=LIMIT,
            queryable_basis="90-day retention at planning" if self.planned_at else "v2 declared window; per-read times unavailable",
            caveat="Scoped message traces only. Returned or empty pages do not establish complete coverage. "
                   "Access, delayed ingestion and retention remain unconfirmed.",
            audit_gap="Mailbox audit was not collected. Current inbox rules were not read.")

    def coverage(self):
        result = {}
        coverage = self.coverage_report()
        if coverage["aged_off_prefix"]:
            gap = coverage["aged_off_prefix"]
            result[f"exchange:{self.sha}:retention"] = dict(dataset="trace", status="gap",
                start=gap["start"], end=gap["end"], receipt_sha256=self.sha,
                reason=f"Requested range {gap['start']} to {gap['end']} is older than live trace retention (90 days).")
        for entry in coverage["reads"]:
            key = entry["id"]
            _, cmdlet, field = READS[entry["direction"]]
            result[f"exchange:{self.sha}:{key}"] = {**entry, "dataset": "trace",
                "status": "collected" if entry["outcome"] == "returned" else "gap",
                "reason": f"{cmdlet} ({field}), {entry['start']} to {entry['end']}: {entry['reason']}",
                "receipt_sha256": self.sha}
            if entry["aged_off_prefix"]:
                gap = entry["aged_off_prefix"]
                result[f"exchange:{self.sha}:{key}:retention"] = dict(dataset="trace", status="gap",
                    start=gap["start"], end=gap["end"], direction=entry["direction"], receipt_sha256=self.sha,
                    reason=f"The rolling retention safety cutoff excluded {gap['start']} to {gap['end']} before read {key}.")
        result["coverage:ual"] = dict(dataset="ual", status="gap", receipt_sha256=self.sha,
            reason="Mailbox audit was not collected. The Exchange adapter captures scoped message traces only.")
        result["exchange:inbox_rules"] = dict(dataset="ual", status="gap", reason="Current inbox rules were not read.")
        return result


def main():
    parser = argparse.ArgumentParser(description="Plan or preserve scoped Exchange message traces.")
    actions = parser.add_subparsers(dest="action", required=True)
    scope = actions.add_parser("plan-session")
    for key in ("tenant", "operator", "connection"):
        scope.add_argument("--" + key, required=True)
    for key in ("start", "end", "root"):
        scope.add_argument("--" + key)
    scope.add_argument("--accounts", nargs="+")
    capture = actions.add_parser("save-trace")
    capture.add_argument("--direction", choices=READS, required=True)
    capture.add_argument("--chunk")
    capture.add_argument("--new-directory", action="store_true")
    for key in ("directory", "tenant", "account", "start", "end"):
        capture.add_argument("--" + key, required=True)
    args = parser.parse_args()
    try:
        if args.action == "plan-session":
            result = plan(args)
        else:
            raw = base64.b64decode(sys.stdin.buffer.read().strip(), validate=True)
            result = save_trace(args, raw)
        print(json.dumps(result))
        return 0
    except TraceEndBoundary as exc:
        print(f"BEC: {exc}", file=sys.stderr)
        return 3 if args.chunk else 1
    except (OSError, ValueError, EOFError, KeyboardInterrupt) as exc:
        print(f"BEC: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
