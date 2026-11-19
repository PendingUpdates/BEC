"""Acquisition checkpoints and immutable raw-byte replay."""
import json

from .bundles import ExportBundle
from .evidence import evidence_references
from .hunting import TABLES
from .normalize import event_time, normalize, object_value, records, ual_body
from .storage import CaseError, SourceError, DATASETS, GOOGLE_APPS, digest, encode, iso, now, read, save, microsoft_enabled
from .google_events import normalize_child


def check_tenant(case, dataset, rows):
    check_record_binding(dataset, rows, case.tenant, case.meta["directory_id"],
                         (case.meta.get("google_workspace") or {}).get("customer_id"))


def check_record_binding(dataset, rows, tenant, directory_id, customer):
    if dataset in GOOGLE_APPS:
        if not customer:
            raise CaseError("Bind a Workspace customer ID before importing Google evidence.")
        for row in rows:
            native = row.get("id") if isinstance(row, dict) else None
            if not isinstance(native, dict) or native.get("customerId") != customer:
                raise CaseError("Workspace evidence customer ID does not match this case.")
            if native.get("applicationName") != GOOGLE_APPS[dataset]:
                raise CaseError("Workspace evidence application does not match the selected dataset.")
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        if "tenant_id" in row and row["tenant_id"] != tenant:
            raise CaseError("Evidence tenant alias differs from the case.")
        ids = [row.get("organizationId"), row.get("OrganizationId"), row.get("AADTenantId")]
        if dataset == "ual":
            try:
                ids.append(ual_body(row).get("OrganizationId"))
            except (TypeError, ValueError):
                pass
        for tid in filter(None, ids):
            if not directory_id or str(tid).casefold() != directory_id:
                raise CaseError("The source directory ID must match directory_id in the tenant profile.")


def verify_export_files(bundle, tenant, directory_id, customer, microsoft, receipt=None):
    """Validate the whole input before case writes. Retain only the original-byte hashes."""
    bundle.check_binding(tenant, directory_id, customer)
    hashes = {}
    for dataset, name, path in bundle.files:
        if dataset not in GOOGLE_APPS and not microsoft:
            raise CaseError("A Microsoft export is outside this Workspace-only case.")
        try:
            raw = path.read_bytes()
            if not raw.strip():
                raise CaseError("Empty export file.")
            rows = records(raw, dataset)
            checked = rows if dataset in GOOGLE_APPS else (object_value(row) for row in rows)
            check_record_binding(dataset, checked, tenant, directory_id, customer)
            if receipt:
                receipt.check_file(name, raw, rows)
        except (OSError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, CaseError) else "Unreadable file or invalid UTF-8 JSON."
            raise CaseError(f"Invalid export {name}: {reason}") from exc
        hashes[dataset, name] = digest(raw)
    return hashes


def acquire(case, dataset, raw, collector, query, remaining):
    try:
        rows = records(raw, dataset)
    except CaseError as exc:
        raise SourceError(str(exc)) from exc
    check_tenant(case, dataset, rows)
    sha = digest(raw)
    rel = f"raw/{dataset}/{sha}.json"
    known = any(a["artifact"] == rel for a in case.manifest()["artifacts"])
    if not known and len(rows) > remaining:
        raise SourceError("Raw record budget reached before the next whole page. Increase max_events in a new profile.")
    low = high = None
    for row in rows:
        try:
            t = iso(event_time(dataset, row))
            low = min(low or t, t)
            high = max(high or t, t)
        except (TypeError, ValueError, AttributeError, KeyError):
            pass  # Replay records the raw pointer and parsing failure.
    case.preserve(dataset, raw, collector, query, len(rows), [low, high])
    return 0 if known else len(rows)


def empty_state(case):
    return dict(tenant=case.tenant, case_id=case.id, mode="export" if case.meta.get("export_only") else None,
                queries={}, gaps=[], updated=None)


class Collection:
    def __init__(self, case):
        self.case = case
        self.path = case.path / "collection_summary.json"
        self.state = read(self.path) if self.path.exists() else empty_state(case)
        if self.state["tenant"] != case.tenant or self.state["case_id"] != case.id:
            raise CaseError("Collection summary identity mismatch.")
        self.workspace = None
        self.remaining = case.options["max_events"] - sum(a["records"] for a in case.manifest()["artifacts"])
        self.attempted = set()

    def update(self):
        self.state["updated"] = now()
        self.state["gaps"] = [q for q in self.state["queries"].values() if q["status"] == "gap"]
        save(self.path, self.state)

    def mode(self, value):
        if self.state["mode"] not in (None, value) or (value == "live" and self.case.meta.get("export_only")):
            raise CaseError("Use a separate case for a different acquisition mode.")
        self.state["mode"] = value

    def import_bundle(self, path):
        self.import_files(ExportBundle.load(path))

    def import_files(self, bundle, *, verified_hashes=None, receipt=None):
        bundle.check_binding(self.case.tenant, self.case.meta["directory_id"],
                             (self.case.meta.get("google_workspace") or {}).get("customer_id"))
        self.mode("export")
        if verified_hashes is not None:
            self.update()  # An interrupted import must resume in export mode.
        completed = set()
        if receipt:
            receipt.preserve(self.case, bundle.raw_manifest)
        for dataset, name, local in bundle.files:
            key = f"file:{dataset}:{name}"
            query = dict(endpoint="local export", file=name, start=self.case.meta["start"],
                         end=self.case.meta["end"], dataset=dataset)
            if receipt:
                query.update(receipt.provenance(name))
            try:
                raw = local.read_bytes()
                if verified_hashes is not None and digest(raw) != verified_hashes[dataset, name]:
                    raise SourceError("Export changed after validation. Retry with the intended file.")
                collector = "exchange_online_powershell" if receipt else "export"
                self.remaining -= acquire(self.case, dataset, raw, collector, query, self.remaining)
                self.state["queries"][key] = {**query, "status": "collected", "records": len(records(raw, dataset))}
                completed.add(dataset)
            except (OSError, UnicodeError, json.JSONDecodeError, SourceError) as exc:
                reason = str(exc) if isinstance(exc, SourceError) else type(exc).__name__ + " reading export"
                self.state["queries"][key] = {**query, "status": "gap", "reason": reason}
            self.case.log("import", dataset=dataset, status=self.state["queries"][key]["status"])
            self.update()
            if verified_hashes is not None and self.state["queries"][key]["status"] == "gap":
                raise CaseError(f"Offline import stopped at {name}: " + self.state["queries"][key]["reason"])
        for dataset in DATASETS:
            if dataset in GOOGLE_APPS and not self.case.meta.get("google_workspace"):
                continue
            if dataset not in GOOGLE_APPS and not microsoft_enabled(self.case):
                continue
            if dataset in TABLES and not self.case.options.get("defender", False):
                continue
            key = "coverage:" + dataset
            if dataset not in completed and not any(q.get("dataset") == dataset and q["status"] == "collected" for q in self.state["queries"].values()):
                reason = "No usable export supplied."
                if receipt and dataset not in ("trace", "ual"):
                    reason = f"{dataset} is outside Exchange PowerShell coverage. Supply an authorized export if available."
                self.state["queries"][key] = dict(dataset=dataset, status="gap", reason=reason)
            else:
                self.state["queries"].pop(key, None)
        if receipt:
            self.state["queries"].update(receipt.coverage())
        self.update()

    def collect(self, queries):
        if self.case.meta.get("microsoft", True):
            raise CaseError("Microsoft collection requires the existing-session PowerShell adapter.")
        self.mode("live")
        from .workspace import Workspace

        for q in queries:
            meta = q.metadata()
            key = digest(encode(meta))
            previous = self.state["queries"].get(key, {})
            if key in self.attempted or previous.get("status") == "collected":
                continue
            self.attempted.add(key)
            count = 0
            try:
                if self.remaining <= 0:
                    raise SourceError("Raw record budget exhausted.")
                if q.dataset not in GOOGLE_APPS:
                    raise CaseError("Workspace collection accepts only Google audit datasets.")
                if self.workspace is None:
                    self.workspace = Workspace(self.case)
                for raw in self.workspace.pages(q):
                    self.remaining -= acquire(self.case, q.dataset, raw, "google_reports", meta, self.remaining)
                    count += len(records(raw, q.dataset))
                outcome = dict(status="collected")
            except (SourceError, json.JSONDecodeError, KeyError, UnicodeError) as exc:
                reason = str(exc) if isinstance(exc, SourceError) else "Unexpected provider response format."
                outcome = dict(status="gap", reason=reason)
            self.state["queries"][key] = {**meta, **outcome, "records": count, "shared_ip": False}
            self.case.log("collect", dataset=q.dataset, api=q.path, **outcome, records=count)
            self.update()


def replay(case):
    events, gaps = {}, []
    for entry in case.manifest()["artifacts"]:
        dataset = entry["dataset"]
        for i, row in enumerate(records(case.raw_path(entry).read_bytes(), dataset)):
            ref = dict(file=entry["artifact"], record_index=i, sha256=entry["sha256"])
            google = dataset in GOOGLE_APPS
            children = row.get("events") if google and isinstance(row, dict) else None
            indexes = range(len(children)) if isinstance(children, list) and children else [None]
            for idx in indexes:
                pointer = {**ref, "event_index": idx} if idx is not None else ref
                try:
                    if google:
                        if idx is None:
                            raise CaseError("Workspace activity has no events.")
                        e = normalize_child(case.tenant, dataset, row, idx, pointer)
                    else:
                        e = normalize(case.tenant, dataset, row, pointer)
                    if dataset in ("interactive", "noninteractive"):
                        e["entities"]["user_id"] = [row["userId"]] if row.get("userId") else []
                except (ValueError, TypeError, IndexError, AttributeError, KeyError, OverflowError) as exc:
                    gaps.append(dict(tenant=case.tenant, dataset=dataset, reason="Unparseable record (" + type(exc).__name__ + ")", evidence=pointer))
                    continue
                if old := events.get(e["event_id"]):
                    old.setdefault("additional_evidence", []).append(e["evidence"])
                else:
                    events[e["event_id"]] = e
    for event in events.values():
        if "additional_evidence" in event:
            event["additional_evidence"] = evidence_references(event, include_primary=False)
    return sorted(events.values(), key=lambda e: (e["timestamp_utc"], e["event_id"])), gaps
