"""Acquisition checkpoints and immutable raw-byte replay."""
import json
from collections.abc import Mapping
from pathlib import Path

from .evidence import evidence_references
from .graph import Graph, SourceError, fetch
from .hunting import HuntingPage, TABLES
from .normalize import event_time, normalize, records, ual_body
from .storage import CaseError, DATASETS, GOOGLE_APPS, digest, encode, iso, now, read, save, microsoft_enabled
from .workspace import Workspace
from .google_events import normalize_child


def check_tenant(case, dataset, rows):
    if dataset in GOOGLE_APPS:
        customer = (case.meta.get("google_workspace") or {}).get("customer_id")
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
        if "tenant_id" in row and row["tenant_id"] != case.tenant:
            raise CaseError("Evidence tenant alias differs from the case.")
        ids = [row.get("organizationId"), row.get("OrganizationId"), row.get("AADTenantId")]
        if dataset == "ual":
            try:
                ids.append(ual_body(row).get("OrganizationId"))
            except (TypeError, ValueError):
                pass
        for tid in filter(None, ids):
            if not case.meta["directory_id"] or str(tid).casefold() != case.meta["directory_id"]:
                raise CaseError("The source directory ID must match directory_id in the tenant profile.")


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
    return dict(tenant=case.tenant, case_id=case.id, mode=None, queries={}, gaps=[], updated=None)


class Collection:
    def __init__(self, case):
        self.case = case
        self.path = case.path / "collection_summary.json"
        self.state = read(self.path) if self.path.exists() else empty_state(case)
        if self.state["tenant"] != case.tenant or self.state["case_id"] != case.id:
            raise CaseError("Collection summary identity mismatch.")
        self.graph = None
        self.workspace = None
        self.remaining = case.options["max_events"] - sum(a["records"] for a in case.manifest()["artifacts"])
        self.attempted = set()

    def update(self):
        self.state["updated"] = now()
        self.state["gaps"] = [q for q in self.state["queries"].values() if q["status"] == "gap"]
        save(self.path, self.state)

    def mode(self, value):
        if self.state["mode"] not in (None, value):
            raise CaseError("Use a separate case for a different acquisition mode.")
        self.state["mode"] = value

    def import_bundle(self, path):
        bundle = read(path)
        if not isinstance(bundle, Mapping):
            raise CaseError("Bundle manifest must be a JSON object.")
        if bundle.get("tenant") != self.case.tenant or bundle.get("directory_id") != self.case.meta["directory_id"]:
            raise CaseError("Bundle tenant binding differs from the case profile.")
        customer = (self.case.meta.get("google_workspace") or {}).get("customer_id")
        if "google_customer_id" in bundle and bundle["google_customer_id"] != customer:
            raise CaseError("Bundle Workspace customer differs from the case profile.")
        files = bundle.get("files")
        if not isinstance(files, list) or not files:
            raise CaseError("Bundle manifest must list one or more files.")
        self.mode("export")
        completed = set()
        for entry in files:
            dataset = entry["dataset"]
            if dataset not in DATASETS:
                raise CaseError("Unsupported bundle dataset.")
            local = (path.parent / entry["path"]).resolve()
            if not local.is_relative_to(path.parent.resolve()):
                raise CaseError("Bundle source must be inside its manifest directory.")
            key = f"file:{dataset}:{entry['path']}"
            query = dict(endpoint="local export", file=entry["path"], start=self.case.meta["start"],
                         end=self.case.meta["end"], dataset=dataset)
            try:
                raw = local.read_bytes()
                self.remaining -= acquire(self.case, dataset, raw, "export", query, self.remaining)
                self.state["queries"][key] = {**query, "status": "collected", "records": len(records(raw, dataset))}
                completed.add(dataset)
            except (OSError, UnicodeError, json.JSONDecodeError, SourceError) as exc:
                reason = str(exc) if isinstance(exc, SourceError) else type(exc).__name__ + " reading export"
                self.state["queries"][key] = {**query, "status": "gap", "reason": reason}
            self.case.log("import", dataset=dataset, status=self.state["queries"][key]["status"])
            self.update()
        for dataset in DATASETS:
            if dataset in GOOGLE_APPS and not self.case.meta.get("google_workspace"):
                continue
            if dataset not in GOOGLE_APPS and not microsoft_enabled(self.case):
                continue
            if dataset in TABLES and not self.case.options.get("defender", False):
                continue
            key = "coverage:" + dataset
            if dataset not in completed and not any(q.get("dataset") == dataset and q["status"] == "collected" for q in self.state["queries"].values()):
                self.state["queries"][key] = dict(dataset=dataset, status="gap", reason="No usable export supplied.")
            else:
                self.state["queries"].pop(key, None)
        self.update()

    def collect(self, queries):
        self.mode("live")
        shared_ips = {v.get("value") for v in self.state["queries"].values() if v.get("shared_ip")}
        for q in queries:
            meta = q.metadata()
            key = digest(encode(meta))
            previous = self.state["queries"].get(key, {})
            if key in self.attempted or previous.get("status") == "collected":
                continue
            self.attempted.add(key)
            count = 0
            ip_users = set()
            try:
                if q.kind == "ip" and q.value in shared_ips:
                    raise SourceError("Shared IP expansion stopped at the configured user threshold.")
                if self.remaining <= 0:
                    raise SourceError("Raw record budget exhausted.")
                google = q.dataset in GOOGLE_APPS
                if google:
                    if self.workspace is None:
                        self.workspace = Workspace(self.case)
                    pages = self.workspace.pages(q)
                else:
                    if not self.graph:
                        try:
                            self.graph = Graph(self.case)
                        except CaseError as exc:
                            if self.case.meta.get("google_workspace"):
                                raise SourceError(str(exc)) from exc
                            raise
                    pages = fetch(self.graph, q, key)
                for page in pages:
                    if isinstance(page, HuntingPage):
                        raw, parameters = page.data, {**meta, **page.parameters}
                    else:
                        raw, parameters = page, meta
                    collector = "google_reports" if google else "graph"
                    self.remaining -= acquire(self.case, q.dataset, raw, collector, parameters, self.remaining)
                    rows = records(raw, q.dataset)
                    count += len(rows)
                    if q.kind == "ip" and q.dataset in ("interactive", "noninteractive"):
                        ip_users.update(str(r["userPrincipalName"]).casefold() for r in rows
                                        if isinstance(r, dict) and r.get("userPrincipalName"))
                        if len(ip_users) >= self.case.options["shared_ip_users"]:
                            shared_ips.add(q.value)
                            raise SourceError("Shared IP expansion stopped at the configured user threshold.")
                outcome = dict(status="collected")
            except (SourceError, json.JSONDecodeError, KeyError, UnicodeError) as exc:
                reason = str(exc) if isinstance(exc, SourceError) else "Unexpected provider response format."
                outcome = dict(status="gap", reason=reason)
            self.state["queries"][key] = {**meta, **outcome, "records": count,
                                          "shared_ip": q.kind == "ip" and q.value in shared_ips}
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
