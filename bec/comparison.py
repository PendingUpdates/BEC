"""Read-only, evidence-linked comparison of two saved cloud case inventories."""
import html
import json
from collections import defaultdict
from pathlib import Path
import uuid

from . import __version__
from .collection import check_tenant
from .google_events import normalize_child
from .hunting import TABLES
from .normalize import normalize, object_value, records, ual_body
from .storage import (Case, CaseError, DATASETS, GOOGLE_APPS, digest, encode, iso,
                      settings, timestamp, user_address, workspace_profile)


MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_CASE_BYTES = 512 * 1024 * 1024
MAX_RECORDS = 1_000_000
QUERY_FIELDS = ("dataset", "kind", "value", "start", "end", "baseline", "field",
                "table", "customer_id", "status", "reason", "shared_ip", "receipt_sha256",
                "captured_at", "operator", "connection", "result_limit")


def _json(data):
    return json.loads(data.decode("utf-8-sig"))


def _read(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise CaseError("Comparison input exceeds the 128 MiB per-file limit: " + str(path))
    return data


def _unique(values):
    return [value for _, value in sorted({encode(v): v for v in values}.items())]


def _mapping(value, label):
    if not isinstance(value, dict):
        raise CaseError("Comparison " + label + " must be a JSON object.")
    return value


def _canonical_record(dataset, row):
    """Decode known transport JSON wrappers, without changing original evidence."""
    if isinstance(row, str):
        try:
            row = object_value(row)
        except (ValueError, TypeError):
            return row  # Keep an unparseable raw value visible as evidence.
    if dataset == "ual" and isinstance(row, dict):
        row = dict(row)
        for key in ("AuditData", "auditData"):
            if isinstance(row.get(key), str):
                try:
                    row[key] = object_value(row[key])
                except (ValueError, TypeError):
                    pass
    return row


def _identity(dataset, row, fingerprint):
    """Use native identities only where their uniqueness contract is understood."""
    body = object_value(row)
    if dataset in GOOGLE_APPS:
        native = body.get("id", {})
        if native.get("uniqueQualifier"):
            return dict(dataset=dataset, basis="workspace_activity", native_id=native)
    elif dataset not in TABLES:
        native = (ual_body(body).get("Id") or body.get("id")) if dataset == "ual" else body.get("id")
        if dataset == "trace":
            native = native or body.get("MessageTraceId")
        if isinstance(native, (str, int)) and str(native):
            result = dict(dataset=dataset, basis="native_id", native_id=str(native))
            if dataset == "trace":
                result["recipient"] = str(body.get("recipientAddress") or body.get("RecipientAddress") or "").casefold()
            return result
    # Defender ReportId/AlertId can identify several observations, not one row.
    return dict(dataset=dataset, basis="content", native_id=fingerprint)


def _describe(tenant, dataset, row, reference):
    observations, issues = [], []
    children = row.get("events") if dataset in GOOGLE_APPS and isinstance(row, dict) else None
    indexes = range(len(children)) if isinstance(children, list) and children else [None]
    for index in indexes:
        try:
            event = (normalize_child(tenant, dataset, row, index, reference)
                     if dataset in GOOGLE_APPS else normalize(tenant, dataset, row, reference))
            observations.append(dict(timestamp_utc=event["timestamp_utc"], event_type=event["event_type"],
                operation=event["operation"], actor=event["actor"], target=event["target"],
                source_event_id=event["evidence"].get("source_event_id"), event_index=index))
        except (ValueError, TypeError, IndexError, AttributeError, KeyError, OverflowError) as exc:
            issues.append(dict(event_index=index, reason="Unparseable record (" + type(exc).__name__ + ")"))
    return observations, issues


class Snapshot:
    """Verify raw inputs without Case.verify's transaction recovery or any case writes."""
    def __init__(self, directory):
        directory = Path(directory).resolve()
        self.watched = {}
        metadata = self.watch(directory / "case.json")
        parsed_metadata = _mapping(_json(metadata), "case metadata")
        for field in ("tenant", "id", "user", "start", "end"):
            if not isinstance(parsed_metadata.get(field), str):
                raise CaseError("Comparison case metadata requires a string " + field + ".")
        _mapping(parsed_metadata.get("options"), "case options")
        user_address(parsed_metadata["user"])
        if parsed_metadata.get("google_workspace") is not None:
            workspace_profile(parsed_metadata["google_workspace"])
        for field in ("directory_id", "client_id"):
            if parsed_metadata.get(field) is not None:
                if not isinstance(parsed_metadata[field], str):
                    raise CaseError("Comparison case metadata requires a string " + field + ".")
                uuid.UUID(parsed_metadata[field])
        if type(parsed_metadata.get("microsoft", True)) is not bool:
            raise CaseError("Comparison case microsoft setting must be true or false.")
        self.case = Case(directory)
        case = self.case
        if case.meta != parsed_metadata:
            raise CaseError("Case metadata changed while comparison was reading it.")
        settings(case.options)
        start, end = timestamp(case.meta["start"]), timestamp(case.meta["end"])
        if start >= end:
            raise CaseError("Invalid comparison case window.")
        if (directory / ".pending-artifact.json").exists():
            raise CaseError("Case has a pending acquisition; finish recovery before comparing.")
        manifest = _mapping(_json(self.watch(directory / "evidence_manifest.json")), "manifest")
        if manifest["tenant"] != case.tenant or manifest["case_id"] != case.id:
            raise CaseError("Manifest identity mismatch.")
        for sha in manifest.get("exchange_receipts", []):
            if digest(self.watch(case.receipt_path(sha))) != sha:
                raise CaseError("Exchange receipt verification failed.")
        if not isinstance(manifest.get("artifacts"), list):
            raise CaseError("Comparison manifest artifacts must be an array.")
        state_bytes = self.watch(directory / "collection_summary.json", optional=True)
        state = _mapping(_json(state_bytes), "collection summary") if state_bytes is not None else None
        if state is not None and (state["tenant"] != case.tenant or state["case_id"] != case.id):
            raise CaseError("Collection summary identity mismatch.")
        pivots = self.watch(directory / "pivots" / "analyst.json", optional=True)
        if pivots is not None and not isinstance(_json(pivots), list):
            raise CaseError("Comparison analyst pivots must be an array.")
        self.inventory, self.coverage, expected = {}, {}, set()
        raw_bytes = raw_records = 0
        queries = list(_mapping((state or {}).get("queries", {}), "collection queries").values())
        for entry in manifest["artifacts"]:
            _mapping(entry, "artifact entry")
            path = case.raw_path(entry).resolve()
            if not path.is_relative_to(directory / "raw"):
                raise CaseError("Comparison evidence must remain inside its case raw directory.")
            if path in expected:
                raise CaseError("Duplicate artifact in evidence manifest.")
            expected.add(path)
            data = self.watch(path)
            if entry["tenant"] != case.tenant or digest(data) != entry["sha256"]:
                raise CaseError("Evidence verification failed: " + entry["artifact"])
            raw_bytes += len(data)
            if raw_bytes > MAX_CASE_BYTES:
                raise CaseError("Comparison exceeds the 512 MiB raw-evidence limit per case.")
            dataset = entry["dataset"]
            rows = records(data, dataset)
            raw_records += len(rows)
            if raw_records > min(case.options["max_events"], MAX_RECORDS):
                raise CaseError("Comparison exceeds the case raw-record budget or 1,000,000-record limit.")
            if type(entry["records"]) is not int or entry["records"] != len(rows):
                raise CaseError("Manifest record count differs from evidence: " + entry["artifact"])
            rows = [_canonical_record(dataset, row) for row in rows]
            check_tenant(case, dataset, rows)
            if not isinstance(entry.get("queries", []), list):
                raise CaseError("Comparison artifact queries must be an array.")
            queries.extend(entry.get("queries", []))
            for index, row in enumerate(rows):
                fingerprint = digest(encode(dict(dataset=dataset, record=row)))
                reference = dict(case_id=case.id, case_directory=str(directory),
                    file=entry["artifact"], uri=path.as_uri(), sha256=entry["sha256"], record_index=index)
                if fingerprint in self.inventory:
                    self.inventory[fingerprint]["evidence"].append(reference)
                    continue
                observations, issues = _describe(case.tenant, dataset, row, reference)
                try:
                    identity = _identity(dataset, row, fingerprint)
                except (ValueError, TypeError, AttributeError, KeyError):
                    identity = dict(dataset=dataset, basis="content", native_id=fingerprint)
                self.inventory[fingerprint] = dict(fingerprint=fingerprint, dataset=dataset, identity=identity,
                    observations=observations, normalization_issues=issues, evidence=[reference])
        self.expected = expected
        self.check_inventory()
        for query in queries:
            _mapping(query, "query metadata")
            if query.get("dataset") is not None and query["dataset"] not in DATASETS:
                raise CaseError("Comparison query has an unsupported dataset.")
        all_datasets = {item["dataset"] for item in self.inventory.values()} | {
            entry["dataset"] for entry in manifest["artifacts"]} | {q["dataset"] for q in queries if q.get("dataset")}
        for dataset in sorted(all_datasets):
            items = [item for item in self.inventory.values() if item["dataset"] == dataset]
            times = [observation["timestamp_utc"] for item in items for observation in item["observations"]]
            contexts = _unique([{key: q[key] for key in QUERY_FIELDS if key in q}
                                for q in queries if q.get("dataset") == dataset])
            self.coverage[dataset] = dict(unique_records=len(items),
                raw_occurrences=sum(len(item["evidence"]) for item in items),
                observed_timeframe=[min(times), max(times)] if times else [None, None],
                normalization_issues=sum(len(item["normalization_issues"]) for item in items),
                queries=contexts)
        directory_id = case.meta.get("directory_id")
        self.binding = dict(tenant=case.tenant,
            directory_id=str(uuid.UUID(directory_id)) if directory_id else None,
            google_customer_id=(case.meta.get("google_workspace") or {}).get("customer_id"))
        self.context = dict(incident_window=[iso(start), iso(end)], user=case.meta["user"],
            microsoft=case.meta.get("microsoft", True), options=case.options,
            analyst_pivots=_json(pivots) if pivots is not None else [],
            collection_mode=(state or {}).get("mode"), collection_summary_present=state is not None)
        self.metadata = dict(case_id=case.id, directory=str(directory), binding=self.binding,
            context=self.context, coverage=self.coverage, raw_artifacts=len(expected), raw_records=raw_records,
            unique_records=len(self.inventory), duplicate_occurrences=raw_records - len(self.inventory))
        self.check_unchanged()

    def watch(self, path, optional=False):
        data = None if optional and not path.exists() else _read(path)
        self.watched[path] = digest(data) if data is not None else None
        return data

    def check_inventory(self):
        found = {path.resolve() for path in (self.case.path / "raw").rglob("*.json")}
        if found != self.expected:
            raise CaseError("Raw artifact inventory differs from the evidence manifest.")

    def check_unchanged(self):
        if (self.case.path / ".pending-artifact.json").exists():
            raise CaseError("Case changed during comparison; retry after collection finishes.")
        for path, expected in self.watched.items():
            current = digest(_read(path)) if path.exists() else None
            if current != expected:
                raise CaseError("Case changed during comparison: " + str(path))
        self.check_inventory()


def compare(before_directory, after_directory):
    """Compare all preserved raw rows, including baseline and out-of-scope evidence."""
    before, after = Snapshot(before_directory), Snapshot(after_directory)
    if before.binding != after.binding:
        raise CaseError("Comparison requires matching tenant aliases, Microsoft directory IDs, and Workspace customer IDs (including missing bindings).")
    old, new = set(before.inventory), set(after.inventory)
    identities = defaultdict(lambda: {"before": [], "after": []})
    for side, snapshot in (("before", before), ("after", after)):
        for item in snapshot.inventory.values():
            if item["identity"]["basis"] != "content":
                identities[encode(item["identity"])][side].append(item)
    conflicts = []
    for key, sides in sorted(identities.items()):
        old_variants = {item["fingerprint"] for item in sides["before"]}
        new_variants = {item["fingerprint"] for item in sides["after"]}
        if len(old_variants | new_variants) > 1:
            conflicts.append(dict(identity=_json(key), changed=old_variants != new_variants,
                before=sorted(sides["before"], key=lambda item: item["fingerprint"]),
                after=sorted(sides["after"], key=lambda item: item["fingerprint"])))
    context_changes = [dict(field=key, before=before.context[key], after=after.context[key])
                       for key in before.context if before.context[key] != after.context[key]]
    coverage_changes = [dict(dataset=key, before=before.coverage.get(key), after=after.coverage.get(key))
                        for key in sorted(set(before.coverage) | set(after.coverage))
                        if before.coverage.get(key) != after.coverage.get(key)]
    before.check_unchanged()
    after.check_unchanged()
    notes = [
        "Newly observed means present only in the later input, not newly created in the tenant.",
        "Only in earlier means not observed in the later input; it never establishes deletion or remediation.",
        "Comparison covers every preserved raw row, including baseline and evidence outside the incident scope.",
        "Window, query, provider, and coverage changes can explain differences; matching coverage does not prove completeness.",
        "Fingerprints decode whole-row and UAL audit-body JSON wrappers and ignore object-key/page/row order; other strings, nested array order, and values remain significant.",
        "Defender rows and rows without a usable native identity use content identity; changed values remain visible as evidence deltas.",
    ]
    if not before.binding["directory_id"] and (before.context["microsoft"] or after.context["microsoft"]):
        notes.append("Microsoft directory ID is unbound in both cases; tenant matching relies on their identical analyst-supplied alias.")
    return dict(format_version=1, bec_version=__version__, before=before.metadata, after=after.metadata,
        summary=dict(newly_observed=len(new - old), only_in_earlier=len(old - new),
            unchanged=len(old & new), identity_conflicts=len(conflicts),
            changed_identity_conflicts=sum(conflict["changed"] for conflict in conflicts),
            context_changes=len(context_changes), coverage_changes=len(coverage_changes)),
        newly_observed=[after.inventory[key] for key in sorted(new - old)],
        only_in_earlier=[before.inventory[key] for key in sorted(old - new)],
        identity_conflicts=conflicts, context_changes=context_changes,
        coverage_changes=coverage_changes, interpretation=notes)


def render_html(result):
    """Render an inert standalone report with escaped source labels and local evidence links."""
    esc = lambda value: html.escape(str(value), quote=True)
    pretty = lambda value: "<pre>" + esc(json.dumps(value, ensure_ascii=False, indent=2)) + "</pre>"

    def rows(items):
        parts = []
        for item in items:
            links = [f'<li><a href="{esc(ref["uri"])}">{esc(ref["case_id"])}: '
                     f'{esc(ref["file"])} row {ref["record_index"]}</a> '
                     f'(SHA-256 {esc(ref["sha256"])})</li>' for ref in item["evidence"]]
            parts.append("<details><summary>" + esc(item["dataset"]) + " · " + esc(item["fingerprint"]) +
                "</summary>" + pretty(item["observations"]) + pretty(item["normalization_issues"]) +
                "<ul>" + "".join(links) + "</ul></details>")
        return "".join(parts) or "<p>None.</p>"

    conflicts = "".join("<section>" + pretty(item["identity"]) + "<h3>Earlier variants</h3>" +
        rows(item["before"]) + "<h3>Later variants</h3>" + rows(item["after"]) + "</section>"
        for item in result["identity_conflicts"]) or "<p>None.</p>"
    return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" "
        "content=\"width=device-width, initial-scale=1\"><title>BEC saved-case comparison</title>"
        "<style>body{max-width:1100px;margin:2rem auto;padding:0 1rem;font:16px system-ui;line-height:1.5}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f7;padding:1rem}"
        "details,section{border:1px solid #ccd4dd;padding:1rem;margin:1rem 0}a,summary{overflow-wrap:anywhere}</style>"
        "<h1>BEC saved-case comparison</h1><p>Earlier: " + esc(result["before"]["directory"]) +
        "<br>Later: " + esc(result["after"]["directory"]) + "</p>" + pretty(result["summary"]) +
        "<ul>" + "".join("<li>" + esc(note) + "</li>" for note in result["interpretation"]) + "</ul>"
        "<h2>Newly observed evidence</h2>" + rows(result["newly_observed"]) +
        "<h2>Only observed in earlier input</h2>" + rows(result["only_in_earlier"]) +
        "<h2>Native identity conflicts</h2>" + conflicts +
        "<h2>Window and investigation context changes</h2>" + pretty(result["context_changes"]) +
        "<h2>Coverage changes</h2>" + pretty(result["coverage_changes"]) +
        "<h2>Complete input coverage</h2>" + pretty(dict(before=result["before"], after=result["after"])) + "</html>")


def write_report(result, output, format_name):
    """Create a new report outside both input cases; never overwrite source or user files."""
    output = Path(output).resolve()
    for side in ("before", "after"):
        if output.is_relative_to(Path(result[side]["directory"])):
            raise CaseError("Comparison output must be outside both input cases.")
    data = render_html(result).encode("utf-8") if format_name == "html" else encode(result)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(data)
    return output
