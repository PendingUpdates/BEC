"""Build a scoped local evidence package from verified sources, never old reports."""
import csv
import io
import json
import math
import os
import re
import shutil
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .bundles import EXCHANGE_SCHEMA, EXCHANGE_SCHEMA_V3, EXCHANGE_SCHEMAS, ExportBundle, exchange_json
from .component_types import BoundSource, SourceCoverage, SourceRow
from .exchange import ExchangeReceipt
from .package_documents import display_text, write_pdf, write_workbook
from .package_safety import PackageSnapshot, inspect_tree, publish_directory, read_bytes, safe_name, safe_path
from .storage import CaseError, digest, encode, iso, timestamp, user_address


SCHEMA = "bec.case-package/v1"
MAX_BYTES = 512 * 1024 * 1024
MAX_ROWS = 200_000
MAX_REFERENCES = 500_000
SOURCE_SLUGS = {
    "exchange_trace": "trace",
    "exchange_current_state": "mailbox-state",
    "purview.mailbox-audit": "purview-audit",
    "entra.audit-logs": "entra-audit",
    "entra.user-signins.interactive": "user-signins",
    "entra.user-signins.noninteractive": "noninteractive",
    "entra.workload-signins.service-principal": "app-signins",
    "entra.workload-signins.managed-identity": "managed-signins",
    "defender.url-clicks": "url-clicks",
}
TRACE_FIELDS = frozenset(name.casefold() for name in (
    "Received", "receivedDateTime", "SenderAddress", "RecipientAddress", "Subject", "Status", "MessageId",
    "MessageTraceId", "FromIP", "ToIP", "Size", "TenantId", "tenant_id", "ExternalDirectoryOrganizationId",
    "OrganizationId", "Organization", "MailDirectionality", "Directionality", "OriginalClientIP",
    "ConnectorId", "Index", "StartDate", "EndDate", "Id"))
FORBIDDEN_FIELDS = frozenset(("body", "bodypreview", "uniquebody", "textbody", "htmlbody", "mimecontent",
    "contentbytes", "attachmentcontent", "accesstoken", "refreshtoken", "idtoken", "clientsecret",
    "password", "authorization", "credential", "credentials", "secret", "token", "privatekey"))


def _source_stem(source, source_id):
    """Canonical source names have one vetted short filename label, without dataset repetition."""
    if source not in SOURCE_SLUGS or not re.fullmatch(r"S[0-9]{4}", source_id):
        raise CaseError("Package source has no approved filename mapping.")
    return safe_name(SOURCE_SLUGS[source] + "-" + source_id)


def _account_folder(account):
    slug = re.sub(r"[^a-z0-9._-]", "-", account.casefold()).strip(".-")[:16] or "account"
    return safe_name(slug + "--" + digest(account.encode())[:12])


def _acquisition_id(when, nonce):
    return "acq-" + when.strftime("%Y%m%dT%H%M%SZ-") + nonce[:12]


def _strict_json(raw):
    value = exchange_json(raw)
    _metadata_only(value)
    return value


def _metadata_only(value, depth=0):
    if depth > 32:
        raise CaseError("Package source exceeds the bounded metadata nesting depth.")
    if isinstance(value, dict):
        for key, item in value.items():
            if re.sub(r"[^a-z0-9]", "", key.casefold()) in FORBIDDEN_FIELDS:
                raise CaseError("Package source contains a body or credential field; original bytes were not copied.")
            if key.casefold() == "auditdata" and isinstance(item, str):
                try:
                    _metadata_only(exchange_json(item.encode()), depth + 1)
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise CaseError("Package audit metadata is not structured JSON.") from exc
            _metadata_only(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _metadata_only(item, depth + 1)
    elif not (value is None or isinstance(value, (str, bool, int)) or isinstance(value, float) and math.isfinite(value)):
        raise CaseError("Package source contains unsupported or non-finite metadata.")


def _text(value):
    return "" if value is None else json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value)


def _trace_safe(rows):
    return all(isinstance(row, dict) and all(key.casefold() in TRACE_FIELDS and
               (value is None or isinstance(value, (str, bool, int)) or isinstance(value, float) and math.isfinite(value))
               for key, value in row.items()) for row in rows)


def _receipt_manifest(raw):
    manifest = exchange_json(raw)
    if not isinstance(manifest, dict):
        raise CaseError("Saved Exchange receipt must be an object.")
    schema = manifest.get("schema")
    if schema not in EXCHANGE_SCHEMAS:
        return None
    fields = {"schema", "tenant", "directory_id", "scope", "reads", "files", "captured_at"}
    if schema == EXCHANGE_SCHEMA_V3:
        fields.add("planned_at")
    if set(manifest) != fields or not isinstance(manifest["files"], list):
        raise CaseError("Saved Exchange receipt has unsupported fields.")
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"dataset", "path", "sha256"} or entry["dataset"] != "trace":
            raise CaseError("Saved Exchange receipt may reference only trace pages.")
        name = entry["path"]
        valid = (name in ("sent.json", "received.json") if schema == EXCHANGE_SCHEMA else
                 isinstance(name, str) and re.fullmatch(r"(?:sent|received)-0[1-9]\.json", name))
        if not valid or not isinstance(entry["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]):
            raise CaseError("Saved Exchange receipt has an invalid page reference.")
    return manifest


def _trace_sources(snapshot):
    case = snapshot.case
    manifest = case.manifest()
    by_sha = {entry["sha256"]: entry for entry in manifest["artifacts"] if entry["dataset"] == "trace"}
    sources, originals, coverage, receipts, receipt_index, admitted = {}, {}, [], [], [], set()
    excluded = set()
    for receipt_sha in manifest.get("exchange_receipts", []):
        raw_receipt = read_bytes(case.receipt_path(receipt_sha))
        if digest(raw_receipt) != receipt_sha:
            raise CaseError("Saved Exchange receipt hash changed.")
        content = _receipt_manifest(raw_receipt)
        if content is None:
            excluded.add("Legacy or unsupported acquisition receipts were excluded.")
            continue
        files, pages = [], {}
        for entry in content["files"]:
            artifact = by_sha.get(entry["sha256"])
            if artifact is None or artifact["collector"] != "exchange_online_powershell":
                raise CaseError("Saved Exchange receipt lacks its preserved native trace artifact.")
            path = case.raw_path(artifact)
            pages[entry["path"]] = read_bytes(path)
            files.append(("trace", entry["path"], path))
        bundle = ExportBundle(content, files, raw_receipt)
        bundle.check_binding(case.tenant, case.meta["directory_id"], None)
        receipt = ExchangeReceipt.check(bundle, case.tenant, case.meta["directory_id"], case.meta["user"],
                                        case.meta["start"], case.meta["end"])
        for name, raw in pages.items():
            receipt.check_file(name, raw, case.meta["directory_id"])
        # The strict receipt binds a current-state sidecar independently of which
        # otherwise-scoped pages have a safe original-byte projection for packaging.
        receipts.append(receipt)
        directory = f"originals/exchange/R{len(receipts):04d}"
        originals[directory + "/bundle.json"] = raw_receipt
        excluded_pages = {name for name, raw in pages.items() if not _trace_safe(exchange_json(raw))}
        receipt_index.append(dict(sha256=receipt_sha, file=directory + "/bundle.json", schema=receipt.schema,
            pages=[dict(source_filename=name, sha256=digest(raw), included=name not in excluded_pages,
                        file=None if name in excluded_pages else directory + "/" + name)
                   for name, raw in sorted(pages.items())]))
        if excluded_pages:
            excluded.add(f"{len(excluded_pages)} scoped trace page(s) contained fields outside the approved metadata projection and were not copied.")
        for name, raw in pages.items():
            if name in excluded_pages:
                continue
            sha = digest(raw)
            original = directory + "/" + name
            originals[original] = raw
            admitted.add(sha)
            reference = dict(file=original, receipt_file=directory + "/bundle.json", receipt_sha256=receipt_sha,
                             read_id=name.removesuffix(".json"))
            if sha in sources:
                sources[sha]["references"].append(reference)
                continue
            rows = []
            for index, row in enumerate(exchange_json(raw)):
                rows.append(SourceRow(dataset="trace", kind="event", utc=iso(timestamp(row["Received"], vendor_utc=True)),
                    operation="Message trace", native_id=_text(row.get("MessageTraceId") or row.get("MessageId") or row.get("id") or row.get("Id")),
                    locator=f"/{index}", fields={key: _text(value) for key, value in row.items()}))
            sources[sha] = dict(source=BoundSource(source="exchange_trace", tenant=case.meta["directory_id"],
                account=case.meta["user"], start=case.meta["start"], end=case.meta["end"],
                acquired_at=receipt.captured_at, extension="json", raw=raw, sha256=sha, rows=tuple(rows),
                coverage=(), provenance={"schema": receipt.schema}), references=[reference])
        capture = receipt.coverage_report()
        common = dict(requested_start=capture["requested"]["start"], requested_end=capture["requested"]["end"],
            queryable_start=capture["queryable"]["start"], queryable_end=capture["queryable"]["end"],
            planned_at=capture["planned_at"], captured_at=capture["captured_at"], queryable_basis=capture["queryable_basis"])
        for entry in receipt.coverage().values():
            detail = dict(source="exchange_trace", dataset=entry["dataset"], status=entry.get("outcome", entry["status"]),
                detail=entry["reason"], start=entry.get("start"), end=entry.get("end"),
                receipt_sha256=receipt_sha, records=entry.get("records"), **common)
            detail.update({key: entry[key] for key in ("id", "direction", "checked_at", "result_limit", "planned_start", "aged_off_prefix") if key in entry})
            if entry.get("file") in excluded_pages:
                detail.update(status="excluded", source_outcome=detail["status"], source_records=detail["records"], records=0,
                    detail="The scoped source page was not copied because it contains fields outside the approved metadata projection. " + entry["reason"])
            coverage.append(detail)
    excluded_count = sum(entry["dataset"] != "trace" or entry["sha256"] not in admitted for entry in manifest["artifacts"])
    if excluded_count:
        excluded.add(f"{excluded_count} other saved-case artifact(s) were not admitted; their rows, derived text and old reports were not copied.")
    for reason in sorted(excluded):
        coverage.append(dict(source="saved_case", dataset="unadmitted", status="excluded", detail=reason,
                             start=None, end=None))
    return [sources[key] for key in sorted(sources)], tuple(receipts), originals, coverage, receipt_index


def _source_rows(source):
    if source.extension == "json":
        return _strict_json(source.raw)
    if source.extension != "csv":
        raise CaseError("Package sources require json or csv originals.")
    try:
        reader = csv.reader(io.StringIO(source.raw.decode("utf-8-sig"), newline=""), strict=True)
        table = list(reader)
    except (UnicodeError, csv.Error) as exc:
        raise CaseError("Package CSV source must be valid UTF-8 CSV.") from exc
    if not table or not table[0] or len(table[0]) != len(set(table[0])) or any(len(row) != len(table[0]) for row in table[1:]):
        raise CaseError("Package CSV source must have unique headers and complete logical rows.")
    _metadata_only(dict.fromkeys(table[0]))
    return table


def _resolve_locator(parsed, extension, locator):
    if extension == "csv":
        if not isinstance(locator, str) or not re.fullmatch(r"csv:[1-9][0-9]*", locator):
            raise CaseError("CSV evidence requires a logical record locator.")
        index = int(locator.split(":")[1]) - 1
        if not 1 <= index < len(parsed):
            raise CaseError("CSV evidence locator does not select a data record.")
        return index - 1
    if not isinstance(locator, str) or not locator.startswith("/") or re.search(r"~(?![01])", locator):
        raise CaseError("JSON evidence requires an exact JSON pointer.")
    item, index = parsed, None
    for encoded in locator.split("/")[1:]:
        key = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(item, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", key) or int(key) >= len(item):
                raise CaseError("JSON evidence index does not resolve.")
            if index is None:
                index = int(key)
            item = item[int(key)]
        elif isinstance(item, dict) and key in item:
            item = item[key]
        else:
            raise CaseError("JSON evidence pointer does not resolve.")
    if not isinstance(item, dict):
        raise CaseError("JSON evidence pointer must select an original record object.")
    return index


def _check_source(source, case):
    if type(source) is not BoundSource or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", source.source):
        raise CaseError("Package loader returned an unsupported typed source.")
    if (source.tenant != case.meta.get("directory_id") or not source.tenant or source.account != case.meta["user"] or
            (source.start, source.end) != (case.meta["start"], case.meta["end"])):
        raise CaseError("Package source differs from the exact native tenant, account or requested window.")
    if type(source.raw) is not bytes or len(source.raw) > 128 * 1024 * 1024 or digest(source.raw) != source.sha256:
        raise CaseError("Package source bytes do not match their bounded hash.")
    timestamp(source.acquired_at)
    if type(source.rows) is not tuple or len(source.rows) > MAX_ROWS or type(source.coverage) is not tuple:
        raise CaseError("Package source rows and coverage must be bounded typed tuples.")
    if not isinstance(source.provenance, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in source.provenance.items()):
        raise CaseError("Package source provenance must contain only text metadata.")
    _metadata_only(source.provenance)
    parsed = _source_rows(source)
    for row in source.rows:
        if type(row) is not SourceRow or row.kind not in {"event", "snapshot"}:
            raise CaseError("Package row requires an explicit event or snapshot type.")
        if any(not isinstance(value, str) for value in (row.dataset, row.utc, row.operation, row.native_id, row.locator)):
            raise CaseError("Package observation metadata must be text.")
        when = timestamp(row.utc)
        if row.kind == "event" and not timestamp(source.start) <= when < timestamp(source.end):
            raise CaseError("Package event is outside the exact case interval.")
        if not isinstance(row.fields, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in row.fields.items()):
            raise CaseError("Package row fields must be validated text projections.")
        _metadata_only(row.fields)
        _resolve_locator(parsed, source.extension, row.locator)
    for item in source.coverage:
        if type(item) is not SourceCoverage or not all(isinstance(value, str) for value in (item.dataset, item.status, item.detail)):
            raise CaseError("Package source coverage is not a typed observation.")
    return parsed


def _csv(path, columns, rows):
    """Create an explicitly labeled display CSV; formulas cannot be activated."""
    def cell(value):
        text = display_text(_text(value))
        leading = text
        while leading and (leading[0].isspace() or leading[0] == "\ufeff"):
            leading = leading[1:]
        if leading.startswith(("=", "+", "-", "@")):
            text = "'" + text
        return text
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow([cell(value) for value in columns])
        writer.writerows([cell(value) for value in row] for row in rows)


def _write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def _component_files(inputs, sources):
    """Watch only paths already accepted by the closed, source-specific loader."""
    watched = {}
    if inputs is None:
        return watched
    receipt_sources = {source.provenance.get("acquisition_receipt_sha256"): source for source in sources
                       if source.acquisition_receipt is not None}

    def remember(path, expected, limit):
        path = safe_path(path, exists=True)
        raw = read_bytes(path, limit)
        info = path.stat()
        if digest(raw) != expected:
            raise CaseError("A validated package component changed before staging.")
        watched[path] = (expected, info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        return raw

    for path in inputs.imports:
        path = safe_path(path, exists=True)
        raw = read_bytes(path, 64 * 1024)
        source = receipt_sources.get(digest(raw))
        if source is None:
            raise CaseError("An acquisition receipt changed after validation.")
        content = exchange_json(remember(path, digest(raw), 64 * 1024))
        remember(path.parent / safe_name(content["file"]), source.sha256, 32 * 1024 * 1024)
    if inputs.exchange_snapshot is not None:
        candidates = [source for source in sources if source.source == "exchange_current_state"]
        if len(candidates) != 1:
            raise CaseError("The selected snapshot did not produce exactly one validated component.")
        remember(inputs.exchange_snapshot, candidates[0].sha256, 32 * 1024 * 1024)
    return watched


def _components_unchanged(watched):
    for path, expected in watched.items():
        raw = read_bytes(path, 32 * 1024 * 1024)
        info = path.stat()
        if (digest(raw), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != expected:
            raise CaseError("A source component changed while the package was being built.")


def _findings(observations):
    """Group equivalent source observations, never infer compromise or effective grants."""
    groups = {}
    outcome_keys = {"status", "result", "resultstatus", "resulttype", "nativeresult", "nativeresulttype",
        "sourceoutcome", "actiontype", "isclickedthrough", "changeconfirmedbysource", "eventtype",
        "enabled", "inerror", "deny", "isinherited", "accesscontroltype", "accessrights"}
    review_keys = {"name", "ruleidentity", "forwardto", "redirectto", "forwardasattachmentto", "from",
        "deletemessage", "markasread", "stopprocessingrules", "forwardingaddress", "forwardingsmtpaddress",
        "delivertomailboxandforward", "user", "trustee", "grantsendonbehalfto", "actortype", "actorupn",
        "actorid", "serviceprincipalid", "workloadidentityclass", "senderaddress", "recipientaddress"}
    for row in observations:
        fields = row["fields"]
        outcomes = {key: value for key, value in fields.items()
                    if re.sub(r"[^a-z0-9]", "", key.casefold()) in outcome_keys}
        properties = {key: value for key, value in fields.items()
                      if re.sub(r"[^a-z0-9]", "", key.casefold()) in review_keys}
        key = (row["source_id"], row["dataset"], row["kind"], row["operation"],
               row["native_id"] if row["kind"] == "snapshot" else "", json.dumps(outcomes, sort_keys=True),
               json.dumps(properties, sort_keys=True))
        if key not in groups:
            event_type = fields.get("event_type", "")
            title = row["operation"] + " observations"
            assessment = "unassessed source observations"
            rationale = "The source recorded these observations. Review their native outcomes and context; they do not establish malicious control."
            if row["kind"] == "snapshot":
                assessment = "current-state review lead"
                if row["dataset"] == "inbox_rules":
                    title = "Review current inbox-rule properties"
                    rationale = "Review enabled state and any forwarding, redirect or deletion action. A current rule observation does not date its creation or establish intent."
                elif row["dataset"] == "forwarding":
                    title = "Review current mailbox forwarding properties"
                    rationale = "Review the exact destination and delivery settings. Empty or null properties are observed current state, not proof of historical absence."
                elif row["dataset"] in {"full_access", "send_as", "send_on_behalf"}:
                    title = "Review current mailbox permission entry"
                    rationale = "Review the named trustee, rights, deny/allow and inheritance properties separately. This entry does not prove an effective grant or historical access."
                else:
                    title = "Review current " + row["dataset"] + " observation"
                    rationale = "This source describes state at acquisition. It does not establish the state during the incident or the time of any configuration change."
            elif event_type.startswith("password."):
                confirmed = fields.get("change_confirmed_by_source") == "true"
                title = "Source-confirmed password change" if confirmed else "Password operation attempt"
                assessment = "historical identity review lead"
                rationale = ("The source explicitly confirms a completed change; independently determine whether it was authorized."
                             if confirmed else "This row records an attempt or progress state. It does not establish a completed password change.")
            elif event_type == "safe_links.click":
                title = "Safe Links click observation"
                assessment = "historical message review lead"
                rationale = "Review action_type and is_clicked_through independently. A blocked action is not a successful navigation, and the observation does not prove page load or execution."
            elif event_type == "workload.signin.related_audit":
                title = "Application activity linked to target-user audit"
                assessment = "correlated application review lead"
                rationale = "An exact workload principal and correlation ID link this application activity to independently admitted target-user audit evidence. It is not a user authentication or proof of compromise."
            elif event_type in {"authentication_method.event", "device.registration.event"}:
                title = "Historical account identity operation"
                assessment = "historical identity review lead"
                rationale = "Review the native result and target identity. This historical operation is not a current method inventory, device posture assessment or proof of an effective change."
            groups[key] = dict(id=f"F{len(groups) + 1:06d}", title=title, dataset=row["dataset"], kind=row["kind"],
                operation=row["operation"], assessment=assessment, observed_outcome=outcomes or {"outcome": "not supplied"},
                observed_properties=properties,
                rationale=rationale, confidence="Source-backed observation; authorization and interpretation require analyst review.",
                evidence_ids=[], observation_ids=[])
        finding = groups[key]
        for evidence_id in [row["evidence_id"], *row.get("supporting_evidence_ids", [])]:
            if evidence_id not in finding["evidence_ids"]:
                finding["evidence_ids"].append(evidence_id)
        finding["observation_ids"].append(row["id"])
        row["finding_id"] = finding["id"]
    return list(groups.values())


def _supporting_references(sources, observations, evidence):
    audit_ids = {source["id"] for source in sources if source["source"] == "entra.audit-logs"}
    index = {}
    for entry in evidence:
        if entry["source_id"] in audit_ids:
            index.setdefault((entry["sha256"], entry["locator"]), []).append(entry)
    count = 0
    for row, primary in zip(observations, evidence):
        fields = row["fields"]
        sha, locators = fields.get("related_audit_sha256"), fields.get("related_audit_locators")
        if sha is None and locators is None:
            continue
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha) or not isinstance(locators, str):
            raise CaseError("Correlated workload evidence requires an exact audit hash and JSON locators.")
        pointers = exchange_json(locators.encode())
        if not isinstance(pointers, list) or not 1 <= len(pointers) <= 128 or any(not isinstance(pointer, str) for pointer in pointers):
            raise CaseError("Correlated workload evidence has invalid audit locators.")
        targets = {}
        for pointer in pointers:
            matches = index.get((sha, pointer), [])
            if not matches:
                raise CaseError("Correlated workload evidence lacks its independently admitted audit record.")
            for target in matches:
                if target["id"] == primary["id"]:
                    raise CaseError("An observation cannot provide its own independent audit support.")
                targets[target["id"]] = target
        ids = sorted(targets)
        count += sum(len(targets[identifier]["references"]) for identifier in ids)
        if count > MAX_REFERENCES:
            raise CaseError("Package exceeds 500,000 supporting source references.")
        references = [dict(evidence_id=identifier, **reference) for identifier in ids for reference in targets[identifier]["references"]]
        row["supporting_evidence_ids"] = ids
        row["supporting_references"] = references
        primary["supporting_evidence_ids"] = ids
        primary["supporting_references"] = references


def _coverage_text(coverage):
    paragraphs, receipts = [], set()
    for entry in coverage:
        receipt = entry.get("receipt_sha256")
        if receipt and receipt not in receipts:
            receipts.add(receipt)
            paragraphs.append(f"Exchange trace requested UTC: {entry['requested_start']} to {entry['requested_end']}. "
                f"Queryable UTC: {entry['queryable_start']} to {entry['queryable_end']}. {entry['queryable_basis']}.")
        label = f"{entry['source']} / {entry['dataset']}"
        if entry.get("id"):
            label += " / " + entry["id"]
        detail = f"{label}: {entry['status']}."
        if entry.get("start") is not None and entry.get("end") is not None:
            detail += f" UTC range: {entry['start']} to {entry['end']} (end excluded)."
        if entry.get("records") is not None:
            detail += f" Preserved rows: {entry['records']}."
        if entry.get("result_limit") is not None:
            detail += f" Row limit: {entry['result_limit']}. Checked UTC: {entry.get('checked_at') or 'unavailable (v2)'}."
        paragraphs.append(detail + " " + display_text(entry["detail"], 350))
    return paragraphs


def package_case(case_dir, output_dir, *, components=None, run_plan=None):
    """Return a fresh per-case acquisition directory without modifying the case.

    components is only package_inputs.PackageInputs or None. Source-specific
    validators, never caller-provided rows or callbacks, produce BoundSource.
    """
    from .package_inputs import PackageInputs, load_components

    if components is not None and type(components) is not PackageInputs:
        raise CaseError("Package components must be PackageInputs or None.")
    inputs = components
    output_root = safe_path(output_dir)
    snapshot = PackageSnapshot(case_dir)
    case = snapshot.case
    if user_address(case.meta["user"]) != case.meta["user"]:
        raise CaseError("Package case requires a canonical primary account.")
    if len(case.meta["user"]) > 320:
        raise CaseError("Package account identity exceeds the bounded display length.")
    if output_root == case.path or output_root.is_relative_to(case.path):
        raise CaseError("Package output must be outside the saved case.")
    items, receipts, originals, coverage, receipt_index = _trace_sources(snapshot)
    if sum(len(raw) for raw in originals.values()) > MAX_BYTES:
        raise CaseError("Package original-byte copies exceed 512 MiB.")
    loaded = load_components(case, receipts, inputs)
    if not isinstance(loaded, tuple):
        raise CaseError("Package component loader must return a typed tuple.")
    if not receipts and not loaded:
        reasons = " ".join(entry["detail"] for entry in coverage if entry["status"] == "excluded")
        raise CaseError("Package requires a verified scoped trace receipt or an explicitly validated bound source. " + reasons)
    watched_components = _component_files(inputs, loaded)
    items.extend(dict(source=source, references=[]) for source in loaded)
    if len(items) > 256 or sum(len(item["source"].raw) for item in items) > MAX_BYTES:
        raise CaseError("Package exceeds 256 sources or 512 MiB of source bytes.")
    if sum(len(item["source"].rows) * max(1, len(item["references"])) for item in items) > MAX_REFERENCES:
        raise CaseError("Package exceeds 500,000 original source references.")
    observations, evidence, sources = [], [], []
    for source_number, item in enumerate(items, 1):
        source = item["source"]
        parsed = _check_source(source, case)
        source_id = f"S{source_number:04d}"
        stem = _source_stem(source.source, source_id)
        if item["references"]:
            references = sorted(item["references"], key=lambda ref: (ref["file"], ref["read_id"]))
            original = references[0]["file"]
        else:
            original = (f"raw/{stem}.original.csv" if source.extension == "csv" else
                        f"originals/{stem}.{source.extension}")
            originals[original] = source.raw
            references = [dict(file=original)]
        display = f"raw/{stem}.display.csv"
        source_metadata = dict(id=source_id, source=source.source, sha256=source.sha256, original=original,
            display_csv=display, extension=source.extension, acquired_at=source.acquired_at, rows=len(source.rows),
            provenance=source.provenance, references=references)
        if source.provenance.get("trace_receipt_sha256"):
            matches = [entry for entry in receipt_index if entry["sha256"] == source.provenance["trace_receipt_sha256"]]
            if len(matches) != 1:
                raise CaseError("Package source lacks its independently verified trace receipt.")
            source_metadata["bound_trace_receipt"] = dict(file=matches[0]["file"], sha256=matches[0]["sha256"])
        if source.acquisition_receipt is not None:
            receipt_raw = source.acquisition_receipt
            if type(receipt_raw) is not bytes or len(receipt_raw) > 64 * 1024:
                raise CaseError("Package acquisition receipt is not bounded original bytes.")
            receipt = _strict_json(receipt_raw)
            if (not isinstance(receipt, dict) or receipt.get("schema") != "bec.authorized-source/v1" or
                    receipt.get("input_sha256") != source.sha256 or receipt.get("source") != source.source or
                    receipt.get("file") != source.provenance.get("source_filename") or
                    source.provenance.get("acquisition_receipt_sha256") != digest(receipt_raw)):
                raise CaseError("Package acquisition receipt differs from its admitted source.")
            safe_name(receipt.get("file", ""))
            receipt_path = f"originals/{source_id}.acquisition.json"
            originals[receipt_path] = receipt_raw
            source_metadata["acquisition_receipt"] = dict(file=receipt_path, sha256=digest(receipt_raw),
                original_filename=receipt["file"], packaged_original=original)
        sources.append(source_metadata)
        for entry in source.coverage:
            coverage.append(dict(source=source.source, source_id=source_id, dataset=entry.dataset, status=entry.status,
                detail=entry.detail, start=entry.start, end=entry.end))
        for row in source.rows:
            if len(observations) >= MAX_ROWS:
                raise CaseError("Package exceeds 200,000 source observations.")
            evidence_id = f"E{len(evidence) + 1:06d}"
            record_index = _resolve_locator(parsed, source.extension, row.locator)
            evidence.append(dict(id=evidence_id, source_id=source_id, sha256=source.sha256, file=original,
                locator=row.locator, record_index=record_index, native_id=row.native_id,
                references=[dict(**ref, sha256=source.sha256, locator=row.locator, record_index=record_index) for ref in references]))
            observations.append(dict(id=f"O{len(observations) + 1:06d}", evidence_id=evidence_id, source_id=source_id,
                dataset=row.dataset, kind=row.kind, utc=row.utc, operation=row.operation,
                native_id=row.native_id, fields=row.fields))
    if not sources:
        coverage.append(dict(source="package", dataset="all", status="unavailable", start=None, end=None,
            detail="No qualifying receipt-backed trace pages or explicitly bound source components were available."))
    present_sources = {source["source"] for source in sources}
    if not receipts:
        coverage.append(dict(source="exchange_trace", dataset="trace", status="not_supplied", start=None, end=None,
            detail="No independently verified scoped trace receipt was supplied for this package."))
    if "exchange_current_state" not in present_sources:
        for dataset in ("inbox_rules", "forwarding", "full_access", "send_as", "send_on_behalf"):
            coverage.append(dict(source="exchange_current_state", dataset=dataset, status="not_supplied", start=None, end=None,
                detail=f"Current {dataset.replace('_', ' ')} evidence was not supplied. This is distinct from an observed empty result."))
    for source, dataset in (("entra.user-signins.interactive", "entra_user_interactive"),
            ("entra.user-signins.noninteractive", "entra_user_noninteractive"), ("entra.audit-logs", "entra_audit"),
            ("purview.mailbox-audit", "purview_mailbox_audit"), ("defender.url-clicks", "defender_url_clicks")):
        if source not in present_sources:
            coverage.append(dict(source=source, dataset=dataset, status="not_supplied", start=None, end=None,
                detail=f"No verified {source} source was supplied; absence of this source is not a zero-event observation."))
    if sum(len(raw) for raw in originals.values()) > MAX_BYTES:
        raise CaseError("Package original-byte copies exceed 512 MiB.")
    _supporting_references(sources, observations, evidence)
    findings = _findings(observations)
    snapshot.check_unchanged()
    _components_unchanged(watched_components)
    package_id = _acquisition_id(datetime.now(UTC), uuid.uuid4().hex)
    if run_plan is None:
        account_folder = _account_folder(case.meta["user"])
        parent = output_root / safe_name(case.tenant) / safe_name(case.id) / account_folder
        target = parent / package_id
    else:
        from .run_index import package_destination

        if len(receipts) != 1:
            raise CaseError("A run mailbox package requires its single verified capture receipt.")
        target = package_destination(output_root, run_plan, case, receipts[0])
        parent = target.parent
    if parent == case.path or parent.is_relative_to(case.path):
        raise CaseError("Package acquisition hierarchy must remain outside the saved case.")
    safe_path(parent)
    if os.name == "nt" and any(len(str(target / relative).encode("utf-16-le")) // 2 > 240 for relative in (
            *originals, *(source["display_csv"] for source in sources), "raw/coverage.display.csv", "manifest.json")):
        raise CaseError("Choose a shorter local output root so package paths fit within 240 characters on Windows.")
    parent.mkdir(parents=True, exist_ok=True)
    safe_path(parent, exists=True, directory=True)
    stage = Path(tempfile.mkdtemp(prefix=".bec-package-", dir=parent))
    try:
        for relative, raw in originals.items():
            _write(stage / relative, raw)
        _write(stage / "evidence.json", encode(evidence))
        _write(stage / "observations.json", encode(observations))
        _write(stage / "findings.json", encode(findings))
        _write(stage / "coverage.json", encode(coverage))
        for source in sources:
            rows = [row for row in observations if row["source_id"] == source["id"]]
            fields = sorted({field for row in rows for field in row["fields"]})
            columns = ["evidence_id", "finding_id", "source_id", "dataset", "kind", "utc", "operation", "native_id", *fields]
            values = [[row[key] for key in columns[:8]] + [row["fields"].get(field, "") for field in fields] for row in rows]
            _csv(stage / source["display_csv"], columns, values)
        has_gaps = any(entry["status"] not in {"collected", "returned"} for entry in coverage)
        scope = dict(case_id=case.id, tenant=case.tenant, directory_id=case.meta.get("directory_id"),
                     account=case.meta["user"], start=case.meta["start"], end=case.meta["end"], bounds="[start,end)")
        limits = ["Only independently admitted sources are included. Saved timelines, findings, baselines and analyst text were not copied.",
            "Historical events are within the requested case interval. Snapshots describe acquisition-time state, not historical changes.",
            "Returned or empty records do not prove complete access, ingestion, retention, absence, maliciousness or remediation.",
            "Original bytes are unchanged source exports or reserialized source objects, not authenticated provider wire responses.",
            "CSV/XLSX/PDF are display copies. CSV formula-like text is prefixed with an apostrophe; display controls and long text are normalized.",
            "The PDF uses standard fonts and displays unsupported characters as [U+XXXX] code points. Unicode originals, UTF-8 CSVs and XLSX retain the source text."]
        summary_rows = [[key, value] for key, value in scope.items()] + [["package_id", package_id],
            ["source_files", len(sources)], ["observations", len(observations)], ["coverage_gaps", has_gaps]] + [["Interpretation limit", text] for text in limits]
        coverage_keys = ("source", "dataset", "status", "id", "direction", "requested_start", "requested_end",
            "queryable_start", "queryable_end", "start", "end", "planned_at", "captured_at", "checked_at", "records", "result_limit", "detail")
        coverage_columns = ["Source", "Dataset", "Status", "Read ID", "Direction", "Requested start UTC", "Requested end UTC",
            "Queryable start UTC", "Queryable end UTC", "Actual start UTC", "Actual end UTC", "Planned UTC", "Captured UTC", "Checked UTC", "Preserved rows", "Row limit", "Detail"]
        coverage_rows = [[entry.get(key, "") for key in coverage_keys] for entry in coverage]
        _csv(stage / "raw/coverage.display.csv", coverage_columns, coverage_rows)
        def observation_rows(kind):
            return [[row[key] for key in ("evidence_id", "finding_id", "source_id", "dataset", "utc", "operation", "native_id")] +
                    [json.dumps(row["fields"], ensure_ascii=False, sort_keys=True)]
                    for row in sorted(observations, key=lambda value: (value["utc"], value["id"])) if row["kind"] == kind]
        observation_index = {row["id"]: row for row in observations}
        finding_rows = [[finding["id"], finding["title"], json.dumps(finding["observed_outcome"], ensure_ascii=False, sort_keys=True),
            finding["rationale"], finding["confidence"], evidence_id, observation_id,
            "primary" if evidence_id == observation_index[observation_id]["evidence_id"] else "supporting audit",
            json.dumps(finding["observed_properties"], ensure_ascii=False, sort_keys=True)]
            for finding in findings for observation_id in finding["observation_ids"]
            for evidence_id in [observation_index[observation_id]["evidence_id"], *observation_index[observation_id].get("supporting_evidence_ids", [])]]
        evidence_rows = [[entry[key] for key in ("id", "source_id", "file", "sha256", "locator", "record_index", "native_id")] +
                         [len(entry["references"])] for entry in evidence]
        reference_rows = [[entry["id"], entry["source_id"], reference["file"], reference["sha256"], reference["locator"],
            reference["record_index"], reference.get("receipt_file", ""), reference.get("receipt_sha256", ""), reference.get("read_id", "")]
            for entry in evidence for reference in entry["references"]]
        tables = [dict(name="Summary", columns=["Field", "Value"], rows=summary_rows),
            dict(name="Findings", columns=["Finding ID", "Review lead", "Observed outcome", "Rationale", "Confidence", "Evidence ID", "Observation ID", "Evidence role", "Observed source properties"],
                 rows=finding_rows, evidence_columns=(5,)),
            dict(name="Coverage", columns=coverage_columns, rows=coverage_rows),
            dict(name="Timeline", columns=["Evidence ID", "Finding ID", "Source ID", "Dataset", "Event UTC", "Operation", "Native ID", "Projected metadata"],
                 rows=observation_rows("event"), evidence_columns=(0,)),
            dict(name="Current state", columns=["Evidence ID", "Finding ID", "Source ID", "Dataset", "Observed UTC", "Operation", "Native ID", "Projected metadata"],
                 rows=observation_rows("snapshot"), evidence_columns=(0,)),
            dict(name="Supporting evidence", columns=["Observation ID", "Primary evidence ID", "Supporting audit evidence ID"],
                 rows=[[row["id"], row["evidence_id"], identifier] for row in observations for identifier in row.get("supporting_evidence_ids", [])],
                 evidence_columns=(1, 2)),
            dict(name="Evidence", columns=["Evidence ID", "Source ID", "Original file", "SHA-256", "Native locator", "Zero-based record index", "Native ID", "Reference count"], rows=evidence_rows),
            dict(name="Source references", columns=["Evidence ID", "Source ID", "Original alias", "SHA-256", "Native locator", "Zero-based record index", "Receipt file", "Receipt SHA-256", "Read ID"],
                 rows=reference_rows, evidence_columns=(0,))]
        write_workbook(stage / "triage.xlsx", tables, {entry["id"]: index + 2 for index, entry in enumerate(evidence)})
        from .mailbox_report import build_mailbox_report, native_snapshot_rows
        sections, references = build_mailbox_report(scope, observations, coverage, findings, evidence, limits,
            coverage_details=_coverage_text(coverage), native_rows=native_snapshot_rows(sources, evidence, originals))
        write_pdf(stage / "investigation.pdf", "Mailbox investigation review", sections, references,
                  subtitle="Current settings, dated activity and the gaps that limit interpretation.")
        _write(stage / "README.txt", ("BEC scoped evidence package\n\n" + "\n".join(limits) +
            "\n\nStart with investigation.pdf and triage.xlsx. Source CSVs under raw/ are display projections unless their filename ends .original.csv. "
            "Exact non-CSV inputs are under originals/. Evidence IDs resolve through evidence.json; all file hashes are in manifest.json and SHA256SUMS.txt.\n").encode())
        files = [{"path": str(path.relative_to(stage)).replace("\\", "/"), "sha256": digest(read_bytes(path)), "bytes": path.stat().st_size}
                 for path in sorted(stage.rglob("*")) if path.is_file()]
        result = dict(schema=SCHEMA, package_id=package_id, scope=scope, sources=sources, files=files,
            trace_receipts=receipt_index,
            has_coverage_gaps=has_gaps, counts=dict(sources=len(sources), observations=len(observations), findings=len(findings),
                evidence_records=len(evidence), evidence_references=sum(len(entry["references"]) for entry in evidence)),
            coverage_file="coverage.json", observations_file="observations.json", findings_file="findings.json", evidence_file="evidence.json", limits=limits)
        _write(stage / "manifest.json", encode(result))
        hashes = [*files, dict(path="manifest.json", sha256=digest(read_bytes(stage / "manifest.json")))]
        _write(stage / "SHA256SUMS.txt", "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in hashes).encode())
        snapshot.check_unchanged()
        _components_unchanged(watched_components)
        inspect_tree(stage)
        publish_directory(stage, target)
        return target
    except BaseException:
        shutil.rmtree(stage)
        raise
