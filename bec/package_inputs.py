"""Read explicitly selected, local evidence for a single investigation package."""
from dataclasses import dataclass, replace
from pathlib import Path
from uuid import UUID

from .bundles import EXCHANGE_SCHEMA_V3, exchange_json
from .package_safety import read_bytes, safe_name, safe_path
from .storage import CaseError, digest


MAX_SOURCES = 32
MAX_RECEIPT = 64 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_INPUT_BYTES = 128 * 1024 * 1024
WORKLOAD_SOURCES = {"entra.workload-signins.service-principal", "entra.workload-signins.managed-identity"}


@dataclass(frozen=True)
class PackageInputs:
    imports: tuple[Path, ...] = ()
    exchange_snapshot: Path | None = None
    user_object_id: str | None = None
    mailbox_guid: str | None = None
    snapshot_sha256: str | None = None


def _guid(value):
    if value is None:
        return None
    try:
        guid = UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise CaseError("Expected a nonempty GUID obtained independently for this case.") from exc
    if not guid.int:
        raise CaseError("An empty GUID cannot identify an investigation target.")
    return str(guid)


def _anchor(supplied, observed):
    supplied, observed = _guid(supplied), _guid(observed)
    if supplied and observed and supplied != observed:
        raise CaseError("An independently supplied identifier differs from the verified mailbox snapshot.")
    return supplied or observed


def _mapping(raw, label):
    try:
        content = exchange_json(raw)
    except (ValueError, RecursionError) as exc:
        raise CaseError(f"Invalid or ambiguous JSON in {label}.") from exc
    if not isinstance(content, dict):
        raise CaseError(f"Expected a JSON object for {label}.")
    return content


def paired_snapshot(path, receipts, tenant, account, start, end, *, expected_hash=None):
    from .exchange_snapshot import validate_snapshot

    if not isinstance(expected_hash, str) or len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash):
        raise CaseError("Supply the original lowercase SHA-256 recorded when the Exchange snapshot was acquired.")
    raw = read_bytes(path, MAX_SOURCE_BYTES)
    if digest(raw) != expected_hash:
        raise CaseError("The mailbox snapshot differs from its original acquisition SHA-256.")
    capture_id = _mapping(raw, "mailbox snapshot").get("trace_receipt_sha256")
    matches = [r for r in receipts if r.schema == EXCHANGE_SCHEMA_V3 and r.sha == capture_id]
    if len(matches) != 1:
        raise CaseError("The mailbox snapshot must reference one verified trace receipt from this case.")
    receipt = matches[0]
    return validate_snapshot(raw, tenant=tenant, account=account, start=start, end=end,
                             operator=receipt.scope["operator"], connection=receipt.scope["connection"],
                             trace_receipt_sha256=receipt.sha)


def _acquisition(manifest_path):
    path = safe_path(manifest_path, exists=True)
    receipt_bytes = read_bytes(path, MAX_RECEIPT)
    manifest = _mapping(receipt_bytes, "authorized acquisition receipt")
    fields = {"schema", "file", "source", "tenant_id", "account", "start", "end", "acquired_at",
              "input_sha256", "scope_basis", "format", "attested_by"}
    if isinstance(manifest.get("source"), str) and manifest["source"] in WORKLOAD_SOURCES:
        fields.update({"related_audit_sha256", "workload_principal_id"})
    if (set(manifest) != fields or manifest["schema"] != "bec.authorized-source/v1"
            or not all(isinstance(value, str) for value in manifest.values())):
        raise CaseError("An acquisition requires the documented bec.authorized-source/v1 fields.")
    filename = safe_name(manifest.pop("file"))
    if manifest["format"] not in ("json", "csv") or Path(filename).suffix.lower() != "." + manifest["format"]:
        raise CaseError("The acquisition filename must match its declared JSON or CSV format.")
    data_path = safe_path(path.parent / filename, exists=True)
    if data_path.samefile(path):
        raise CaseError("An acquisition must reference a separate original file.")
    manifest.pop("schema")
    return data_path, receipt_bytes, manifest


def _read_source(info, scope, remaining, sources):
    from .incident_imports import AcquisitionAttestation, verify_incident_source

    data_path, receipt_bytes, fields = info
    manifest = fields.copy()
    binding = {}
    if manifest["source"] in WORKLOAD_SOURCES:
        audit_sha = manifest.pop("related_audit_sha256")
        audit = next((s for s in sources if s.source == "entra.audit-logs" and s.sha256 == audit_sha), None)
        if audit is None:
            raise CaseError("A workload sign-in requires its explicitly referenced, verified Entra audit export.")
        binding = dict(related_audit=audit, workload_principal_id=_guid(manifest.pop("workload_principal_id")))
    acquisition = AcquisitionAttestation(**manifest)
    raw = read_bytes(data_path, min(MAX_SOURCE_BYTES, remaining))
    verified = verify_incident_source(raw, source=acquisition.source, scope=scope, acquisition=acquisition, **binding)
    provenance = {**verified.provenance, "acquisition_receipt_sha256": digest(receipt_bytes),
                  "source_filename": data_path.name, "attested_by": acquisition.attested_by}
    return replace(verified, provenance=provenance, acquisition_receipt=receipt_bytes)


def load_components(case, receipts, inputs):
    if inputs is None or inputs == PackageInputs():
        return ()
    if not isinstance(inputs, PackageInputs) or len(inputs.imports) > MAX_SOURCES:
        raise CaseError(f"Use at most {MAX_SOURCES} local acquisition receipts for one package.")
    from .incident_imports import IncidentScope

    meta = case.meta
    tenant = _guid(meta.get("directory_id"))
    if not tenant:
        raise CaseError("Additional Microsoft evidence requires an independently directory-bound case.")
    sources = []
    provenance = {}
    if inputs.snapshot_sha256 is not None and inputs.exchange_snapshot is None:
        raise CaseError("--snapshot-sha256 requires the corresponding --exchange-snapshot file.")
    if inputs.exchange_snapshot is not None:
        snapshot = paired_snapshot(inputs.exchange_snapshot, receipts, tenant, meta["user"],
                                   meta["start"], meta["end"], expected_hash=inputs.snapshot_sha256)
        sources.append(snapshot)
        provenance = snapshot.provenance
    scope = IncidentScope(tenant_id=tenant, account=meta["user"], start=meta["start"], end=meta["end"],
                          user_object_id=_anchor(inputs.user_object_id, provenance.get("user_object_id")),
                          mailbox_guid=_anchor(inputs.mailbox_guid, provenance.get("mailbox_guid")))
    remaining = MAX_INPUT_BYTES - sum(len(source.raw) for source in sources)
    seen = set()
    acquisitions = [_acquisition(path) for path in inputs.imports]
    # Admit the referenced audit evidence first, independent of the order of command-line options.
    acquisitions.sort(key=lambda info: info[2]["source"] in WORKLOAD_SOURCES)
    for info in acquisitions:
        receipt = digest(info[1])
        if receipt in seen:
            raise CaseError("The same acquisition receipt was supplied more than once.")
        seen.add(receipt)
        source = _read_source(info, scope, remaining, sources)
        remaining -= len(source.raw)
        sources.append(source)
    return tuple(sources)
