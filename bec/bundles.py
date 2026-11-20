"""Read export manifests and resolve their source files without provider access."""
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from .storage import CaseError, DATASETS

EXCHANGE_SCHEMA = "bec.exchange-powershell/v2"
EXCHANGE_SCHEMA_V3 = "bec.exchange-powershell/v3"
EXCHANGE_SCHEMAS = (EXCHANGE_SCHEMA, EXCHANGE_SCHEMA_V3)


def exchange_json(raw):
    """Reject ambiguous fields in a versioned receipt or message trace page."""
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CaseError("Duplicate field in Exchange JSON.")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_fields)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CaseError("Invalid UTF-8 JSON in the Exchange capture.") from exc


def local_path(value):
    """Reject network and device paths before probing a workstation file."""
    text = os.fspath(value)
    win = PureWindowsPath(text)
    if (not text.strip() or "\x00" in text or text.replace("\\", "/").startswith("//")
            or (re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", text) and not (os.name == "nt" and win.is_absolute()))):
        raise CaseError("Offline mode requires a path on a local drive.")
    path = Path(text).absolute()
    if os.name == "nt":
        from ctypes import windll
        # Check the drive and its components before traversing any redirected directory.
        if PureWindowsPath(path).drive.startswith("\\\\") or windll.kernel32.GetDriveTypeW(path.anchor) not in (2, 3, 5, 6):
            raise CaseError("Offline mode requires a local drive, not a mapped share.")
        for component in (*reversed(path.parents), path):
            if component.is_symlink() or component.is_junction():
                raise CaseError("Use a local path without a symbolic link or junction in offline mode.")
    return path


@dataclass(frozen=True)
class ExportBundle:
    manifest: dict
    files: list
    raw_manifest: bytes

    @classmethod
    def load(cls, path, *, offline=False):
        if offline:
            path = local_path(path)
            if not path.is_file():
                raise CaseError("The local bundle manifest is missing or is not a regular file.")
        path = Path(path).resolve()
        try:
            raw = path.read_bytes()
            manifest = json.loads(raw.decode("utf-8-sig"))
        except (ValueError, UnicodeError) as exc:
            raise CaseError("Bundle manifest must contain valid UTF-8 JSON.") from exc
        if not isinstance(manifest, dict):
            raise CaseError("Bundle manifest must be a JSON object.")
        if not isinstance(manifest.get("tenant"), str) or not manifest["tenant"].strip():
            raise CaseError("Bundle manifest must identify its tenant.")
        schema = manifest.get("schema")
        exchange = schema in EXCHANGE_SCHEMAS
        capture_fields = "reads" in manifest or {"scope", "captured_at"} <= manifest.keys()
        exchange_version = isinstance(schema, str) and schema.startswith("bec.exchange-powershell/")
        if not exchange and (capture_fields or exchange_version):
            raise CaseError("Exchange capture import requires a trace-only v2 or v3 receipt.")
        if exchange:
            manifest = exchange_json(raw)
        receipt_fields = {"schema", "tenant", "directory_id", "files", "scope", "reads", "captured_at"}
        if schema == EXCHANGE_SCHEMA_V3:
            receipt_fields.add("planned_at")
        if exchange and set(manifest) != receipt_fields:
            raise CaseError("Unexpected fields in the Exchange trace receipt.")
        if exchange and not offline:
            raise CaseError("Use bec offline for a versioned Exchange PowerShell bundle.")
        if exchange and (path.parent / "audit.json").exists():
            raise CaseError("Exchange trace capture directory contains a legacy audit file.")
        entries = manifest.get("files")
        if not isinstance(entries, list) or (not entries and not exchange):
            raise CaseError("Bundle manifest must list one or more files.")
        files = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("dataset") not in DATASETS:
                raise CaseError("Each bundle entry must name a supported dataset.")
            if exchange:
                name = entry.get("path")
                scoped_name = (name in ("sent.json", "received.json") if schema == EXCHANGE_SCHEMA else
                               isinstance(name, str) and re.fullmatch(r"(?:sent|received)-0[1-9]\.json", name))
                if set(entry) != {"dataset", "path", "sha256"} or entry["dataset"] != "trace" or not scoped_name:
                    raise CaseError("Exchange receipts may list only their scoped trace files.")
            name = entry.get("path")
            if not isinstance(name, str) or not name.strip() or "\x00" in name:
                raise CaseError("Each bundle entry must name an export file.")
            if offline:
                relative = PureWindowsPath(name)
                if relative.anchor or ":" in name or ".." in relative.parts:
                    raise CaseError("Offline bundle entries must use local paths relative to the manifest.")
                source = local_path(path.parent / name).resolve()
            else:
                source = (path.parent / name).resolve()
            if source == path.parent or not source.is_relative_to(path.parent):
                raise CaseError("Bundle source must be inside its manifest directory.")
            if offline and (source == path or not source.is_file()):
                raise CaseError("A listed export is missing or is not a separate regular file: " + name)
            files.append((entry["dataset"], name, source))
        return cls(manifest, files, raw)

    def check_binding(self, tenant, directory_id, customer_id):
        if self.manifest["tenant"] != tenant or self.manifest.get("directory_id") != directory_id:
            raise CaseError("Bundle tenant binding differs from the case profile.")
        if "google_customer_id" in self.manifest and self.manifest["google_customer_id"] != customer_id:
            raise CaseError("Bundle Workspace customer differs from the case profile.")
