"""Read export manifests and resolve their source files without provider access."""
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from .storage import CaseError, DATASETS

EXCHANGE_SCHEMA = "bec.exchange-powershell/v1"


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
        if isinstance(schema, str) and schema.startswith("bec.exchange-powershell/") and schema != EXCHANGE_SCHEMA:
            raise CaseError("Unsupported Exchange PowerShell receipt version.")
        exchange = schema == EXCHANGE_SCHEMA
        if exchange and not offline:
            raise CaseError("Use bec offline for a versioned Exchange PowerShell bundle.")
        entries = manifest.get("files")
        if not isinstance(entries, list) or (not entries and not exchange):
            raise CaseError("Bundle manifest must list one or more files.")
        files = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("dataset") not in DATASETS:
                raise CaseError("Each bundle entry must name a supported dataset.")
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
