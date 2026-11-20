"""Verified observations exchanged by the case packager and source-specific readers."""
from dataclasses import dataclass


@dataclass(frozen=True)
class SourceRow:
    dataset: str
    kind: str
    utc: str
    operation: str
    native_id: str
    locator: str
    fields: dict[str, str]


@dataclass(frozen=True)
class SourceCoverage:
    dataset: str
    status: str
    detail: str
    start: str | None = None
    end: str | None = None


@dataclass(frozen=True)
class BoundSource:
    source: str
    tenant: str
    account: str
    start: str
    end: str
    acquired_at: str
    extension: str
    raw: bytes
    sha256: str
    rows: tuple[SourceRow, ...]
    coverage: tuple[SourceCoverage, ...]
    provenance: dict[str, str]
    acquisition_receipt: bytes | None = None
