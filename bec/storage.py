"""Tenant-scoped cases, content-addressed evidence and case locking."""
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from . import __version__
from .hunting import TABLES

DATA = Path(__file__).parent / "data"
GOOGLE_APPS = {"google_login": "login", "google_oauth": "token", "google_gmail": "gmail"}
DATASETS = ("interactive", "noninteractive", "directory", "ual", "trace", "service_principal") + TABLES + tuple(GOOGLE_APPS)
DEFAULTS = dict(baseline_days=30, max_depth=3, max_users=15, max_ips=30,
                max_events=100000, shared_ip_users=5, timezone="UTC", trusted_networks=[], defender=True)
CASE_ID = re.compile(r"INC-[0-9]{4}-[a-f0-9]{12}")
LABEL = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}")
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(1, 10)}


class CaseError(ValueError):
    pass


class SourceError(Exception):
    """A reportable telemetry gap with a safe-to-log explanation."""


def timestamp(value, vendor_utc=False):
    if not isinstance(value, str) or "T" not in value and " " not in value:
        raise CaseError("An ISO date and time with timezone is required.")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        if not vendor_utc:
            raise CaseError("Timestamp has no UTC offset.")
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def iso(dt):
    return dt.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def now():
    return iso(datetime.now(UTC))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def read(path):
    return json.loads(path.read_bytes().decode("utf-8-sig"))


def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".writing-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def save(path, obj):
    atomic(path, encode(obj))


def user_address(value):
    if not isinstance(value, str) or not re.fullmatch(r"[^\s@/\\\x00-\x1f]+@[^\s@/\\\x00-\x1f]+", value):
        raise CaseError("Provide a user principal name such as analyst@example.com.")
    return value.casefold()


def settings(options):
    unknown = set(options) - set(DEFAULTS)
    if unknown:
        raise CaseError("Unknown investigation options: " + ", ".join(sorted(unknown)))
    cfg = {**DEFAULTS, **options}
    if type(cfg["defender"]) is not bool:
        raise CaseError("defender must be true or false.")
    for key in ("baseline_days", "max_depth", "max_users", "max_ips", "max_events", "shared_ip_users"):
        if type(cfg[key]) is not int or cfg[key] < (0 if key in ("baseline_days", "max_depth") else 1):
            raise CaseError("Invalid investigation option: " + key)
    if cfg["baseline_days"] > 365 or cfg["max_depth"] > 10:
        raise CaseError("Maximum baseline is 365 days and maximum depth is 10.")
    if not isinstance(cfg["trusted_networks"], list):
        raise CaseError("trusted_networks must be a list of CIDRs.")
    for cidr in cfg["trusted_networks"]:
        ipaddress.ip_network(cidr)
    ZoneInfo(cfg["timezone"])
    return cfg


def workspace_profile(value):
    if not isinstance(value, dict) or set(value) - {"customer_id", "admin_email"}:
        raise CaseError("google_workspace accepts customer_id and optional admin_email.")
    if not re.fullmatch(r"C[A-Za-z0-9]+", str(value.get("customer_id", ""))):
        raise CaseError("Set google_workspace.customer_id to the Workspace customer ID.")
    profile = {"customer_id": value["customer_id"]}
    if value.get("admin_email"):
        profile["admin_email"] = user_address(value["admin_email"])
    return profile


def microsoft_enabled(case):
    return case.meta.get("microsoft", True)


def create(root, tenant, user, start, end, profile=None, *, delegated=False, export_only=False, named_account=False):
    if not LABEL.fullmatch(tenant) or tenant.upper() in RESERVED:
        raise CaseError("Invalid tenant alias.")
    start, end = timestamp(start), timestamp(end)
    if start >= end:
        raise CaseError("The end must be later than the start.")
    user = user_address(user)
    p = profile or {}
    if p and (p.get("tenant") != tenant or set(p) - {"tenant", "directory_id", "client_id", "options", "google_workspace", "microsoft"}):
        raise CaseError("Profile must match the tenant and contain only documented keys.")
    directory_id = str(uuid.UUID(p["directory_id"])) if p.get("directory_id") else None
    client_id = str(uuid.UUID(p["client_id"])) if p.get("client_id") else None
    if export_only and (client_id or delegated):
        raise CaseError("An offline case accepts evidence identifiers only.")
    if not export_only and bool(directory_id) != bool(client_id):
        raise CaseError("Supply both directory_id and client_id for a live profile.")
    cfg = settings(p.get("options", {}))
    google = workspace_profile(p["google_workspace"]) if "google_workspace" in p else None
    microsoft = p.get("microsoft", bool(directory_id) or not google)
    if type(microsoft) is not bool or not (microsoft or google):
        raise CaseError("Enable at least one provider using a valid tenant profile.")
    if delegated and (not directory_id or not microsoft or google):
        raise CaseError("Investigator sign-in requires a Microsoft-only case bound to its directory.")
    case_id = f"INC-{datetime.now(UTC).year}-{uuid.uuid4().hex[:12]}"
    path = root / tenant / case_id
    path.mkdir(parents=True)
    save(path / "case.json", dict(version=__version__, id=case_id, tenant=tenant, user=user,
         start=iso(start), end=iso(end), created=now(), directory_id=directory_id, client_id=client_id,
         microsoft=microsoft, google_workspace=google, options=cfg,
         **({"microsoft_auth": "delegated"} if delegated else {}),
         **({"export_only": True} if export_only else {}),
         **({"collection_scope": "named_account"} if named_account else {})))
    save(path / "evidence_manifest.json", dict(case_id=case_id, tenant=tenant, artifacts=[]))
    return Case(path)


class Case:
    def __init__(self, path):
        self.path = path
        self.meta = read(path / "case.json")
        self.tenant = self.meta["tenant"]
        self.id = self.meta["id"]
        if path.name != self.id or path.parent.name != self.tenant:
            raise CaseError("Tenant or case directory does not match metadata.")
        self.options = self.meta["options"]

    @classmethod
    def find(cls, root, case_id, *, other_root=None):
        if not CASE_ID.fullmatch(case_id):
            raise CaseError("Invalid case ID.")
        roots = {root.resolve()}
        if other_root is not None:
            roots.add(other_root.resolve())
        matches = [path for directory in roots for path in directory.glob("*/" + case_id + "/case.json")]
        if len(matches) != 1:
            raise CaseError("Case not found or ambiguous in this case store.")
        return cls(matches[0].parent)

    @contextmanager
    def lock(self):
        # Kernel locks are released on process termination.
        with (self.path / ".lock").open("a+b") as f:
            f.seek(0)
            if os.name == "nt":
                import msvcrt
                acquire = lambda: msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                acquire = lambda: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                acquire()
            except OSError as exc:
                raise CaseError("Another process is using this case.") from exc
            yield

    def log(self, action, **fields):
        with (self.path / "bec.log").open("a", encoding="utf-8") as f:
            f.write(json.dumps(dict(time=now(), tenant=self.tenant, case_id=self.id, action=action, **fields)) + "\n")

    def manifest(self):
        m = read(self.path / "evidence_manifest.json")
        if m["tenant"] != self.tenant or m["case_id"] != self.id:
            raise CaseError("Manifest identity mismatch.")
        return m

    def raw_path(self, entry):
        path = self.path / entry["artifact"]
        expected = self.path / "raw" / entry["dataset"] / (entry["sha256"] + ".json")
        if (entry["dataset"] not in DATASETS or not re.fullmatch("[a-f0-9]{64}", entry["sha256"])
                or path != expected or not path.resolve().is_relative_to((self.path / "raw").resolve())):
            raise CaseError("Invalid artifact location.")
        return path

    def receipt_path(self, sha):
        if not isinstance(sha, str) or not re.fullmatch("[a-f0-9]{64}", sha):
            raise CaseError("Invalid Exchange receipt reference.")
        path = self.path / "collection" / "exchange" / (sha + ".json")
        if not path.resolve().is_relative_to(self.path.resolve()):
            raise CaseError("Exchange receipt must remain inside its case.")
        return path

    def verify(self):
        # A raw page and its manifest are two files. Finish any interrupted
        # transaction while the caller holds the case lock.
        journal = self.path / ".pending-artifact.json"
        if journal.exists():
            pending = read(journal)
            path = self.raw_path(pending)
            if pending["tenant"] != self.tenant:
                raise CaseError("Pending acquisition belongs to another tenant.")
            if path.exists():
                if digest(path.read_bytes()) != pending["sha256"]:
                    raise CaseError("Pending artifact verification failed.")
                m = self.manifest()
                if not any(a["artifact"] == pending["artifact"] for a in m["artifacts"]):
                    m["artifacts"].append(pending)
                    save(self.path / "evidence_manifest.json", m)
            journal.unlink()
        manifest = self.manifest()
        for sha in manifest.get("exchange_receipts", []):
            receipt = self.receipt_path(sha)
            if not receipt.is_file() or digest(receipt.read_bytes()) != sha:
                raise CaseError("Exchange receipt verification failed.")
        expected = set()
        for entry in manifest["artifacts"]:
            path = self.raw_path(entry)
            if entry["tenant"] != self.tenant or not path.is_file() or digest(path.read_bytes()) != entry["sha256"]:
                raise CaseError("Evidence verification failed: " + entry["artifact"])
            expected.add(path)
        extra = set((self.path / "raw").rglob("*.json")) - expected
        if extra:
            raise CaseError("Unmanifested raw artifact: " + str(next(iter(extra))))
        return len(expected)

    def preserve(self, dataset, data, collector, query, records, actual):
        sha = digest(data)
        rel = f"raw/{dataset}/{sha}.json"
        m = self.manifest()
        path = self.path / rel
        if path.exists():
            if digest(path.read_bytes()) != sha:
                raise CaseError("Existing evidence hash mismatch.")
        for item in m["artifacts"]:
            if item["artifact"] == rel:
                if query not in item["queries"]:
                    item["queries"].append(query)
                    save(self.path / "evidence_manifest.json", m)
                return
        item = dict(artifact=rel, dataset=dataset, tenant=self.tenant,
            sha256=sha, collected_at=now(), collector=collector, version=__version__, queries=[query],
            records=records, actual_timeframe=actual)
        journal = self.path / ".pending-artifact.json"
        save(journal, item)
        if not path.exists():
            atomic(path, data)
        m["artifacts"].append(item)
        save(self.path / "evidence_manifest.json", m)
        journal.unlink()
