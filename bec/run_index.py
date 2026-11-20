"""Owned, monotone local run indexes for an already confirmed Exchange plan.

This module never confirms a plan or acquires provider data. The interactive
planner calls it only after consent. Every subsequent operation supplies that
same plan. A run is one-shot: accounts, cases, receipts and package destinations
cannot be rebound, resumed into a different session, or overwritten. The index
describes orchestration status only; it does not combine mailbox evidence.

State and PDF replacements are individually atomic. State is committed before
the new PDF, so a hard stop can leave an older, incomplete PDF but cannot publish
a premature completion. A narrow transition journal permits only the exact
owned prior PDF to be replaced on a later finalization attempt.
Local hashes detect changed files; they are not signatures or access control.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
import unicodedata
import uuid

from .bundles import EXCHANGE_SCHEMA_V3, ExportBundle
from .exchange import ExchangeReceipt, LIMIT, affected_accounts
from .package_documents import write_pdf
from .package_safety import MAX_FILE_BYTES, inspect_tree, publish_directory, read_bytes, safe_name, safe_path
from .storage import CASE_ID, Case, CaseError, digest, encode, iso, timestamp
from .trace_windows import chunk_plan, requested_window

SCHEMA = "bec.run-index/v1"
PLAN_BYTES = 1024 * 1024
STATE_BYTES = 16 * 1024 * 1024
RUN_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}")
SUMMARY = "Run summary.pdf"
INTERNAL = ".bec-run"
ACCOUNT_STATUSES = {"not-yet-attempted", "active", "packaged", "gaps", "failed", "canceled",
                    "not-attempted-after-interruption"}
FINISHED = {"packaged", "gaps"}
STATE_FIELDS = {"schema", "run_id", "plan", "plan_sha256", "created_at", "updated_at", "revision",
                "status", "closed_at", "accounts", "summary_sha256"}
ACCOUNT_FIELDS = {"account", "folder", "status", "started_at", "finished_at", "case_id", "case_path",
                  "case_metadata_sha256", "case_manifest_sha256", "receipt_sha256", "package_manifest_sha256"}
PIN_FIELDS = ("case_id", "case_path", "case_metadata_sha256", "case_manifest_sha256", "receipt_sha256")


def _json(raw, label):
    def pairs(items):
        result, seen = {}, set()
        for key, value in items:
            if key.casefold() in seen:
                raise CaseError(f"Duplicate or ambiguous fields in {label}.")
            seen.add(key.casefold())
            result[key] = value
        return result

    def nonfinite(_):
        raise CaseError(f"Non-finite numbers in {label}.")

    try:
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs, parse_constant=nonfinite)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, CaseError):
            raise
        raise CaseError(f"Invalid bounded UTF-8 JSON in {label}.") from None


def _text(value, label, limit=320):
    if (not isinstance(value, str) or not value or len(value) > limit or value != value.strip()
            or any(unicodedata.category(c).startswith("C") for c in value)):
        raise CaseError(f"Invalid {label}.")
    return value


def _guid(value):
    value = _text(value, "run identity GUID", 36)
    try:
        result = uuid.UUID(value)
    except ValueError:
        raise CaseError("A nonempty tenant/connection GUID is required.") from None
    if not result.int:
        raise CaseError("A nonempty tenant/connection GUID is required.")
    return str(result)


def _account(value):
    value = _text(value, "exact run account")
    values = affected_accounts([value])
    if len(values) != 1 or values[0] != value.casefold():
        raise CaseError("Use one exact account address.")
    return values[0]


def _utc(value):
    if (not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value)):
        raise CaseError("Run ownership needs an explicit UTC timestamp with at most six fractional digits.")
    return iso(timestamp(value))


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise CaseError("A lowercase original SHA-256 is required.")
    return value


def validate_plan(plan, *, case_root=None):
    """Normalize the existing planner result without writes; usable before consent."""
    required = {"tenant", "operator", "connection", "start", "end", "planned_at", "chunks", "accounts", "root", "limit"}
    if not isinstance(plan, dict) or not required <= plan.keys() or set(plan) - required - {"snapshot_schema"}:
        raise CaseError("Run ownership requires the complete confirmed Exchange plan.")
    try:
        if len(encode(plan)) > PLAN_BYTES:
            raise CaseError("The confirmed plan exceeds the 1 MiB local planning limit.")
    except (TypeError, RecursionError, OverflowError):
        raise CaseError("The confirmed plan must contain bounded JSON values.") from None
    tenant, connection, operator = _guid(plan["tenant"]), _guid(plan["connection"]), _account(plan["operator"])
    start, end = requested_window(_utc(plan["start"]), _utc(plan["end"]))
    planned_at = _utc(plan["planned_at"])
    if not end <= planned_at <= iso(datetime.now(UTC)):
        raise CaseError("Run planning time is outside its completed requested window.")
    chunks = chunk_plan(start, end, planned_at)
    if not chunks or plan["chunks"] != chunks or type(plan["limit"]) is not int or plan["limit"] != LIMIT:
        raise CaseError("Run trace limits or retained ranges differ from the confirmed plan.")
    if not isinstance(plan["accounts"], list) or not plan["accounts"]:
        raise CaseError("The confirmed plan needs its ordered affected accounts.")
    accounts = [_account(account) for account in plan["accounts"]]
    if len(set(accounts)) != len(accounts):
        raise CaseError("The confirmed plan must not repeat an account.")
    root = safe_path(_text(plan["root"], "local case root", 32767))
    if case_root is not None and safe_path(case_root) != root:
        raise CaseError("Run case root differs from the confirmed plan.")
    result = dict(tenant=tenant, operator=operator, connection=connection, start=start, end=end,
                  planned_at=planned_at, chunks=chunks, accounts=accounts, root=str(root), limit=LIMIT)
    if "snapshot_schema" in plan:
        if plan["snapshot_schema"] != "bec.exchange-snapshot/v1":
            raise CaseError("Unknown confirmed mailbox-state contract.")
        result["snapshot_schema"] = plan["snapshot_schema"]
    return result


def read_plan(stream):
    """Read only bounded UTF-8 confirmed-plan JSON from a binary stream."""
    raw = stream.read(PLAN_BYTES + 1)
    if type(raw) is not bytes or not raw or len(raw) > PLAN_BYTES:
        raise CaseError("Supply the confirmed plan as bounded UTF-8 JSON on stdin.")
    return validate_plan(_json(raw, "confirmed plan"))


def _folders(accounts):
    width = max(2, len(str(len(accounts))))
    result = []
    for index, account in enumerate(accounts, 1):
        prefix = f"{index:0{width}d} - "
        slug = re.sub(r"[^a-z0-9@._-]", "-", account).strip(".-") or "mailbox"
        result.append(safe_name(prefix + slug[:64 - len(prefix)].rstrip(".-")))
    if len({name.casefold() for name in result}) != len(result):
        raise CaseError("Run mailbox labels are ambiguous on Windows.")
    return result


def _local_file(path, limit):
    raw = read_bytes(path, limit)
    if path.stat().st_nlink != 1:
        raise CaseError("Run ownership files cannot use hard links.")
    return raw


def _exclusive(path, raw):
    safe_path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _atomic(path, raw, *, expected_sha=None):
    safe_path(path, exists=True)
    previous = _local_file(path, STATE_BYTES)
    if expected_sha is not None and digest(previous) != expected_sha:
        raise CaseError("An owned run file changed before its atomic update.")
    temporary = path.parent / (".update-" + uuid.uuid4().hex)
    try:
        _exclusive(temporary, raw)
        safe_path(path, exists=True)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextmanager
def _lock(path, *, wait=False):
    safe_path(path, exists=True)
    expected = path.stat()
    fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "r+b") as stream:
        current = os.fstat(stream.fileno())
        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or current.st_size != 1
                or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino)):
            raise CaseError("Invalid local run lock.")
        for attempt in range(41 if wait else 1):
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if not wait or attempt == 40:
                    raise CaseError("Another process is updating this run index; retry the same operation.") from exc
                time.sleep(0.05)
        yield


def _run_path(run_dir, plan):
    directory = safe_path(run_dir, exists=True, directory=True)
    if directory.parent != Path(plan["root"]) / "Runs" or not RUN_ID.fullmatch(directory.name):
        raise CaseError("Run directory is outside the confirmed case root or has an invalid identity.")
    safe_path(directory / INTERNAL, exists=True, directory=True)
    return directory


def _state(directory, plan, *, repair=False, defer_summary=True):
    state_raw = _local_file(directory / INTERNAL / "state.json", STATE_BYTES)
    state = _json(state_raw, "run state")
    if (not isinstance(state, dict) or set(state) != STATE_FIELDS or state["schema"] != SCHEMA
            or state["run_id"] != directory.name or state["plan"] != plan or state["plan_sha256"] != digest(encode(plan))):
        raise CaseError("Run ownership differs from the supplied confirmed plan.")
    if (type(state["revision"]) is not int or state["revision"] < 0
            or not plan["planned_at"] <= _utc(state["created_at"]) <= _utc(state["updated_at"]) <= iso(datetime.now(UTC))):
        raise CaseError("Run state chronology is invalid.")
    if not isinstance(state["status"], str) or state["status"] not in {"active", "completed", "gaps", "failed", "canceled"}:
        raise CaseError("Invalid run status.")
    if (state["closed_at"] is None) != (state["status"] == "active"):
        raise CaseError("Run closure and status disagree.")
    if state["closed_at"] is not None and _utc(state["closed_at"]) != state["updated_at"]:
        raise CaseError("Run closure time differs from its last update.")
    rows = state["accounts"]
    if not isinstance(rows, list) or len(rows) != len(plan["accounts"]):
        raise CaseError("Run account inventory changed.")
    active = 0
    for row, account, folder in zip(rows, plan["accounts"], _folders(plan["accounts"])):
        if (not isinstance(row, dict) or set(row) != ACCOUNT_FIELDS or row["account"] != account
                or row["folder"] != folder or not isinstance(row["status"], str) or row["status"] not in ACCOUNT_STATUSES):
            raise CaseError("Run account ownership or status changed.")
        active += row["status"] == "active"
        unattempted = row["status"] in {"not-yet-attempted", "not-attempted-after-interruption"}
        if unattempted != (row["started_at"] is None):
            raise CaseError("Run account attempt chronology is invalid.")
        if row["started_at"] is not None and not state["created_at"] <= _utc(row["started_at"]) <= state["updated_at"]:
            raise CaseError("Run account start time is invalid.")
        if row["finished_at"] is not None and not (row["started_at"] or state["created_at"]) <= _utc(row["finished_at"]) <= state["updated_at"]:
            raise CaseError("Run account finish time is invalid.")
        if (row["status"] in {"active", "not-yet-attempted"}) != (row["finished_at"] is None):
            raise CaseError("Run account terminal status and finish time disagree.")
        if row["status"] == "not-attempted-after-interruption" and state["status"] == "active":
            raise CaseError("An interrupted account cannot belong to an active run.")
        pinned = row["case_id"] is not None
        if any((row[key] is not None) != pinned for key in PIN_FIELDS):
            raise CaseError("Run case/receipt ownership is incomplete.")
        if pinned:
            if (not isinstance(row["case_id"], str) or not CASE_ID.fullmatch(row["case_id"])
                    or row["case_path"] != str(Path(plan["root"]) / plan["tenant"] / row["case_id"])):
                raise CaseError("Run case is outside the owned tenant directory.")
            for key in PIN_FIELDS[2:]:
                _sha(row[key])
        if row["status"] in FINISHED:
            if not pinned or row["finished_at"] is None:
                raise CaseError("A packaged account lacks its case or completion record.")
            _sha(row["package_manifest_sha256"])
        elif row["package_manifest_sha256"] is not None:
            raise CaseError("An unfinished account claims a package digest.")
        if unattempted and (pinned or row["package_manifest_sha256"] is not None):
            raise CaseError("An unattempted account has package ownership.")
    if active > 1 or (state["status"] != "active" and any(r["status"] in {"active", "not-yet-attempted"} for r in rows)):
        raise CaseError("Run has conflicting active or closed account states.")
    if state["status"] in {"completed", "gaps"}:
        if (not all(r["status"] in FINISHED for r in rows)
                or (state["status"] == "gaps") != any(r["status"] == "gaps" for r in rows)):
            raise CaseError("Partial or interrupted runs cannot claim completion.")
    registration = directory.parent / ".bec-run-index" / "plans" / (state["plan_sha256"] + ".json")
    if _json(_local_file(registration, PLAN_BYTES), "run registration") != dict(
            schema=SCHEMA, plan_sha256=state["plan_sha256"], run_id=directory.name):
        raise CaseError("This run does not own the confirmed plan registration.")
    _summary_consistency(directory, state, digest(state_raw), repair=repair, defer=defer_summary)
    return state


def _summary(path, state):
    plan = state["plan"]
    saved = sum(row["status"] in FINISHED for row in state["accounts"])
    outcome = {"active": "The run is still open and may be incomplete.",
               "completed": "All requested mailbox reports were saved.",
               "gaps": "Reports were saved with coverage gaps. Read each account report for its limits.",
               "failed": "The run failed. Unfinished accounts do not have a verified report.",
               "canceled": "The run was canceled. Unfinished accounts do not have a verified report."}[state["status"]]
    lead = f"{saved} of {len(state['accounts'])} mailbox reports saved. {outcome}"
    labels = {"not-yet-attempted": "Not yet attempted.", "active": "In progress; no verified report yet.",
              "packaged": "Report saved and local files verified.", "gaps": "Report saved with coverage gaps.",
              "failed": "Stopped with an error; no verified report.", "canceled": "Canceled before a report was verified.",
              "not-attempted-after-interruption": "Not attempted because the run stopped."}
    sections = []
    for row in state["accounts"]:
        lines = [labels[row["status"]]]
        if row["status"] in FINISHED:
            lines.append("Open: " + row["folder"] + "/investigation.pdf")
        sections.append((row["account"], lines))
    sections.extend((("Confirmed scope", [f"Tenant GUID: {plan['tenant']}", f"Operator: {plan['operator']}",
        f"Requested UTC: {plan['start']} to {plan['end']} (end excluded)", f"Last updated UTC: {state['updated_at']}"]),
        ("Reading this index", ["Each saved report covers only its named account. This index does not combine case evidence.",
        "An open or interrupted run is incomplete. A partially written folder is not a verified report.",
        "Saved reports do not establish complete telemetry, a clean account or remediation."])))
    write_pdf(path, "BEC run summary", sections, [],
              subtitle=lead, reference_heading=None)


def _refresh_hint(directory):
    return f'Close "Run summary.pdf", then run: bec run-summary "{directory}"'


def _summary_consistency(directory, state, state_sha, *, repair, defer=True):
    """Validate authoritative state while permitting only our known PDF to lag.

At most the current and previous pending PDFs are referenced during an atomic
state transition. Obsolete, hash-matched pending files are removed on the next
write; no history of generated PDFs accumulates during a viewer lock.
"""
    current = digest(_local_file(directory / SUMMARY, STATE_BYTES))
    expected = _sha(state["summary_sha256"])
    journal = directory / INTERNAL / "summary-transition.json"
    if not journal.exists():
        if current != expected:
            raise CaseError("Run summary changed outside a recorded update; no file was overwritten.")
        return dict(visible_sha256=current, pending_pdf=None)
    transition = _json(_local_file(journal, PLAN_BYTES), "run summary transition")
    fields = {"schema", "run_id", "plan_sha256", "from_revision", "to_revision", "previous_state_sha256",
              "next_state_sha256", "previous_summary_sha256", "next_summary_sha256", "pending_pdf",
              "published_summary_sha256", "previous_pending_pdf"}
    if (not isinstance(transition, dict) or set(transition) != fields or transition["schema"] != "bec.run-summary-transition/v2"
            or transition["run_id"] != directory.name or transition["plan_sha256"] != state["plan_sha256"]
            or type(transition["from_revision"]) is not int or type(transition["to_revision"]) is not int
            or transition["from_revision"] < 0
            or transition["to_revision"] != transition["from_revision"] + 1
            or not isinstance(transition["pending_pdf"], str)
            or not re.fullmatch(r"\.summary-[a-f0-9]{32}\.pdf", transition["pending_pdf"])):
        raise CaseError("Run summary transition does not belong to this index.")
    if (transition["previous_pending_pdf"] is not None and
            (not isinstance(transition["previous_pending_pdf"], str)
             or not re.fullmatch(r"\.summary-[a-f0-9]{32}\.pdf", transition["previous_pending_pdf"])
             or transition["previous_pending_pdf"] == transition["pending_pdf"])):
        raise CaseError("Invalid prior owned summary filename.")
    for key in ("previous_state_sha256", "next_state_sha256", "previous_summary_sha256", "next_summary_sha256", "published_summary_sha256"):
        _sha(transition[key])
    old = state_sha == transition["previous_state_sha256"] and state["revision"] == transition["from_revision"]
    new = state_sha == transition["next_state_sha256"] and state["revision"] == transition["to_revision"]
    if not (old or new) or expected != transition["next_summary_sha256" if new else "previous_summary_sha256"]:
        raise CaseError("Run state differs from both owned summary transition revisions.")
    if current not in {transition["published_summary_sha256"], expected}:
        raise CaseError("Run summary was replaced by an unrelated file; it will not be overwritten.")
    pending_files = {}
    for name_key, sha_key in (("pending_pdf", "next_summary_sha256"), ("previous_pending_pdf", "previous_summary_sha256")):
        name = transition[name_key]
        if name is not None:
            path = directory / INTERNAL / name
            if path.exists() and digest(_local_file(path, STATE_BYTES)) != transition[sha_key]:
                raise CaseError("Pending run summary differs from its recorded hash.")
            pending_files[name] = path
    effective = transition["pending_pdf" if new else "previous_pending_pdf"]
    if current != expected and (effective is None or not pending_files[effective].exists()):
        raise CaseError("The exact pending run summary is missing; no replacement was generated.")
    if repair and current != expected:
        pending = pending_files[effective]
        try:
            os.replace(pending, directory / SUMMARY)
            current = digest(_local_file(directory / SUMMARY, STATE_BYTES))
            if current != expected:
                raise CaseError("Run summary changed during authorized publication.")
        except OSError as exc:
            # A viewer may hold the visible PDF open on Windows. Continue only
            # while both the exact visible PDF and pending replacement survive.
            actual = digest(_local_file(directory / SUMMARY, STATE_BYTES))
            if actual == expected:
                current = actual
            elif actual != current or not pending.exists() or digest(_local_file(pending, STATE_BYTES)) != expected:
                raise CaseError("Owned summary files changed during deferred publication.") from exc
            elif not defer:
                raise CaseError("Run status is saved but its PDF is still locked. " + _refresh_hint(directory)) from exc
    if not repair:
        return dict(visible_sha256=current, pending_pdf=effective if current != expected else None)
    for name, path in pending_files.items():
        if path.exists() and (name != effective or current == expected):
            path.unlink()
    if current == expected:
        journal.unlink()
        return dict(visible_sha256=current, pending_pdf=None)
    if effective is None:
        raise CaseError("The exact pending run summary is missing; no replacement was generated.")
    return dict(visible_sha256=current, pending_pdf=effective)


def _commit(directory, state):
    previous = _local_file(directory / INTERNAL / "state.json", STATE_BYTES)
    prior = _summary_consistency(directory, state, digest(previous), repair=True)
    previous_summary = state["summary_sha256"]
    previous_revision = state["revision"]
    state["revision"] += 1
    state["updated_at"] = iso(datetime.now(UTC))
    if state["status"] != "active":
        state["closed_at"] = state["updated_at"]
    temporary = directory / INTERNAL / (".summary-" + uuid.uuid4().hex + ".pdf")
    journal = directory / INTERNAL / "summary-transition.json"
    journaled = False
    try:
        _summary(temporary, state)
        state["summary_sha256"] = digest(_local_file(temporary, STATE_BYTES))
        raw = encode(state)
        if len(raw) > STATE_BYTES:
            raise CaseError("Run state exceeds its bounded local limit.")
        transition = dict(schema="bec.run-summary-transition/v2", run_id=directory.name, plan_sha256=state["plan_sha256"],
            from_revision=previous_revision, to_revision=state["revision"], previous_state_sha256=digest(previous),
            next_state_sha256=digest(raw), previous_summary_sha256=previous_summary,
            next_summary_sha256=state["summary_sha256"], pending_pdf=temporary.name,
            published_summary_sha256=prior["visible_sha256"], previous_pending_pdf=prior["pending_pdf"])
        if journal.exists():
            _atomic(journal, encode(transition), expected_sha=digest(_local_file(journal, PLAN_BYTES)))
        else:
            _exclusive(journal, encode(transition))
        journaled = True
        _atomic(directory / INTERNAL / "state.json", raw, expected_sha=digest(previous))
        _summary_consistency(directory, state, digest(raw), repair=True)
    finally:
        if not journaled and temporary.exists():
            temporary.unlink()
    return state


@contextmanager
def _owned(run_dir, supplied, *, active=True, repair=True, defer_summary=True):
    plan = validate_plan(supplied)
    directory = _run_path(run_dir, plan)
    with _lock(directory / INTERNAL / "lock"):
        state = _state(directory, plan, repair=repair, defer_summary=defer_summary)
        if active and state["status"] != "active":
            raise CaseError("A closed run cannot be resumed or repackaged.")
        yield directory, plan, state


def create_run(case_root, plan):
    """Publish one fresh Runs/UTC-short-id index after interactive confirmation."""
    plan = validate_plan(plan, case_root=case_root)
    root = Path(plan["root"])
    root.mkdir(parents=True, exist_ok=True)
    safe_path(root, exists=True, directory=True)
    runs = root / "Runs"
    runs.mkdir(exist_ok=True)
    safe_path(runs, exists=True, directory=True)
    registry = runs / ".bec-run-index"
    if not registry.exists():
        staged_registry = Path(tempfile.mkdtemp(prefix=".new-run-index-", dir=runs))
        try:
            _exclusive(staged_registry / "owner.json", encode(dict(schema=SCHEMA, root=str(root))))
            _exclusive(staged_registry / "lock", b"0")
            (staged_registry / "plans").mkdir()
            try:
                publish_directory(staged_registry, registry)
            except (OSError, CaseError):
                if not registry.exists():
                    raise
        finally:
            if staged_registry.exists():
                shutil.rmtree(staged_registry)
    safe_path(registry, exists=True, directory=True)
    if _json(_local_file(registry / "owner.json", PLAN_BYTES), "run registry") != dict(schema=SCHEMA, root=str(root)):
        raise CaseError("The existing run registry belongs to a different case root.")
    safe_path(registry / "plans", exists=True, directory=True)
    with _lock(registry / "lock", wait=True):
        plan_sha = digest(encode(plan))
        registration = registry / "plans" / (plan_sha + ".json")
        if registration.exists():
            raise CaseError("This confirmed plan already owns a run; it cannot be replayed.")
        now = iso(datetime.now(UTC))
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
        target = runs / run_id
        if target.exists():
            raise CaseError("Run identity collision; no existing run was changed.")
        folders = _folders(plan["accounts"])
        if os.name == "nt" and any(len(str(target / folder / "originals/exchange/R0001/bundle.json").encode("utf-16-le")) // 2 > 240 for folder in folders):
            raise CaseError("Choose a shorter case root so run package paths fit within 240 Windows characters.")
        stage = Path(tempfile.mkdtemp(prefix=".new-run-", dir=runs))
        registration_raw = encode(dict(schema=SCHEMA, plan_sha256=plan_sha, run_id=run_id))
        registration_attempted = False
        try:
            (stage / INTERNAL).mkdir()
            _exclusive(stage / INTERNAL / "lock", b"0")
            rows = [dict(account=account, folder=folder, status="not-yet-attempted", started_at=None, finished_at=None,
                         case_id=None, case_path=None, case_metadata_sha256=None, case_manifest_sha256=None,
                         receipt_sha256=None, package_manifest_sha256=None) for account, folder in zip(plan["accounts"], folders)]
            state = dict(schema=SCHEMA, run_id=run_id, plan=plan, plan_sha256=plan_sha, created_at=now,
                         updated_at=now, revision=0, status="active", closed_at=None, accounts=rows, summary_sha256=None)
            _summary(stage / SUMMARY, state)
            state["summary_sha256"] = digest(_local_file(stage / SUMMARY, STATE_BYTES))
            _exclusive(stage / INTERNAL / "state.json", encode(state))
            registration_attempted = True
            _exclusive(registration, registration_raw)
            publish_directory(stage, target)
            return target
        except BaseException:
            if (registration_attempted and not target.exists() and registration.exists()
                    and _local_file(registration, PLAN_BYTES) == registration_raw):
                registration.unlink()  # Only this newly created exact marker; earlier runs are untouched.
            if stage.exists():
                shutil.rmtree(stage)
            raise


def _account_row(state, account, *, status=None):
    account = _account(account)
    matches = [row for row in state["accounts"] if row["account"] == account]
    if len(matches) != 1 or status is not None and matches[0]["status"] != status:
        raise CaseError("Account is outside this run or its one-shot status does not permit this action.")
    return matches[0]


def start_account(run_dir, plan, account):
    with _owned(run_dir, plan) as (directory, _, state):
        if any(row["status"] == "active" for row in state["accounts"]):
            raise CaseError("Finish the current account before beginning another.")
        row = _account_row(state, account, status="not-yet-attempted")
        if any(child.name.casefold() == row["folder"].casefold() for child in directory.iterdir()):
            raise CaseError("The account folder already exists; no overwrite is permitted.")
        row.update(status="active", started_at=iso(datetime.now(UTC)))
        _commit(directory, state)
        return row["folder"]


def _checked_capture(bundle, plan, row):
    if not isinstance(bundle, ExportBundle):
        raise CaseError("A native Exchange capture bundle is required before creating a run case.")
    if type(bundle.raw_manifest) is not bytes or not 0 < len(bundle.raw_manifest) <= PLAN_BYTES:
        raise CaseError("Run capture receipt must be bounded original bytes.")
    manifest = _json(bundle.raw_manifest, "run capture receipt")
    required = {"schema", "tenant", "directory_id", "scope", "reads", "files", "captured_at", "planned_at"}
    if (not isinstance(manifest, dict) or set(manifest) != required or bundle.manifest != manifest
            or manifest["schema"] != EXCHANGE_SCHEMA_V3):
        raise CaseError("Run collection requires the unchanged native v3 receipt.")
    try:
        if not isinstance(manifest["files"], list) or not isinstance(bundle.files, list):
            raise CaseError("Run capture file inventory is invalid.")
        for entry in manifest["files"]:
            if (not isinstance(entry, dict) or set(entry) != {"dataset", "path", "sha256"}
                    or entry["dataset"] != "trace"):
                raise CaseError("Run capture has unsupported source metadata.")
        bundle.check_binding(plan["tenant"], plan["tenant"], None)
        receipt = ExchangeReceipt.check(bundle, plan["tenant"], plan["tenant"], row["account"], plan["start"], plan["end"])
        if (receipt.scope["operator"] != plan["operator"] or receipt.scope["connection"] != plan["connection"]
                or receipt.planned_at != plan["planned_at"] or receipt.captured_at < row["started_at"]):
            raise CaseError("Run receipt differs from the pinned operator, connection, plan or account attempt.")
        if any(_utc(read["checked_at"]) < row["started_at"] for read in receipt.reads.values()):
            raise CaseError("Each run read must have been checked during this active account attempt.")
        names = [filename for _, filename, _ in bundle.files]
        if len(set(names)) != len(names) or set(names) != set(receipt.files):
            raise CaseError("Run capture must account for each receipt file exactly once.")
        for dataset, filename, path in bundle.files:
            if dataset != "trace" or filename not in receipt.files:
                raise CaseError("Run capture contains an unrelated source file.")
            receipt.check_file(filename, read_bytes(path), plan["tenant"])
        return receipt
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        if isinstance(exc, CaseError):
            raise
        raise CaseError("Invalid scoped run capture receipt.") from None


def check_capture(run_dir, plan, bundle):
    """Read-only admission before case creation; return a verified ExchangeReceipt."""
    with _owned(run_dir, plan, repair=False) as (_, bound, state):
        active = [row for row in state["accounts"] if row["status"] == "active"]
        if len(active) != 1 or active[0]["case_id"] is not None:
            raise CaseError("Begin exactly one fresh account before admitting its capture.")
        return _checked_capture(bundle, bound, active[0])


def _case_capture(case, plan, row):
    if not isinstance(case, Case) or not CASE_ID.fullmatch(case.id):
        raise CaseError("Run packaging requires the actual verified Case object.")
    expected = Path(plan["root"]) / plan["tenant"] / case.id
    if safe_path(case.path, exists=True, directory=True) != expected:
        raise CaseError("Run case is outside its pinned tenant case store.")
    raw = _local_file(expected / "case.json", PLAN_BYTES)
    metadata = _json(raw, "run case metadata")
    if (metadata != case.meta or case.tenant != plan["tenant"] or metadata.get("directory_id") != plan["tenant"]
            or metadata.get("user") != row["account"] or (metadata.get("start"), metadata.get("end")) != (plan["start"], plan["end"])
            or metadata.get("export_only") is not True or metadata.get("collection_scope") != "named_account"
            or not row["started_at"] <= _utc(metadata.get("created")) <= iso(datetime.now(UTC))):
        raise CaseError("Case metadata differs from the active run account, window or acquisition attempt.")
    manifest_raw = _local_file(expected / "evidence_manifest.json", PLAN_BYTES)
    manifest = _json(manifest_raw, "run evidence manifest")
    if (not isinstance(manifest, dict) or manifest.get("tenant") != case.tenant or manifest.get("case_id") != case.id
            or not isinstance(manifest.get("exchange_receipts"), list) or len(manifest["exchange_receipts"]) != 1
            or not isinstance(manifest.get("artifacts"), list)):
        raise CaseError("A run case must contain exactly its own capture receipt.")
    receipt_sha = _sha(manifest["exchange_receipts"][0])
    receipt_raw = _local_file(case.receipt_path(receipt_sha), PLAN_BYTES)
    if digest(receipt_raw) != receipt_sha:
        raise CaseError("The saved run capture receipt changed.")
    receipt_data = _json(receipt_raw, "saved run receipt")
    if not isinstance(receipt_data, dict) or not isinstance(receipt_data.get("files"), list):
        raise CaseError("Invalid saved run receipt file inventory.")
    files = []
    for entry in receipt_data["files"]:
        if not isinstance(entry, dict) or set(entry) != {"dataset", "path", "sha256"} or entry["dataset"] != "trace":
            raise CaseError("A run receipt may reference only its trace pages.")
        matches = [artifact for artifact in manifest["artifacts"] if isinstance(artifact, dict)
                   and artifact.get("dataset") == "trace" and artifact.get("sha256") == entry["sha256"]]
        if len(matches) != 1 or matches[0].get("collector") != "exchange_online_powershell":
            raise CaseError("Run receipt lacks exactly one preserved native trace page.")
        files.append(("trace", entry["path"], case.raw_path(matches[0])))
    checked = _checked_capture(ExportBundle(receipt_data, files, receipt_raw), plan, row)
    return checked, digest(raw), digest(manifest_raw)


def package_destination(run_dir, plan, case, receipt):
    with _owned(run_dir, plan) as (directory, bound, state):
        row = _account_row(state, case.meta.get("user") if isinstance(case, Case) else None, status="active")
        if row["case_id"] is not None:
            raise CaseError("This run account has already allocated its one-shot package.")
        checked, case_sha, manifest_sha = _case_capture(case, bound, row)
        if (not isinstance(receipt, ExchangeReceipt) or any(getattr(receipt, name) != getattr(checked, name)
                for name in ("sha", "scope", "reads", "files", "captured_at", "schema", "planned_at"))):
            raise CaseError("Package receipt differs from the run's reverified saved capture.")
        target = directory / row["folder"]
        safe_path(target)
        if any(child.name.casefold() == target.name.casefold() for child in directory.iterdir()):
            raise CaseError("Run mailbox destination already exists; it cannot be reused.")
        row.update(case_id=case.id, case_path=str(case.path), case_metadata_sha256=case_sha,
                   case_manifest_sha256=manifest_sha, receipt_sha256=checked.sha)
        _commit(directory, state)
        return target


def _package(directory, plan, row, package_dir, manifest_sha):
    target = safe_path(package_dir, exists=True, directory=True)
    if target != directory / row["folder"]:
        raise CaseError("Package result is outside the account's exact owned folder.")
    inspect_tree(target)
    raw = _local_file(target / "manifest.json", STATE_BYTES)
    if digest(raw) != _sha(manifest_sha):
        raise CaseError("Finished package manifest differs from its expected digest.")
    package = _json(raw, "finished package manifest")
    scope = dict(case_id=row["case_id"], tenant=plan["tenant"], directory_id=plan["tenant"], account=row["account"],
                 start=plan["start"], end=plan["end"], bounds="[start,end)")
    if (not isinstance(package, dict) or package.get("schema") != "bec.case-package/v1" or package.get("scope") != scope
            or type(package.get("has_coverage_gaps")) is not bool or not isinstance(package.get("files"), list)
            or not 1 <= len(package["files"]) <= 20000):
        raise CaseError("Finished package does not belong to the pinned case/window.")
    paths = {}
    for item in package["files"]:
        if (not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes"} or not isinstance(item["path"], str)
                or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= MAX_FILE_BYTES):
            raise CaseError("Invalid package file inventory.")
        parts = item["path"].split("/")
        if any(not part or safe_name(part) != part for part in parts) or item["path"].casefold() in paths:
            raise CaseError("Package file names are ambiguous or outside the account folder.")
        path = target.joinpath(*parts)
        if path in {target / "manifest.json", target / "SHA256SUMS.txt"}:
            raise CaseError("A package inventory cannot hash itself.")
        content = _local_file(path, max(1, item["bytes"]))
        if len(content) != item["bytes"] or digest(content) != _sha(item["sha256"]):
            raise CaseError("A finished package file differs from its manifest.")
        paths[item["path"].casefold()] = item["path"]
    actual = {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()}
    if actual != set(paths.values()) | {"manifest.json", "SHA256SUMS.txt"}:
        raise CaseError("Finished package contains missing or unaccounted files.")
    sums = "".join(f"{item['sha256']}  {item['path']}\n" for item in package["files"])
    sums += f"{manifest_sha}  manifest.json\n"
    if _local_file(target / "SHA256SUMS.txt", STATE_BYTES) != sums.encode():
        raise CaseError("Package checksum list differs from the verified manifest.")
    receipts = package.get("trace_receipts")
    if (not isinstance(receipts, list) or len(receipts) != 1 or not isinstance(receipts[0], dict)
            or receipts[0].get("sha256") != row["receipt_sha256"] or receipts[0].get("schema") != EXCHANGE_SCHEMA_V3
            or receipts[0].get("file") not in paths.values()):
        raise CaseError("Finished package lacks its one pinned native capture receipt.")
    if digest(_local_file(target / receipts[0]["file"], PLAN_BYTES)) != row["receipt_sha256"]:
        raise CaseError("The packaged run receipt differs from the pinned original.")
    for filename, key in (("case.json", "case_metadata_sha256"), ("evidence_manifest.json", "case_manifest_sha256")):
        if digest(_local_file(Path(row["case_path"]) / filename, PLAN_BYTES)) != row[key]:
            raise CaseError("The source case changed after run destination allocation.")
    if _local_file(target / "manifest.json", STATE_BYTES) != raw:
        raise CaseError("Package manifest changed during completion verification.")
    return package["has_coverage_gaps"]


def finish_account(run_dir, plan, account, package_dir, manifest_sha256):
    with _owned(run_dir, plan) as (directory, bound, state):
        row = _account_row(state, account, status="active")
        if row["case_id"] is None:
            raise CaseError("Allocate the run-owned package before finishing the account.")
        gaps = _package(directory, bound, row, package_dir, manifest_sha256)
        row.update(status="gaps" if gaps else "packaged", finished_at=iso(datetime.now(UTC)),
                   package_manifest_sha256=manifest_sha256)
        return _commit(directory, state)


def close_run(run_dir, plan, *, outcome):
    if not isinstance(outcome, str) or outcome not in {"completed", "failed", "canceled"}:
        raise CaseError("Unknown requested run outcome.")
    with _owned(run_dir, plan, active=False) as (directory, _, state):
        if state["status"] != "active":
            return state  # Finalization retry may finish only the exact journaled PDF.
        for row in state["accounts"]:
            if row["status"] == "active":
                row.update(status="canceled" if outcome == "canceled" else "failed", finished_at=iso(datetime.now(UTC)))
            elif row["status"] == "not-yet-attempted":
                row.update(status="not-attempted-after-interruption", finished_at=iso(datetime.now(UTC)))
        if outcome == "completed":
            outcome = ("gaps" if any(row["status"] == "gaps" for row in state["accounts"]) else "completed") if all(
                row["status"] in FINISHED for row in state["accounts"]) else "failed"
        state["status"] = outcome
        return _commit(directory, state)


def inspect_run(run_dir, plan):
    """Read authoritative owned state; a hash-authorized visible PDF may lag."""
    with _owned(run_dir, plan, active=False, repair=False) as (_, _, state):
        return state


def refresh_run(run_dir):
    """Publish an already authorized local summary; never infer or alter status.

The selected path supplies the expected root. Embedded metadata is compared
before it is allowed to name a registry or any path outside this directory.
"""
    directory = safe_path(run_dir, exists=True, directory=True)
    if directory.parent.name != "Runs" or not RUN_ID.fullmatch(directory.name):
        raise CaseError("Select a local Runs/<run-id> directory to refresh its summary.")
    expected_root = directory.parent.parent
    state = _json(_local_file(directory / INTERNAL / "state.json", STATE_BYTES), "selected run state")
    if (not isinstance(state, dict) or state.get("schema") != SCHEMA or state.get("run_id") != directory.name
            or not isinstance(state.get("plan"), dict) or state["plan"].get("root") != str(expected_root)):
        raise CaseError("Selected run metadata does not belong to this local run directory.")
    plan = validate_plan(state["plan"], case_root=expected_root)
    with _owned(directory, plan, active=False, repair=True, defer_summary=False):
        return directory / SUMMARY


def main():
    parser = argparse.ArgumentParser(description="Maintain a local index for an already confirmed BEC run.")
    actions = parser.add_subparsers(dest="action", required=True)
    create = actions.add_parser("create")
    create.add_argument("--root")
    begin = actions.add_parser("begin")
    begin.add_argument("--run", required=True)
    begin.add_argument("--account", required=True)
    close = actions.add_parser("close")
    close.add_argument("--run", required=True)
    close.add_argument("--outcome", choices=("completed", "failed", "canceled"), required=True)
    args = parser.parse_args()
    try:
        plan = read_plan(sys.stdin.buffer)
        if args.action == "create":
            print(json.dumps(str(create_run(args.root or plan["root"], plan)), ensure_ascii=True))
        elif args.action == "begin":
            folder = start_account(args.run, plan, args.account)
            print(json.dumps(dict(status="active", folder=folder)))
        else:
            state = close_run(args.run, plan, outcome=args.outcome)
            inspect_run(args.run, plan)  # Unknown/replaced summaries still refuse.
            if digest(_local_file(Path(args.run) / SUMMARY, STATE_BYTES)) != state["summary_sha256"]:
                print("BEC: Run status is saved; its summary PDF is waiting for the viewer to release it. "
                      + _refresh_hint(args.run), file=sys.stderr)
            print(json.dumps(dict(status=state["status"])))
            return {"completed": 0, "gaps": 2, "failed": 1, "canceled": 130}[state["status"]]
        return 0
    except KeyboardInterrupt:
        print("BEC: Run operation interrupted; existing status remains incomplete.", file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        print(f"BEC: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
