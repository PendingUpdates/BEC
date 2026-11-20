"""Scope and provenance guards for the Exchange adapter. No tenant or SDK is required."""
import base64
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from bec.bundles import EXCHANGE_SCHEMA
from bec.cli import main
from bec.exchange import ADAPTER, LIMIT, save_trace, utc_window
from bec.storage import CaseError, create, digest, save


class TraceContainment(unittest.TestCase):
    def setUp(self):
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.root = self.work / "cases"
        self.path = self.work / "bundle.json"
        self.tenant = str(uuid.uuid4())
        self.account = "target@example.invalid"
        self.peer = "peer@example.invalid"
        self.start, self.end = utc_window("2020-01-01T00:00Z", "2020-01-01T01:00Z")

    def args(self, direction):
        return SimpleNamespace(directory=self.work, tenant=self.tenant, account=self.account,
                               start=self.start, end=self.end, direction=direction)

    def row(self, direction):
        sender, recipient = (self.account, self.peer) if direction == "sent" else (self.peer, self.account)
        return dict(SenderAddress=sender, RecipientAddress=recipient, Received=self.start)

    def receipt(self):
        return dict(schema=EXCHANGE_SCHEMA, tenant=self.tenant, directory_id=self.tenant, captured_at=self.end,
                    scope=dict(account=self.account, start=self.start, end=self.end,
                               operator="operator@example.invalid", connection=str(uuid.uuid4())),
                    reads=dict(sent="unavailable", received="unavailable"), files=[])

    def cli(self, manifest, *, case=None):
        self.path.write_text(json.dumps(manifest), encoding="utf-8")
        args = ["--root", str(self.root), "offline", "--bundle", str(self.path)]
        if case:
            args.extend(["--case", case])
        else:
            args.extend(["--user", self.account, "--tenant", self.tenant, "--directory-id", self.tenant,
                         "--start", self.start, "--end", self.end])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(args)

    def test_unavailable_sources_make_a_verified_gap_only_package(self):
        self.assertEqual(self.cli(self.receipt()), 2)
        case_dir = next(self.root.rglob("case.json")).resolve().parent
        output_root = (self.work / "review").resolve()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["package", str(case_dir), "--output", str(output_root)]), 2)
        package_manifest, = output_root.rglob("manifest.json")
        package = package_manifest.parent
        metadata = json.loads(package_manifest.read_bytes())
        original_receipt, = metadata["trace_receipts"]
        self.assertTrue(metadata["has_coverage_gaps"])
        self.assertEqual(metadata["counts"]["observations"], 0)
        self.assertEqual((package / original_receipt["file"]).read_bytes(), self.path.read_bytes())
        for member in ("triage.xlsx", "investigation.pdf", "coverage.json", "SHA256SUMS.txt"):
            self.assertTrue((package / member).is_file())

    def test_directional_pages_preserve_exact_bytes_hash_and_report_gap(self):
        manifest = self.receipt()
        raw_by_name = {}
        for direction in ("sent", "received"):
            row = self.row(direction)
            row["Received"] = "2020-01-01T01:00:00+01:00"
            row["Subject"] = "Café"
            raw = (json.dumps([row], ensure_ascii=False, indent=2) + "\r\n").encode()
            saved = save_trace(self.args(direction), raw)
            name = direction + ".json"
            self.assertEqual(saved, {"status": "returned", "sha256": digest(raw)})
            self.assertEqual((self.work / name).read_bytes(), raw)
            raw_by_name[name] = raw
            manifest["reads"][direction] = saved["status"]
            manifest["files"].append(dict(dataset="trace", path=name, sha256=saved["sha256"]))
        self.assertEqual(self.cli(manifest), 2)  # Completed with documented coverage gaps.
        case_dir = next(self.root.rglob("case.json")).parent
        evidence = json.loads((case_dir / "evidence_manifest.json").read_bytes())
        self.assertEqual(len(evidence["artifacts"]), 2)
        self.assertEqual(evidence["exchange_receipts"], [digest(self.path.read_bytes())])
        for item in evidence["artifacts"]:
            self.assertEqual(item["dataset"], "trace")
            self.assertEqual(item["collector"], "exchange_online_powershell")
            self.assertEqual((case_dir / item["artifact"]).read_bytes(), raw_by_name[item["queries"][0]["file"]])
        self.assertIn("Mailbox audit was not collected", (case_dir / "telemetry_gaps.json").read_text())
        self.assertIn("Mailbox audit was not collected", (case_dir / "timeline" / "timeline.html").read_text())

    def test_every_row_is_checked_before_the_export_and_again_before_case_creation(self):
        for direction, field in (("sent", "SenderAddress"), ("received", "RecipientAddress")):
            mismatches = [{field: self.peer}, {"Received": "2019-12-31T23:59:59Z"},
                          {"Received": self.end}, {"Received": "2020-01-01T01:00:01Z"},
                          {"Received": None}, {field: None}, {"OrganizationId": str(uuid.uuid4())}, {"AuditData": None}]
            for changed in mismatches:
                with self.subTest(direction=direction, changed=list(changed), value=list(changed.values())):
                    good = self.row(direction)
                    raw = json.dumps([good, {**good, **changed}]).encode()
                    path = self.work / (direction + ".json")
                    before = set(self.work.iterdir())
                    with self.assertRaises(CaseError):
                        save_trace(self.args(direction), raw)
                    self.assertEqual(set(self.work.iterdir()), before)
                    # A separately supplied existing file must pass a fresh scope check even with a matching hash.
                    path.write_bytes(raw)
                    manifest = self.receipt()
                    manifest["files"].append(dict(dataset="trace", path=path.name, sha256=digest(raw)))
                    manifest["reads"][direction] = "returned"
                    self.assertEqual(self.cli(manifest), 1)
                    self.assertFalse(self.root.exists())
                    path.unlink()

    def test_file_count_status_and_digest_must_match_the_receipt(self):
        raw = b"[]"
        (self.work / "sent.json").write_bytes(raw)
        for status, sha in (("returned", digest(raw)), ("empty", "0" * 64), ("at-limit", digest(raw)),
                            ("unavailable", digest(raw))):
            manifest = self.receipt()
            manifest["files"].append(dict(dataset="trace", path="sent.json", sha256=sha))
            manifest["reads"]["sent"] = status
            self.assertEqual(self.cli(manifest), 1)
            self.assertFalse(self.root.exists())

    def test_reject_legacy_schemas_audit_declarations_and_files(self):
        for version in ("bec.exchange-powershell/v1", "bec.exchange-powershell/v3", None, EXCHANGE_SCHEMA):
            for status in ("returned", "bounded-audit", "empty", "unavailable"):
                manifest = self.receipt()
                if version is None:
                    del manifest["schema"]
                else:
                    manifest["schema"] = version
                manifest["reads"]["audit"] = status
                self.assertEqual(self.cli(manifest), 1)
                self.assertFalse(self.root.exists())
        manifest = self.receipt()
        (self.work / "separate.json").write_bytes(b"[]")
        manifest["files"].append(dict(dataset="ual", path="separate.json", sha256=digest(b"[]")))
        self.assertEqual(self.cli(manifest), 1)
        self.assertFalse(self.root.exists())
        manifest = self.receipt()
        manifest["schema"] = "bec.exchange-powershell/v1"
        self.assertEqual(self.cli(manifest), 1)
        self.assertFalse(self.root.exists())

    def test_unlisted_legacy_audit_file_stops_capture_import(self):
        (self.work / "audit.json").write_bytes(b"[]")
        self.assertEqual(self.cli(self.receipt()), 1)
        self.assertFalse(self.root.exists())

    def test_offline_audit_is_separate_in_both_directions(self):
        audit = dict(tenant=self.tenant, directory_id=self.tenant, files=[dict(dataset="ual", path="offline.json")])
        (self.work / "offline.json").write_bytes(b"[]")
        self.assertEqual(self.cli(audit), 2)
        offline = next(self.root.rglob("case.json")).parent
        existing = (offline / "evidence_manifest.json").read_bytes()
        self.assertEqual(json.loads(existing)["artifacts"][0]["collector"], "export")
        self.assertEqual(self.cli(self.receipt(), case=offline.name), 1)
        self.assertEqual((offline / "evidence_manifest.json").read_bytes(), existing)
        self.assertEqual(self.cli(self.receipt()), 2)
        capture = next(p.parent for p in self.root.rglob("case.json") if p.parent != offline)
        receipt_only = (capture / "evidence_manifest.json").read_bytes()
        self.assertEqual(self.cli(audit, case=capture.name), 1)
        self.assertEqual((capture / "evidence_manifest.json").read_bytes(), receipt_only)
        self.assertFalse(list(capture.glob("raw/ual/*.json")))

    def test_existing_v1_case_can_be_verified_and_refuses_fresh_capture(self):
        profile = dict(tenant=self.tenant, directory_id=self.tenant, microsoft=True)
        case = create(self.root, self.tenant, self.account, self.start, self.end, profile,
                      export_only=True, named_account=True)
        old = self.receipt()
        old["schema"] = "bec.exchange-powershell/v1"
        old["reads"]["audit"] = "unavailable"
        raw = json.dumps(old).encode()
        sha = digest(raw)
        old_path = case.receipt_path(sha)
        old_path.parent.mkdir(parents=True, exist_ok=True)
        old_path.write_bytes(raw)
        manifest = case.manifest()
        manifest["exchange_receipts"] = [sha]
        save(case.path / "evidence_manifest.json", manifest)
        self.assertEqual(case.verify(), 0)
        self.assertEqual(self.cli(self.receipt(), case=case.id), 1)
        self.assertEqual(case.manifest(), manifest)
        self.assertEqual(old_path.read_bytes(), raw)

    def test_child_process_stream_rejects_page_before_opening_target(self):
        command = [sys.executable, "-B", "-S", "-m", "bec.exchange", "save-trace", "--direction", "sent",
                   "--directory", str(self.work), "--tenant", self.tenant, "--account", self.account,
                   "--start", self.start, "--end", self.end]
        raw = json.dumps([self.row("received")]).encode()
        result = subprocess.run(command, input=base64.b64encode(raw), capture_output=True, timeout=15,
                                cwd=ADAPTER.parents[2])
        self.assertEqual(result.returncode, 1)
        self.assertFalse(list(self.work.iterdir()))
        self.assertNotIn(self.peer.encode(), result.stderr)
        result = subprocess.run(command, input=base64.b64encode(b"[]") + b"\r\n", capture_output=True,
                                timeout=15, cwd=ADAPTER.parents[2])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), dict(status="empty", sha256=digest(b"[]")))
        self.assertEqual((self.work / "sent.json").read_bytes(), b"[]")

    def test_export_limit_is_visible_and_extra_rows_are_never_saved(self):
        rows = [self.row("received")] * LIMIT
        with self.assertRaises(CaseError):
            save_trace(self.args("received"), json.dumps(rows + rows[:1]).encode())
        self.assertFalse(list(self.work.iterdir()))
        self.assertEqual(save_trace(self.args("received"), json.dumps(rows).encode())["status"], "at-limit")


if __name__ == "__main__":
    unittest.main()
