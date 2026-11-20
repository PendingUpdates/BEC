"""Run organisation checks with generated identifiers and no mailbox records."""
import contextlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import io
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from bec.bundles import EXCHANGE_SCHEMA_V3
from bec.cli import main
from bec.exchange import LIMIT
from bec.run_index import close_run, create_run, start_account
from bec.storage import iso
from bec.trace_windows import chunk_plan


class RunLayout(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.temp).resolve() / "cases"
        end = datetime.now(UTC) - timedelta(hours=1)
        self.start, self.end = iso(end - timedelta(hours=1)), iso(end)
        self.tenant = str(uuid.uuid4())
        self.accounts = [uuid.uuid4().hex + "@example.invalid" for _ in range(2)]
        self.plan = dict(tenant=self.tenant, operator=uuid.uuid4().hex + "@example.invalid",
                         connection=str(uuid.uuid4()), start=self.start, end=self.end, planned_at=self.end,
                         chunks=chunk_plan(self.start, self.end, self.end), accounts=self.accounts,
                         root=str(self.root), limit=LIMIT, snapshot_schema="bec.exchange-snapshot/v1")
        self.enterContext(patch("socket.getaddrinfo", side_effect=AssertionError("network")))
        self.enterContext(patch("socket.socket.connect", side_effect=AssertionError("network")))

    def receipt(self, account):
        scope = dict(account=account, start=self.start, end=self.end, operator=self.plan["operator"],
                     connection=self.plan["connection"])
        checked = dict(start=self.start, end=self.end, checked_at=iso(datetime.now(UTC)), status="unavailable")
        return dict(schema=EXCHANGE_SCHEMA_V3, tenant=self.tenant, directory_id=self.tenant,
                    scope=scope, planned_at=self.end, captured_at=iso(datetime.now(UTC)), files=[],
                    reads={"sent-01": checked.copy(), "received-01": checked.copy()})

    def import_to_run(self, directory, account, receipt):
        capture = Path(self.temp, "capture")
        capture.mkdir(exist_ok=True)
        bundle = capture / "bundle.json"
        bundle.write_text(json.dumps(receipt), encoding="utf-8")
        args = ["--root", str(self.root), "offline", "--bundle", str(bundle), "--tenant", self.tenant,
                "--directory-id", self.tenant, "--user", account, "--start", self.start, "--end", self.end,
                "--review-package", "--run-directory", str(directory)]
        with io.TextIOWrapper(io.BytesIO(json.dumps(self.plan).encode())) as stream:
            with patch("sys.stdin", stream), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as error:
                return main(args), error.getvalue()

    def test_multi_account_packages_directly_under_one_run(self):
        run = create_run(self.root, self.plan)
        for account in self.accounts:
            start_account(run, self.plan, account)
            code, detail = self.import_to_run(run, account, self.receipt(account))
            self.assertEqual(code, 2, detail)
        close_run(run, self.plan, outcome="completed")
        self.assertEqual(run.parent, self.root / "Runs")
        self.assertTrue((run / "Run summary.pdf").is_file())
        mailboxes = [p.parent for p in run.glob("*/investigation.pdf")]
        self.assertEqual(len(mailboxes), 2)
        scopes = set()
        for mailbox in mailboxes:
            self.assertTrue((mailbox / "triage.xlsx").is_file())
            self.assertTrue((mailbox / "raw").is_dir())
            manifest = json.loads((mailbox / "manifest.json").read_bytes())
            self.assertTrue(manifest["has_coverage_gaps"])
            self.assertEqual(manifest["counts"]["observations"], 0)
            scopes.add(manifest["scope"]["account"])
        self.assertEqual(scopes, set(self.accounts))
        self.assertFalse((self.root / "review-packages").exists())
        self.assertEqual(len(list((self.root / self.tenant).glob("*/case.json"))), 2)

    def test_canceled_run_lists_the_active_and_unattempted_accounts(self):
        run = create_run(self.root, self.plan)
        start_account(run, self.plan, self.accounts[0])
        state = close_run(run, self.plan, outcome="canceled")
        self.assertEqual(state["status"], "canceled")
        self.assertEqual([row["status"] for row in state["accounts"]],
                         ["canceled", "not-attempted-after-interruption"])
        self.assertTrue((run / "Run summary.pdf").is_file())
        self.assertFalse(any(run.glob("*/investigation.pdf")))
        original = (run / "Run summary.pdf").read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["run-summary", str(run)]), 0)
        self.assertEqual((run / "Run summary.pdf").read_bytes(), original)

    def test_simultaneous_runs_create_separate_indexes(self):
        second = dict(self.plan, connection=str(uuid.uuid4()))
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = [workers.submit(create_run, self.root, plan) for plan in (self.plan, second)]
            first_run, second_run = [result.result(timeout=15) for result in results]
        self.assertNotEqual(first_run, second_run)
        first_index = (first_run / "Run summary.pdf").read_bytes()
        close_run(second_run, second, outcome="canceled")
        self.assertEqual((first_run / "Run summary.pdf").read_bytes(), first_index)

    @unittest.skipUnless(os.name == "nt", "uses the Windows file-sharing API")
    def test_open_pdf_does_not_interrupt_a_windows_run(self):
        import ctypes
        from ctypes import wintypes

        run = create_run(self.root, self.plan)
        summary = run / "Run summary.pdf"
        first_index = summary.read_bytes()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL
        # A reader can allow other readers and writers while denying replacement.
        handle = kernel.CreateFileW(str(summary), 0x80000000, 0x3, None, 3, 0x80, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            for account in self.accounts:
                start_account(run, self.plan, account)
                code, detail = self.import_to_run(run, account, self.receipt(account))
                self.assertEqual(code, 2, detail)
            state = close_run(run, self.plan, outcome="completed")
            self.assertEqual([row["status"] for row in state["accounts"]], ["gaps", "gaps"])
            self.assertEqual(summary.read_bytes(), first_index)
            self.assertEqual(len(list(run.glob("*/investigation.pdf"))), 2)
        finally:
            kernel.CloseHandle(handle)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["run-summary", str(run)]), 0)
        self.assertNotEqual(summary.read_bytes(), first_index)

    def test_different_connection_stops_before_creating_a_case(self):
        run = create_run(self.root, self.plan)
        account = self.accounts[0]
        start_account(run, self.plan, account)
        receipt = self.receipt(account)
        receipt["scope"]["connection"] = str(uuid.uuid4())
        code, detail = self.import_to_run(run, account, receipt)
        self.assertEqual(code, 1, detail)
        self.assertFalse((self.root / self.tenant).exists())
        self.assertFalse(any(run.glob("*/investigation.pdf")))
