"""CLI, receipt-shape and session guards. No provider responses or incident records."""
import argparse
import contextlib
import io
import json
import re
import socket
import sys
import tempfile
import unittest
import uuid
import webbrowser
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bec.bundles import EXCHANGE_SCHEMA, ExportBundle
from bec.cli import main
from bec.collection import Collection
from bec.exchange import ADAPTER, ExchangeReceipt, affected_accounts, plan, utc_window
from bec.storage import CaseError, DATASETS, digest


class OperatorBoundary(unittest.TestCase):
    def setUp(self):
        self.stack = self.enterContext(contextlib.ExitStack())
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.root = self.folder / "case-store"
        self.manifest = self.folder / "bundle.json"
        self.output = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.errors = self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        for owner, name in ((socket, "getaddrinfo"), (socket.socket, "connect"), (webbrowser, "open")):
            self.stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
        for target in ("bec.cli.run_case", "bec.cli.Collection.collect", "bec.microsoft_login.sign_in", "bec.cli.create"):
            self.stack.enter_context(patch(target, side_effect=AssertionError(target)))

    def tearDown(self):
        self.assertFalse(self.root.exists())

    def command(self, *args):
        return main(["--root", str(self.root), *args])

    def test_microsoft_requires_the_current_powershell_window(self):
        self.assertEqual(self.command("microsoft"), 1)
        self.assertIn("connected PowerShell", self.errors.getvalue())
        self.assertEqual(self.command("microsoft", "--adapter"), 0)
        self.assertEqual(Path(self.output.getvalue().strip()), ADAPTER)
        self.assertTrue(ADAPTER.is_file())

    def test_help_distinguishes_live_and_offline(self):
        for args in (["--help"], ["offline", "--help"], ["microsoft", "--help"], ["package", "--help"]):
            with self.subTest(args=args), self.assertRaises(SystemExit) as result:
                self.command(*args)
            self.assertEqual(result.exception.code, 0)
        self.assertIn("--bundle", self.output.getvalue())
        self.assertIn("Invoke-BEC.ps1", self.output.getvalue())
        self.assertIn("--source", self.output.getvalue())

    def test_offline_requires_explicit_manifest_and_scope(self):
        for args in (["--case", "missing"], ["--bundle", str(self.manifest)]):
            with self.subTest(args=args), self.assertRaises(SystemExit) as result:
                self.command("offline", *args)
            self.assertEqual(result.exception.code, 2)

    def test_unusable_bundle_stops_before_case_lookup(self):
        with patch("bec.cli.Case.find", side_effect=AssertionError("case lookup")):
            for path in ("", str(self.manifest), str(self.folder), "https://example.invalid/export", r"\\host\share\file"):
                with self.subTest(path=path):
                    self.assertEqual(self.command("offline", "--case", "missing", "--bundle", path), 1)
            for content in (b"not JSON", b"[]", b"{}", b'{"tenant":"case","files":[]}',
                            b'{"tenant":"case","files":[null]}',
                            b'{"tenant":"case","files":[{"dataset":"trace","path":"absent.json"}]}'):
                self.manifest.write_bytes(content)
                self.assertEqual(self.command("offline", "--case", "missing", "--bundle", str(self.manifest)), 1)

    def test_invalid_member_and_wrong_expected_tenant_stop_before_case_creation(self):
        self.manifest.write_text(json.dumps({"tenant": "case", "files": [{"dataset": "trace", "path": "input.json"}]}))
        (self.folder / "input.json").write_bytes(b"invalid JSON")
        for alias, message in (("other", "binding"), ("case", "Invalid export")):
            self.assertEqual(self.command("offline", "--bundle", str(self.manifest), "--tenant", alias,
                "--user", "analyst@example.invalid", "--start", "2020-01-01T00:00Z", "--end", "2020-01-01T01:00Z"), 1)
            self.assertIn(message, self.errors.getvalue())

    def test_scope_plan_has_fixed_reads_and_no_case_write(self):
        args = argparse.Namespace(tenant=str(uuid.uuid4()), operator="analyst@example.invalid",
            connection=str(uuid.uuid4()), root=str(self.root), start=None, end=None, accounts=None)
        entry = io.StringIO("target@example.invalid\n\nyes\n")
        with patch.object(entry, "isatty", return_value=True), patch.object(sys, "stdin", entry):
            scope = plan(args)
        self.assertEqual(scope["accounts"], ["target@example.invalid"])
        self.assertEqual(scope["tenant"], args.tenant)
        self.assertEqual(scope["limit"], 1000)
        self.assertEqual(utc_window(scope["start"], scope["end"]), (scope["start"], scope["end"]))
        self.assertIn(args.operator, self.errors.getvalue())

    def test_scope_rejects_non_exact_addresses_or_unbounded_times(self):
        for address in ("", "*@example.invalid", "partial", "x@[example].invalid"):
            with self.subTest(address=address), self.assertRaises(CaseError):
                affected_accounts([address])
        for start, end in ((None, "2020-01-01T01:00Z"), ("2020-01-01T00:00Z", None),
                           ("2020-01-01T00:00Z", "2020-01-03T00:00Z"), ("2020-01-02T00:00Z", "2020-01-01T00:00Z"),
                           ("2020-01-01T00:00", "2020-01-01T01:00"), ("9999-01-01T00:00Z", "9999-01-01T01:00Z")):
            with self.subTest(start=start, end=end), self.assertRaises(CaseError):
                utc_window(start, end)

    def test_receipt_requires_all_read_outcomes_and_independent_scope(self):
        tenant = str(uuid.uuid4())
        account = "target@example.invalid"
        start, end = utc_window("2020-01-01T00:00Z", "2020-01-01T01:00Z")
        content = {"schema": EXCHANGE_SCHEMA, "tenant": tenant, "directory_id": tenant, "files": [],
            "scope": {"account": account, "start": start, "end": end, "operator": "analyst@example.invalid",
                      "connection": str(uuid.uuid4())}, "captured_at": end,
            "reads": dict(sent="unavailable", received="unavailable")}
        self.manifest.write_text(json.dumps(content))
        bundle = ExportBundle.load(self.manifest, offline=True)
        receipt = ExchangeReceipt.check(bundle, tenant, tenant, account, start, end)
        self.assertEqual(receipt.sha, digest(self.manifest.read_bytes()))
        self.assertTrue(all(q["status"] == "gap" for q in receipt.coverage().values()))
        self.assertTrue(all(q["dataset"] in DATASETS for q in receipt.coverage().values()))
        with self.assertRaises(CaseError):
            ExchangeReceipt.check(bundle, tenant, tenant, "other@example.invalid", start, end)
        del bundle.manifest["reads"]["sent"]
        with self.assertRaises(CaseError):
            ExchangeReceipt.check(bundle, tenant, tenant, account, start, end)

    def test_adapter_static_read_allowlist(self):
        source = ADAPTER.read_text()
        self.assertEqual(set(re.findall(r"\$commands\['([^']+)'\]", source)),
                         {"Get-Mailbox", "Get-MessageTraceV2"})
        launcher = (ADAPTER.parents[2] / "Invoke-BEC.ps1").read_text()
        self.assertIn("Join-Path $PSScriptRoot 'bec/data/Invoke-BEC.ps1'", launcher)
        self.assertIn("& $adapter -Python $python @PSBoundParameters", launcher)
        self.assertNotIn("Search-UnifiedAuditLog", launcher)
        self.assertIn("$planText = & $Python -I -m bec.exchange plan-session --mailbox-state @scopeArgs", source)
        self.assertEqual(set(re.findall(r"'(Get-[A-Za-z0-9]+)' = \(Get-BecCommandPin \$sourceModule", source)),
                         {"Get-Mailbox", "Get-MessageTraceV2", "Get-InboxRule", "Get-MailboxPermission",
                          "Get-RecipientPermission"})
        self.assertIn("foreach ($direction in 'sent', 'received')", source)
        self.assertIn("if ($direction -eq 'sent') { $parameters['SenderAddress'] = $account }", source)
        self.assertIn("else { $parameters['RecipientAddress'] = $account }", source)
        self.assertIn("$encoded | & $Python -I -m bec.exchange save-trace", source)
        self.assertEqual(re.findall(r"\[IO.File\]::WriteAllText\(([^,]+),", source), ["$bundle"])
        self.assertIn("Get-BecCommandPin $metadataModule 'Get-ConnectionInformation'", source)
        self.assertIn("@(& $metadataRead -ErrorAction Stop)", source)
        for term in ("Search-UnifiedAuditLog", "Connect-ExchangeOnline", "Invoke-Expression", "Start-Process",
                     "New-ComplianceSearch", "Invoke-RestMethod", "Invoke-WebRequest", "AccessToken"):
            self.assertNotIn(term, source)
        self.assertLess(source.index("$session = Get-BecSession"), source.index("& $mailboxRead"))
        capture = source[source.index("foreach ($account in $plan.accounts)"):]
        self.assertLess(capture.index("& $mailboxRead"), capture.index("Get-BecSnapshotObservations"))
        self.assertLess(capture.index("& $mailboxRead"), capture.index("& $read @parameters"))


class RetiredMicrosoftRoutes(unittest.TestCase):
    def test_legacy_live_collection_stops_before_provider_or_case_access(self):
        state = Collection.__new__(Collection)
        state.case = SimpleNamespace(meta={"microsoft": True})
        with patch.object(Collection, "mode", side_effect=AssertionError("case write")), self.assertRaises(CaseError):
            state.collect([])

    def test_retired_signin_does_not_examine_credentials(self):
        from bec.microsoft_login import sign_in
        with patch("os.environ.get", side_effect=AssertionError("credential lookup")), self.assertRaises(CaseError):
            sign_in()


if __name__ == "__main__":
    unittest.main()
