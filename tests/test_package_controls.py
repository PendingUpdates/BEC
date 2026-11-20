"""Offline package and document boundary checks. No incident data is used."""
import contextlib
import io
import os
import tempfile
import unittest
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from zipfile import ZipFile

from bec.cli import main
from bec.package_documents import write_workbook
from bec.package_inputs import _anchor
from bec.package_safety import read_bytes, safe_name
from bec.storage import CaseError


class PackageControls(unittest.TestCase):
    def setUp(self):
        self.stack = self.enterContext(contextlib.ExitStack())
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.output = self.root / "analyst-output"
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.stack.enter_context(patch("socket.getaddrinfo", side_effect=AssertionError("network")))

    def test_unbound_package_stops_without_output(self):
        self.assertEqual(main(["package", str(self.root / "absent"), "--output", str(self.output)]), 1)
        self.assertFalse(self.output.exists())

    def test_new_directory_bound_case_requires_approved_evidence(self):
        case_root = self.root / "cases"
        account = uuid.uuid4().hex + "@example.invalid"
        args = ["--root", str(case_root), "case", "create", "--tenant", "case", "--user", account,
                "--start", "2020-01-01T00:00Z", "--end", "2020-01-02T00:00Z", "--directory-id", str(uuid.uuid4())]
        self.assertEqual(main(args), 0)
        directory, = (case_root / "case").iterdir()
        self.assertEqual(main(["package", str(directory), "--output", str(self.output)]), 1)
        self.assertFalse(self.output.exists())

    def test_independent_identifiers_must_agree(self):
        known = str(uuid.uuid4())
        self.assertEqual(_anchor(known, known.upper()), known)
        with self.assertRaises(CaseError):
            _anchor(known, str(uuid.uuid4()))
        with self.assertRaises(CaseError):
            _anchor(None, str(uuid.UUID(int=0)))

    def test_package_reader_preserves_an_ordinary_binary_file(self):
        path = self.root / "bytes.dat"
        data = bytes(range(256))
        path.write_bytes(data)
        self.assertEqual(read_bytes(path, len(data)), data)
        with self.assertRaises(CaseError):
            read_bytes(path, len(data) - 1)

    def test_reader_checks_change_times_within_each_stat_api(self):
        path = self.root / "bytes.dat"
        path.write_bytes(b"abc")
        actual_fstat = os.fstat
        for changes in ((1, 1), (1, 2)):
            increments = iter(changes)

            def descriptor_state(fd):
                info = actual_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev, st_ino=info.st_ino,
                                       st_size=info.st_size, st_mtime_ns=info.st_mtime_ns,
                                       st_ctime_ns=info.st_ctime_ns + next(increments))

            with self.subTest(changes=changes), patch("bec.package_safety.os.fstat", descriptor_state):
                if changes[0] == changes[1]:
                    self.assertEqual(read_bytes(path), b"abc")
                else:
                    with self.assertRaisesRegex(CaseError, "changed during"):
                        read_bytes(path)

    def test_reserved_components_are_refused(self):
        for part in ("", "..", "CON", "lpt1.csv", "trailing.", "one/two", "one:two"):
            with self.subTest(part=part), self.assertRaises(CaseError):
                safe_name(part)

    def test_xlsx_writes_literals_and_uses_only_internal_links(self):
        path = self.root / "triage.xlsx"
        tables = [dict(name="Evidence", columns=["Evidence ID", "Text"], rows=[["E000001", "  +1"]])]
        write_workbook(path, tables, {"E000001": 2})
        with ZipFile(path) as book:
            self.assertFalse(any("vba" in item.lower() for item in book.namelist()))
            sheet = ET.fromstring(book.read("xl/worksheets/sheet1.xml"))
            self.assertFalse(sheet.findall(".//{*}f"))
            self.assertTrue(all(cell.get("t") == "inlineStr" for cell in sheet.findall(".//{*}c")))
            self.assertIn("  +1", [value.text for value in sheet.findall(".//{*}t")])
            for name in (item for item in book.namelist() if item.endswith(".rels")):
                self.assertTrue(all(rel.get("TargetMode") != "External" for rel in ET.fromstring(book.read(name))))
