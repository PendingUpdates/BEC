"""Offline source-reference fidelity across replay, findings and report exports."""
import csv
from copy import deepcopy
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bec.collection import Collection, acquire, replay
from bec.evidence import evidence_references
from bec.google_events import normalize_child
from bec.normalize import normalize, records
from bec.reporting import report, timesketch
from bec.storage import DATA, GOOGLE_APPS, create, digest, encode, read, save


class PayloadParser(HTMLParser):
    """Read the public report payload without executing browser code."""

    def __init__(self):
        super().__init__()
        self.in_payload = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        self.in_payload = tag == "script" and dict(attrs).get("id") == "payload"

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_payload = False

    def handle_data(self, data):
        if self.in_payload:
            self.parts.append(data)


class EvidenceReferenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for target in ("bec.graph.Graph.__init__", "bec.graph.Graph.request",
                       "bec.workspace.Workspace.__init__", "bec.workspace.Workspace.request",
                       "socket.create_connection", "socket.getaddrinfo",
                       "socket.socket.connect", "socket.socket.connect_ex"):
            self.enterContext(patch(target, side_effect=AssertionError("Offline fixture test: provider/network forbidden")))

    def render(self, case):
        report(case)
        exported = timesketch(case)
        payload = read(case.path / "timeline" / "timeline.json")
        normalized = [json.loads(line) for line in (case.path / "normalized" / "events.jsonl").read_text().splitlines()]
        sketch = [json.loads(line) for line in exported.read_text().splitlines()]
        return payload, {event["event_id"]: event for event in normalized}, sketch

    def duplicated_case(self):
        case = create(self.root, "TEST", "compromised@example.com",
                      "2026-10-30T12:00Z", "2026-10-31T12:00Z",
                      dict(tenant="TEST", microsoft=True,
                           google_workspace=dict(customer_id="C02becdemo")))
        Collection(case).import_bundle(DATA / "demo" / "workspace-bundle.json")
        initial, issues = replay(case)
        self.assertFalse(issues)
        baseline = self.render(case)
        expected = {event["event_id"]: deepcopy([event["evidence"], *event.get("additional_evidence", [])])
                    for event in initial}
        original_refs = deepcopy(expected)
        artifacts = case.manifest()["artifacts"]
        original_bytes = {entry["artifact"]: case.raw_path(entry).read_bytes() for entry in artifacts}
        for entry in artifacts:
            rows = records(original_bytes[entry["artifact"]], entry["dataset"])
            # Two occurrences in a separately hashed export retain different record pointers.
            raw = encode(rows + deepcopy(rows))
            sha = digest(raw)
            self.assertNotEqual(sha, entry["sha256"])
            acquire(case, entry["dataset"], raw, "export", dict(dataset=entry["dataset"]), 100000)
            for event_id, references in original_refs.items():
                for reference in references:
                    if reference["file"] == entry["artifact"]:
                        for offset in (0, len(rows)):
                            expected[event_id].append({**reference,
                                "file": f"raw/{entry['dataset']}/{sha}.json", "sha256": sha,
                                "record_index": reference["record_index"] + offset})
        self.assertEqual(len(case.manifest()["artifacts"]), 2 * len(artifacts))
        return case, expected, baseline, original_bytes

    def assert_resolves(self, case, event_id, reference):
        raw = (case.path / reference["file"]).read_bytes()
        self.assertEqual(digest(raw), reference["sha256"])
        dataset = reference["file"].split("/")[1]
        row = records(raw, dataset)[reference["record_index"]]
        if dataset in GOOGLE_APPS:
            self.assertIn("event_index", reference)
            event = normalize_child(case.tenant, dataset, row, reference["event_index"], reference)
        else:
            event = normalize(case.tenant, dataset, row, reference)
        self.assertEqual(event["event_id"], event_id)

    def assert_full_references(self, case, event_id, actual, expected):
        self.assertCountEqual(actual, expected[event_id])
        self.assertEqual(len(actual), len({json.dumps(ref, sort_keys=True) for ref in actual}))
        self.assertGreaterEqual(len({ref["file"] for ref in actual}), 2)
        for reference in actual:
            self.assert_resolves(case, event_id, reference)

    def assert_timeline_references(self, case, rows, expected):
        for row in rows:
            by_event = {}
            for reference in row["evidence_reference"]:
                pointer = dict(reference)
                event_id = pointer.pop("event_id")
                by_event.setdefault(event_id, []).append(pointer)
            # Event counts remain independent of the number of source references.
            self.assertEqual(len(by_event), row["count"])
            for event_id, references in by_event.items():
                self.assert_full_references(case, event_id, references, expected)

    def semantic_events(self, events):
        return {event_id: {key: value for key, value in event.items()
                           if key not in ("evidence", "additional_evidence")}
                for event_id, event in events.items()}

    def reference_projection(self, payload, sketch):
        return dict(
            complete=[row["evidence_reference"] for row in payload["complete"]],
            relevant=[row["evidence_reference"] for row in payload["relevant"]],
            findings={finding["id"]: finding["event_evidence"] for finding in payload["findings"]},
            messages={message["id"]: {observation["event_id"]: observation["evidence_references"]
                      for observation in message["observations"]} for message in payload["messages"]},
            timesketch={row["event_id"]: row["evidence_references"] for row in sketch})

    def test_helper_deduplicates_whole_pointers_without_mutating_inputs(self):
        first = dict(file="raw/google_gmail/a.json", sha256="a" * 64, record_index=0, event_index=0)
        child = {**first, "event_index": 1}
        other = dict(file="raw/google_gmail/b.json", sha256="b" * 64, record_index=0, event_index=0,
                     provenance=dict(labels=["synthetic"]))
        event = dict(evidence=child, additional_evidence=[other, first, dict(reversed(list(child.items()))), deepcopy(first)],
                     unrelated=dict(keep=True))
        before = deepcopy(event)
        references = evidence_references(event)
        # Canonical ordering can place the legacy primary after other pointers.
        self.assertEqual(references, [first, other, child])
        self.assertEqual(event, before)
        reordered = dict(evidence=first, additional_evidence=[child, other, deepcopy(first), deepcopy(child)])
        self.assertEqual(evidence_references(reordered), references)
        references[0]["file"] = "caller-only change"
        references[1]["provenance"]["labels"].append("caller-only change")
        self.assertEqual(event, before)

    def test_replay_and_report_exports_keep_all_source_pointers(self):
        case, expected, baseline, original_bytes = self.duplicated_case()
        events, issues = replay(case)
        self.assertFalse(issues)
        self.assertEqual(set(expected), {event["event_id"] for event in events})
        for event in events:
            self.assert_full_references(case, event["event_id"],
                [event["evidence"], *event.get("additional_evidence", [])], expected)
        payload, normalized, sketch = self.render(case)
        self.assertEqual(self.semantic_events(normalized), self.semantic_events(baseline[1]))
        for event_id, event in normalized.items():
            self.assertEqual(event["evidence"], baseline[1][event_id]["evidence"])
        for view, filename in (("complete", "complete.csv"), ("relevant", "timeline.csv")):
            self.assert_timeline_references(case, payload[view], expected)
            with (case.path / "timeline" / filename).open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), len(payload[view]))
            for csv_row, json_row in zip(rows, payload[view]):
                self.assertEqual(int(csv_row["count"]), json_row["count"])
                self.assertEqual(json.loads(csv_row["evidence_reference"]), json_row["evidence_reference"])
        parser = PayloadParser()
        parser.feed((case.path / "timeline" / "timeline.html").read_text(encoding="utf-8"))
        self.assertEqual(json.loads("".join(parser.parts)), payload)
        self.assertEqual(len(sketch), len(normalized))
        for row in sketch:
            self.assertEqual(row["evidence"], normalized[row["event_id"]]["evidence"])
            self.assert_full_references(case, row["event_id"], row["evidence_references"], expected)
        child, = [event for event in normalized.values() if event["event_type"] == "google.gmail.view"]
        self.assertEqual({ref["event_index"] for ref in expected[child["event_id"]]}, {1})
        self.assertGreaterEqual(len(expected[child["event_id"]]), 3)
        for filename, raw in original_bytes.items():
            self.assertEqual((case.path / filename).read_bytes(), raw)
        case.verify()

    def test_findings_and_messages_preserve_legacy_alignment_and_full_references(self):
        case, expected, baseline, _ = self.duplicated_case()
        payload, normalized, _ = self.render(case)
        before = {finding["id"]: finding for finding in baseline[0]["findings"]}
        self.assertEqual({finding["id"] for finding in payload["findings"]}, set(before))
        self.assertTrue({"auth-mail", "workspace-grant-gmail", "mailbox-message"} <=
                        {finding["rule"] for finding in payload["findings"]})
        for finding in payload["findings"]:
            self.assertEqual(finding["event_ids"], before[finding["id"]]["event_ids"])
            self.assertEqual(finding["evidence"], before[finding["id"]]["evidence"])
            self.assertEqual(len(finding["evidence"]), len(finding["event_ids"]))
            self.assertEqual([item["event_id"] for item in finding["event_evidence"]], finding["event_ids"])
            for event_id, primary, item in zip(finding["event_ids"], finding["evidence"], finding["event_evidence"]):
                self.assertEqual(primary, normalized[event_id]["evidence"])
                self.assert_resolves(case, event_id, primary)
                self.assert_full_references(case, event_id, item["references"], expected)
        self.assertTrue(payload["messages"])
        previous = {message["id"]: message for message in baseline[0]["messages"]}
        self.assertEqual({message["id"] for message in payload["messages"]}, set(previous))
        for message in payload["messages"]:
            primaries = {observation["event_id"]: observation["evidence"]
                         for observation in previous[message["id"]]["observations"]}
            self.assertEqual(len(message["observations"]), len(primaries))
            for observation in message["observations"]:
                event_id = observation["event_id"]
                self.assertEqual(observation["evidence"], primaries[event_id])
                self.assert_full_references(case, event_id, observation["evidence_references"], expected)

    def test_reversing_artifacts_keeps_full_references_and_event_semantics(self):
        case, expected, baseline, _ = self.duplicated_case()
        first, first_events, first_sketch = self.render(case)
        manifest = case.manifest()
        manifest["artifacts"].reverse()
        save(case.path / "evidence_manifest.json", manifest)
        second, second_events, second_sketch = self.render(case)
        self.assertTrue(any(first_events[event_id]["evidence"] != second_events[event_id]["evidence"]
                            for event_id in first_events))
        self.assertEqual(self.semantic_events(first_events), self.semantic_events(second_events))
        self.assertEqual(self.semantic_events(first_events), self.semantic_events(baseline[1]))
        self.assertEqual(self.reference_projection(first, first_sketch), self.reference_projection(second, second_sketch))
        for events, sketch in ((first_events, first_sketch), (second_events, second_sketch)):
            for row in sketch:
                event = events[row["event_id"]]
                self.assertEqual(event.get("additional_evidence", []),
                                 [ref for ref in row["evidence_references"] if ref != event["evidence"]])
        for payload in (first, second):
            self.assertEqual({key: value for key, value in payload["summary"].items() if key != "generated"},
                             {key: value for key, value in baseline[0]["summary"].items() if key != "generated"})
            for row in payload["complete"]:
                self.assertEqual(row["count"], 1)
        for row in second_sketch:
            self.assert_full_references(case, row["event_id"], row["evidence_references"], expected)


if __name__ == "__main__":
    unittest.main()
