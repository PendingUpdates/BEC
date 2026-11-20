"""Date planning checks that use no accounts, source records or provider sessions."""
import unittest
from datetime import timedelta

from bec.storage import CaseError, iso, timestamp
from bec.trace_windows import MAX_CHUNK, PRESETS, chunk_plan, preset_start, read_start, requested_window


class TraceWindows(unittest.TestCase):
    def test_calendar_month_and_year_clamp_the_day_in_utc(self):
        cases = [
            ("2024-03-31T12:34:56Z", "1 month", "2024-02-29T12:34:56Z"),
            ("2025-03-31T12:34:56Z", "1 month", "2025-02-28T12:34:56Z"),
            ("2025-01-31T12:34:56Z", "1 month", "2024-12-31T12:34:56Z"),
            ("2024-02-29T12:34:56Z", "1 year", "2023-02-28T12:34:56Z"),
        ]
        for end, preset, start in cases:
            with self.subTest(end=end, preset=preset):
                self.assertEqual(preset_start(timestamp(end), preset), timestamp(start))

    def test_frozen_windows_have_contiguous_bounded_ranges(self):
        end = timestamp("2024-03-31T12:34:56Z")
        counts = (1, 1, 4, 9, 9)
        for preset, count in zip(PRESETS, counts, strict=True):
            with self.subTest(preset=preset):
                start = preset_start(end, preset)
                plan = chunk_plan(iso(start), iso(end), iso(end))
                self.assertEqual(len(plan), count)
                self.assertEqual(plan[0]["start"], iso(max(start, end - timedelta(days=90))))
                self.assertEqual(plan[-1]["end"], iso(end))
                for n, chunk in enumerate(plan, 1):
                    self.assertEqual(chunk["id"], f"{n:02d}")
                    span = timestamp(chunk["end"]) - timestamp(chunk["start"])
                    self.assertTrue(timedelta() < span <= MAX_CHUNK)
                self.assertEqual([c["end"] for c in plan[:-1]], [c["start"] for c in plan[1:]])

    def test_explicit_requests_respect_reference_and_year_limit(self):
        ref = "2024-03-31T00:00:00Z"
        self.assertEqual(chunk_plan("2023-03-31T00:00:00Z", "2023-06-01T00:00:00Z", ref), [])
        with self.assertRaises(CaseError):
            requested_window("2023-03-30T23:59:59Z", ref)
        with self.assertRaises(CaseError):
            chunk_plan(ref, "2024-04-01T00:00:00Z", ref)

    def test_moving_retention_edge_is_attributable_and_never_extends_a_range(self):
        ref = timestamp("2025-04-01T00:00:43Z")
        start = ref - timedelta(days=90)
        stop = start + timedelta(days=10)
        expected = timestamp("2025-01-01T00:01:00Z")
        self.assertEqual(read_start(iso(start), iso(stop), iso(ref)), iso(expected))
        self.assertEqual(read_start(iso(start), iso(stop), iso(ref + timedelta(days=11))), iso(stop))
        self.assertEqual(read_start(iso(stop), iso(stop + MAX_CHUNK), iso(ref)), iso(stop))
