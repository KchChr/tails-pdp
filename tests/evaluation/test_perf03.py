"""Local checks for rejecting confounded or incomplete PERF-03 timing records."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("perf03", Path(__file__).with_name("PERF-03.py"))
perf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perf)


class TimingEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.entries = [("policy_event_received", 20, 0),
                        ("policy_debounce_completed", 100_000_020, 0),
                        ("policy_activation_started", 100_000_030, 7),
                        ("policy_activation_completed", 100_000_040, 7)]

    def test_complete_isolated_measurement(self):
        self.assertEqual(perf.phase_timestamps(self.entries, 7, 10, 100_000_050),
                         (20, 100_000_020, 100_000_030, 100_000_040))

    def test_event_before_measurement_is_rejected(self):
        with self.assertRaises(AssertionError):
            perf.phase_timestamps(self.entries, 7, 21, 100_000_050)

    def test_partial_debounce_is_rejected(self):
        self.entries[1] = ("policy_debounce_completed", 99_000_020, 0)
        with self.assertRaises(AssertionError):
            perf.phase_timestamps(self.entries, 7, 10, 100_000_050)

    def test_missing_wrong_generation_or_extra_events_are_rejected(self):
        for entries in (self.entries[:-1],
                        self.entries + [("policy_event_received", 30, 0)],
                        self.entries[:-1] + [("policy_activation_completed", 100_000_040, 8)]):
            with self.subTest(entries=entries), self.assertRaises(AssertionError):
                perf.phase_timestamps(entries, 7, 10, 100_000_050)

    def test_revocation_before_activation_is_rejected(self):
        with self.assertRaises(AssertionError):
            perf.phase_timestamps(self.entries, 7, 10, 100_000_035)

    def test_waiting_watcher_alone_does_not_prove_idle_scan(self):
        class Runtime:
            def alive(self):
                pass

        entries = [("policy_waiting", 10, 0), ("scan_started", 20, 0)]
        with patch.object(perf, "markers", return_value=entries), \
             patch.object(perf.time, "monotonic", side_effect=[0, 0, perf.TIMEOUT + 1]), \
             patch.object(perf.time, "sleep"), self.assertRaises(AssertionError):
            perf.wait_for_quiet(Runtime())


if __name__ == "__main__":
    unittest.main()
