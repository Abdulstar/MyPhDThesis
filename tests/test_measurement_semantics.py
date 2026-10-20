"""Scientific counterexamples to unsafe measurement assumptions."""
import json
from pathlib import Path
import tempfile
import unittest

from baseline.measurement_semantics import PROTOCOL_PATH, synthetic_audit


class MeasurementSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.vectors, cls.cases = synthetic_audit(Path(cls.temporary.name), json.loads(PROTOCOL_PATH.read_text()))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_missing_and_literal_zero_collide(self):
        self.assertEqual(self.vectors["missing_packets"], self.vectors["literal_zero_packets"])
        self.assertEqual(self.cases["missing_packets"]["missing_packet_cells"], 2)
        self.assertEqual(self.cases["literal_zero_packets"]["missing_packet_cells"], 0)
        self.assertEqual(self.cases["missing_packets"]["packet_total"], 0)
        self.assertEqual(self.cases["missing_packets"]["duration_sum"], 0.665524)
        self.assertTrue(self.cases["missing_packets"]["conditional_bound_violated"])

    def test_complete_counts_satisfy_example_bound(self):
        case = self.cases["complete_packets"]
        self.assertEqual(case["packet_total"], 4)
        self.assertFalse(case["conditional_bound_violated"])

    def test_positive_packet_total_does_not_cure_missingness(self):
        case = self.cases["partially_missing_positive_total"]
        self.assertEqual((case["records"], case["packet_total"], case["duration_sum"], case["duration_max"]), (2, 1, 2, 1))
        self.assertTrue(case["conditional_bound_violated"])

    def test_passing_bound_does_not_establish_completeness(self):
        case = self.cases["partially_missing_passing_bound"]
        self.assertEqual(case["missing_packet_cells"], 2)
        self.assertEqual(case["packet_total"], 1)
        self.assertFalse(case["conditional_bound_violated"])

    def test_minimum_cannot_count_all_records_after_leading_zeros(self):
        case = self.cases["leading_all_zero_record"]
        self.assertEqual(case["records"], 2)
        self.assertEqual(case["distinct_source_ports"], 2)
        self.assertEqual(case["packet_total"], 1)
        self.assertEqual(case["packet_min_out"], 1)

    def test_window_is_not_a_duration_cap(self):
        self.assertEqual(self.cases["duration_exceeds_window"]["duration_max"], 120)


if __name__ == "__main__":
    unittest.main()
