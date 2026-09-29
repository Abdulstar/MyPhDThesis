"""Checks for diagnostic bookkeeping, not alternative attack implementations."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "baseline"))
from candidate_trace import CandidateTrace, failure_buckets, observe_selector


class AlwaysValid:
    def _check_relationship_constraints(self, x): return np.ones(len(x), dtype=bool)
    def _check_boundary_constraints(self, clean, x): return np.ones(len(x), dtype=bool)
    def _check_type_constraints(self, x): return np.ones(len(x), dtype=bool)
    def _check_mutable_constraints(self, clean, x): return np.ones(len(x), dtype=bool)


class TraceTests(unittest.TestCase):
    def test_disjoint_buckets_preserve_overlapping_failures(self):
        # Each of the eight combinations occurs exactly once.
        valid = np.array([False] * 4 + [True] * 4)
        distance = np.array([False, False, True, True] * 2)
        fooled = np.array([False, True] * 4)
        buckets = failure_buckets(valid, distance, fooled)
        self.assertEqual([b["candidates"] for b in buckets], [1] * 8)
        self.assertEqual(sum(b["candidates"] for b in buckets), len(valid))
        # Marginal failures overlap; summing them is not a candidate count.
        self.assertEqual(int((~valid).sum() + (~distance).sum() + (~fooled).sum()), 12)

    def test_observer_preserves_selector_and_tracks_duplicate_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            trace = CandidateTrace(Path(temp) / "trace", [101, 202],
                                   ["First", "Second"], AlwaysValid(), {"distance": .5})
            clean = np.array([[1., 2.], [1., 2.]], dtype=np.float32)
            candidates = clean[:, None, :].copy()
            selected = (np.array([0]), np.array([0]))
            valid = np.ones((2, 1), dtype=bool)
            fooled = np.array([[True], [False]])
            calculator = SimpleNamespace(
                objectives_eval=SimpleNamespace(distance=np.zeros((2, 1)), misclassification=np.array([[-.1], [.8]])),
                objectives_respected=SimpleNamespace(constraints=valid, distance=valid, misclassification=fooled, mdc=fooled),
                get_successful_attacks_indexes=lambda *args, **kwargs: selected)
            observe_selector(calculator, trace)
            result = calculator.get_successful_attacks_indexes(clean, np.ones(2, dtype=int), candidates)
            self.assertIs(result, selected)
            np.testing.assert_array_equal(trace.remaining, [1])
            np.testing.assert_array_equal(candidates, clean[:, None, :])
            # Identical feature rows must retain their distinct original IDs.
            trace.record(clean[1:], np.ones(1, dtype=int), candidates[1:],
                         SimpleNamespace(distance=np.zeros((1, 1)), misclassification=np.ones((1, 1))),
                         SimpleNamespace(constraints=np.ones((1, 1), dtype=bool), distance=np.ones((1, 1), dtype=bool),
                                         misclassification=np.zeros((1, 1), dtype=bool), mdc=np.zeros((1, 1), dtype=bool)),
                         (np.array([], dtype=int), np.array([], dtype=int)))
            with np.load(Path(temp) / "trace/01_Second_candidates.npz", allow_pickle=False) as output:
                np.testing.assert_array_equal(output["csv_rows"], [202])
            summary = json.loads((Path(temp) / "trace/stage_summary.json").read_text())
            self.assertEqual(summary["remaining_original_csv_rows"], [202])


if __name__ == "__main__":
    unittest.main()
