"""Numerical and archive-integrity regression tests for the saved-output audit."""
import io
from pathlib import Path
import sys
import unittest
import zipfile

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "baseline"))
from relationship_audit import RuleEngine, checked_zip, load_candidates, precision_counts


class RelationshipAuditTests(unittest.TestCase):
    def test_wider_arithmetic_can_clear_or_reveal_failures(self):
        sys.path.insert(0, str(ROOT / "vendor/tabularbench"))
        from tabularbench.constraints.constraints_backend_executor import ConstraintsExecutor
        from tabularbench.constraints.numpy_backend import NumpyBackend
        from tabularbench.constraints.relation_constraint import AndConstraint, Feature
        engine = RuleEngine.__new__(RuleEngine)
        a, b, c, d = [Feature(i) for i in range(4)]
        engine.rules = [(a + b + c) == d, a <= d]
        engine.conjunction = AndConstraint(engine.rules)
        engine.execute = lambda node, x: ConstraintsExecutor(node, NumpyBackend()).execute(x)
        x = np.array([[[2**24, 1, 0, 2**24]],
                      [[2**24, 1, 1, 2**24 + 2]],
                      [[10, 1, 0, 10]]], dtype=np.float32)
        before = x.copy()
        native, _, _ = engine.evaluate(x, np.float32)
        wider, _, _ = engine.evaluate(x, np.float64)
        self.assertEqual(precision_counts(native, wider), {
            "native_invalid": 2, "float64_invalid": 2,
            "native_invalid_but_float64_valid": 1,
            "native_valid_but_float64_invalid": 1,
        })
        np.testing.assert_array_equal(x, before)

    def test_rule_level_clearance_is_not_candidate_clearance(self):
        native = np.array([[[1., 2.], [3., 0.], [0., 0.]]])
        wider = np.array([[[0., 2.], [0., 0.], [1., 0.]]])
        counts = precision_counts(native, wider)
        self.assertEqual(counts["native_invalid_but_float64_valid"], 1)
        self.assertEqual(counts["native_valid_but_float64_invalid"], 1)

    def test_unsafe_zip_path_is_rejected_without_extraction(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as z:
            z.writestr("../outside.txt", "test")
        payload.seek(0)
        with self.assertRaisesRegex(ValueError, "Unsafe ZIP"):
            checked_zip(payload)

    def test_pickled_arrays_are_not_loaded(self):
        payload = io.BytesIO()
        np.savez(payload, x_candidates=np.array([object()], dtype=object))
        with self.assertRaisesRegex(ValueError, "Object arrays"):
            load_candidates(payload.getvalue(), 757)


if __name__ == "__main__":
    unittest.main()
