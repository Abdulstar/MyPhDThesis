import copy
from pathlib import Path
import sys
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "baseline"))
sys.path.insert(0, str(ROOT / "vendor/tabularbench"))
from consistency_repair import BlockRollbackRepair, pool_summary
from tabularbench.constraints.constraints import Constraints
from tabularbench.constraints.constraints_checker import ConstraintChecker
from tabularbench.constraints.relation_constraint import Feature


class ConsistencyRepairTests(unittest.TestCase):
    def setUp(self):
        # An immutable anchor, one coupled integer block, one real block and
        # an unconstrained mutable feature. Values are chosen independently
        # of CTU attack outputs.
        self.names = ["anchor", "a", "b", "minimum", "maximum", "free"]
        f = {n: Feature(n) for n in self.names}
        self.constraints = Constraints(np.array(["int", "int", "int", "real", "real", "real"]),
            np.array([False, True, True, True, True, True]), np.zeros(6), np.full(6, 20.),
            [f["a"] + f["b"] == f["anchor"], f["minimum"] <= f["maximum"]], self.names)
        self.clean = np.array([[4, 2, 2, 1, 2, 0]], dtype=np.float32)
        self.checker = ConstraintChecker(self.constraints, 0.0)
        self.scaler = lambda x: np.asarray(x, dtype=np.float32) / np.float32(20)

    def test_broken_equality_restores_whole_block_and_keeps_valid_changes(self):
        repair = BlockRollbackRepair(self.constraints, self.scaler, .5)
        proposed = np.array([[4, 5, 2, 1, 3, 1]], dtype=np.float32)
        before = proposed.copy()
        result, audit = repair.repair_population(self.clean, proposed)
        np.testing.assert_array_equal(result, [[4, 2, 2, 1, 3, 1]])
        np.testing.assert_array_equal(proposed, before)
        self.assertTrue(self.checker.check_constraints(self.clean, result).all())
        self.assertEqual(audit["relation_blocks_restored"].tolist(), [1])

    def test_budget_only_control_retains_in_budget_relationship_failure(self):
        repair = BlockRollbackRepair(self.constraints, self.scaler, .5)
        proposed = np.array([[4, 5, 2, 1, 3, 1]], dtype=np.float32)
        control, _ = repair.repair_population(self.clean, proposed, repair_relations=False)
        self.assertFalse(self.checker.check_constraints(self.clean, control).all())
        full, _ = repair.repair_population(self.clean, proposed, repair_relations=True)
        self.assertTrue(self.checker.check_constraints(self.clean, full).all())

    def test_bounds_types_and_immutability_use_original_values(self):
        repair = BlockRollbackRepair(self.constraints, self.scaler, .5)
        proposed = np.array([[7, 2.5, 1.5, 1, 21, 1]], dtype=np.float32)
        result, audit = repair.repair_population(self.clean, proposed)
        np.testing.assert_array_equal(result, [[4, 2, 2, 1, 2, 1]])
        self.assertTrue(self.checker.check_constraints(self.clean, result).all())
        self.assertEqual(audit["basic_blocks_restored"].tolist(), [2])
        self.assertEqual(audit["immutable_features_restored"].tolist(), [1])

    def test_budget_rollback_removes_largest_whole_block(self):
        repair = BlockRollbackRepair(self.constraints, self.scaler, .15)
        proposed = np.array([[4, 3, 1, 3, 7, 1]], dtype=np.float32)
        result, audit = repair.repair_population(self.clean, proposed)
        np.testing.assert_array_equal(result, [[4, 3, 1, 1, 2, 1]])
        self.assertTrue(self.checker.check_constraints(self.clean, result).all())
        self.assertTrue(np.all(audit["distance_after_budget"] <= .15))
        self.assertEqual(audit["budget_blocks_restored"].tolist(), [1])

    def test_feasible_candidate_is_preserved_exactly_and_repeat_is_deterministic(self):
        repair = BlockRollbackRepair(self.constraints, self.scaler, .5)
        proposed = np.array([[4, 3, 1, 1, 3, 1]], dtype=np.float32)
        rng = copy.deepcopy(np.random.get_state())
        result, _ = repair.repair_population(self.clean, proposed)
        result2, _ = repair.repair_population(self.clean, proposed)
        np.testing.assert_array_equal(result, proposed)
        np.testing.assert_array_equal(result2, result)
        after = np.random.get_state()
        self.assertEqual(rng[0], after[0]); np.testing.assert_array_equal(rng[1], after[1])
        self.assertEqual(rng[2:], after[2:])

    def test_clean_fallback_does_not_count_as_feasible_changed_coverage(self):
        counts, coverage, success = pool_summary(
            np.array([[False, False], [True, False]]),
            np.array([[True, True], [False, True]]),
            np.ones((2, 2), dtype=bool), np.zeros((2, 2), dtype=bool))
        self.assertEqual(counts["changed_valid_in_budget"], 0)
        self.assertFalse(coverage.any())
        self.assertFalse(success.any())

    def test_final_gate_rejects_invalid_evasion_and_keeps_original_success(self):
        from run_development_repair import final_gate
        class ToyModel:
            def predict_proba(self, x):
                benign = (x[:, 5] >= 2).astype(float)
                return np.stack([benign, 1-benign], axis=1)
        clean = np.repeat(self.clean, 2, axis=0)
        baseline = clean.copy(); baseline[1,5] = 3
        proposed = clean.copy(); proposed[0,1] = 5; proposed[0,5] = 3
        final, prediction, distance, rejected = final_gate(clean, proposed, baseline,
            np.array([1,0]), ToyModel(), self.checker,
            type("Scaler", (), {"transform": staticmethod(self.scaler)})(), .5)
        np.testing.assert_array_equal(final, baseline)
        np.testing.assert_array_equal(prediction, [1,0])
        self.assertEqual(rejected, 2)
        self.assertTrue(np.all(distance <= .5))


if __name__ == "__main__":
    unittest.main()
