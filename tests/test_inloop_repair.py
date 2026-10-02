from pathlib import Path
import sys
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "baseline"))
sys.path.insert(0, str(ROOT / "vendor/tabularbench"))
from consistency_repair import BlockRollbackRepair
from inloop_repair import AuditedProblem, InLoopMoeva2, PopulationRollback
from pymoo.core.population import Population
from tabularbench.constraints.constraints import Constraints
from tabularbench.constraints.constraints_checker import ConstraintChecker
from tabularbench.constraints.relation_constraint import Feature


class InLoopRepairTests(unittest.TestCase):
    def setUp(self):
        names = ["anchor", "a", "b", "free"]
        f = {name: Feature(name) for name in names}
        self.constraints = Constraints(np.array(["int", "int", "int", "real"]),
            np.array([False, True, True, True]), np.zeros(4), np.full(4, 20.),
            [f["a"] + f["b"] == f["anchor"], f["a"] <= f["anchor"]], names)
        self.clean = np.array([4, 2, 2, 0], dtype=np.float32)
        self.checker = ConstraintChecker(self.constraints, 0.0)
        self.scale = lambda x: np.asarray(x, dtype=np.float32) / np.float32(20)
        self.rollback = BlockRollbackRepair(self.constraints, self.scale, .5)
        self.scored = []

    def predict(self, x):
        self.scored.append(x.copy())
        positive = np.clip(.8 - x[:, 3] / 20, 0, 1)
        return np.column_stack([1-positive, positive])

    def problem(self):
        return AuditedProblem(x_clean=self.clean, y_clean=1, classifier=self.predict,
            constraints=self.constraints, fun_distance_preprocess=self.scale, norm="L2",
            audit_checker=self.checker, audit_epsilon=.5)

    def test_population_repair_changes_genotype_before_fitness(self):
        p = self.problem()
        pop = Population.new("X", np.array([[5., 2., 3.], [2., 2., 4.]]))
        fixed = PopulationRollback(self.rollback, True).do(p, pop)
        np.testing.assert_array_equal(fixed.get("X"), [[2, 2, 3], [2, 2, 4]])
        p._evaluate(fixed.get("X"), {})
        self.assertEqual(p.evaluation_log[0]["valid_rows"], 2)
        np.testing.assert_array_equal(self.scored[0][:, 1:], fixed.get("X"))

    def test_budget_control_keeps_invalid_relation_for_upstream_penalty(self):
        p = self.problem()
        pop = Population.new("X", np.array([[5., 2., 3.]]))
        fixed = PopulationRollback(self.rollback, False).do(p, pop)
        out = {}
        p._evaluate(fixed.get("X"), out)
        self.assertEqual(p.evaluation_log[0]["valid_rows"], 0)
        self.assertGreater(out["F"][0, 2], 0)

    def test_scoring_rejects_unrepaired_or_substituted_population(self):
        p = self.problem()
        with self.assertRaises(AssertionError):
            p._evaluate(np.array([[2., 2., 1.]]), {})
        pop = Population.new("X", np.array([[2., 2., 1.]]))
        PopulationRollback(self.rollback, True).do(p, pop)
        with self.assertRaises(AssertionError):
            p._evaluate(np.array([[2., 2., 2.]]), {})

    def test_two_generations_repair_every_fitness_batch_and_keep_budget(self):
        attack = InLoopMoeva2(self.predict, constraints=self.constraints, norm="L2",
            fun_distance_preprocess=self.scale, n_gen=2, n_pop=8, n_offsprings=4,
            seed=0, n_jobs=1, rollback=self.rollback, checker=self.checker,
            epsilon=.5, repair_relations=True)
        population = attack(self.clean[None], np.array([1]))
        report = attack.audit([7], population.shape[1])
        self.assertEqual(report["expected_per_record"], population.shape[1] + 4)
        self.assertEqual(len(report["records"][0]["evaluation_batches"]), 2)
        self.assertTrue(self.checker.check_constraints(self.clean[None], population[0]).all())
        self.assertTrue(np.all(np.linalg.norm(self.scale(population[0])-self.scale(self.clean[None]), axis=1) <= .5))


if __name__ == "__main__":
    unittest.main()
