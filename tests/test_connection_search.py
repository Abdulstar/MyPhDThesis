from pathlib import Path
import sys
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "baseline"))
sys.path.insert(0, str(ROOT / "vendor/tabularbench"))
from connection_profile import ConnectionProfile, ConnectionRollback, observe_profile_selector
from connection_search import ConnectionMoeva2, ConnectionProblem, ConnectionPopulationRollback
from pymoo.core.population import Population
from tabularbench.constraints.constraints import Constraints
from tabularbench.constraints.constraints_checker import ConstraintChecker
from tabularbench.constraints.relation_constraint import Feature
from tabularbench.attacks.objective_calculator import ObjectiveCalculator


class ConnectionSearchTests(unittest.TestCase):
    def setUp(self):
        self.names = ["duration_sum_s_443", "duration_min_s_443", "duration_max_s_443",
                      "distinct_external_ips_s_443", "distinct_src_port_s_443", "distinct_dst_port_s_443", "free"]
        f = {n: Feature(n) for n in self.names}
        self.constraints = Constraints(np.array(["real"] * 3 + ["int"] * 3 + ["real"]),
            np.array([True] * 3 + [False] * 3 + [True]), np.zeros(7), np.full(7, 20.),
            [f[self.names[1]] <= f[self.names[2]], f[self.names[2]] <= f[self.names[0]]], self.names)
        self.profile = ConnectionProfile(self.names, {"metrics": ["duration"], "directions": ["s"],
            "ports": ["443"], "aggregate_pairs": 1, "duration_endpoint_pairs": 3})
        self.scale = lambda x: np.asarray(x, dtype=np.float32) / np.float32(20)
        self.checker = ConstraintChecker(self.constraints, 0.0)
        self.repair = ConnectionRollback(self.constraints, self.scale, .5, self.profile)
        self.clean = np.zeros((1, 7), dtype=np.float32)
        self.scored = []

    def predict(self, x):
        self.scored.append(x.copy())
        score = np.clip(.8 - (x[:, 0] + x[:, 6]) / 10, 0, 1)
        return np.stack([1 - score, score], axis=1)

    def problem(self):
        return ConnectionProblem(x_clean=self.clean[0], y_clean=1, classifier=self.predict,
            constraints=self.constraints, fun_distance_preprocess=self.scale, norm="L2",
            audit_checker=self.checker, audit_epsilon=.5, profile=self.profile)

    def test_nonexistent_connection_duration_is_rolled_back_without_inventing_counts(self):
        proposed = np.array([[5, 0, 2, 0, 0, 0, 3]], dtype=np.float32)
        before = proposed.copy()
        self.assertTrue(self.checker.check_constraints(self.clean, proposed).all())
        self.assertFalse(self.profile.ok(proposed).all())
        after, audit = self.repair.repair_population(self.clean, proposed, False)
        np.testing.assert_array_equal(after, [[0, 0, 0, 0, 0, 0, 3]])
        np.testing.assert_array_equal(proposed, before)
        self.assertTrue(self.profile.ok(after).all())
        self.assertEqual(audit["presence_failures_before_profile"].tolist(), [3])
        self.assertEqual(audit["profile_blocks_restored"].tolist(), [1])

    def test_existing_connection_allows_consistent_duration_changes(self):
        clean = np.array([[6, 2, 4, 1, 1, 1, 0]], dtype=np.float32)
        proposed = np.array([[8, 2, 5, 1, 1, 1, 1]], dtype=np.float32)
        after, _ = self.repair.repair_population(clean, proposed, True)
        np.testing.assert_array_equal(after, proposed)
        broken = proposed.copy(); broken[0, 2] = 0; broken[0, 1] = 0
        after, _ = self.repair.repair_population(clean, broken, False)
        np.testing.assert_array_equal(after, [[6, 2, 4, 1, 1, 1, 1]])

    def test_bad_original_rejected_without_tuning_or_replacement(self):
        bad = self.clean.copy(); bad[0, 0] = 2; bad[0, 2] = 1
        with self.assertRaisesRegex(ValueError, "original"):
            self.repair.repair_population(bad, bad)

    def test_real_genotype_is_repaired_before_model_fitness(self):
        problem = self.problem()
        pop = Population.new("X", np.array([[5., 0., 2., 3.], [0., 0., 0., 4.]]))
        fixed = ConnectionPopulationRollback(self.repair, True).do(problem, pop)
        np.testing.assert_array_equal(fixed.get("X"), [[0, 0, 0, 3], [0, 0, 0, 4]])
        problem._evaluate(fixed.get("X"), {})
        self.assertTrue(self.profile.ok(self.scored[-1]).all())
        self.assertEqual(problem.evaluation_log[0]["added_profile_valid_rows"], 2)
        self.assertEqual(problem.repair_log[0]["profile_blocks_restored"], 1)

    def test_unrepaired_population_cannot_be_scored(self):
        problem = self.problem()
        with self.assertRaisesRegex(AssertionError, "profile"):
            problem._evaluate(np.array([[5., 0., 2., 3.]]), {})
        self.assertEqual(self.scored, [])

    def test_selector_recovers_passing_alternative_to_native_best(self):
        population = np.array([[[5, 0, 2, 0, 0, 0, 1], [0, 0, 0, 0, 0, 0, 5]]], dtype=np.float32)
        calculator = ObjectiveCalculator(self.predict, self.constraints, {"distance": .5}, "L2", self.scale)
        class Trace:
            def record(self, clean, labels, x, measured, respected, selected):
                self.selected = selected
        trace = Trace()
        observe_profile_selector(calculator, trace, self.profile)
        selected = calculator.get_successful_attacks_indexes(self.clean, np.array([1]), population, max_inputs=1)
        np.testing.assert_array_equal(selected[0], [0])
        np.testing.assert_array_equal(selected[1], [1])

    def test_actual_moeva_repair_and_evaluation_budget(self):
        attack = ConnectionMoeva2(self.predict, constraints=self.constraints, norm="L2",
            fun_distance_preprocess=self.scale, n_gen=2, n_pop=8, n_offsprings=4, seed=0, n_jobs=1,
            rollback=self.repair, checker=self.checker, epsilon=.5, repair_relations=True, profile=self.profile)
        population = attack(self.clean, np.array([1]))
        audit = attack.audit([123], population.shape[1])
        self.assertEqual(audit["expected_per_record"], population.shape[1] + 4)
        self.assertTrue(audit["all_fitness_rows_pass_added_profile"])
        self.assertTrue(self.profile.ok(population).all())
        self.assertTrue(self.checker.check_constraints(self.clean, population[0]).all())


if __name__ == "__main__":
    unittest.main()
