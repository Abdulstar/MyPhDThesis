"""Apply the preserved rollback operator inside pinned MOEVA's reproduction.

Only the pymoo repair hooks change. Sampling, mutation, crossover, selection,
objectives, populations, generations and model queries remain upstream code.
"""
import hashlib
import time

import numpy as np
from pymoo.core.repair import Repair
from tabularbench.attacks.moeva.adversarial_problem import AdversarialProblem
from tabularbench.attacks.moeva.moeva import Moeva2


def population_checks(problem, population):
    original = problem.x_clean.reshape(1, -1)
    checker = problem.audit_checker
    parts = {
        "relationship": checker._check_relationship_constraints(population),
        "bounds": checker._check_boundary_constraints(original, population),
        "types": checker._check_type_constraints(population),
        "immutable": checker._check_mutable_constraints(original, population),
    }
    valid = np.logical_and.reduce(list(parts.values()))
    distance = np.linalg.norm(problem.fun_distance_preprocess(population) -
                              problem.fun_distance_preprocess(original), axis=1)
    changed = np.any(population != original, axis=1)
    return parts, valid, distance, changed


class PopulationRollback(Repair):
    def __init__(self, rollback, repair_relations):
        self.rollback = rollback
        self.repair_relations = repair_relations

    def _do(self, problem, pop, **kwargs):
        started = time.perf_counter()
        original = problem.x_clean.reshape(1, -1)
        mutable = problem.constraints.mutable_features
        before = np.repeat(original, len(pop), axis=0)
        before[:, mutable] = pop.get("X")
        if before.dtype != np.float32:
            raise ValueError("Use the original native float32 CTU inputs")
        after, details = self.rollback.repair_population(original, before, self.repair_relations)
        parts, valid, distance, changed = population_checks(problem, after)
        if not (parts["bounds"] & parts["types"] & parts["immutable"]).all():
            raise AssertionError("Rollback failed an unchanged basic feature rule")
        if np.any(distance > problem.audit_epsilon):
            raise AssertionError("Rollback exceeded the unchanged distance budget")
        # Numerical acceptance is always the full official checker. A rare
        # full-rule rejection after block checks falls back to the clean input.
        fallback = ~valid if self.repair_relations else np.zeros(len(pop), dtype=bool)
        if fallback.any():
            after[fallback] = original
            parts, valid, distance, changed = population_checks(problem, after)
        if self.repair_relations and not valid.all():
            raise AssertionError("Clean fallback is not valid in this population shape")
        pop.set("X", after[:, mutable].astype(pop.get("X").dtype))
        problem.repair_log.append({
            "batch_index": len(problem.repair_log), "candidates": len(pop),
            "altered_by_repair": int(np.any(after != before, axis=1).sum()),
            "fully_reverted_changed_candidates": int((np.any(before != original, axis=1) & ~changed).sum()),
            "final_checker_clean_fallbacks": int(fallback.sum()),
            "changed_valid_in_budget": int((changed & valid & (distance <= problem.audit_epsilon)).sum()),
            "relationship_invalid_after": int((~parts["relationship"]).sum()),
            "relation_blocks_restored": int(details["relation_blocks_restored"].sum()),
            "budget_blocks_restored": int(details["budget_blocks_restored"].sum()),
            "native_population_sha256": hashlib.sha256(after.tobytes()).hexdigest(),
            "repair_and_check_seconds": time.perf_counter() - started,
        })
        return pop


class AuditedProblem(AdversarialProblem):
    def __init__(self, *args, audit_checker, audit_epsilon, **kwargs):
        super().__init__(*args, **kwargs)
        self.audit_checker = audit_checker
        self.audit_epsilon = audit_epsilon
        self.repair_log = []
        self.evaluation_log = []
        self.unique_evaluated = set()

    def _evaluate(self, x, out, *args, **kwargs):
        population = np.repeat(self.x_clean.reshape(1, -1), len(x), axis=0)
        population[:, self.constraints.mutable_features] = x
        digest = hashlib.sha256(population.tobytes()).hexdigest()
        if len(self.repair_log) != len(self.evaluation_log) + 1:
            raise AssertionError("Repair must run once before each objective evaluation batch")
        if digest != self.repair_log[-1]["native_population_sha256"]:
            raise AssertionError("Scored candidates differ from the repaired population")
        parts, valid, distance, changed = population_checks(self, population)
        before = time.perf_counter()
        super()._evaluate(x, out, *args, **kwargs)
        seconds = time.perf_counter() - before
        for row in population:
            self.unique_evaluated.add(hashlib.sha256(row.tobytes()).hexdigest())
        self.evaluation_log.append({
            "batch_index": len(self.evaluation_log), "model_rows_evaluated": len(x),
            "valid_rows": int(valid.sum()), "in_budget_rows": int((distance <= self.audit_epsilon).sum()),
            "changed_valid_in_budget_rows": int((changed & valid & (distance <= self.audit_epsilon)).sum()),
            "unchanged_rows": int((~changed).sum()),
            "cumulative_unique_evaluated_vectors": len(self.unique_evaluated),
            "native_population_sha256": digest, "upstream_objective_seconds": seconds,
        })


class InLoopMoeva2(Moeva2):
    def __init__(self, *args, rollback, checker, epsilon, repair_relations, **kwargs):
        super().__init__(*args, **kwargs)
        if self.n_jobs != 1:
            raise ValueError("This audited comparison requires n_jobs=1")
        self.rollback = rollback
        self.checker = checker
        self.epsilon = epsilon
        self.repair_relations = repair_relations
        self.problem_class = self._make_problem
        self.problems = []

    def _make_problem(self, **kwargs):
        problem = AuditedProblem(audit_checker=self.checker, audit_epsilon=self.epsilon, **kwargs)
        self.problems.append(problem)
        return problem

    def _create_algorithm(self):
        algorithm = super()._create_algorithm()
        repair = PopulationRollback(self.rollback, self.repair_relations)
        # pymoo 0.5.0 stores these three references when constructing the
        # genetic algorithm. Set all of them; leave every other operator intact.
        algorithm.repair = repair
        algorithm.initialization.repair = repair
        algorithm.mating.repair = repair
        return algorithm

    def _one_generate(self, x, y, classifier):
        index = len(self.problems) + 1
        started = time.perf_counter()
        result = super()._one_generate(x, y, classifier)
        if index == 1 or index % 4 == 0:
            print("  MOEVA completed input {} ({} generations; {:.1f}s)".format(
                index, self.n_gen, time.perf_counter() - started), flush=True)
        return result

    def audit(self, csv_rows, final_population_size):
        if len(csv_rows) != len(self.problems):
            raise AssertionError("MOEVA input-to-audit alignment changed")
        expected = final_population_size + (self.n_gen - 1) * self.n_offsprings
        records = []
        for row, problem in zip(csv_rows, self.problems):
            actual = sum(b["model_rows_evaluated"] for b in problem.evaluation_log)
            if actual != expected or len(problem.evaluation_log) != self.n_gen:
                raise AssertionError("Evolutionary objective evaluation budget changed")
            if self.repair_relations and any(b["valid_rows"] != b["model_rows_evaluated"] for b in problem.evaluation_log):
                raise AssertionError("Relationship repair scored an invalid population")
            records.append({"csv_row_zero_based": int(row), "objective_model_rows": actual,
                            "expected_objective_model_rows": expected,
                            "unique_evaluated_vectors": len(problem.unique_evaluated),
                            "repair_batches": problem.repair_log, "evaluation_batches": problem.evaluation_log})
        return {"records": records, "total_objective_model_rows": sum(r["objective_model_rows"] for r in records),
                "expected_per_record": expected, "all_evaluation_budgets_match": True,
                "relation_repair_enabled": self.repair_relations}
