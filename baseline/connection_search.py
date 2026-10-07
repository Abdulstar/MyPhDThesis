"""Enforce the fixed added profile before every MOEVA fitness evaluation."""
import numpy as np

from inloop_repair import AuditedProblem, InLoopMoeva2, PopulationRollback


class ConnectionPopulationRollback(PopulationRollback):
    def _do(self, problem, pop, **kwargs):
        result = super()._do(problem, pop, **kwargs)
        original = problem.x_clean.reshape(1, -1)
        x = np.repeat(original, len(pop), axis=0)
        x[:, problem.constraints.mutable_features] = result.get("X")
        if not problem.profile.ok(x).all():
            raise AssertionError("Repaired genotype violates the added profile")
        details = self.rollback.last_profile_audit
        problem.repair_log[-1].update(
            profile_blocks_restored=int(details["profile_blocks_restored"].sum()),
            aggregate_failures_before_profile=int(details["aggregate_failures_before_profile"].sum()),
            presence_failures_before_profile=int(details["presence_failures_before_profile"].sum()),
            added_profile_valid_rows=len(pop))
        return result


class ConnectionProblem(AuditedProblem):
    def __init__(self, *args, profile, **kwargs):
        super().__init__(*args, **kwargs)
        self.profile = profile

    def _evaluate(self, x, out, *args, **kwargs):
        population = np.repeat(self.x_clean.reshape(1, -1), len(x), axis=0)
        population[:, self.constraints.mutable_features] = x
        if not self.profile.ok(population).all():
            raise AssertionError("Attempt to score a MOEVA population violating the added profile")
        super()._evaluate(x, out, *args, **kwargs)
        self.evaluation_log[-1]["added_profile_valid_rows"] = len(x)


class ConnectionMoeva2(InLoopMoeva2):
    def __init__(self, *args, profile, **kwargs):
        self.profile = profile
        super().__init__(*args, **kwargs)

    def _make_problem(self, **kwargs):
        p = ConnectionProblem(audit_checker=self.checker, audit_epsilon=self.epsilon,
                              profile=self.profile, **kwargs)
        self.problems.append(p)
        return p

    def _create_algorithm(self):
        algorithm = super()._create_algorithm()
        repair = ConnectionPopulationRollback(self.rollback, self.repair_relations)
        algorithm.repair = repair
        algorithm.initialization.repair = repair
        algorithm.mating.repair = repair
        return algorithm

    def audit(self, csv_rows, final_population_size):
        report = super().audit(csv_rows, final_population_size)
        for record in report["records"]:
            for batch in record["evaluation_batches"]:
                if batch["added_profile_valid_rows"] != batch["model_rows_evaluated"]:
                    raise AssertionError("A scored generation violated the fixed profile")
        report["all_fitness_rows_pass_added_profile"] = True
        return report
