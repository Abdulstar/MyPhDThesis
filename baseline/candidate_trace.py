"""Observe stage outputs at CAA's final selector without changing selection.

The pinned selector has already evaluated these candidates when record() runs.
Its cached objective values are reused. No candidate generation, extra model
prediction, tolerance changes or RNG draws are performed by this observer.
"""
import csv
import itertools
import json
from pathlib import Path
import time

import numpy as np


def failure_buckets(valid, in_budget, fooled):
    """Eight disjoint combinations; unlike marginal failures these sum to N."""
    return [
        {"valid": v, "in_budget": d, "fooled": m,
         "candidates": int(((valid == v) & (in_budget == d) & (fooled == m)).sum())}
        for v, d, m in itertools.product([False, True], repeat=3)
    ]


class CandidateTrace:
    def __init__(self, output_dir, csv_rows, stage_names, checker, thresholds):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=False)
        self.csv_rows = np.asarray(csv_rows, dtype=np.int64)
        self.remaining = np.arange(len(self.csv_rows))
        self.stage_names = stage_names
        self.checker = checker
        self.thresholds = dict(thresholds)
        self.stages = []
        self.originals = None

    def record(self, x_clean, y_clean, x_adv, measured, respected, selected):
        started = time.perf_counter()
        x_clean, x_adv = np.asarray(x_clean), np.asarray(x_adv)
        labels = np.asarray(y_clean)
        n, k, features = x_adv.shape
        if n != len(self.remaining) or x_clean.shape != (n, features):
            raise AssertionError("CAA candidate/input alignment changed.")
        if not np.all(labels == 1):
            raise AssertionError("This binary IDS diagnostic expects malicious label 1.")
        if self.originals is None:
            self.originals = x_clean.copy()
        np.testing.assert_array_equal(x_clean, self.originals[self.remaining])
        rows = self.csv_rows[self.remaining]
        changed = np.any(x_adv != x_clean[:, None, :], axis=-1)
        valid = np.asarray(respected.constraints, dtype=bool)
        in_budget = np.asarray(respected.distance, dtype=bool)
        fooled = np.asarray(respected.misclassification, dtype=bool)
        accepted = valid & in_budget & fooled
        np.testing.assert_array_equal(accepted, respected.mdc)

        # Decompose the same pinned checker, at the same tolerance. Each row's
        # original is broadcast against its own candidate population only.
        parts = {name: [] for name in ["relation_ok", "bounds_ok", "types_ok", "immutable_ok"]}
        for i in range(n):
            original, candidates = x_clean[i:i + 1], x_adv[i]
            parts["relation_ok"].append(self.checker._check_relationship_constraints(candidates))
            parts["bounds_ok"].append(self.checker._check_boundary_constraints(original, candidates))
            parts["types_ok"].append(self.checker._check_type_constraints(candidates))
            parts["immutable_ok"].append(self.checker._check_mutable_constraints(original, candidates))
        parts = {name: np.asarray(values, dtype=bool) for name, values in parts.items()}
        np.testing.assert_array_equal(np.logical_and.reduce(list(parts.values())), valid)
        if any(np.asarray(v).shape != (n, k) for v in [valid, in_budget, fooled, measured.distance]):
            raise AssertionError("Unexpected cached objective dimensions.")

        stage_index = len(self.stages)
        stage = self.stage_names[stage_index]
        prefix = "{:02d}_{}".format(stage_index, stage)
        np.savez_compressed(
            self.output_dir / (prefix + "_candidates.npz"),
            x_clean=x_clean, x_candidates=x_adv, labels=labels, csv_rows=rows,
            changed=changed, distance=np.asarray(measured.distance),
            correct_minus_wrong_score=np.asarray(measured.misclassification),
            valid=valid, within_budget=in_budget, fooled=fooled,
            selected_input_indices=np.asarray(selected[0]),
            selected_candidate_indices=np.asarray(selected[1]), **parts
        )
        with (self.output_dir / (prefix + "_candidates.csv")).open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["csv_row_zero_based", "candidate_index", "changed", "valid",
                             "within_budget", "fooled", "successful", "distance_l2_scaled",
                             "correct_minus_wrong_score"] + list(parts))
            for i in range(n):
                for j in range(k):
                    writer.writerow([int(rows[i]), j, bool(changed[i, j]), bool(valid[i, j]),
                                     bool(in_budget[i, j]), bool(fooled[i, j]), bool(accepted[i, j]),
                                     float(measured.distance[i, j]), float(measured.misclassification[i, j])]
                                    + [bool(p[i, j]) for p in parts.values()])

        changed_feasible = changed & valid & in_budget
        summary = {
            "stage": stage, "inputs": n, "candidates_per_input": k, "candidates": n * k,
            "changed_candidates": int(changed.sum()),
            "changed_valid_in_budget": int(changed_feasible.sum()),
            "fooled_candidates": int(fooled.sum()),
            "successful_candidates": int(accepted.sum()),
            "rows_with_changed_candidate": int(changed.any(axis=1).sum()),
            "rows_with_changed_valid_in_budget_candidate": int(changed_feasible.any(axis=1).sum()),
            "rows_with_successful_candidate": int(accepted.any(axis=1).sum()),
            "selected_rows_by_CAA": int(len(selected[0])),
            "invalid_candidates": int((~valid).sum()),
            "over_budget_candidates": int((~in_budget).sum()),
            "still_detected_candidates": int((~fooled).sum()),
            "constraint_failures_overlapping": {name: int((~p).sum()) for name, p in parts.items()},
            "disjoint_objective_buckets": failure_buckets(valid, in_budget, fooled),
            "minimum_scaled_l2_distance": float(np.min(measured.distance)),
            "maximum_scaled_l2_distance": float(np.max(measured.distance)),
            "diagnostic_wall_seconds": time.perf_counter() - started,
        }
        self.stages.append(summary)
        # Mirror only the selected-row bookkeeping; leave original arrays,
        # objective caches and the selector's returned indices untouched.
        keep = np.ones(n, dtype=bool)
        keep[np.asarray(selected[0], dtype=np.int64)] = False
        self.remaining = self.remaining[keep]
        (self.output_dir / "stage_summary.json").write_text(json.dumps({
            "scope": "Subattack outputs before CAA selection, not all optimizer iterations.",
            "thresholds": self.thresholds,
            "failure_counts_overlap": True,
            "disjoint_buckets_sum_to_candidate_count": True,
            "timings_include_diagnostic_overhead": True,
            "remaining_original_csv_rows": self.csv_rows[self.remaining].tolist(),
            "stages": self.stages,
        }, indent=2) + "\n")
        print("TRACE {}: {} changed, {} changed/valid/in-budget, {} successful candidates across {} inputs".format(
            stage, summary["changed_candidates"], summary["changed_valid_in_budget"],
            summary["successful_candidates"], n), flush=True)


def observe_selector(calculator, trace):
    original = calculator.get_successful_attacks_indexes

    def observed(x_clean, y_clean, x_adv, *args, **kwargs):
        selected = original(x_clean, y_clean, x_adv, *args, **kwargs)
        trace.record(x_clean, y_clean, x_adv, calculator.objectives_eval,
                     calculator.objectives_respected, selected)
        return selected

    calculator.get_successful_attacks_indexes = observed

