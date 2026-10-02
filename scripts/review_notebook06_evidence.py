"""Recheck saved notebook-06 results with the pinned native model/checker.

Usage: .baseline-env/bin/python scripts/review_notebook06_evidence.py
       PROJECT_ROOT BASELINE_RUN INLOOP_RUN NEW_REVIEW_JSON
No attacks are generated. Intermediate population digests/counters are checked
for consistency; only exported final-stage vectors can be independently rescored.
"""
import os
for key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
    os.environ[key] = "2"
import hashlib
import json
from pathlib import Path
import sys
import time

import numpy as np
import pandas as pd
import torch


def load(path):
    with np.load(path, allow_pickle=False) as f:
        return {k: f[k] for k in f.files}


def main():
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    root, baseline, run, output = [Path(p).resolve() for p in sys.argv[1:]]
    if output.exists():
        raise SystemExit("Preserving earlier reviews: choose a NEW output filename")
    sys.path.insert(0, str(root / "vendor/tabularbench"))
    from tabularbench.models.tab_scaler import TabScaler, ScalerData
    from tabularbench.models.tabsurvey.mlp_rln import TORCHRLN
    from tabularbench.datasets.dataset import CsvDataSource
    from tabularbench.datasets.samples.ctu_13_neris import get_relation_constraints
    from tabularbench.constraints.constraints import get_constraints_from_metadata
    from tabularbench.constraints.constraints_checker import ConstraintChecker
    torch.set_num_threads(2)
    started = time.perf_counter()
    protocol = json.loads((run / "protocol.json").read_text())
    result = json.loads((run / "results.json").read_text())
    assert protocol["status"] == result["status"] == "completed"
    for field, filename in [("baseline_protocol_sha256", "protocol.json"),
                            ("baseline_selected_inputs_sha256", "selected_development_inputs.npz"),
                            ("baseline_results_sha256", "results.json")]:
        assert protocol[field] == hashlib.sha256((baseline / filename).read_bytes()).hexdigest()
    settings, epsilon = protocol["settings"], protocol["settings"]["eps"]
    selected = load(baseline / "selected_development_inputs.npz")
    clean, rows = selected["x_clean"], selected["csv_rows"]
    assert len(rows) == settings["n_dev"] and np.all(selected["labels"] == 1)
    assert (rows < 143046).all() and np.isin(rows, np.load(baseline / "development_indices.npy")).all()
    positions = {int(row): i for i, row in enumerate(rows)}
    names = json.loads((baseline / "feature_names.json").read_text())
    metadata = pd.read_csv(root / "assets/ctu_13_neris_metadata.csv")
    metadata = metadata[metadata.feature.isin(names)].reset_index(drop=True)
    assert metadata.feature.tolist() == names
    constraints = get_constraints_from_metadata(metadata, get_relation_constraints(
        CsvDataSource(str(root / "assets/ctu_13_neris_metadata.csv"))), names)
    checker = ConstraintChecker(constraints, 0.0)
    scaler = TabScaler(num_scaler="min_max", one_hot_encode=True)
    scaler.fit_scaler_data(ScalerData.load(str(baseline / "compatibility_scaler.json")))
    comparison = pd.read_csv(run / "comparison.csv")
    assert len(comparison) == len(settings["models"]) * len(settings["seeds"]) * 5
    assert len(result["runs"]) == len(settings["models"]) * len(settings["seeds"]) * 2
    counts = {"stage_files": 0, "stage_candidate_entries": 0, "final_vectors_rescored": 0,
              "generation_batches_checked": 0, "logged_objective_model_rows": 0}
    summaries = []
    for model_name in settings["models"]:
        model = TORCHRLN.load_class(str(root / "assets" / ("torchrln_ctu_13_neris_" + model_name + ".model")),
                                   x_metadata=metadata, scaler=scaler, force_device="cpu")
        clean_pred = model.predict_proba(clean).argmax(1)
        for seed in settings["seeds"]:
            prefix = Path(model_name) / ("seed_" + str(seed))
            original = load(baseline / prefix / "original_final.npz")
            original_report = json.loads((baseline / prefix / "results.json").read_text())
            original_success = (clean_pred == 1) & (original["predictions"] == 0)
            for method in ["caa_budget_inloop", "caa_relation_inloop"]:
                folder = run / prefix / method
                report = json.loads((folder / "results.json").read_text())
                assert report["generation_forward_counts"] == original_report["attack_forward_counts"]
                assert report["original_generation_forward_counts"] == original_report["attack_forward_counts"]
                unique = [set() for _ in rows]
                audit = json.loads((folder / "generation_audit.json").read_text())
                expected_inputs = []
                invalid_count = 0
                for file in sorted((folder / "raw_pool").glob("*_candidates.npz")):
                    data = load(file)
                    x = data["x_candidates"]
                    np.testing.assert_array_equal(data["x_clean"], clean[[positions[int(r)] for r in data["csv_rows"]]])
                    assert np.isfinite(x).all() and x.dtype == np.float32
                    changed = np.any(x != data["x_clean"][:, None], axis=-1)
                    np.testing.assert_array_equal(data["changed"], changed)
                    if "Moeva2" not in file.name:
                        source = load(baseline / prefix / "raw_pool" / file.name)
                        for key in ["x_clean", "x_candidates", "csv_rows", "labels", "valid", "within_budget", "fooled"]:
                            np.testing.assert_array_equal(data[key], source[key])
                    else:
                        expected_inputs = data["csv_rows"].tolist()
                        expected_evals = x.shape[1] + (settings["generations"] - 1) * settings["offspring"]
                        assert audit["expected_per_record"] == expected_evals
                    for i, population in enumerate(x):
                        original_input = data["x_clean"][i:i+1]
                        parts = {
                            "relation_ok": checker._check_relationship_constraints(population),
                            "bounds_ok": checker._check_boundary_constraints(original_input, population),
                            "types_ok": checker._check_type_constraints(population),
                            "immutable_ok": checker._check_mutable_constraints(original_input, population),
                        }
                        for key, value in parts.items():
                            np.testing.assert_array_equal(data[key][i], value)
                        valid = np.logical_and.reduce(list(parts.values()))
                        np.testing.assert_array_equal(data["valid"][i], valid)
                        distance = np.linalg.norm(scaler.transform(population) - scaler.transform(original_input), axis=1)
                        np.testing.assert_allclose(data["distance"][i], distance, rtol=1e-6, atol=1e-8)
                        np.testing.assert_array_equal(data["within_budget"][i], distance <= epsilon)
                        feasible = valid & (distance <= epsilon) & changed[i]
                        for candidate in population[feasible]:
                            unique[positions[int(data["csv_rows"][i])]].add(hashlib.sha256(candidate.tobytes()).hexdigest())
                    predicted = model.predict_proba(x.reshape(-1, x.shape[-1])).argmax(1).reshape(x.shape[:2])
                    np.testing.assert_array_equal(data["fooled"], predicted == 0)
                    invalid_count += int((~data["valid"]).sum())
                    counts["stage_files"] += 1
                    counts["stage_candidate_entries"] += data["valid"].size
                assert [r["csv_row_zero_based"] for r in audit["records"]] == expected_inputs
                for record in audit["records"]:
                    repairs, evaluations = record["repair_batches"], record["evaluation_batches"]
                    assert len(repairs) == len(evaluations) == settings["generations"]
                    assert sum(e["model_rows_evaluated"] for e in evaluations) == record["objective_model_rows"] == record["expected_objective_model_rows"] == audit["expected_per_record"]
                    assert evaluations[-1]["cumulative_unique_evaluated_vectors"] == record["unique_evaluated_vectors"]
                    for repair, evaluation in zip(repairs, evaluations):
                        assert repair["batch_index"] == evaluation["batch_index"]
                        assert repair["native_population_sha256"] == evaluation["native_population_sha256"]
                        assert repair["candidates"] == evaluation["model_rows_evaluated"] == evaluation["in_budget_rows"]
                        assert repair["changed_valid_in_budget"] == evaluation["changed_valid_in_budget_rows"]
                        if method == "caa_relation_inloop":
                            assert repair["relationship_invalid_after"] == 0
                            assert evaluation["valid_rows"] == evaluation["model_rows_evaluated"]
                    counts["generation_batches_checked"] += len(evaluations)
                    counts["logged_objective_model_rows"] += record["objective_model_rows"]
                assert audit["total_objective_model_rows"] == sum(r["objective_model_rows"] for r in audit["records"])
                final = load(folder / "final_results.npz")
                np.testing.assert_array_equal(final["csv_rows"], rows)
                np.testing.assert_array_equal(final["x_clean"], clean)
                np.testing.assert_array_equal(final["clean_predictions"], clean_pred)
                returned_valid = checker.check_constraints(clean, final["x_returned"]).astype(bool)
                returned_distance = np.linalg.norm(scaler.transform(final["x_returned"]) - scaler.transform(clean), axis=1)
                np.testing.assert_array_equal(returned_valid, final["returned_valid"])
                accepted = returned_valid & (returned_distance <= epsilon)
                np.testing.assert_array_equal(final["x_effective"], np.where(accepted[:, None], final["x_returned"], clean))
                for vector_key, prediction_key, distance_key in [("x_effective", "predictions", "effective_distance"),
                                                                  ("x_union", "union_predictions", "union_distance")]:
                    x = final[vector_key]
                    assert checker.check_constraints(clean, x).all()
                    distance = np.linalg.norm(scaler.transform(x) - scaler.transform(clean), axis=1)
                    assert np.all(distance <= epsilon)
                    np.testing.assert_allclose(final[distance_key], distance, rtol=1e-6, atol=1e-8)
                    np.testing.assert_array_equal(final[prediction_key], model.predict_proba(x).argmax(1))
                    counts["final_vectors_rescored"] += len(x)
                evaded = (clean_pred == 1) & (final["predictions"] == 0)
                union_evaded = (clean_pred == 1) & (final["union_predictions"] == 0)
                assert union_evaded[original_success].all()
                records = pd.read_csv(folder / "records.csv")
                np.testing.assert_array_equal(records.csv_row_zero_based, rows)
                np.testing.assert_array_equal(records.covered_by_method_pool, [bool(s) for s in unique])
                np.testing.assert_array_equal(records.unique_feasible_changes, [len(s) for s in unique])
                np.testing.assert_array_equal(records.newly_evaded, evaded)
                np.testing.assert_array_equal(records.union_newly_evaded, union_evaded)
                selected_row = comparison[(comparison.model == model_name) & (comparison.seed == seed) & (comparison.method == method)]
                assert len(selected_row) == 1
                row = selected_row.iloc[0]
                assert row.covered_records == sum(bool(s) for s in unique)
                assert row.newly_evaded == evaded.sum() and row.union_newly_evaded == union_evaded.sum()
                assert row.pool_invalid_candidates == invalid_count
                assert row.clean_detected == (clean_pred == 1).sum()
                assert row.generation_forward_rows == original_report["attack_forward_counts"]["forward_rows"]
                summaries.append({"model": model_name, "seed": seed, "method": method,
                                  "covered_records": int(row.covered_records), "newly_evaded": int(row.newly_evaded),
                                  "union_newly_evaded": int(row.union_newly_evaded)})
                print("Verified", model_name, seed, method, flush=True)
    output.write_text(json.dumps({"status": "passed", "counts": counts, "runs": summaries,
        "scope": "Exported final-stage vectors independently checked/rescored; intermediate logs and digests checked for consistency, not independent reconstruction of every intermediate vector",
        "wall_seconds": time.perf_counter() - started}, indent=2) + "\n")
    print("NOTEBOOK 06 SAVED EVIDENCE CHECK PASSED", flush=True)


if __name__ == "__main__":
    main()
