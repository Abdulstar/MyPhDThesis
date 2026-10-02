"""Independent checks of saved experiment evidence; does not rerun attacks."""
import os
for key in ["OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"]:
    os.environ[key] = "2"
import hashlib
import json
from pathlib import Path
import sys
import time
import numpy as np
import pandas as pd
import torch

root = Path(sys.argv[1]).resolve()
run = Path(sys.argv[2]).resolve()
out = Path(sys.argv[3]).resolve()
if out.exists():
    raise SystemExit("Preserving earlier reviews: choose a NEW output filename")
sys.path.insert(0, str(root / "vendor/tabularbench"))
from tabularbench.models.tab_scaler import TabScaler, ScalerData
from tabularbench.models.tabsurvey.mlp_rln import TORCHRLN
from tabularbench.datasets.dataset import CsvDataSource
from tabularbench.datasets.samples.ctu_13_neris import get_relation_constraints
from tabularbench.constraints.constraints import get_constraints_from_metadata
from tabularbench.constraints.constraints_checker import ConstraintChecker

started = time.perf_counter()
torch.set_num_threads(2)
names = json.loads((run / "feature_names.json").read_text())
metadata = pd.read_csv(root / "assets/ctu_13_neris_metadata.csv")
metadata = metadata[metadata.feature.isin(names)].reset_index(drop=True)
assert metadata.feature.tolist() == names
constraints = get_constraints_from_metadata(metadata, get_relation_constraints(
    CsvDataSource(str(root / "assets/ctu_13_neris_metadata.csv"))), names)
checker = ConstraintChecker(constraints, 0.0)
scaler = TabScaler(num_scaler="min_max", one_hot_encode=True)
scaler.fit_scaler_data(ScalerData.load(str(run / "compatibility_scaler.json")))
protocol = json.loads((run / "protocol.json").read_text())
results = json.loads((run / "results.json").read_text())
assert protocol["status"] == results["status"] == "completed"
epsilon = protocol["settings"]["eps"]
selected = np.load(run / "selected_development_inputs.npz")
rows, clean = selected["csv_rows"], selected["x_clean"]
lookup = {int(row): i for i, row in enumerate(rows)}
assert len(rows) == 32 and np.all(selected["labels"] == 1)
assert np.isin(rows, np.load(run / "development_indices.npy")).all()
assert (rows < 143046).all()
summary = pd.read_csv(run / "comparison.csv")
assert len(summary) == 18
counts = {"raw_stage_files": 0, "repaired_stage_files": 0, "raw_candidates": 0,
          "repaired_candidates": 0, "final_vectors_rescored": 0, "changed_feasible_unique_vectors_rescored": 0}
checks = []
score_comparison = {"compared_candidate_entries": 0, "nonidentical_probability_entries": 0, "max_absolute_difference": 0.0, "class_predictions_required_exact": True, "constraint_and_budget_decisions_required_exact": True}


def load(path):
    with np.load(path, allow_pickle=False) as npz:
        return {key: npz[key] for key in npz.files}

def inspect(data):
    x, original = data["x_candidates"], data["x_clean"]
    np.testing.assert_array_equal(original, clean[[lookup[int(r)] for r in data["csv_rows"]]])
    assert x.dtype == original.dtype == np.float32 and np.isfinite(x).all()
    for i, population in enumerate(x):
        c = original[i:i+1]
        components = {
            "relation_ok": checker._check_relationship_constraints(population),
            "bounds_ok": checker._check_boundary_constraints(c, population),
            "types_ok": checker._check_type_constraints(population),
            "immutable_ok": checker._check_mutable_constraints(c, population),
        }
        for key, value in components.items():
            np.testing.assert_array_equal(data[key][i], value)
        np.testing.assert_array_equal(data["valid"][i], np.logical_and.reduce(list(components.values())))
        distance = np.linalg.norm(scaler.transform(population) - scaler.transform(c), axis=1)
        np.testing.assert_allclose(data["distance"][i], distance, rtol=1e-6, atol=1e-8)
        np.testing.assert_array_equal(data["within_budget"][i], distance <= epsilon)
    np.testing.assert_array_equal(data["changed"], np.any(x != original[:, None], axis=-1))
    feasible = data["changed"] & data["valid"] & data["within_budget"]
    hashes = {int(row): set() for row in rows}
    for i, row in enumerate(data["csv_rows"]):
        for candidate in x[i, feasible[i]]:
            hashes[int(row)].add(hashlib.sha256(candidate.tobytes()).hexdigest())
    return hashes, feasible

for model_name in ["default", "madry"]:
    model = TORCHRLN.load_class(str(root / "assets" / ("torchrln_ctu_13_neris_" + model_name + ".model")),
                               x_metadata=metadata, scaler=scaler, force_device="cpu")
    clean_prediction = model.predict_proba(clean).argmax(1)
    for seed in [0, 1, 2]:
        directory = run / model_name / ("seed_" + str(seed))
        report = json.loads((directory / "results.json").read_text())
        original_final = load(directory / "original_final.npz")
        np.testing.assert_array_equal(original_final["csv_rows"], rows)
        np.testing.assert_array_equal(original_final["clean_predictions"], clean_prediction)
        original_success = (clean_prediction == 1) & (original_final["predictions"] == 0)
        all_hashes = {}
        for method in ["original", "budget_only", "relation_and_budget"]:
            method_hashes = {int(row): set() for row in rows}
            totals = dict(candidates=0, changed_candidates=0, unchanged_candidates=0, invalid_candidates=0,
                          over_budget_candidates=0, changed_valid_in_budget=0, successful_candidates=0)
            stages = report["methods"][method]["stages"]
            for index, path in enumerate(sorted((directory / "raw_pool").glob("*_candidates.npz"))):
                source = load(path)
                assert hashlib.sha256(path.read_bytes()).hexdigest() == stages[index]["source_npz_sha256"]
                stage = path.stem.split("_", 1)[1].rsplit("_candidates", 1)[0]
                if method == "original":
                    data = source
                    counts["raw_stage_files"] += 1
                    counts["raw_candidates"] += data["valid"].size
                else:
                    data = load(directory / method / stage / "repaired_candidates.npz")
                    np.testing.assert_array_equal(data["csv_rows"], source["csv_rows"])
                    assert np.all((data["x_candidates"] == source["x_candidates"]) |
                                  (data["x_candidates"] == source["x_clean"][:, None]))
                    np.testing.assert_array_equal(data["repair_changed_vs_raw"],
                                                  np.any(data["x_candidates"] != source["x_candidates"], axis=-1))
                    assert data["within_budget"].all() and data["bounds_ok"].all()
                    assert data["immutable_ok"].all() and data["types_ok"].all()
                    counts["repaired_stage_files"] += 1
                    counts["repaired_candidates"] += data["valid"].size
                hashes, feasible = inspect(data)
                for row in rows:
                    method_hashes[int(row)].update(hashes[int(row)])
                if method != "original":
                    np.testing.assert_array_equal(data["prediction_query_mask"], feasible)
                    np.testing.assert_array_equal(data["repair_changed_vs_clean"], data["changed"])
                    if feasible.any():
                        unique, inverse = np.unique(data["x_candidates"][feasible], axis=0, return_inverse=True)
                        probabilities = model.predict_proba(unique)
                        np.testing.assert_array_equal(data["predicted_class"][feasible], probabilities.argmax(1)[inverse])
                        saved_scores = data["score_malicious"][feasible]
                        rescored = probabilities[:, 1][inverse]
                        assert np.isfinite(saved_scores).all() and np.isfinite(rescored).all()
                        differences = np.abs(saved_scores - rescored)
                        score_comparison["compared_candidate_entries"] += len(differences)
                        score_comparison["nonidentical_probability_entries"] += int(np.count_nonzero(differences))
                        score_comparison["max_absolute_difference"] = max(score_comparison["max_absolute_difference"], float(differences.max()))
                        counts["changed_feasible_unique_vectors_rescored"] += len(unique)
                    for i, row in enumerate(data["csv_rows"]):
                        unchanged = ~data["changed"][i]
                        assert np.all(data["predicted_class"][i, unchanged] == clean_prediction[lookup[int(row)]])
                    np.testing.assert_array_equal(data["fooled"], data["predicted_class"] == 0)
                totals["candidates"] += data["valid"].size
                totals["changed_candidates"] += int(data["changed"].sum())
                totals["unchanged_candidates"] += int((~data["changed"]).sum())
                totals["invalid_candidates"] += int((~data["valid"]).sum())
                totals["over_budget_candidates"] += int((~data["within_budget"]).sum())
                totals["changed_valid_in_budget"] += int(feasible.sum())
                totals["successful_candidates"] += int((data["valid"] & data["within_budget"] & data["fooled"]).sum())
            all_hashes[method] = method_hashes
            unions = {int(row): all_hashes["original"][int(row)] | method_hashes[int(row)] for row in rows}
            records = pd.read_csv(directory / method / "records.csv")
            np.testing.assert_array_equal(records.csv_row_zero_based, rows)
            np.testing.assert_array_equal(records.covered_by_method_pool, [bool(method_hashes[int(r)]) for r in rows])
            np.testing.assert_array_equal(records.covered_by_union, [bool(unions[int(r)]) for r in rows])
            np.testing.assert_array_equal(records.unique_changed_feasible_candidates_union, [len(unions[int(r)]) for r in rows])
            entry = summary[(summary.model == model_name) & (summary.seed == seed) & (summary.method == method)].iloc[0]
            for key, value in totals.items():
                assert entry["pool_" + key] == value, (model_name, seed, method, key)
            assert entry.union_covered_records == records.covered_by_union.sum()
            assert entry.unique_changed_feasible_candidates_union == records.unique_changed_feasible_candidates_union.sum()
            if method == "original":
                final_x, final_prediction = original_final["x_effective"], original_final["predictions"]
            else:
                final_data = load(directory / method / "final_union.npz")
                final_x, final_prediction = final_data["x_adv"], final_data["predictions"]
                np.testing.assert_array_equal(final_data["csv_rows"], rows)
            assert checker.check_constraints(clean, final_x).all()
            distance = np.linalg.norm(scaler.transform(final_x) - scaler.transform(clean), axis=1)
            assert (distance <= epsilon).all()
            np.testing.assert_array_equal(final_prediction, model.predict_proba(final_x).argmax(1))
            counts["final_vectors_rescored"] += len(final_x)
            evaded = (clean_prediction == 1) & (final_prediction == 0)
            assert np.all(evaded[original_success])
            np.testing.assert_array_equal(records.final_prediction, final_prediction)
            np.testing.assert_array_equal(records.newly_evaded, evaded)
            assert entry.newly_evaded == evaded.sum()
            assert entry.clean_detected == (clean_prediction == 1).sum()
            assert entry.already_missed_before_attack == (clean_prediction == 0).sum()
            assert entry.added_wall_seconds >= 0 and entry.added_prediction_forward_rows >= 0
            assert entry.baseline_attack_seconds_with_trace > 0 and entry.baseline_attack_forward_rows > 0
            checks.append(dict(model=model_name, seed=seed, method=method,
                               covered=int(entry.union_covered_records), newly_evaded=int(entry.newly_evaded)))
        print("Verified", model_name, seed, flush=True)
out.write_text(json.dumps({"status":"passed", "scope":"Colab arrays checked with pinned local engine; exact masks and class decisions; probability differences recorded without requiring bitwise equality; no new attacks",
                           "counts":counts,"probability_rescoring_comparison":score_comparison,"checks":checks,"wall_seconds":time.perf_counter()-started}, indent=2) + "\n")
print("SAVED EVIDENCE VERIFICATION PASSED", json.dumps(counts), flush=True)
