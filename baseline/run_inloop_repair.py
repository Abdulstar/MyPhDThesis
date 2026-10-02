"""Compare end-only and in-search repair using a fresh notebook-05 baseline.

Run the baseline in this same environment first. Exact pre-MOEVA candidate
matching and equal attack forward counts are required, not assumed.
"""
import os
for _key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "LOKY_MAX_CPU_COUNT"):
    os.environ[_key] = "2"

import argparse
import gc
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import torch

from candidate_trace import CandidateTrace, observe_selector
from consistency_repair import BlockRollbackRepair
from download_assets import CODE_REVISION, DATA_REVISION, MODEL_REVISION, sha256
from metrics import attack_metrics
from relationship_audit import write_csv, write_json
from run_development_repair import ForwardCounter, final_gate, postprocess


def arrays(path):
    with np.load(path, allow_pickle=False) as f:
        return {k: f[k] for k in f.files}


def aggregates(comparison):
    rows = []
    for model, method in sorted({(r["model"], r["method"]) for r in comparison}):
        group = [r for r in comparison if (r["model"], r["method"]) == (model, method)]
        row = {"model": model, "method": method, "seeds": len(group)}
        for key in ["covered_records", "newly_evaded", "union_newly_evaded", "generation_wall_seconds"]:
            values = [r[key] for r in group]
            row[key + "_mean"] = statistics.mean(values)
            row[key + "_sample_std"] = statistics.stdev(values) if len(values) > 1 else None
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path("vendor/tabularbench"))
    parser.add_argument("--assets", type=Path, default=Path("assets"))
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Preserving earlier results: --out must be a NEW directory")
    if (platform.python_version(), np.__version__, torch.__version__) != ("3.8.20", "1.23.5", "1.12.1+cpu"):
        raise RuntimeError("Run with the pinned .baseline-env/bin/python")
    if subprocess.check_output(["git", "-C", str(args.repo), "rev-parse", "HEAD"], text=True).strip() != CODE_REVISION:
        raise RuntimeError("Wrong upstream revision")
    if subprocess.check_output(["git", "-C", str(args.repo), "diff", "HEAD", "--"], text=True):
        raise RuntimeError("Upstream tracked code changed")
    sys.path.insert(0, str(args.repo.resolve()))
    from inloop_repair import InLoopMoeva2
    from tabularbench.models.tab_scaler import TabScaler, ScalerData
    from tabularbench.models.tabsurvey.mlp_rln import TORCHRLN
    from tabularbench.datasets.dataset import CsvDataSource
    from tabularbench.datasets.samples.ctu_13_neris import get_relation_constraints
    from tabularbench.constraints.constraints import get_constraints_from_metadata
    from tabularbench.constraints.constraints_checker import ConstraintChecker
    from tabularbench.attacks.caa.caa import ConstrainedAutoAttack
    torch.set_num_threads(2)
    source = args.baseline_run
    parent_protocol = json.loads((source / "protocol.json").read_text())
    parent_results = json.loads((source / "results.json").read_text())
    if parent_protocol["status"] != "completed" or parent_results["status"] != "completed":
        raise RuntimeError("The fresh baseline must finish successfully first")
    for key, expected in [("code_revision", CODE_REVISION), ("data_revision", DATA_REVISION), ("model_revision", MODEL_REVISION)]:
        if parent_protocol[key] != expected:
            raise RuntimeError("Baseline pin mismatch: " + key)
    settings = parent_protocol["settings"]
    if parent_protocol["test_partition_evaluated"] or parent_protocol["relationship_tolerance"] != 0:
        raise RuntimeError("Use the preserved development protocol and original tolerance")
    pins = json.loads(Path(__file__).with_name("asset_hashes.json").read_text())
    for name, expected in pins.items():
        if sha256(args.assets / name) != expected:
            raise RuntimeError("Pinned asset mismatch: " + name)
    names = json.loads((source / "feature_names.json").read_text())
    metadata = pd.read_csv(args.assets / "ctu_13_neris_metadata.csv")
    metadata = metadata[metadata.feature.isin(names)].reset_index(drop=True)
    if metadata.feature.tolist() != names or len(names) != 757:
        raise ValueError("Unexpected CTU feature order")
    scaler = TabScaler(num_scaler="min_max", one_hot_encode=True)
    scaler.fit_scaler_data(ScalerData.load(str(source / "compatibility_scaler.json")))
    if scaler.cat_idx or scaler.num_idx != list(range(len(names))):
        raise ValueError("Use the pinned all-numeric feature geometry")
    constraints = get_constraints_from_metadata(metadata, get_relation_constraints(
        CsvDataSource(str(args.assets / "ctu_13_neris_metadata.csv"))), names)
    checker = ConstraintChecker(constraints, 0.0)
    selected = arrays(source / "selected_development_inputs.npz")
    clean, labels, rows = selected["x_clean"], selected["labels"], selected["csv_rows"]
    if clean.dtype != np.float32 or not np.all(labels == 1) or len(rows) != settings["n_dev"]:
        raise ValueError("Unexpected development inputs")
    if not (rows < 143046).all() or not np.isin(rows, np.load(source / "development_indices.npy")).all():
        raise ValueError("Selected inputs must be in the official development partition")
    if not checker.check_constraints(clean, clean).all():
        raise ValueError("Development originals fail the unchanged constraints")
    epsilon = settings["eps"]
    repair = BlockRollbackRepair(constraints, scaler.transform, epsilon)
    args.out.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    protocol = {
        "experiment": "repair_during_evolutionary_search", "status": "running",
        "baseline_protocol_sha256": sha256(source / "protocol.json"),
        "baseline_selected_inputs_sha256": sha256(source / "selected_development_inputs.npz"),
        "baseline_results_sha256": sha256(source / "results.json"),
        "baseline_run": str(source.resolve()), "settings": settings,
        "code_revision": CODE_REVISION, "data_revision": DATA_REVISION, "model_revision": MODEL_REVISION,
        "python": platform.python_version(), "numpy": np.__version__, "torch": torch.__version__,
        "device": "cpu", "relationship_tolerance": 0.0, "new_model_training": False,
        "test_partition_evaluated": False, "repair_inside_optimizer": True,
        "baseline_and_inloop_attack_forward_counts_required_equal": True,
        "pre_moeva_candidate_arrays_required_identical": True,
        "equal_wall_time_claim": False, "early_stop_on_new_evasion_inside_moeva": False,
        "limitations": [
            "Simple rollback inside existing evolutionary search, not a novelty or optimality claim.",
            "Repair may collapse many offspring to clean or duplicate vectors; all evaluations still count.",
            "The compatibility scaler uses all feature rows and inherits frozen checkpoint training history.",
            "Development records and repeated attack seeds are not independent final test observations.",
            "The baseline end-only methods reuse one attack run; in-loop methods generate new trajectories.",
            "Union-with-original results require both attacks and are not an equal-total-compute comparison.",
            "Valid aggregate features do not prove packet realizability or retained malicious functionality.",
        ],
    }
    write_json(args.out / "protocol.json", protocol)
    comparison, details = [], []
    label_map = {"original": "caa_original", "budget_only": "caa_budget_end", "relation_and_budget": "caa_relation_end"}
    for entry in parent_results["comparison"]:
        comparison.append({"model": entry["model"], "seed": entry["seed"], "method": label_map[entry["method"]],
            "n_selected": len(rows), "clean_detected": entry["clean_detected"],
            "already_missed": entry["already_missed_before_attack"],
            "covered_records": entry["union_covered_records"], "newly_evaded": entry["newly_evaded"],
            "new_evasion_rate": entry["new_evasion_rate_among_initially_detected"],
            "union_newly_evaded": entry["newly_evaded"],
            "pool_invalid_candidates": entry["pool_invalid_candidates"],
            "generation_wall_seconds": entry["baseline_attack_seconds_with_trace"],
            "generation_forward_rows": entry["baseline_attack_forward_rows"],
            "additional_postprocess_seconds": entry["added_wall_seconds"],
            "additional_postprocess_forward_rows": entry["added_prediction_forward_rows"],
            "separate_union_check_forward_rows": 0,
            "generation_forward_counts_match_original": True})
    for model_name in settings["models"]:
        model = TORCHRLN.load_class(str(args.assets / ("torchrln_ctu_13_neris_" + model_name + ".model")),
                                   x_metadata=metadata, scaler=scaler, force_device="cpu")
        counter = ForwardCounter(model.wrapper_model)
        clean_predictions = model.predict_proba(clean).argmax(1)
        for seed in settings["seeds"]:
            original_dir = source / model_name / ("seed_" + str(seed))
            original_report = json.loads((original_dir / "results.json").read_text())
            original = arrays(original_dir / "original_final.npz")
            np.testing.assert_array_equal(original["csv_rows"], rows)
            np.testing.assert_array_equal(original["x_clean"], clean)
            np.testing.assert_array_equal(original["clean_predictions"], clean_predictions)
            baseline = original["x_effective"]
            baseline_predictions = model.predict_proba(baseline).argmax(1)
            np.testing.assert_array_equal(baseline_predictions, original["predictions"])
            baseline_distance = np.linalg.norm(scaler.transform(baseline) - scaler.transform(clean), axis=1)
            if not checker.check_constraints(clean, baseline).all() or np.any(baseline_distance > epsilon):
                raise AssertionError("Original effective representatives are not feasible")
            for method, relations in [("caa_budget_inloop", False), ("caa_relation_inloop", True)]:
                out = args.out / model_name / ("seed_" + str(seed)) / method
                out.mkdir(parents=True, exist_ok=False)
                np.random.seed(seed); torch.manual_seed(seed)
                attack = ConstrainedAutoAttack(constraints=constraints, constraints_eval=constraints, scaler=scaler,
                    model=model.wrapper_model, model_objective=model.predict_proba, n_jobs=1,
                    fix_equality_constraints_end=True, fix_equality_constraints_iter=True,
                    norm="L2", eps=epsilon, seed=seed, steps=settings["steps"], n_gen=settings["generations"],
                    n_offsprings=settings["offspring"], verbose=False, n_classes=2)
                upstream = attack._autoattack.attacks[-1]
                evo = InLoopMoeva2(model.predict_proba, constraints=constraints, norm=upstream.norm,
                    fun_distance_preprocess=scaler.transform, n_gen=upstream.n_gen, n_pop=upstream.n_pop,
                    n_offsprings=upstream.n_offsprings, seed=upstream.seed, n_jobs=1,
                    rollback=repair, checker=checker, epsilon=epsilon, repair_relations=relations)
                attack._autoattack.attacks[-1] = evo
                trace = CandidateTrace(out / "raw_pool", rows, ["NoAttack", "CAPGD", "Moeva2"],
                    checker, attack.objective_calculator.thresholds)
                original_record = trace.record
                def checked_record(*a, **kw):
                    original_record(*a, **kw)
                    stage_index = len(trace.stages) - 1
                    if stage_index < 2:
                        name = "{:02d}_{}_candidates.npz".format(stage_index, trace.stage_names[stage_index])
                        expected, actual = arrays(original_dir / "raw_pool" / name), arrays(out / "raw_pool" / name)
                        for key in ["x_clean", "x_candidates", "csv_rows", "labels", "valid", "within_budget", "fooled"]:
                            np.testing.assert_array_equal(actual[key], expected[key],
                                err_msg="Fresh pre-MOEVA stage mismatch: " + key)
                trace.record = checked_record
                observe_selector(attack._autoattack.objective_calculator, trace)
                print("{} seed {}: {}".format(model_name, seed, method), flush=True)
                before = counter.snapshot(); start = time.perf_counter()
                returned = attack(clean, labels)
                wall = time.perf_counter() - start
                counts = counter.since(before)
                if counts != original_report["attack_forward_counts"]:
                    raise AssertionError("Core attack model-evaluation budget differs from the fresh original CAA")
                for path in sorted((original_dir / "raw_pool").glob("*_candidates.npz")):
                    if "Moeva2" in path.name:
                        continue
                    expected, actual = arrays(path), arrays(out / "raw_pool" / path.name)
                    for key in ["x_clean", "x_candidates", "csv_rows", "labels", "valid", "within_budget", "fooled"]:
                        np.testing.assert_array_equal(actual[key], expected[key], err_msg="Fresh pre-MOEVA stage mismatch: " + key)
                moeva_files = list((out / "raw_pool").glob("*_Moeva2_candidates.npz"))
                if moeva_files:
                    population = arrays(moeva_files[0])
                    reference = arrays(original_dir / "raw_pool" / moeva_files[0].name)
                    np.testing.assert_array_equal(population["csv_rows"], reference["csv_rows"])
                    if population["x_candidates"].shape != reference["x_candidates"].shape:
                        raise AssertionError("Population size or MOEVA input count changed")
                    audit = evo.audit(population["csv_rows"], population["x_candidates"].shape[1])
                else:
                    audit = evo.audit([], 0)
                write_json(out / "generation_audit.json", audit)
                before = counter.snapshot(); start = time.perf_counter()
                returned_valid = checker.check_constraints(clean, returned).astype(bool)
                returned_distance = np.linalg.norm(scaler.transform(returned) - scaler.transform(clean), axis=1)
                prediction = model.predict_proba(returned).argmax(1)
                accepted = returned_valid & (returned_distance <= epsilon)
                effective = np.where(accepted[:, None], returned, clean).astype(np.float32)
                effective_prediction = np.where(accepted, prediction, clean_predictions)
                effective_distance = np.where(accepted, returned_distance, 0)
                metrics = attack_metrics(clean_predictions, prediction, returned_valid, returned_distance <= epsilon)
                # Summarize the new trajectory without adding end-only repair.
                pool, _, stages = postprocess(out / "raw_pool", out / "pool_summary", "original", repair, checker,
                    scaler, model, counter, epsilon, rows, clean_predictions, effective,
                    effective_prediction, effective_distance)
                post_seconds, post_counts = time.perf_counter() - start, counter.since(before)
                before = counter.snapshot(); start = time.perf_counter()
                union, union_prediction, union_distance, rejected = final_gate(clean, effective, baseline,
                    baseline_predictions, model, checker, scaler, epsilon)
                union_seconds, union_counts = time.perf_counter() - start, counter.since(before)
                union_metrics = attack_metrics(clean_predictions, union_prediction,
                    np.ones(len(rows), dtype=bool), union_distance <= epsilon)
                if union_metrics["newly_evaded"] < original_report["methods"]["original"]["summary"]["newly_evaded"]:
                    raise AssertionError("Union lost an original validated evasion")
                np.savez_compressed(out / "final_results.npz", x_clean=clean, csv_rows=rows, labels=labels,
                    clean_predictions=clean_predictions, x_returned=returned, returned_valid=returned_valid,
                    returned_distance=returned_distance, x_effective=effective, predictions=effective_prediction,
                    effective_distance=effective_distance, x_union=union, union_predictions=union_prediction,
                    union_distance=union_distance)
                record_rows = [{"csv_row_zero_based": int(row), "clean_prediction": int(clean_predictions[i]),
                    "covered_by_method_pool": bool(pool.covered[i]), "unique_feasible_changes": len(pool.unique[i]),
                    "final_prediction": int(effective_prediction[i]), "union_prediction": int(union_prediction[i]),
                    "newly_evaded": bool(clean_predictions[i] == 1 and effective_prediction[i] == 0),
                    "union_newly_evaded": bool(clean_predictions[i] == 1 and union_prediction[i] == 0)} for i, row in enumerate(rows)]
                write_csv(out / "records.csv", record_rows)
                entry = {"model": model_name, "seed": seed, "method": method, "n_selected": len(rows),
                    "clean_detected": metrics["clean_detected"], "already_missed": metrics["already_missed_before_attack"],
                    "covered_records": int(pool.covered.sum()), "newly_evaded": metrics["newly_evaded"],
                    "new_evasion_rate": metrics["new_evasion_rate_among_initially_detected"],
                    "union_newly_evaded": union_metrics["newly_evaded"],
                    "pool_invalid_candidates": pool.totals["invalid_candidates"],
                    "generation_wall_seconds": wall, "generation_forward_rows": counts["forward_rows"],
                    "additional_postprocess_seconds": post_seconds,
                    "additional_postprocess_forward_rows": post_counts["forward_rows"],
                    "separate_union_check_forward_rows": union_counts["forward_rows"],
                    "generation_forward_counts_match_original": True}
                comparison.append(entry)
                result = {"summary": entry, "standalone_metrics": metrics, "union_metrics": union_metrics,
                    "generation_forward_counts": counts, "original_generation_forward_counts": original_report["attack_forward_counts"],
                    "pre_moeva_stages_match_original": True, "generation_audit": "generation_audit.json",
                    "stages": stages, "union_check_seconds": union_seconds, "union_rejections": rejected}
                write_json(out / "results.json", result)
                details.append({"model": model_name, "seed": seed, "method": method,
                                "results": str((out / "results.json").relative_to(args.out))})
                write_csv(args.out / "comparison.csv", comparison)
                write_csv(args.out / "seed_summary.csv", aggregates(comparison))
                write_json(args.out / "results.json", {"status": "running", "comparison": comparison, "runs": details})
                print("  coverage {}/{}; new evasions {}/{}; union {}; matched forwards {}".format(
                    entry["covered_records"], len(rows), entry["newly_evaded"], entry["clean_detected"],
                    entry["union_newly_evaded"], counts["forward_rows"]), flush=True)
                del attack, evo, trace; gc.collect()
        counter.handle.remove()
        del model; gc.collect()
    protocol.update(status="completed", wall_seconds=time.perf_counter() - started)
    write_json(args.out / "protocol.json", protocol)
    write_json(args.out / "results.json", {"status": "completed", "comparison": comparison,
                                          "seed_summary": aggregates(comparison), "runs": details})
    print("In-search comparison complete: " + str(args.out.resolve()), flush=True)


if __name__ == "__main__":
    main()
