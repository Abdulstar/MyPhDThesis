"""Checkpoint compatibility check and optional SMALL constrained-attack smoke test.

This is not a leakage-free training experiment or a packet-level IDS.
Run from the extracted starter-pack directory. No files in the upstream repo change.
"""
import os
for key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "LOKY_MAX_CPU_COUNT"):
    os.environ[key] = "2"

import argparse
import gc
import json
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import torch
from download_assets import CODE_REVISION, DATA_REVISION, MODEL_REVISION, sha256
from metrics import clean_metrics, select_malicious, attack_metrics


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repo", type=Path, default=Path("vendor/tabularbench"))
    p.add_argument("--assets", type=Path, default=Path("assets"))
    p.add_argument("--out", type=Path, required=True, help="Must be a NEW directory")
    p.add_argument("--models", nargs="+", choices=["default", "madry"], default=["default", "madry"])
    p.add_argument("--attack", action="store_true")
    p.add_argument("--n-attack", type=int, default=8, help="0 means all eligible malicious records")
    p.add_argument("--steps", type=int, default=10)
    p.add_argument("--generations", type=int, default=2)
    p.add_argument("--offspring", type=int, default=20)
    p.add_argument("--eps", type=float, default=0.5)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()
    run_started = time.perf_counter()
    if args.n_attack < 0 or min(args.steps, args.generations, args.offspring) < 1 or args.eps <= 0:
        p.error("Attack sizes must be positive; n-attack may be 0 for all eligible records.")
    if args.out.exists():
        p.error("Output already exists. Choose a NEW --out directory to preserve earlier results.")
    revision = subprocess.check_output(["git", "-C", str(args.repo), "rev-parse", "HEAD"], text=True).strip()
    if revision != CODE_REVISION:
        raise RuntimeError("Unexpected upstream commit: " + revision)
    if subprocess.check_output(["git", "-C", str(args.repo), "diff", "HEAD", "--"], text=True):
        raise RuntimeError("Tracked upstream files changed. Use a clean pinned checkout.")
    sys.path.insert(0, str(args.repo.resolve()))
    from tabularbench.models.tab_scaler import TabScaler
    from tabularbench.models.tabsurvey.mlp_rln import TORCHRLN
    from tabularbench.datasets.dataset import CsvDataSource
    from tabularbench.datasets.samples.ctu_13_neris import get_relation_constraints
    from tabularbench.constraints.constraints import get_constraints_from_metadata
    from tabularbench.constraints.constraints_checker import ConstraintChecker

    torch.set_num_threads(2)
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    args.out.mkdir(parents=True)
    report = {
        "stage": "pretrained_checkpoint_compatibility_and_optional_smoke_test",
        "code_revision": revision, "data_revision": DATA_REVISION, "model_revision": MODEL_REVISION,
        "python": platform.python_version(), "torch": torch.__version__, "device": "cpu",
        "threads": 2, "settings": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        "limitations": [
            "Scaler fitted to all feature rows to match current upstream checkpoint loader; NOT a leakage-free research baseline.",
            "Native test split only; CTU-Neris feature rows, not live packets, requests or general-network traffic.",
            "Attack subset explicitly malicious and valid under metadata constraints; not the upstream helper's positional call.",
            "Default attack configuration is a smoke test, not a published robust-score reproduction.",
        ], "models": {},
    }
    expected = json.loads(Path(__file__).with_name("asset_hashes.json").read_text())
    for name, digest in expected.items():
        if sha256(args.assets / name) != digest:
            raise RuntimeError("Asset hash mismatch: " + name)
    print("Loading CTU data and preserving native feature order...", flush=True)
    df = pd.read_csv(args.assets / "ctu_13_neris.csv", low_memory=False)
    y = df.pop("is_botnet").to_numpy(dtype=np.int64)
    columns = df.columns.tolist()
    metadata = pd.read_csv(args.assets / "ctu_13_neris_metadata.csv")
    metadata = metadata[metadata.feature.isin(columns)].reset_index(drop=True)
    assert metadata.feature.tolist() == columns, "Metadata/feature-order mismatch"
    assert set(np.unique(y)) == {0, 1}
    assert len(y) > 143046
    x = df.to_numpy(dtype=np.float32)
    del df
    gc.collect()
    assert np.isfinite(x).all(), "Nonfinite features"
    scaler = TabScaler(num_scaler="min_max", one_hot_encode=True)
    scaler.fit(torch.from_numpy(x), x_type=metadata["type"])
    scaler.get_scaler_data().save(str(args.out / "compatibility_scaler.json"))
    x_test, y_test = x[143046:].copy(), y[143046:].copy()
    del x
    gc.collect()
    test_rows = np.arange(143046, len(y))
    report["dataset"] = {"rows_total": len(y), "features": len(columns), "native_test_start_row_zero_based": 143046,
                         "test_rows": len(y_test), "test_benign": int((y_test == 0).sum()), "test_malicious": int((y_test == 1).sum()),
                         "includes_window_timestamp": "window_timestamp" in columns}
    (args.out / "feature_names.json").write_text(json.dumps(columns, indent=2) + "\n")
    constraints = get_constraints_from_metadata(metadata, get_relation_constraints(CsvDataSource(str(args.assets / "ctu_13_neris_metadata.csv"))), columns)
    checker = ConstraintChecker(constraints, tolerance=0.0)
    if args.attack:
        # Check only malicious originals; never choose records by a model's predictions.
        malicious = np.flatnonzero(y_test == 1)
        valid = np.zeros(len(y_test), dtype=bool)
        valid[malicious] = checker.check_constraints(x_test[malicious], x_test[malicious]).astype(bool)
        selected = select_malicious(y_test, valid, args.n_attack, args.seed)
        assert np.all(y_test[selected] == 1)
        report["selection"] = {"malicious_total": int(len(malicious)), "constraint_valid_malicious": int(valid.sum()),
                               "excluded_malicious": int(len(malicious) - valid.sum()), "selected": len(selected),
                               "selection_seed": args.seed, "filter_correct": False,
                               "global_csv_row_indices_zero_based": test_rows[selected].tolist()}
        np.save(args.out / "selected_test_indices.npy", selected)
    for training in args.models:
        print("Loading RLN " + training, flush=True)
        folder = args.assets / ("torchrln_ctu_13_neris_{}.model".format(training))
        model = TORCHRLN.load_class(str(folder), x_metadata=metadata, scaler=scaler, force_device="cpu")
        t0 = time.perf_counter()
        probabilities = model.predict_proba(x_test)
        elapsed = time.perf_counter() - t0
        assert probabilities.shape == (len(y_test), 2)
        assert np.isfinite(probabilities).all()
        result = {"clean": clean_metrics(y_test, probabilities), "whole_test_prediction_wall_seconds": elapsed}
        prediction = probabilities.argmax(1)
        pd.DataFrame({"csv_row_zero_based": test_rows, "label": y_test, "predicted": prediction, "score_malicious": probabilities[:, 1]}).to_csv(args.out / (training + "_clean_predictions.csv"), index=False)
        print(training + " clean: " + json.dumps(result["clean"]), flush=True)
        if args.attack:
            from tabularbench.attacks.caa.caa import ConstrainedAutoAttack
            from tabularbench.attacks.objective_calculator import ObjectiveCalculator
            clean = x_test[selected].copy()
            labels = y_test[selected].copy()
            torch.manual_seed(args.seed)
            np.random.seed(args.seed)
            attack = ConstrainedAutoAttack(constraints=constraints, constraints_eval=constraints, scaler=scaler,
                model=model.wrapper_model, model_objective=model.predict_proba, n_jobs=1,
                fix_equality_constraints_end=True, fix_equality_constraints_iter=True,
                norm="L2", eps=args.eps, seed=args.seed, steps=args.steps,
                n_gen=args.generations, n_offsprings=args.offspring, verbose=False, n_classes=2)
            t0 = time.perf_counter()
            adversarial = attack(clean, labels)
            attack_elapsed = time.perf_counter() - t0
            assert adversarial.shape == clean.shape
            valid_adv = checker.check_constraints(clean, adversarial).astype(bool)
            distance = np.linalg.norm(scaler.transform(adversarial) - scaler.transform(clean), axis=1)
            distance_ok = distance <= args.eps
            adv_prediction = model.predict_proba(adversarial).argmax(1)
            summary = attack_metrics(prediction[selected], adv_prediction, valid_adv, distance_ok)
            calc = ObjectiveCalculator(model.predict_proba, constraints=constraints, thresholds={"distance": args.eps}, norm="L2", fun_distance_preprocess=scaler.transform)
            summary["upstream_one_minus_mdc_on_malicious_subset"] = float(1 - calc.get_success_rate(clean, labels, adversarial).mdc)
            summary["attack_wall_seconds"] = attack_elapsed
            summary["max_returned_scaled_l2_distance"] = float(distance.max())
            result["attack"] = summary
            np.savez_compressed(args.out / (training + "_attack_arrays.npz"), x_clean=clean, x_adv=adversarial, y=labels, csv_rows=test_rows[selected])
            pd.DataFrame({"csv_row_zero_based": test_rows[selected], "label": labels, "clean_prediction": prediction[selected],
                          "adversarial_prediction": adv_prediction, "valid": valid_adv, "distance_l2_scaled": distance,
                          "within_budget": distance_ok}).to_csv(args.out / (training + "_attack_audit.csv"), index=False)
            print(training + " attack: " + json.dumps(summary), flush=True)
            del attack, calc
        report["models"][training] = result
        (args.out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        del model
        gc.collect()
    report["run_wall_seconds"] = time.perf_counter() - run_started
    report["main_process_peak_rss_kib_linux"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    (args.out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Saved results to " + str(args.out.resolve()), flush=True)


if __name__ == "__main__":
    main()
