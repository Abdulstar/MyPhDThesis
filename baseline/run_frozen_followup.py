"""Notebook 10: fixed 128-record development replication of notebook 08.

Uses the unchanged generation/repair/selection functions and frozen models.
The two reviewed ZIPs are required; no new sample is selected at runtime.
"""
import os
for _name in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "LOKY_MAX_CPU_COUNT"):
    os.environ[_name] = "2"

import argparse
import gc
import json
from pathlib import Path
import platform
import shutil
import subprocess
import time

import numpy as np
import torch

from connection_profile import ConnectionProfile, ConnectionRollback
from download_assets import CODE_REVISION, DATA_REVISION, MODEL_REVISION, sha256
from frozen_followup_inputs import load_frozen_inputs, FROZEN_INPUT_SHA256
from relationship_audit import RuleEngine, write_csv, write_json
from run_connection_search import METHODS, PoolEvaluation, audit_controls, generation, read, select_policy
from run_development_repair import ForwardCounter
from traffic_consistency import load_npz


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pilot-zip", type=Path, required=True)
    parser.add_argument("--semantics-zip", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path("vendor/tabularbench"))
    parser.add_argument("--assets", type=Path, default=Path("assets"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--smoke", action="store_true", help="First four frozen records, reduced budgets: implementation check only")
    mode.add_argument("--preflight-only", action="store_true", help="Verify all 128 inputs and score both frozen models; no attacks")
    mode.add_argument("--pair", nargs=2, metavar=("MODEL", "SEED"), help="One full-budget partial pair; never label as the complete experiment")
    args = parser.parse_args()
    if args.pair and (args.pair[0] not in ("default", "madry") or args.pair[1] not in ("0", "1", "2")):
        parser.error("--pair requires default/madry and 0/1/2")
    if args.out.exists():
        parser.error("Use a NEW output directory; preserve earlier evidence")
    if (platform.python_version(), np.__version__, torch.__version__) != ("3.8.20", "1.23.5", "1.12.1+cpu"):
        raise RuntimeError("Use the pinned .baseline-env/bin/python")
    head = subprocess.check_output(["git", "-C", str(args.repo), "rev-parse", "HEAD"], text=True).strip()
    if head != CODE_REVISION or subprocess.check_output(["git", "-C", str(args.repo), "diff", "HEAD", "--"], text=True):
        raise ValueError("Upstream code is not the clean pinned revision")
    args.out.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    selected, names, manifest, parent, base = load_frozen_inputs(
        args.pilot_zip, args.semantics_zip, args.out / "input_evidence")
    for field, expected in (("code_revision", CODE_REVISION), ("data_revision", DATA_REVISION), ("model_revision", MODEL_REVISION)):
        if parent[field] != expected:
            raise ValueError("Source revision differs: " + field)
    config_path = Path(__file__).with_name("connection_profile_v1.json")
    config = read(config_path)
    if sha256(config_path) != manifest["profile_sha256"] or sha256(base / "compatibility_scaler.json") != config["scaler_sha256"]:
        raise ValueError("Profile/scaler changed")
    for name, expected in read(Path(__file__).with_name("asset_hashes.json")).items():
        if sha256(args.assets / name) != expected:
            raise ValueError("Pinned asset mismatch: " + name)
    settings = {k: manifest[k] for k in ("selection_seed", "models", "seeds", "steps", "generations", "offspring", "eps")}
    settings["n_dev"] = 128
    profile = ConnectionProfile(names, config)
    print("Checking all 128 frozen inputs and 143046 train/development controls...", flush=True)
    controls = audit_controls(args.assets, base, selected, profile, args.out)
    engine = RuleEngine(args.repo, args.assets / "ctu_13_neris_metadata.csv", names)
    from tabularbench.models.tab_scaler import TabScaler, ScalerData
    from tabularbench.models.tabsurvey.mlp_rln import TORCHRLN
    torch.set_num_threads(2)
    scaler = TabScaler(num_scaler="min_max", one_hot_encode=True)
    scaler.fit_scaler_data(ScalerData.load(str(base / "compatibility_scaler.json")))
    if scaler.cat_idx or scaler.num_idx != list(range(len(names))):
        raise ValueError("Unexpected feature geometry")
    if not engine.checker.check_constraints(selected["x_clean"], selected["x_clean"]).all() or not profile.ok(selected["x_clean"]).all():
        raise ValueError("A frozen original fails a final gate. Preserve all rows; investigate rather than filter")
    preflight = {"status": "passed", "sample_size": 128, "frozen_inputs_sha256": FROZEN_INPUT_SHA256,
                 "test_rows_evaluated": 0, "models": {}}
    for model_name in ("default", "madry"):
        model = TORCHRLN.load_class(str(args.assets / ("torchrln_ctu_13_neris_" + model_name + ".model")),
                                   x_metadata=engine.metadata, scaler=scaler, force_device="cpu")
        predicted = model.predict_proba(selected["x_clean"]).argmax(1)
        preflight["models"][model_name] = {"clean_detected": int((predicted == 1).sum()),
            "already_missed": int((predicted == 0).sum()), "clean_predictions": predicted.tolist()}
        del model
    write_json(args.out / "preflight.json", preflight)
    print("Frozen-input preflight:", {k: {q: v[q] for q in ("clean_detected", "already_missed")}
                                      for k, v in preflight["models"].items()}, flush=True)
    if args.smoke:
        selected = {k: v[:4].copy() for k, v in selected.items()}
        settings.update(n_dev=4, steps=2, generations=3, offspring=4, models=["default"], seeds=[0])
    elif args.pair:
        settings.update(models=[args.pair[0]], seeds=[int(args.pair[1])])
    protocol = {"experiment": "frozen_128_development_replication", "status": "running", "settings": settings,
        "smoke_check_only": args.smoke, "single_pair_only": args.pair is not None,
        "preflight_only": args.preflight_only, "input_zip_sha256": sha256(args.semantics_zip),
        "pilot_zip_sha256": sha256(args.pilot_zip),
        "parent_protocol_sha256": sha256(args.out / "input_evidence/notebook09/protocol.json"),
        "frozen_inputs_sha256": FROZEN_INPUT_SHA256, "profile_sha256": sha256(config_path), "profile": config,
        "code_revision": CODE_REVISION, "data_revision": DATA_REVISION, "model_revision": MODEL_REVISION,
        "python": platform.python_version(), "numpy": np.__version__, "torch": torch.__version__, "device": "cpu",
        "new_model_training": False, "test_partition_evaluated": False, "native_relationship_tolerance": 0.0,
        "methods": list(METHODS), "generation_runs": 0 if args.preflight_only else len(settings["models"]) * len(settings["seeds"]) * 3,
        "primary_comparison": manifest["primary_comparison"], "analysis_unit": manifest["analysis_unit"],
        "evaluation_notes": manifest["evaluation_notes"], "claim_scope": manifest["claim_scope"],
        "cost_note": "Core generation counts must match. End methods share original generation/evaluation. Postprocessing counters are incremental in this shared audit, not standalone runtime estimates. No equal-total-compute claim."}
    write_json(args.out / "protocol.json", protocol)
    shutil.copy2(config_path, args.out / "fixed_profile.json")
    shutil.copy2(base / "compatibility_scaler.json", args.out / "compatibility_scaler.json")
    write_json(args.out / "feature_names.json", names)
    write_json(args.out / "frozen_followup_manifest.json", manifest)
    np.savez_compressed(args.out / "selected_inputs.npz", **selected)
    write_json(args.out / "rule_catalog.json", profile.catalog())
    if args.preflight_only:
        protocol.update(status="preflight_completed", wall_seconds=time.perf_counter() - started)
        write_json(args.out / "protocol.json", protocol)
        print("PREFLIGHT ONLY: no attacks run", flush=True)
        return
    clean, rows, labels = selected["x_clean"], selected["csv_rows"], selected["labels"]
    if not engine.checker.check_constraints(clean, clean).all():
        raise ValueError("Selected matrix geometry fails native clean check")
    repair = ConnectionRollback(engine.constraints, scaler.transform, settings["eps"], profile)
    write_json(args.out / "native_dependency_blocks.json", repair.description())
    summaries, manifests, native_reference = [], [], []
    # The loop below is retained from notebook 08. Generation, repair, pool
    # evaluation and final-matrix selection use its unchanged shared functions.
    for model_name in settings["models"]:
        model = TORCHRLN.load_class(str(args.assets / ("torchrln_ctu_13_neris_" + model_name + ".model")),
                                   x_metadata=engine.metadata, scaler=scaler, force_device="cpu")
        counter = ForwardCounter(model.wrapper_model)
        clean_prediction = model.predict_proba(clean).argmax(1)
        for seed in settings["seeds"]:
            folder = args.out / model_name / ("seed_" + str(seed))
            print(model_name, seed, "fresh original CAA", flush=True)
            original = generation(model, counter, engine, scaler, profile, repair, clean, labels, rows,
                                  settings, seed, folder / "original_generation")
            native_reference.append({"model": model_name, "seed": seed,
                "newly_evaded_native_returned": int(((clean_prediction == 1) & (original["native_returned_predictions"] == 0)).sum()),
                "clean_detected": int((clean_prediction == 1).sum())})
            evaluation = PoolEvaluation(args.out, model, engine.checker, scaler, profile, settings["eps"], clean, rows)
            for method in METHODS:
                target = folder / method
                start_post = time.perf_counter(); before_post = counter.snapshot()
                if method.endswith("inloop"):
                    relation = method == "caa_profile_relation_inloop"
                    print(model_name, seed, method, flush=True)
                    generated = generation(model, counter, engine, scaler, profile, repair, clean, labels, rows,
                                           settings, seed, target, relations=relation, reference=original)
                    source_list = generated["sources"]
                    start_post = time.perf_counter(); before_post = counter.snapshot()
                else:
                    target.mkdir(parents=True, exist_ok=False)
                    generated = original
                    source_list = list(original["sources"])
                    if method.endswith("end"):
                        for path, matrix in original["sources"]:
                            if matrix:
                                continue
                            data = load_npz(path)
                            fixed, details = [], []
                            for c, population in zip(data["x_clean"], data["x_candidates"]):
                                x, audit = repair.repair_population(c[None], population,
                                                                   repair_relations=method == "caa_profile_relation_end")
                                fixed.append(x); details.append(audit)
                            destination = target / "repaired_pool" / path.name
                            destination.parent.mkdir(exist_ok=True)
                            np.savez_compressed(destination, x_clean=data["x_clean"], x_candidates=np.stack(fixed),
                                csv_rows=data["csv_rows"], labels=data["labels"],
                                **{"repair_" + k: np.stack([d[k] for d in details]) for k in details[0]})
                            source_list.append((destination, False))
                summary = select_policy(evaluation, source_list, clean_prediction, target)
                summary.update(model=model_name, seed=seed, method=method,
                    generation_wall_seconds=generated["wall_seconds"],
                    generation_forward_rows=generated["forward_counts"]["forward_rows"],
                    generation_forward_counts_match_original=generated["forward_counts"] == original["forward_counts"],
                    incremental_postprocessing_seconds=time.perf_counter() - start_post,
                    incremental_postprocessing_forward_rows=counter.since(before_post)["forward_rows"])
                write_json(target / "results.json", summary)
                summaries.append(summary)
                write_csv(args.out / "comparison.csv", summaries)
                write_json(args.out / "results.json", {"status": "running", "comparison": summaries})
                print("  Final profile coverage {}/{}; newly evaded {}/{}; core forwards {}".format(
                    summary["covered_records"], len(rows), summary["newly_evaded"], summary["clean_detected"],
                    summary["generation_forward_rows"]), flush=True)
            manifests.extend(evaluation.manifest)
            write_json(args.out / "source_manifest.json", manifests)
            del evaluation; gc.collect()
        counter.handle.remove()
        del model; gc.collect()
    write_json(args.out / "source_manifest.json", manifests)
    write_csv(args.out / "native_original_reference.csv", native_reference)
    protocol.update(status="completed", wall_seconds=time.perf_counter() - started)
    write_json(args.out / "protocol.json", protocol)
    write_json(args.out / "results.json", {"status": "completed", "comparison": summaries,
        "native_original_reference": native_reference, "clean_controls": controls,
        "physical_source_files": len(manifests), "wall_seconds": protocol["wall_seconds"]})
    print("FROZEN DEVELOPMENT REPLICATION COMPLETED:", args.out, flush=True)


if __name__ == "__main__":
    main()
