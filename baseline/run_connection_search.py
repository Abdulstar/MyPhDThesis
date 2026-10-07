"""Notebook 08: paired connection-aware evolutionary search on development data.

Input is a completed notebook-07 ZIP. Every result is written to a NEW folder.
The original frozen IDS checkpoints are evaluated; no IDS is trained.
"""
import os
for _name in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "LOKY_MAX_CPU_COUNT"):
    os.environ[_name] = "2"

import argparse
import gc
import hashlib
import io
import json
from pathlib import Path
import platform
import shutil
import sys
import time

import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import train_test_split

from candidate_trace import CandidateTrace, observe_selector
from connection_profile import ConnectionProfile, ConnectionRollback, observe_profile_selector
from download_assets import CODE_REVISION, DATA_REVISION, MODEL_REVISION, sha256
from relationship_audit import RuleEngine, write_csv, write_json
from run_development_repair import ForwardCounter, measured_pool
from traffic_consistency import load_npz, unpack_evidence, merge_candidate, evasion_options, select_with_final_gate


METHODS = ("caa_filter", "caa_profile_budget_end", "caa_profile_relation_end",
           "caa_profile_budget_inloop", "caa_profile_relation_inloop")


def read(path):
    return json.loads(path.read_text())


def audit_controls(assets, base, selected, profile, out):
    """Verify the saved split/originals and both rules without reading test rows."""
    limit = 143046
    labels = pd.read_csv(assets / "ctu_13_neris.csv", usecols=["is_botnet"], nrows=limit).is_botnet.to_numpy(np.int64)
    train, dev = train_test_split(np.arange(limit, dtype=np.int64), test_size=.2,
                                  random_state=1319, shuffle=True, stratify=labels)
    buf = io.BytesIO(); np.save(buf, dev)
    if (base / "development_indices.npy").read_bytes() != buf.getvalue():
        raise ValueError("Input development split differs from the native split")
    rows = selected["csv_rows"]
    if not np.isin(rows, dev).all() or len(set(rows.tolist())) != len(rows):
        raise ValueError("Selected originals must be distinct native development records")
    np.testing.assert_array_equal(labels[rows], selected["labels"])
    split = np.zeros(limit, dtype=np.int8); split[dev] = 1
    counts = {(s, y, precision): {"rows": 0, "aggregate_flagged_rows": 0, "presence_flagged_rows": 0,
                                  "nonfinite_rows": 0, "negative_rows": 0}
              for s in (0, 1) for y in (0, 1) for precision in ("float64", "float32")}
    offset, verified = 0, 0
    for frame in pd.read_csv(assets / "ctu_13_neris.csv", nrows=limit, chunksize=4096, low_memory=False):
        y = frame.pop("is_botnet").to_numpy(np.int64)
        if frame.columns.tolist() != profile.names:
            raise ValueError("Feature order mismatch")
        local = np.arange(offset, offset + len(frame))
        pos = np.flatnonzero((rows >= offset) & (rows < offset + len(frame)))
        for precision in ("float64", "float32"):
            x = frame.to_numpy(dtype=precision)
            if precision == "float32" and len(pos):
                np.testing.assert_array_equal(selected["x_clean"][pos], x[rows[pos] - offset])
                verified += len(pos)
            parts = profile.failures(x)
            flags = {"aggregate_flagged_rows": parts["aggregate"].any(axis=1),
                     "presence_flagged_rows": parts["presence"].any(axis=1),
                     "nonfinite_rows": ~np.isfinite(x).all(axis=1), "negative_rows": (x < 0).any(axis=1)}
            for s in (0, 1):
                for label in (0, 1):
                    mask = (split[local] == s) & (y == label)
                    c = counts[(s, label, precision)]
                    c["rows"] += int(mask.sum())
                    for name, flag in flags.items():
                        c[name] += int((mask & flag).sum())
        offset += len(frame)
    if offset != limit or verified != len(rows):
        raise ValueError("Incomplete original/control verification")
    result = [dict(partition="development" if s else "train", label=y, precision=p, **c)
              for (s, y, p), c in counts.items()]
    write_csv(out / "clean_controls.csv", result)
    write_json(out / "clean_controls.json", {"rows": limit, "train_rows": len(train),
        "development_rows": len(dev), "test_rows_parsed_or_scored": 0, "selected_originals_verified": verified, "groups": result})
    if any(v for c in counts.values() for k, v in c.items() if k != "rows"):
        raise ValueError("A clean control failed. Evidence preserved; do not filter records or tune the profile")
    return result


class PoolEvaluation:
    """Recheck each physical source once, preserving native population geometry."""
    def __init__(self, root, model, checker, scaler, profile, epsilon, clean, rows):
        self.root, self.model, self.checker, self.scaler = root, model, checker, scaler
        self.profile, self.epsilon, self.clean, self.rows = profile, epsilon, clean, rows
        self.positions = {int(r): i for i, r in enumerate(rows)}
        self.cache, self.manifest = {}, []

    def get(self, path, matrix=False):
        relative = str(path.relative_to(self.root))
        if relative in self.cache:
            return self.cache[relative]
        d = load_npz(path)
        clean, x, rows = d["x_clean"], d["x_candidates"], d["csv_rows"]
        positions = np.array([self.positions[int(r)] for r in rows])
        np.testing.assert_array_equal(clean, self.clean[positions])
        if x.dtype != np.float32 or not np.isfinite(x).all():
            raise ValueError("Expected finite native float32 candidates")
        if matrix:
            np.testing.assert_array_equal(rows, self.rows)
            native = self.checker.check_constraints(clean, x).astype(bool)[:, None]
            distance = np.linalg.norm(self.scaler.transform(x) - self.scaler.transform(clean), axis=1)[:, None]
            x = x[:, None]
            masks = {"valid": native, "distance": distance, "within_budget": distance <= self.epsilon,
                     "changed": np.any(x != clean[:, None], axis=-1)}
        else:
            masks = measured_pool(clean, x, self.checker, self.scaler, self.epsilon)
            if "valid" in d:
                for key in ("valid", "within_budget", "changed", "relation_ok", "bounds_ok", "types_ok", "immutable_ok"):
                    np.testing.assert_array_equal(masks[key], d[key], err_msg=relative + ": " + key)
                np.testing.assert_allclose(masks["distance"], d["distance"], rtol=1e-6, atol=1e-8)
        probabilities = self.model.predict_proba(x.reshape(-1, x.shape[-1])).reshape(x.shape[:2] + (2,))
        if not np.isfinite(probabilities).all():
            raise ValueError("Nonfinite model output")
        prediction = probabilities.argmax(-1)
        if "fooled" in d:
            np.testing.assert_array_equal(prediction == 0, d["fooled"])
        parts = self.profile.failures(x)
        added_ok = ~parts["aggregate"].any(-1) & ~parts["presence"].any(-1)
        feasible = masks["valid"] & masks["within_budget"] & masks["changed"]
        data = dict(x=x, rows=rows, positions=positions, score=probabilities[..., 1], prediction=prediction,
                    native_feasible=feasible, profile_ok=added_ok, distance=masks["distance"])
        target = self.root / "evaluated_sources" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(target, csv_rows=rows, predictions=prediction, malicious_score=probabilities[..., 1],
                            aggregate_failed=parts["aggregate"], presence_failed=parts["presence"], **masks)
        self.manifest.append({"source": relative, "source_sha256": sha256(path), "matrix_geometry": matrix,
            "candidate_entries": int(feasible.size), "native_changed_feasible": int(feasible.sum()),
            "profile_changed_feasible": int((feasible & added_ok).sum())})
        self.cache[relative] = data
        return data


def select_policy(evaluation, sources, clean_predictions, out):
    pools = [dict() for _ in evaluation.rows]
    for path, matrix in sources:
        data = evaluation.get(path, matrix)
        source = str(path.relative_to(evaluation.root))
        for i, position in enumerate(data["positions"]):
            for j in np.flatnonzero(data["native_feasible"][i]):
                merge_candidate(pools, position, data["x"][i, j], data["score"][i, j],
                    data["distance"][i, j], source, j, data["profile_ok"][i, j], data["prediction"][i, j])
    options = evasion_options(pools, clean_predictions, require_support=True)
    clean = evaluation.clean
    def gate(x):
        native = evaluation.checker.check_constraints(clean, x).astype(bool)
        distance = np.linalg.norm(evaluation.scaler.transform(x) - evaluation.scaler.transform(clean), axis=1)
        prediction = evaluation.model.predict_proba(x).argmax(1)
        changed = np.any(x != clean, axis=1)
        return (native & (distance <= evaluation.epsilon) & evaluation.profile.ok(x)
                & (~changed | ((clean_predictions == 1) & (prediction == 0))))
    final, chosen, rejected = select_with_final_gate(clean, options, gate)
    predicted = evaluation.model.predict_proba(final).argmax(1)
    success = (clean_predictions == 1) & (predicted == 0) & np.any(final != clean, axis=1)
    distance = np.linalg.norm(evaluation.scaler.transform(final) - evaluation.scaler.transform(clean), axis=1)
    covered = [any(c["support_ok"] for c in pool.values()) for pool in pools]
    records = [{"csv_row_zero_based": int(row), "clean_prediction": int(clean_predictions[i]),
                "unique_native_feasible": len(pools[i]),
                "unique_profile_feasible": sum(c["support_ok"] for c in pools[i].values()),
                "unique_profile_evasions": len(options[i]), "covered": covered[i],
                "newly_evaded": bool(success[i]), "final_prediction": int(predicted[i])}
               for i, row in enumerate(evaluation.rows)]
    np.savez_compressed(out / "final.npz", x_clean=clean, x_final=final, csv_rows=evaluation.rows,
                        clean_predictions=clean_predictions, predictions=predicted, distance=distance, newly_evaded=success)
    write_csv(out / "records.csv", records)
    write_json(out / "selection.json", {"sources": [{"path": str(p.relative_to(evaluation.root)), "matrix": m} for p, m in sources],
        "selected": [None if c is None else {k: v for k, v in c.items() if k != "vector"} for c in chosen],
        "final_gate_rejections": rejected})
    detected = int((clean_predictions == 1).sum())
    return {"n_selected": len(clean), "clean_detected": detected, "already_missed": len(clean) - detected,
            "covered_records": sum(covered), "pool_evaded_records": sum(bool(o) for o in options),
            "newly_evaded": int(success.sum()), "new_evasion_rate": float(success.sum() / detected) if detected else None,
            "final_gate_rejections": len(rejected),
            "unique_profile_feasible": sum(r["unique_profile_feasible"] for r in records)}


def generation(model, counter, engine, scaler, profile, repair, clean, labels, rows,
               settings, seed, out, relations=None, reference=None):
    """One fresh CAA run; relations=None means unchanged native CAA control."""
    from connection_search import ConnectionMoeva2
    from tabularbench.attacks.caa.caa import ConstrainedAutoAttack
    out.mkdir(parents=True, exist_ok=False)
    np.random.seed(seed); torch.manual_seed(seed)
    attack = ConstrainedAutoAttack(constraints=engine.constraints, constraints_eval=engine.constraints,
        scaler=scaler, model=model.wrapper_model, model_objective=model.predict_proba, n_jobs=1,
        fix_equality_constraints_end=True, fix_equality_constraints_iter=True, norm="L2", eps=settings["eps"],
        seed=seed, steps=settings["steps"], n_gen=settings["generations"], n_offsprings=settings["offspring"],
        verbose=False, n_classes=2)
    evo = None
    if relations is not None:
        upstream = attack._autoattack.attacks[-1]
        evo = ConnectionMoeva2(model.predict_proba, constraints=engine.constraints, norm=upstream.norm,
            fun_distance_preprocess=scaler.transform, n_gen=upstream.n_gen, n_pop=upstream.n_pop,
            n_offsprings=upstream.n_offsprings, seed=upstream.seed, n_jobs=1,
            rollback=repair, checker=engine.checker, epsilon=settings["eps"], repair_relations=relations, profile=profile)
        attack._autoattack.attacks[-1] = evo
    trace = CandidateTrace(out / "raw_pool", rows, ["NoAttack", "CAPGD", "Moeva2"],
                           engine.checker, attack.objective_calculator.thresholds)
    if reference is not None:
        native_record = trace.record
        def checked_record(*args, **kwargs):
            native_record(*args, **kwargs)
            stage = len(trace.stages) - 1
            if stage < 2:
                filename = "{:02d}_{}_candidates.npz".format(stage, trace.stage_names[stage])
                a, b = load_npz(reference["directory"] / "raw_pool" / filename), load_npz(out / "raw_pool" / filename)
                for key in ("x_clean", "x_candidates", "csv_rows", "labels", "valid", "within_budget", "fooled"):
                    np.testing.assert_array_equal(a[key], b[key], err_msg="Pre-MOEVA mismatch: " + key)
        trace.record = checked_record
    if evo is None:
        observe_selector(attack._autoattack.objective_calculator, trace)
        selectors = None
    else:
        selectors = observe_profile_selector(attack._autoattack.objective_calculator, trace, profile)
    before = counter.snapshot(); started = time.perf_counter()
    returned = attack(clean, labels)
    wall = time.perf_counter() - started; counts = counter.since(before)
    if reference is not None and counts != reference["forward_counts"]:
        raise AssertionError("Core forward budget changed; do not report a matched-budget comparison")
    moeva = list((out / "raw_pool").glob("*_Moeva2_candidates.npz"))
    if len(moeva) != 1:
        raise ValueError("Expected the fixed pilot's MOEVA stage; investigate changed stage schedule")
    population = load_npz(moeva[0])
    if reference is not None:
        original = load_npz(reference["directory"] / "raw_pool" / moeva[0].name)
        np.testing.assert_array_equal(population["csv_rows"], original["csv_rows"])
        if population["x_candidates"].shape != original["x_candidates"].shape:
            raise AssertionError("MOEVA population dimensions changed")
        write_json(out / "generation_audit.json", evo.audit(population["csv_rows"], population["x_candidates"].shape[1]))
        write_json(out / "profile_stage_selection.json", selectors)
    post_start = time.perf_counter(); before = counter.snapshot()
    native = engine.checker.check_constraints(clean, returned).astype(bool)
    distance = np.linalg.norm(scaler.transform(returned) - scaler.transform(clean), axis=1)
    accepted = native & (distance <= settings["eps"])
    effective = np.where(accepted[:, None], returned, clean).astype(np.float32)
    if not engine.checker.check_constraints(clean, effective).all():
        raise ValueError("Native effective matrix is invalid; investigate numerical geometry before continuing")
    prediction = model.predict_proba(effective).argmax(1)
    np.savez_compressed(out / "returned_source.npz", x_clean=clean, x_candidates=effective,
                        x_returned=returned, csv_rows=rows, labels=labels, predictions=prediction,
                        returned_valid=native, returned_distance=distance)
    sources = [(p, False) for p in sorted((out / "raw_pool").glob("*_candidates.npz"))] + [(out / "returned_source.npz", True)]
    result = {"directory": out, "sources": sources, "wall_seconds": wall, "forward_counts": counts,
              "native_returned_predictions": prediction, "matrix_export_seconds": time.perf_counter() - post_start,
              "matrix_export_forward_counts": counter.since(before)}
    write_json(out / "generation.json", {"wall_seconds": wall, "forward_counts": counts,
        "matrix_export_seconds": result["matrix_export_seconds"], "matrix_export_forward_counts": result["matrix_export_forward_counts"],
        "profile_repair_inside_moeva": evo is not None, "native_relationship_repair": relations,
        "core_counts_match_original": reference is None or counts == reference["forward_counts"],
        "pre_moeva_arrays_match_original": reference is not None,
        "moeva_csv_rows": population["csv_rows"].tolist(), "population_size": population["x_candidates"].shape[1]})
    del attack, evo, trace; gc.collect()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-zip", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path("vendor/tabularbench"))
    parser.add_argument("--assets", type=Path, default=Path("assets"))
    parser.add_argument("--smoke", action="store_true", help="Separate 4-record/3-generation implementation check; not the research experiment")
    parser.add_argument("--pair", nargs=2, metavar=("MODEL", "SEED"),
                        help="Run one full-budget model/seed pair for independent execution; marks the protocol as a partial experiment")
    args = parser.parse_args()
    if args.pair and (args.smoke or args.pair[0] not in ("default", "madry") or args.pair[1] not in ("0", "1", "2")):
        parser.error("--pair requires default/madry and 0/1/2, and cannot be combined with --smoke")
    if args.out.exists():
        parser.error("Preserving earlier evidence: --out must be a NEW directory")
    if (platform.python_version(), np.__version__, torch.__version__) != ("3.8.20", "1.23.5", "1.12.1+cpu"):
        raise RuntimeError("Run with the pinned .baseline-env/bin/python")
    args.out.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    evidence = unpack_evidence(args.input_zip, args.out / "input_evidence")
    parent_paths = list((args.out / "input_evidence").glob("**/audit/protocol.json"))
    if len(parent_paths) != 1:
        raise ValueError("Upload the completed notebook 07 ZIP")
    parent_path = parent_paths[0]; parent = read(parent_path)
    if (parent["status"] != "completed" or parent["experiment"] != "saved_pool_traffic_consistency_audit"
            or parent["profile"]["profile"] != "positive_sum_requires_positive_max_v1" or parent["test_partition_evaluated"]):
        raise ValueError("Expected the completed development-only notebook 07 profile")
    base = evidence / "baseline"
    inherited = read(base / "protocol.json")
    if inherited["status"] != "completed" or inherited["relationship_tolerance"] != 0:
        raise ValueError("Incomplete or altered source experiment")
    for field, expected in [("code_revision", CODE_REVISION), ("data_revision", DATA_REVISION), ("model_revision", MODEL_REVISION)]:
        if parent[field] != inherited[field] or parent[field] != expected:
            raise ValueError("Pinned revision mismatch: " + field)
    settings = dict(parent["settings"])
    if settings != inherited["settings"] or settings["models"] != ["default", "madry"] or settings["seeds"] != [0, 1, 2]:
        raise ValueError("Expected the reviewed paired experiment settings")
    if (settings["n_dev"], settings["steps"], settings["generations"], settings["offspring"], settings["eps"]) != (32, 10, 100, 50, .5):
        raise ValueError("Use the reviewed 32-record pilot to keep inputs and budgets fixed")
    config_path = Path(__file__).with_name("connection_profile_v1.json")
    config = read(config_path)
    if sha256(base / "compatibility_scaler.json") != config["scaler_sha256"]:
        raise ValueError("Frozen scaler mismatch")
    for name, digest in read(Path(__file__).with_name("asset_hashes.json")).items():
        if sha256(args.assets / name) != digest:
            raise ValueError("Pinned asset mismatch: " + name)
    names = read(base / "feature_names.json")
    selected = load_npz(base / "selected_development_inputs.npz")
    if selected["x_clean"].shape != (32, 757) or not np.all(selected["labels"] == 1):
        raise ValueError("Expected the fixed malicious development originals")
    if args.smoke:
        selected = {k: v[:4].copy() for k, v in selected.items()}
        settings.update(n_dev=4, steps=2, generations=3, offspring=4, models=["default"], seeds=[0])
    elif args.pair:
        settings.update(models=[args.pair[0]], seeds=[int(args.pair[1])])
    # Path fields from the input are provenance, not filesystem instructions.
    settings = {k: v for k, v in settings.items() if k not in ("repo", "assets", "out")}
    protocol = {"experiment": "connection_aware_evolutionary_search", "status": "running", "settings": settings,
        "smoke_check_only": args.smoke, "single_pair_only": args.pair is not None,
        "input_zip_sha256": sha256(args.input_zip),
        "parent_protocol_sha256": sha256(parent_path), "profile_sha256": sha256(config_path), "profile": config,
        "code_revision": CODE_REVISION, "data_revision": DATA_REVISION, "model_revision": MODEL_REVISION,
        "python": platform.python_version(), "numpy": np.__version__, "torch": torch.__version__, "device": "cpu",
        "new_model_training": False, "test_partition_evaluated": False, "native_relationship_tolerance": 0.0,
        "methods": list(METHODS), "generation_runs": len(settings["models"]) * len(settings["seeds"]) * 3,
        "cost_note": "Core generation counts must match. End methods share original generation/evaluation. Postprocessing counters are incremental in this shared audit, not standalone runtime estimates. No equal-total-compute claim."}
    write_json(args.out / "protocol.json", protocol)
    shutil.copy2(config_path, args.out / "fixed_profile.json")
    shutil.copy2(base / "compatibility_scaler.json", args.out / "compatibility_scaler.json")
    write_json(args.out / "feature_names.json", names)
    np.savez_compressed(args.out / "selected_inputs.npz", **selected)
    profile = ConnectionProfile(names, config)
    write_json(args.out / "rule_catalog.json", profile.catalog())
    print("Checking both fixed rules on all native train/development controls...", flush=True)
    controls = audit_controls(args.assets, base, selected, profile, args.out)
    print("All 143046 clean controls passed both rules in float64 and float32.", flush=True)
    engine = RuleEngine(args.repo, args.assets / "ctu_13_neris_metadata.csv", names)
    from tabularbench.models.tab_scaler import TabScaler, ScalerData
    from tabularbench.models.tabsurvey.mlp_rln import TORCHRLN
    torch.set_num_threads(2)
    scaler = TabScaler(num_scaler="min_max", one_hot_encode=True)
    scaler.fit_scaler_data(ScalerData.load(str(base / "compatibility_scaler.json")))
    if scaler.cat_idx or scaler.num_idx != list(range(len(names))):
        raise ValueError("Unexpected feature geometry")
    clean, rows, labels = selected["x_clean"], selected["csv_rows"], selected["labels"]
    if not engine.checker.check_constraints(clean, clean).all() or not profile.ok(clean).all():
        raise ValueError("Selected originals fail a final gate")
    repair = ConnectionRollback(engine.constraints, scaler.transform, settings["eps"], profile)
    write_json(args.out / "native_dependency_blocks.json", repair.description())
    summaries, manifests, native_reference = [], [], []
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
    print("CONNECTION-AWARE DEVELOPMENT EXPERIMENT COMPLETED:", args.out, flush=True)


if __name__ == "__main__":
    main()
