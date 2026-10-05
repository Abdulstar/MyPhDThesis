"""Notebook 07: audit clean controls and all exported notebook-06 candidates.

Run with .baseline-env/bin/python. No attacks, training or packet replay.
"""
import os
for _key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
    os.environ[_key] = "2"

import argparse
import csv
import io
import json
from pathlib import Path
import platform
import sys
import time

import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import train_test_split

from download_assets import CODE_REVISION, DATA_REVISION, MODEL_REVISION, sha256
from relationship_audit import RuleEngine, MASK_NAMES, write_csv, write_json
from traffic_consistency import (aggregate_pairs, support_failures, unpack_evidence,
                                 load_npz, merge_candidate, evasion_options,
                                 select_with_final_gate, vector_digest)


METHODS = ("caa_original", "caa_budget_end", "caa_relation_end",
           "caa_budget_inloop", "caa_relation_inloop")


def read_json(path):
    return json.loads(path.read_text())


def clean_audit(assets, evidence, out, profile, names, pairs, selected):
    """Read only the native training prefix; never parse native test rows."""
    limit = profile["native_training_prefix_rows"]
    path = assets / "ctu_13_neris.csv"
    labels = pd.read_csv(path, usecols=["is_botnet"], nrows=limit)["is_botnet"].to_numpy(np.int64)
    if len(labels) != limit or not np.isin(labels, [0, 1]).all():
        raise ValueError("Unexpected clean-control labels")
    train, dev = train_test_split(np.arange(limit, dtype=np.int64),
        test_size=profile["validation_fraction"], random_state=profile["split_seed"],
        shuffle=True, stratify=labels)
    expected_npy = io.BytesIO()
    np.save(expected_npy, dev)
    if (evidence / "baseline/development_indices.npy").read_bytes() != expected_npy.getvalue():
        raise ValueError("Saved development indices differ from the pinned split")
    split = np.zeros(limit, dtype=np.int8)
    split[dev] = 1
    rows = selected["csv_rows"]
    if np.any(rows < 0) or np.any(rows >= limit) or not np.isin(rows, dev).all():
        raise ValueError("Selected inputs must belong to native development rows")
    np.testing.assert_array_equal(labels[rows], selected["labels"])
    counts = {(s, y, p): {"rows": 0, "flagged_rows": 0, "failed_pairs": 0,
                          "nonfinite_rows": 0, "negative_rows": 0,
                          "pairs": np.zeros(len(pairs), dtype=np.int64)}
              for s in (0, 1) for y in (0, 1) for p in profile["clean_audit_precisions"]}
    offset, seen, precision_disagreements = 0, 0, 0
    with (out / "clean_flagged_records.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["csv_row_zero_based", "partition", "label", "precision",
                                              "failed_pair_ids", "nonfinite", "negative"])
        writer.writeheader()
        for frame in pd.read_csv(path, nrows=limit, chunksize=4096, low_memory=False):
            y = frame.pop("is_botnet").to_numpy(np.int64)
            if frame.columns.tolist() != names:
                raise ValueError("Clean-control feature order mismatch")
            x64 = frame.to_numpy(np.float64)
            x32 = x64.astype(np.float32)
            local_rows = np.arange(offset, offset + len(frame))
            np.testing.assert_array_equal(y, labels[local_rows])
            positions = np.flatnonzero((rows >= offset) & (rows < offset + len(frame)))
            if len(positions):
                np.testing.assert_array_equal(selected["x_clean"][positions], x32[rows[positions] - offset])
                seen += len(positions)
            previous = None
            for precision, x in [("parsed_float64", x64), ("native_float32", x32)]:
                failed = support_failures(x, pairs)
                flagged = failed.any(axis=1)
                nonfinite = ~np.isfinite(x).all(axis=1)
                negative = (x < 0).any(axis=1)
                for s in (0, 1):
                    for label in (0, 1):
                        mask = (split[local_rows] == s) & (y == label)
                        c = counts[(s, label, precision)]
                        for name, v in [("rows", mask), ("flagged_rows", mask & flagged),
                                        ("nonfinite_rows", mask & nonfinite), ("negative_rows", mask & negative)]:
                            c[name] += int(v.sum())
                        per_pair = failed[mask].sum(axis=0)
                        c["pairs"] += per_pair
                        c["failed_pairs"] += int(per_pair.sum())
                for i in np.flatnonzero(flagged | nonfinite | negative):
                    writer.writerow({"csv_row_zero_based": int(local_rows[i]),
                        "partition": "development" if split[local_rows[i]] else "train", "label": int(y[i]),
                        "precision": precision, "failed_pair_ids": json.dumps(np.flatnonzero(failed[i]).tolist()),
                        "nonfinite": bool(nonfinite[i]), "negative": bool(negative[i])})
                if previous is not None:
                    precision_disagreements += int(np.any(failed != previous, axis=1).sum())
                previous = failed
            offset += len(frame)
    if offset != limit or seen != len(rows):
        raise ValueError("Incomplete clean-control audit")
    table, pair_table = [], []
    for (s, label, precision), c in counts.items():
        context = {"partition": "development" if s else "train", "label": label, "precision": precision}
        table.append(dict(context, **{k: v for k, v in c.items() if k != "pairs"}))
        for pair, n in zip(pairs, c["pairs"]):
            pair_table.append(dict(context, pair_id=pair["pair_id"], sum_feature=pair["sum_feature"],
                                  max_feature=pair["max_feature"], flagged_rows=int(n)))
    write_csv(out / "clean_controls.csv", table)
    write_csv(out / "clean_pair_counts.csv", pair_table)
    summary = {"rows": limit, "train_rows": len(train), "development_rows": len(dev),
        "test_rows_parsed_or_scored": 0, "precision_disagreement_rows": precision_disagreements,
        "selected_clean_rows_verified": seen, "groups": table,
        "rule_passed_all_clean_controls": all(c["flagged_rows"] == 0 for c in table),
        "all_controls_finite_and_nonnegative": all(c["nonfinite_rows"] == c["negative_rows"] == 0 for c in table)}
    write_json(out / "clean_controls.json", summary)
    if support_failures(selected["x_clean"], pairs).any():
        raise ValueError("Selected clean controls fail the added rule. Evidence retained; investigate without filtering them.")
    return summary


class SourceAudit:
    def __init__(self, evidence, out, model, engine, scaler, epsilon, selected, pairs, counts):
        self.evidence, self.out, self.model = evidence, out, model
        self.engine, self.scaler, self.epsilon = engine, scaler, epsilon
        self.clean, self.rows = selected["x_clean"], selected["csv_rows"]
        self.positions = {int(r): i for i, r in enumerate(self.rows)}
        self.pairs, self.counts = pairs, counts
        self.cache, self.reports = {}, []

    def predict(self, x):
        p = self.model.predict_proba(x)
        self.counts["rescoring_calls"] += 1
        self.counts["rescoring_rows"] += len(x)
        if p.shape != (len(x), 2) or not np.isfinite(p).all():
            raise ValueError("Invalid native model probabilities")
        return p

    def source(self, relative, final_key=None):
        if relative in self.cache:
            return self.cache[relative]
        path = self.evidence / relative
        d = load_npz(path)
        rows = d["csv_rows"]
        if rows.ndim != 1 or not np.issubdtype(rows.dtype, np.integer) or len(set(rows.tolist())) != len(rows):
            raise ValueError("Invalid source row identifiers: " + relative)
        positions = np.array([self.positions[int(r)] for r in rows])
        clean = d["x_clean"]
        np.testing.assert_array_equal(clean, self.clean[positions])
        if not np.all(d["labels"] == 1):
            raise ValueError("Expected malicious development labels")
        x = d[final_key] if final_key else d["x_candidates"]
        if x.dtype != np.float32 or clean.dtype != np.float32 or not np.isfinite(x).all():
            raise ValueError("Expected finite float32 source vectors")
        if final_key:
            np.testing.assert_array_equal(rows, self.rows)
            if x.shape != clean.shape:
                raise ValueError("Invalid final matrix shape")
            native = self.engine.checker.check_constraints(clean, x).astype(bool)
            distance = np.linalg.norm(self.scaler.transform(x) - self.scaler.transform(clean), axis=1)
            prediction = self.predict(x)
            np.testing.assert_array_equal(d["predictions"], prediction.argmax(1))
            if not native.all() or np.any(distance > self.epsilon):
                raise ValueError("Saved effective final matrix fails the original gate")
            x, native, distance, prediction = x[:, None], native[:, None], distance[:, None], prediction[:, None]
            self.counts["final_source_files"] += 1
            self.counts["final_source_vectors"] += len(rows)
        else:
            if x.ndim != 3 or x.shape[0] != len(rows) or x.shape[2] != clean.shape[1] or x.shape[1] < 1:
                raise ValueError("Invalid saved population shape")
            masks = self.engine.recompute_masks(clean, x)
            for key, value in masks.items():
                np.testing.assert_array_equal(d[key], value, err_msg=relative + ": " + key)
            native = np.logical_and.reduce(list(masks.values()))
            distance = np.stack([np.linalg.norm(self.scaler.transform(pop) - self.scaler.transform(c[None]), axis=1)
                                 for c, pop in zip(clean, x)])
            for key, value in [("valid", native), ("within_budget", distance <= self.epsilon),
                               ("changed", np.any(x != clean[:, None], axis=-1))]:
                np.testing.assert_array_equal(d[key], value, err_msg=relative + ": " + key)
            np.testing.assert_allclose(d["distance"], distance, rtol=1e-6, atol=1e-8)
            prediction = self.predict(x.reshape(-1, x.shape[-1])).reshape(x.shape[:2] + (2,))
            if "prediction_query_mask" in d:
                query = d["changed"] & native & (distance <= self.epsilon)
                np.testing.assert_array_equal(d["prediction_query_mask"], query)
                np.testing.assert_array_equal(d["predicted_class"][query], prediction.argmax(-1)[query])
                np.testing.assert_allclose(d["score_malicious"][query], prediction[..., 1][query], rtol=1e-6, atol=1e-8)
            else:
                np.testing.assert_array_equal(d["fooled"], prediction.argmax(-1) == 0)
            self.counts["stage_source_files"] += 1
            self.counts["stage_candidate_entries"] += native.size
        failed = support_failures(x, self.pairs)
        changed = np.any(x != clean[:, None], axis=-1)
        feasible = native & (distance <= self.epsilon) & changed
        strengthened = feasible & ~failed.any(axis=-1)
        scored = prediction.argmax(axis=-1)
        result = {"x": x, "rows": rows, "positions": positions, "native_feasible": feasible,
                  "strengthened_feasible": strengthened, "distance": distance,
                  "score": prediction[..., 1], "prediction": scored, "support_ok": ~failed.any(axis=-1)}
        saved = self.out / "source_audits" / relative
        saved.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(saved, csv_rows=rows, native_valid=native, changed=changed,
            within_budget=distance <= self.epsilon, distance=distance, predictions=scored,
            score_malicious=prediction[..., 1], support_failed_pairs=failed)
        report = {"source": relative, "source_sha256": sha256(path), "final_key": final_key,
            "inputs": len(rows), "candidate_entries": int(native.size), "native_changed_feasible": int(feasible.sum()),
            "strengthened_changed_feasible": int(strengthened.sum()),
            "native_feasible_flagged": int((feasible & failed.any(axis=-1)).sum()),
            "native_feasible_benign": int((feasible & (scored == 0)).sum()),
            "strengthened_feasible_benign": int((strengthened & (scored == 0)).sum()),
            "saved_native_masks_and_predictions_reproduced": True}
        self.reports.append(report)
        self.cache[relative] = result
        return result


def pool_sources(evidence, model, seed):
    base = "baseline/{}/seed_{}".format(model, seed)
    inside = "inloop/{}/seed_{}".format(model, seed)
    def stages(folder, repaired=False):
        pattern = "*/repaired_candidates.npz" if repaired else "*_candidates.npz"
        paths = sorted((evidence / folder).glob(pattern))
        if len(paths) != 3:
            raise ValueError("Expected three saved CAA stages in " + folder)
        return [(str(p.relative_to(evidence)), None) for p in paths]
    original_final = (base + "/original_final.npz", "x_effective")
    original = stages(base + "/raw_pool") + [original_final]
    sources = {"caa_original": original}
    published = {"caa_original": original_final}
    for method, folder in [("caa_budget_end", "budget_only"), ("caa_relation_end", "relation_and_budget")]:
        final = (base + "/" + folder + "/final_union.npz", "x_adv")
        sources[method] = original + stages(base + "/" + folder, True) + [final]
        published[method] = final
    for method in METHODS[3:]:
        final = (inside + "/" + method + "/final_results.npz", "x_effective")
        sources[method] = stages(inside + "/" + method + "/raw_pool") + [final]
        published[method] = final
    return sources, published


def evaluate_method(audit, method, sources, published, clean_pred, context, out):
    clean, rows = audit.clean, audit.rows
    pools = [dict() for _ in rows]
    source_entries, feasible_entries = 0, 0
    for path, key in sources:
        data = audit.source(path, key)
        source_entries += int(data["native_feasible"].size)
        feasible_entries += int(data["native_feasible"].sum())
        for i, position in enumerate(data["positions"]):
            for j in np.flatnonzero(data["native_feasible"][i]):
                merge_candidate(pools, position, data["x"][i, j], data["score"][i, j],
                    data["distance"][i, j], path, j, data["support_ok"][i, j], data["prediction"][i, j])
    final = audit.source(*published)
    published_success = (clean_pred == 1) & (final["prediction"][:, 0] == 0)
    published_flagged = published_success & ~final["support_ok"][:, 0]
    summary = dict(context, method=method, n_selected=len(rows), clean_detected=int((clean_pred == 1).sum()),
        already_missed=int((clean_pred == 0).sum()), published_newly_evaded=int(published_success.sum()),
        published_evasions_flagged=int(published_flagged.sum()),
        published_evasions_passing_added_rule=int((published_success & ~published_flagged).sum()),
        source_entries_including_reused_originals=source_entries, native_feasible_entries=feasible_entries,
        unique_native_feasible=sum(len(p) for p in pools),
        duplicate_native_feasible_entries=feasible_entries - sum(len(p) for p in pools))
    selected_by_policy, chosen_by_policy, options_by_policy = {}, {}, {}
    output = out / context["model"] / ("seed_" + str(context["seed"])) / method
    output.mkdir(parents=True, exist_ok=False)
    for policy, strengthened in [("native", False), ("native_plus_support", True)]:
        options = evasion_options(pools, clean_pred, strengthened)
        covered = [any(c["support_ok"] or not strengthened for c in p.values()) for p in pools]
        def accept(x):
            valid = audit.engine.checker.check_constraints(clean, x).astype(bool)
            distance = np.linalg.norm(audit.scaler.transform(x) - audit.scaler.transform(clean), axis=1)
            prediction = audit.predict(x).argmax(1)
            changed = np.any(x != clean, axis=1)
            ok = valid & (distance <= audit.epsilon) & (~changed | ((clean_pred == 1) & (prediction == 0)))
            if strengthened:
                ok &= ~support_failures(x, audit.pairs).any(axis=1)
            return ok
        x, chosen, rejections = select_with_final_gate(clean, options, accept)
        predicted = audit.predict(x).argmax(1)
        success = (clean_pred == 1) & (predicted == 0) & np.any(x != clean, axis=1)
        summary[policy + "_covered_records"] = sum(covered)
        summary[policy + "_pool_evaded_records"] = sum(bool(o) for o in options)
        summary[policy + "_final_newly_evaded"] = int(success.sum())
        summary[policy + "_final_evasion_rate"] = float(success.sum() / max(1, (clean_pred == 1).sum()))
        summary[policy + "_final_gate_rejections"] = len(rejections)
        np.savez_compressed(output / (policy + "_final.npz"), x_clean=clean, x_final=x, csv_rows=rows,
                            clean_predictions=clean_pred, predictions=predicted, newly_evaded=success)
        write_json(output / (policy + "_selection.json"), {
            "sources": [{"path": p, "final_key": k} for p, k in sources],
            "selected": [None if c is None else {k: v for k, v in c.items() if k != "vector"} for c in chosen],
            "final_gate_rejections": rejections})
        selected_by_policy[policy], chosen_by_policy[policy] = success, chosen
        options_by_policy[policy] = options
    records = []
    for i, row in enumerate(rows):
        record = dict(context, method=method, csv_row_zero_based=int(row), clean_prediction=int(clean_pred[i]),
            published_new_evasion=bool(published_success[i]), published_evasion_flagged=bool(published_flagged[i]),
            unique_native_feasible=len(pools[i]),
            unique_support_feasible=sum(c["support_ok"] for c in pools[i].values()))
        for policy in selected_by_policy:
            c = chosen_by_policy[policy][i]
            record[policy + "_pool_evasions"] = len(options_by_policy[policy][i])
            record[policy + "_final_new_evasion"] = bool(selected_by_policy[policy][i])
            record[policy + "_selected_sha256"] = None if c is None else c["sha256"]
        record["flagged_published_evasion_recovered"] = bool(published_flagged[i] and selected_by_policy["native_plus_support"][i])
        records.append(record)
    summary["flagged_published_evasions_with_passing_alternative"] = sum(r["flagged_published_evasion_recovered"] for r in records)
    summary["published_evasions_not_recovered_after_rule"] = int((published_success & ~selected_by_policy["native_plus_support"]).sum())
    write_json(output / "summary.json", summary)
    write_csv(output / "records.csv", records)
    return summary, records


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-zip", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--assets", type=Path, default=Path("assets"))
    p.add_argument("--repo", type=Path, default=Path("vendor/tabularbench"))
    args = p.parse_args()
    if args.out.exists():
        p.error("Preserving earlier results: --out must be a NEW directory")
    if (platform.python_version(), np.__version__, torch.__version__) != ("3.8.20", "1.23.5", "1.12.1+cpu"):
        raise RuntimeError("Use the pinned .baseline-env/bin/python installed by scripts/bootstrap.py")
    if args.input_zip.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("Input ZIP is too large for this pilot audit")
    args.out.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    profile_path = Path(__file__).with_name("traffic_consistency_protocol.json")
    profile = read_json(profile_path)
    protocol = {"experiment": profile["experiment"], "status": "running", "profile": profile,
        "profile_sha256": sha256(profile_path), "input_zip_sha256": sha256(args.input_zip),
        "input_zip_name": args.input_zip.name, "code_revision": CODE_REVISION, "data_revision": DATA_REVISION,
        "model_revision": MODEL_REVISION, "python": platform.python_version(), "numpy": np.__version__,
        "torch": torch.__version__, "device": "cpu", "native_relationship_tolerance": 0,
        "new_attack_generation": False, "new_model_training": False, "test_partition_evaluated": False}
    write_json(args.out / "protocol.json", protocol)
    print("Checking input archive and pinned assets...", flush=True)
    evidence = unpack_evidence(args.input_zip, args.out / "input_evidence")
    base, inside = evidence / "baseline", evidence / "inloop"
    b, r = read_json(base / "protocol.json"), read_json(inside / "protocol.json")
    for obj in (b, r):
        if obj["status"] != "completed" or obj["test_partition_evaluated"] or obj["relationship_tolerance"] != 0:
            raise ValueError("Use completed notebook-06 development evidence with the original tolerance")
        for key in ("code_revision", "data_revision", "model_revision"):
            if obj[key] != protocol[key]:
                raise ValueError("Evidence revision mismatch: " + key)
    if b["experiment"] != "development_candidate_consistency_comparison" or r["experiment"] != "repair_during_evolutionary_search":
        raise ValueError("Wrong input experiment")
    for key, name in [("baseline_protocol_sha256", "protocol.json"),
                      ("baseline_selected_inputs_sha256", "selected_development_inputs.npz"),
                      ("baseline_results_sha256", "results.json")]:
        if r[key] != sha256(base / name):
            raise ValueError("Mismatched baseline/in-loop evidence: " + key)
    for folder in (base, inside):
        if read_json(folder / "results.json")["status"] != "completed":
            raise ValueError("Incomplete source results")
    settings = b["settings"]
    if settings != r["settings"] or set(settings["models"]) != {"default", "madry"}:
        raise ValueError("Unexpected or mismatched experiment settings")
    if len(settings["seeds"]) != len(set(settings["seeds"])) or not settings["seeds"]:
        raise ValueError("Expected distinct attack seeds")
    if not np.isfinite(settings["eps"]) or settings["eps"] <= 0:
        raise ValueError("Invalid inherited budget")
    hashes = read_json(Path(__file__).with_name("asset_hashes.json"))
    for name, digest in hashes.items():
        if sha256(args.assets / name) != digest:
            raise ValueError("Pinned asset mismatch: " + name)
    if sha256(base / "compatibility_scaler.json") != profile["scaler_sha256"]:
        raise ValueError("Expected the frozen checkpoint compatibility scaler")
    names = read_json(base / "feature_names.json")
    pairs = aggregate_pairs(names, profile)
    write_json(args.out / "rule_catalog.json", pairs)
    selected = load_npz(base / "selected_development_inputs.npz")
    clean, rows = selected["x_clean"], selected["csv_rows"]
    if (clean.shape != (settings["n_dev"], len(names)) or clean.dtype != np.float32
            or rows.shape != (len(clean),) or not np.issubdtype(rows.dtype, np.integer)
            or len(set(rows.tolist())) != len(rows) or not np.isfinite(clean).all()
            or selected["labels"].shape != rows.shape or not np.all(selected["labels"] == 1)):
        raise ValueError("Unexpected selected development inputs")
    print("Auditing all native train/development controls in both precisions...", flush=True)
    controls = clean_audit(args.assets, evidence, args.out, profile, names, pairs, selected)
    print("Clean controls:", controls["rows"], "rows; rule passed:", controls["rule_passed_all_clean_controls"], flush=True)
    engine = RuleEngine(args.repo, args.assets / "ctu_13_neris_metadata.csv", names)
    if not engine.checker.check_constraints(clean, clean).all():
        raise ValueError("Selected clean controls fail native validity")
    from tabularbench.models.tab_scaler import TabScaler, ScalerData
    from tabularbench.models.tabsurvey.mlp_rln import TORCHRLN
    torch.set_num_threads(2)
    scaler = TabScaler(num_scaler="min_max", one_hot_encode=True)
    scaler.fit_scaler_data(ScalerData.load(str(base / "compatibility_scaler.json")))
    if scaler.cat_idx or scaler.num_idx != list(range(len(names))):
        raise ValueError("Unexpected scaler geometry")
    old_comparison = pd.read_csv(inside / "comparison.csv")
    expected_keys = {(m, s, a) for m in settings["models"] for s in settings["seeds"] for a in METHODS}
    keys = list(zip(old_comparison.model, old_comparison.seed, old_comparison.method))
    if set(keys) != expected_keys or len(keys) != len(expected_keys):
        raise ValueError("Missing or duplicate source comparison rows")
    counts = {k: 0 for k in ["stage_source_files", "stage_candidate_entries", "final_source_files",
                             "final_source_vectors", "rescoring_calls", "rescoring_rows"]}
    summaries, records, source_reports = [], [], []
    for model_name in settings["models"]:
        model = TORCHRLN.load_class(str(args.assets / ("torchrln_ctu_13_neris_" + model_name + ".model")),
                                   x_metadata=engine.metadata, scaler=scaler, force_device="cpu")
        clean_pred = model.predict_proba(clean).argmax(1)
        counts["rescoring_calls"] += 1
        counts["rescoring_rows"] += len(clean)
        for seed in settings["seeds"]:
            audit = SourceAudit(evidence, args.out, model, engine, scaler, settings["eps"], selected, pairs, counts)
            sources, published = pool_sources(evidence, model_name, seed)
            for method in METHODS:
                context = {"model": model_name, "seed": int(seed)}
                summary, detail = evaluate_method(audit, method, sources[method], published[method],
                                                 clean_pred, context, args.out)
                old = old_comparison[(old_comparison.model == model_name) & (old_comparison.seed == seed)
                                     & (old_comparison.method == method)].iloc[0]
                if int(old.newly_evaded) != summary["published_newly_evaded"] or int(old.clean_detected) != summary["clean_detected"]:
                    raise ValueError("Published source result was not reproduced")
                summaries.append(summary)
                records.extend(detail)
                print("Audited", model_name, seed, method, "published/native-pool-final/added-rule-final:",
                      summary["published_newly_evaded"], summary["native_final_newly_evaded"],
                      summary["native_plus_support_final_newly_evaded"], flush=True)
            source_reports.extend(audit.reports)
            del audit
    write_csv(args.out / "comparison.csv", summaries)
    write_csv(args.out / "records.csv", records)
    write_csv(args.out / "source_summary.csv", source_reports)
    write_json(args.out / "source_manifest.json", source_reports)
    protocol.update(status="completed", settings=settings, clean_controls_passed=controls["rule_passed_all_clean_controls"],
                    wall_seconds=time.perf_counter() - started)
    result = {"status": "completed", "counts": counts, "clean_controls": controls, "comparison": summaries,
              "wall_seconds": protocol["wall_seconds"], "interpretation": profile["limitations"]}
    write_json(args.out / "protocol.json", protocol)
    write_json(args.out / "results.json", result)
    print("TRAFFIC CONSISTENCY AUDIT COMPLETED. Evidence:", args.out, flush=True)


if __name__ == "__main__":
    main()
