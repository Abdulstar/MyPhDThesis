"""Recheck notebook-08 exported evidence independently of its profile/selector.

Usage: .baseline-env/bin/python scripts/review_notebook08_evidence.py RUN NEW_JSON
Checks all exported vectors and final matrices with fresh native masks/scores.
Intermediate fitness vectors are not exported; their repair/evaluation digests
and budget logs are cross-checked, not independently reconstructed.
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


def read(path):
    return json.loads(path.read_text())


def arrays(path):
    with np.load(path, allow_pickle=False) as f:
        return {k: f[k] for k in f.files}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    run, output = [Path(p).resolve() for p in sys.argv[1:]]
    if output.exists():
        raise FileExistsError("Preserving earlier reviews: " + str(output))
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "vendor/tabularbench"))
    from tabularbench.models.tab_scaler import TabScaler, ScalerData
    from tabularbench.models.tabsurvey.mlp_rln import TORCHRLN
    from tabularbench.datasets.dataset import CsvDataSource
    from tabularbench.datasets.samples.ctu_13_neris import get_relation_constraints
    from tabularbench.constraints.constraints import get_constraints_from_metadata
    from tabularbench.constraints.constraints_checker import ConstraintChecker
    torch.set_num_threads(2)
    started = time.perf_counter()
    protocol = read(run / "protocol.json")
    assert protocol["status"] == "completed" and not protocol["test_partition_evaluated"]
    assert protocol["native_relationship_tolerance"] == 0
    assert digest(run / "fixed_profile.json") == protocol["profile_sha256"]
    assert digest(run / "compatibility_scaler.json") == protocol["profile"]["scaler_sha256"]
    names = read(run / "feature_names.json")
    aggregate = [(i, names.index(n.replace("_sum_", "_max_"))) for i, n in enumerate(names)
                 if any(n.startswith(m + "_sum_") for m in ("bytes_in", "bytes_out", "pkts_in", "pkts_out", "duration"))]
    presence = [(i, names.index(family + n[len("duration_sum"):]))
                for i, n in enumerate(names) if n.startswith("duration_sum_")
                for family in ("distinct_external_ips", "distinct_src_port", "distinct_dst_port")]
    assert len(aggregate) == 180 and len(presence) == 108
    catalog = read(run / "rule_catalog.json")
    ordered = {}
    for family, independent in (("aggregate", aggregate), ("presence", presence)):
        ordered[family] = [(names.index(c["positive_feature"]), names.index(c["required_positive_feature"]))
                           for c in catalog if c["family"] == family]
        assert set(ordered[family]) == set(independent)

    def flags(x, pairs):
        return np.stack([(x[..., a] > 0) & (x[..., b] == 0) for a, b in pairs], axis=-1)

    def profile_ok(x):
        return ~flags(x, aggregate).any(-1) & ~flags(x, presence).any(-1)

    selected = arrays(run / "selected_inputs.npz")
    clean, rows = selected["x_clean"], selected["csv_rows"]
    assert clean.dtype == np.float32 and profile_ok(clean).all()
    positions = {int(r): i for i, r in enumerate(rows)}
    manifest = read(run / "source_manifest.json")
    assert len({s["source"] for s in manifest}) == len(manifest)
    metadata = pd.read_csv(root / "assets/ctu_13_neris_metadata.csv")
    metadata = metadata[metadata.feature.isin(names)].reset_index(drop=True)
    assert metadata.feature.tolist() == names
    constraints = get_constraints_from_metadata(metadata, get_relation_constraints(
        CsvDataSource(str(root / "assets/ctu_13_neris_metadata.csv"))), names)
    checker = ConstraintChecker(constraints, 0.0)
    scaler = TabScaler(num_scaler="min_max", one_hot_encode=True)
    scaler.fit_scaler_data(ScalerData.load(str(run / "compatibility_scaler.json")))
    epsilon = protocol["settings"]["eps"]
    comparison = pd.read_csv(run / "comparison.csv")
    assert len(comparison) == len(protocol["methods"]) * len(protocol["settings"]["models"]) * len(protocol["settings"]["seeds"])
    counts = dict(source_files=0, source_vectors=0, added_rule_decisions=0,
                  final_matrices=0, final_vectors=0, inloop_generation_runs=0,
                  logged_fitness_batches=0, logged_fitness_rows=0)
    score_max_difference = 0.0
    summary, audit_summary = [], []
    for model_name in protocol["settings"]["models"]:
        model = TORCHRLN.load_class(str(root / "assets" / ("torchrln_ctu_13_neris_" + model_name + ".model")),
                                   x_metadata=metadata, scaler=scaler, force_device="cpu")
        clean_pred = model.predict_proba(clean).argmax(1)
        cache = {}
        for entry in [s for s in manifest if s["source"].split("/")[0] == model_name]:
            source = run / entry["source"]
            assert digest(source) == entry["source_sha256"]
            d = arrays(source)
            source_positions = np.array([positions[int(r)] for r in d["csv_rows"]])
            np.testing.assert_array_equal(d["x_clean"], clean[source_positions])
            x = d["x_candidates"]
            if entry["matrix_geometry"]:
                np.testing.assert_array_equal(d["csv_rows"], rows)
                valid = checker.check_constraints(d["x_clean"], x).astype(bool)[:, None]
                distance = np.linalg.norm(scaler.transform(x) - scaler.transform(d["x_clean"]), axis=1)[:, None]
                x = x[:, None]
            else:
                valid = np.stack([checker.check_constraints(d["x_clean"][i:i+1], population).astype(bool)
                                  for i, population in enumerate(x)])
                distance = np.stack([np.linalg.norm(scaler.transform(population) -
                    scaler.transform(d["x_clean"][i:i+1]), axis=1) for i, population in enumerate(x)])
            saved = arrays(run / "evaluated_sources" / entry["source"])
            changed = np.any(x != d["x_clean"][:, None], axis=-1)
            for key, value in (("valid", valid), ("within_budget", distance <= epsilon), ("changed", changed)):
                np.testing.assert_array_equal(saved[key], value)
            np.testing.assert_allclose(saved["distance"], distance, rtol=1e-6, atol=1e-8)
            for family in ("aggregate", "presence"):
                failed = flags(x, ordered[family])
                np.testing.assert_array_equal(saved[family + "_failed"], failed)
                counts["added_rule_decisions"] += failed.size
            probability = model.predict_proba(x.reshape(-1, len(names))).reshape(x.shape[:2] + (2,))
            prediction = probability.argmax(-1)
            np.testing.assert_array_equal(saved["predictions"], prediction)
            score_max_difference = max(score_max_difference, float(np.abs(saved["malicious_score"] - probability[..., 1]).max()))
            np.testing.assert_allclose(saved["malicious_score"], probability[..., 1], rtol=1e-4, atol=1e-5)
            feasible = valid & (distance <= epsilon) & changed
            support = profile_ok(x)
            assert entry["candidate_entries"] == feasible.size
            assert entry["native_changed_feasible"] == feasible.sum()
            assert entry["profile_changed_feasible"] == (feasible & support).sum()
            cache[entry["source"]] = (x, source_positions, feasible, support, prediction)
            counts["source_files"] += 1
            counts["source_vectors"] += feasible.size

        for row in comparison[comparison.model == model_name].itertuples(index=False):
            folder = run / model_name / ("seed_" + str(row.seed)) / row.method
            selection = read(folder / "selection.json")
            detail = pd.read_csv(folder / "records.csv")
            np.testing.assert_array_equal(detail.csv_row_zero_based, rows)
            pools = [dict() for _ in rows]
            for source in selection["sources"]:
                x, source_positions, feasible, support, prediction = cache[source["path"]]
                for i, position in enumerate(source_positions):
                    for j in np.flatnonzero(feasible[i]):
                        pools[position][x[i, j].tobytes()] = (bool(support[i, j]), int(prediction[i, j]))
            native_counts = [len(p) for p in pools]
            profile_counts = [sum(v[0] for v in p.values()) for p in pools]
            evasion_counts = [sum(v[0] and v[1] == 0 for v in p.values()) if clean_pred[i] == 1 else 0
                              for i, p in enumerate(pools)]
            np.testing.assert_array_equal(detail.unique_native_feasible, native_counts)
            np.testing.assert_array_equal(detail.unique_profile_feasible, profile_counts)
            np.testing.assert_array_equal(detail.unique_profile_evasions, evasion_counts)
            assert sum(n > 0 for n in profile_counts) == row.covered_records
            assert sum(n > 0 for n in evasion_counts) == row.pool_evaded_records
            final = arrays(folder / "final.npz")
            x = final["x_final"]
            np.testing.assert_array_equal(final["x_clean"], clean)
            np.testing.assert_array_equal(final["csv_rows"], rows)
            np.testing.assert_array_equal(final["clean_predictions"], clean_pred)
            assert checker.check_constraints(clean, x).all() and profile_ok(x).all()
            distance = np.linalg.norm(scaler.transform(x) - scaler.transform(clean), axis=1)
            assert np.all(distance <= epsilon)
            np.testing.assert_allclose(final["distance"], distance, rtol=1e-6, atol=1e-8)
            prediction = model.predict_proba(x).argmax(1)
            np.testing.assert_array_equal(final["predictions"], prediction)
            success = (clean_pred == 1) & (prediction == 0) & np.any(x != clean, axis=1)
            np.testing.assert_array_equal(final["newly_evaded"], success)
            np.testing.assert_array_equal(detail.newly_evaded, success)
            assert success.sum() == row.newly_evaded
            assert (clean_pred == 1).sum() == row.clean_detected
            for i, item in enumerate(selection["selected"]):
                if item is None:
                    np.testing.assert_array_equal(x[i], clean[i])
                else:
                    assert pools[i][x[i].tobytes()] == (True, 0) and success[i]
                    assert hashlib.sha256(x[i].tobytes()).hexdigest() == item["sha256"]
                    source_x, source_pos, _, _, _ = cache[item["source"]]
                    source_i = np.flatnonzero(source_pos == i)
                    assert len(source_i) == 1
                    np.testing.assert_array_equal(x[i], source_x[source_i[0], item["index"]])
            counts["final_matrices"] += 1
            counts["final_vectors"] += len(x)
            summary.append(dict(model=model_name, seed=int(row.seed), method=row.method,
                newly_evaded=int(success.sum()), evaded_csv_rows=rows[success].tolist()))

        for seed in protocol["settings"]["seeds"]:
            folder = run / model_name / ("seed_" + str(seed))
            original = read(folder / "original_generation/generation.json")
            for method in ("caa_profile_budget_inloop", "caa_profile_relation_inloop"):
                generated = read(folder / method / "generation.json")
                assert generated["forward_counts"] == original["forward_counts"]
                assert generated["moeva_csv_rows"] == original["moeva_csv_rows"]
                assert generated["population_size"] == original["population_size"]
                for filename in ("00_NoAttack_candidates.npz", "01_CAPGD_candidates.npz"):
                    a = arrays(folder / "original_generation/raw_pool" / filename)
                    b = arrays(folder / method / "raw_pool" / filename)
                    for key in ("x_clean", "x_candidates", "csv_rows", "labels", "valid", "within_budget", "fooled"):
                        np.testing.assert_array_equal(a[key], b[key])
                report = read(folder / method / "generation_audit.json")
                expected = generated["population_size"] + (protocol["settings"]["generations"] - 1) * protocol["settings"]["offspring"]
                assert [r["csv_row_zero_based"] for r in report["records"]] == generated["moeva_csv_rows"]
                batch_rows = unique = unchanged = restored = 0
                for record in report["records"]:
                    repairs, evaluations = record["repair_batches"], record["evaluation_batches"]
                    assert len(repairs) == len(evaluations) == protocol["settings"]["generations"]
                    assert sum(e["model_rows_evaluated"] for e in evaluations) == expected == record["objective_model_rows"]
                    unique += record["unique_evaluated_vectors"]
                    for repair, evaluation in zip(repairs, evaluations):
                        n = evaluation["model_rows_evaluated"]
                        assert repair["batch_index"] == evaluation["batch_index"]
                        assert repair["native_population_sha256"] == evaluation["native_population_sha256"]
                        assert repair["candidates"] == repair["added_profile_valid_rows"] == evaluation["added_profile_valid_rows"] == n
                        assert evaluation["in_budget_rows"] == n
                        if method == "caa_profile_relation_inloop":
                            assert evaluation["valid_rows"] == n
                        batch_rows += n
                        unchanged += evaluation["unchanged_rows"]
                        restored += repair["profile_blocks_restored"]
                        counts["logged_fitness_batches"] += 1
                assert batch_rows == report["total_objective_model_rows"]
                counts["logged_fitness_rows"] += batch_rows
                counts["inloop_generation_runs"] += 1
                audit_summary.append(dict(model=model_name, seed=seed, method=method,
                    fitness_rows=batch_rows, unique_vectors_summed_per_original=unique,
                    unchanged_fitness_rows=unchanged, profile_blocks_restored=restored,
                    core_forward_rows=generated["forward_counts"]["forward_rows"]))
        print("Independent exported-vector/final/budget review passed:", model_name, flush=True)
    result = {"status": "passed", "smoke_check_only": protocol["smoke_check_only"], "counts": counts,
              "comparison": summary, "generation_audits": audit_summary,
              "maximum_score_difference": score_max_difference,
              "wall_seconds": time.perf_counter() - started,
              "scope": "All exported native masks, rule masks, distances and classes recomputed; pools independently deduplicated; final provenance/validity/evasions checked. Intermediate fitness vectors are not exported: generation logs and matching repair/evaluation digests are cross-checked, not reconstructed."}
    output.write_text(json.dumps(result, indent=2) + "\n")
    print("NOTEBOOK 08 INDEPENDENT REVIEW PASSED", flush=True)


if __name__ == "__main__":
    main()
