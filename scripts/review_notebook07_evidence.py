"""Independently check notebook-07 rule flags, pool counts and final selections.

Usage: .baseline-env/bin/python scripts/review_notebook07_evidence.py
       AUDIT_DIRECTORY NEW_REVIEW_JSON
Uses direct feature-name pairing rather than the audit's rule/selector helpers.
Source masks were freshly checked by the main runner; this review reconstructs
pool availability from the saved evidence and freshly checks final vectors.
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


def arrays(path):
    with np.load(path, allow_pickle=False) as f:
        return {k: f[k] for k in f.files}


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
    protocol = json.loads((run / "protocol.json").read_text())
    assert protocol["status"] == "completed" and not protocol["test_partition_evaluated"]
    evidence = next((run / "input_evidence").glob("*/baseline/protocol.json")).parent.parent
    base = evidence / "baseline"
    names = json.loads((base / "feature_names.json").read_text())
    pairs = [(i, names.index(n.replace("_sum_", "_max_"))) for i, n in enumerate(names)
             if "_sum_" in n and any(n.startswith(m + "_sum_")
                 for m in ("bytes_in", "bytes_out", "pkts_in", "pkts_out", "duration"))]
    assert len(pairs) == 180
    selected = arrays(base / "selected_development_inputs.npz")
    clean, rows = selected["x_clean"], selected["csv_rows"]
    positions = {int(r): i for i, r in enumerate(rows)}
    manifest = json.loads((run / "source_manifest.json").read_text())
    by_path = {s["source"]: s for s in manifest}
    counts = {"source_files": 0, "source_vectors": 0, "source_pair_decisions": 0,
              "final_matrices": 0, "final_vectors": 0, "pool_record_policy_checks": 0}
    catalog = json.loads((run / "rule_catalog.json").read_text())
    # Align the independently found pairs to the exported catalog only for
    # checking its pair-by-pair mask; acceptance itself uses the independent list.
    ordered = [(names.index(p["sum_feature"]), names.index(p["max_feature"])) for p in catalog]
    assert set(ordered) == set(pairs)
    for entry in manifest:
        source = evidence / entry["source"]
        assert hashlib.sha256(source.read_bytes()).hexdigest() == entry["source_sha256"]
        d = arrays(source)
        x = d[entry["final_key"]][:, None] if entry["final_key"] else d["x_candidates"]
        fresh = np.stack([(x[..., a] > 0) & (x[..., b] == 0) for a, b in ordered], axis=-1)
        saved = arrays(run / "source_audits" / entry["source"])
        np.testing.assert_array_equal(saved["support_failed_pairs"], fresh)
        counts["source_files"] += 1
        counts["source_vectors"] += int(np.prod(x.shape[:2]))
        counts["source_pair_decisions"] += fresh.size
    metadata = pd.read_csv(root / "assets/ctu_13_neris_metadata.csv")
    metadata = metadata[metadata.feature.isin(names)].reset_index(drop=True)
    assert metadata.feature.tolist() == names
    constraints = get_constraints_from_metadata(metadata, get_relation_constraints(
        CsvDataSource(str(root / "assets/ctu_13_neris_metadata.csv"))), names)
    checker = ConstraintChecker(constraints, 0.0)
    scaler = TabScaler(num_scaler="min_max", one_hot_encode=True)
    scaler.fit_scaler_data(ScalerData.load(str(base / "compatibility_scaler.json")))
    comparison = pd.read_csv(run / "comparison.csv")
    summary = []
    for model_name in protocol["settings"]["models"]:
        model = TORCHRLN.load_class(str(root / "assets" / ("torchrln_ctu_13_neris_" + model_name + ".model")),
                                   x_metadata=metadata, scaler=scaler, force_device="cpu")
        clean_pred = model.predict_proba(clean).argmax(1)
        for row in comparison[comparison.model == model_name].itertuples(index=False):
            folder = run / model_name / ("seed_" + str(row.seed)) / row.method
            detail = pd.read_csv(folder / "records.csv")
            np.testing.assert_array_equal(detail.csv_row_zero_based, rows)
            for policy in ("native", "native_plus_support"):
                selection = json.loads((folder / (policy + "_selection.json")).read_text())
                pools = [dict() for _ in rows]
                for source in selection["sources"]:
                    entry = by_path[source["path"]]
                    assert entry["final_key"] == source["final_key"]
                    data = arrays(evidence / source["path"])
                    x = data[source["final_key"]][:, None] if source["final_key"] else data["x_candidates"]
                    masks = arrays(run / "source_audits" / source["path"])
                    eligible = masks["changed"] & masks["native_valid"] & masks["within_budget"]
                    if policy == "native_plus_support":
                        eligible &= ~np.stack([(x[..., a] > 0) & (x[..., b] == 0) for a, b in pairs], axis=-1).any(axis=-1)
                    for i, csv_row in enumerate(data["csv_rows"]):
                        position = positions[int(csv_row)]
                        for j in np.flatnonzero(eligible[i]):
                            pools[position][x[i, j].tobytes()] = masks["predictions"][i, j] == 0
                counts["pool_record_policy_checks"] += len(rows)
                coverage = sum(bool(p) for p in pools)
                evasion_counts = [sum(p.values()) if clean_pred[i] == 1 else 0 for i, p in enumerate(pools)]
                assert coverage == getattr(row, policy + "_covered_records")
                assert sum(n > 0 for n in evasion_counts) == getattr(row, policy + "_pool_evaded_records")
                np.testing.assert_array_equal(detail[policy + "_pool_evasions"], evasion_counts)
                final = arrays(folder / (policy + "_final.npz"))
                x = final["x_final"]
                np.testing.assert_array_equal(final["x_clean"], clean)
                np.testing.assert_array_equal(final["csv_rows"], rows)
                assert checker.check_constraints(clean, x).all()
                distance = np.linalg.norm(scaler.transform(x) - scaler.transform(clean), axis=1)
                assert np.all(distance <= protocol["settings"]["eps"])
                prediction = model.predict_proba(x).argmax(1)
                np.testing.assert_array_equal(final["predictions"], prediction)
                changed = np.any(x != clean, axis=1)
                success = (clean_pred == 1) & (prediction == 0) & changed
                np.testing.assert_array_equal(final["newly_evaded"], success)
                assert success.sum() == getattr(row, policy + "_final_newly_evaded")
                for i, c in enumerate(selection["selected"]):
                    if c is None:
                        np.testing.assert_array_equal(x[i], clean[i])
                    else:
                        assert x[i].tobytes() in pools[i]
                        assert hashlib.sha256(x[i].tobytes()).hexdigest() == c["sha256"]
                        assert pools[i][x[i].tobytes()] and success[i]
                if policy == "native_plus_support":
                    assert not any(np.any((x[:, a] > 0) & (x[:, b] == 0)) for a, b in pairs)
                counts["final_matrices"] += 1
                counts["final_vectors"] += len(x)
            summary.append({"model": model_name, "seed": int(row.seed), "method": row.method,
                            "native_newly_evaded": int(row.native_final_newly_evaded),
                            "added_rule_newly_evaded": int(row.native_plus_support_final_newly_evaded)})
        print("Independent pool/final review passed:", model_name, flush=True)
    result = {"status": "passed", "counts": counts, "comparison": summary,
              "wall_seconds": time.perf_counter() - started,
              "scope": "All exported rule masks independently recomputed; availability deduplicated per original; all final matrices freshly checked and scored with pinned models. Source native masks were checked by the main runner, not independently recomputed in this review."}
    output.write_text(json.dumps(result, indent=2) + "\n")
    print("NOTEBOOK 07 INDEPENDENT REVIEW PASSED", flush=True)


if __name__ == "__main__":
    main()
