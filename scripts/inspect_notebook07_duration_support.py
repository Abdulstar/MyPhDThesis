"""Exploratory follow-up to notebook 07; no change to its acceptance policy.

Check whether positive duration has an observed endpoint in the same bucket.
This is source-informed development analysis, not a frozen final evaluation.
Reads native train/development controls and exported notebook-07 source pools.
No attacks, model training, new inference, packet replay or test-row evaluation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "baseline"))
from download_assets import sha256
from relationship_audit import write_json, write_csv
from traffic_consistency import load_npz


def read(path):
    return json.loads(path.read_text())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--audit-run", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--assets", type=Path, default=ROOT / "assets")
    args = p.parse_args()
    if args.out.exists():
        p.error("Preserving earlier work: --out must be a NEW directory")
    run = args.audit_run
    old = read(run / "protocol.json")
    if old["status"] != "completed" or old["profile"]["profile"] != "positive_sum_requires_positive_max_v1":
        raise ValueError("Use a completed notebook 07 audit")
    matches = [v.parent.parent for v in (run / "input_evidence").glob("**/baseline/protocol.json")
               if (v.parent.parent / "inloop/protocol.json").is_file()]
    if len(matches) != 1:
        raise ValueError("Expected one paired notebook 06 evidence root")
    evidence, assets = matches[0], args.assets
    base = evidence / "baseline"
    hashes = read(ROOT / "baseline/asset_hashes.json")
    for filename in ("ctu_13_neris.csv", "ctu_13_neris_metadata.csv"):
        if sha256(assets / filename) != hashes[filename]:
            raise ValueError("Pinned asset mismatch: " + filename)
    names = read(base / "feature_names.json")
    index = {name: i for i, name in enumerate(names)}
    rules = []
    count_families = ["distinct_external_ips", "distinct_src_port", "distinct_dst_port"]
    for direction in old["profile"]["directions"]:
        for port in old["profile"]["ports"]:
            suffix = "_" + direction + "_" + port
            for count in count_families:
                rules.append({"duration_feature": "duration_sum" + suffix,
                              "count_feature": count + suffix,
                              "duration_index": index["duration_sum" + suffix],
                              "count_index": index[count + suffix]})
    assert len(rules) == 108
    def failures(x):
        a, b = [r["duration_index"] for r in rules], [r["count_index"] for r in rules]
        return (x[..., a] > 0) & (x[..., b] == 0)
    args.out.mkdir(parents=True, exist_ok=False)
    protocol = {"status": "running", "experiment": "exploratory_duration_connection_support",
        "parent_protocol_sha256": sha256(run / "protocol.json"),
        "script_sha256": sha256(Path(__file__)),
        "rule": "Reject duration_sum > 0 paired with zero distinct external IPs, zero distinct source ports or zero distinct destination ports in the same bucket.",
        "rules": rules, "source_commit": "2f1624ce0f06055901edfc90219d5072d8d04895",
        "source_url": "https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/aggregated_features_bro_logs.py",
        "timing": "Chosen after inspecting the surviving development candidate; recorded before scanning all clean controls and pools. Post-hoc exploratory analysis.",
        "basis": "The inspected extractor updates duration and all three endpoint sets for every processed connection in a bucket. Their cardinalities cannot remain zero when duration is positive.",
        "limitations": ["Exact reproduction of the pinned CSV from this extractor remains unestablished.",
            "Distinct counts are not connection counts; no multiplication by these counts or duration cap is inferred.",
            "Original notebook 07 metrics are preserved; these are separate exploratory pool availability counts.",
            "Cached native masks and predictions come from the separately verified notebook 07 audit; no new inference occurs here.",
            "No surviving pool candidate would not establish robustness against new or stronger searches.",
            "Passing these necessary conditions would not establish packet realizability or retained malicious function.",
            "Native test rows are not parsed or scored; prior all-row compatibility scaler limitations remain."]}
    write_json(args.out / "protocol.json", protocol)
    limit = old["profile"]["native_training_prefix_rows"]
    dev = np.load(base / "development_indices.npy", allow_pickle=False)
    if dev.shape != (28610,) or np.any(dev < 0) or np.any(dev >= limit):
        raise ValueError("Unexpected native development split")
    split = np.zeros(limit, dtype=np.int8)
    split[dev] = 1
    counts = {(s, y, precision): {"rows": 0, "flagged_rows": 0, "failed_rule_pairs": 0}
              for s in (0, 1) for y in (0, 1) for precision in ("float64", "float32")}
    offset = 0
    flagged = []
    for frame in pd.read_csv(assets / "ctu_13_neris.csv", nrows=limit, chunksize=4096, low_memory=False):
        labels = frame.pop("is_botnet").to_numpy(np.int64)
        assert frame.columns.tolist() == names
        row_ids = np.arange(offset, offset + len(frame))
        for precision in ("float64", "float32"):
            x = frame.to_numpy(dtype=precision)
            bad = failures(x)
            for s in (0, 1):
                for y in (0, 1):
                    mask = (split[row_ids] == s) & (labels == y)
                    item = counts[(s, y, precision)]
                    item["rows"] += int(mask.sum())
                    item["flagged_rows"] += int(bad[mask].any(axis=1).sum())
                    item["failed_rule_pairs"] += int(bad[mask].sum())
            for i in np.flatnonzero(bad.any(axis=1)):
                flagged.append({"csv_row_zero_based": int(row_ids[i]), "label": int(labels[i]),
                    "partition": "development" if split[row_ids[i]] else "train", "precision": precision,
                    "failed_rule_indices": np.flatnonzero(bad[i]).tolist()})
        offset += len(frame)
    assert offset == limit
    clean_summary = [dict(partition="development" if s else "train", label=y, precision=precision, **c)
                     for (s, y, precision), c in counts.items()]
    write_csv(args.out / "clean_controls.csv", clean_summary)
    write_json(args.out / "clean_flagged_records.json", flagged)
    print("Exploratory clean-control flagged rows (both precisions):", len(flagged), flush=True)
    selected = load_npz(base / "selected_development_inputs.npz")
    rows = selected["csv_rows"]
    positions = {int(row): i for i, row in enumerate(rows)}
    assert not failures(selected["x_clean"]).any()
    comparison = pd.read_csv(run / "comparison.csv")
    source_cache, source_reports = {}, []
    summaries, records = [], []
    for row in comparison.itertuples(index=False):
        method_root = run / row.model / ("seed_" + str(row.seed)) / row.method
        selection = read(method_root / "native_plus_support_selection.json")
        final = load_npz(method_root / "native_plus_support_final.npz")
        clean_predictions = final["clean_predictions"]
        pools_before, pools_after = [set() for _ in rows], [set() for _ in rows]
        for source in selection["sources"]:
            path = source["path"]
            if path not in source_cache:
                original = load_npz(evidence / path)
                x = original[source["final_key"]][:, None] if source["final_key"] else original["x_candidates"]
                audit = load_npz(run / "source_audits" / path)
                eligible = (audit["native_valid"] & audit["within_budget"] & audit["changed"]
                            & ~audit["support_failed_pairs"].any(axis=-1))
                bad = failures(x).any(axis=-1)
                entries = []
                for i, csv_row in enumerate(original["csv_rows"]):
                    pos = positions[int(csv_row)]
                    for j in np.flatnonzero(eligible[i] & (audit["predictions"][i] == 0)):
                        digest = hashlib.sha256(x[i, j].tobytes()).hexdigest()
                        entries.append((pos, digest, bool(bad[i, j])))
                source_cache[path] = entries
                source_reports.append({"source": path, "sha256": sha256(evidence / path),
                    "candidate_entries": int(np.prod(x.shape[:2])),
                    "notebook07_feasible_entries": int(eligible.sum()),
                    "notebook07_feasible_entries_flagged": int((eligible & bad).sum()),
                    "notebook07_feasible_benign_entries": len(entries),
                    "notebook07_feasible_benign_entries_flagged": sum(b for _, _, b in entries)})
            for pos, digest, bad in source_cache[path]:
                if clean_predictions[pos] == 1:
                    pools_before[pos].add(digest)
                    if not bad:
                        pools_after[pos].add(digest)
        details = pd.read_csv(method_root / "records.csv")
        np.testing.assert_array_equal(details.csv_row_zero_based, rows)
        np.testing.assert_array_equal(details.native_plus_support_pool_evasions, [len(s) for s in pools_before])
        assert sum(bool(s) for s in pools_before) == row.native_plus_support_pool_evaded_records
        for i, csv_row in enumerate(rows):
            records.append({"model": row.model, "seed": int(row.seed), "method": row.method,
                "csv_row_zero_based": int(csv_row), "before_unique_evasion_vectors": len(pools_before[i]),
                "after_unique_evasion_vectors": len(pools_after[i])})
        summaries.append({"model": row.model, "seed": int(row.seed), "method": row.method,
            "initially_detected": int(row.clean_detected), "notebook07_final_newly_evaded": int(row.native_plus_support_final_newly_evaded),
            "notebook07_pool_evaded_records": sum(bool(s) for s in pools_before),
            "exploratory_pool_evaded_records": sum(bool(s) for s in pools_after),
            "notebook07_unique_evasion_vectors": sum(len(s) for s in pools_before),
            "exploratory_unique_evasion_vectors": sum(len(s) for s in pools_after)})
    write_csv(args.out / "comparison.csv", summaries)
    write_csv(args.out / "records.csv", records)
    write_csv(args.out / "source_summary.csv", source_reports)
    protocol["status"] = "completed"
    write_json(args.out / "protocol.json", protocol)
    result = {"status": "completed", "clean_controls": clean_summary, "clean_flagged_record_precision_entries": len(flagged),
              "source_files_checked": len(source_cache), "source_entries_checked": sum(s["candidate_entries"] for s in source_reports),
              "comparison": summaries, "limitations": protocol["limitations"]}
    write_json(args.out / "results.json", result)
    print("Duration/endpoint exploratory diagnostic complete:", args.out, flush=True)
    for row in summaries:
        if row["model"] == "default":
            print(row["seed"], row["method"], "pool records before/after:",
                  row["notebook07_pool_evaded_records"], row["exploratory_pool_evaded_records"], flush=True)


if __name__ == "__main__":
    main()
