"""Summarize the complete 128-record replication after independent review.

Seeds are repeated measurements of each original, not additional samples.
Bootstrap intervals are exploratory and do not resolve host/window dependence.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

PRIMARY_END = "caa_profile_relation_end"
PRIMARY_LOOP = "caa_profile_relation_inloop"
BOOTSTRAP_SEED = 20261021
BOOTSTRAP_REPLICATES = 10000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text())


def array_file(path):
    with np.load(path, allow_pickle=False) as f:
        return {k: f[k] for k in f.files}


def paired_effect(end_success, loop_success, detected, seed=BOOTSTRAP_SEED):
    end_success = np.asarray(end_success)
    loop_success = np.asarray(loop_success)
    detected = np.asarray(detected)
    require(end_success.dtype == np.bool_ and loop_success.dtype == np.bool_ and detected.dtype == np.bool_,
            "Expected Boolean outcomes/detection masks")
    require(end_success.ndim == 2 and end_success.shape == loop_success.shape
            and detected.shape == (end_success.shape[0],) and end_success.shape[1] == 3, "Expected originals by three seeds")
    require(not end_success[~detected].any() and not loop_success[~detected].any(), "Clean misses counted as new evasions")
    differences = (loop_success.astype(float) - end_success.astype(float)).mean(axis=1)
    values = differences[detected]
    if len(values) == 0:
        return differences, {"mean_difference_pp": None, "exploratory_95pct_interval_pp": None, "detected_originals": 0}
    rng = np.random.RandomState(seed)
    estimates = values[rng.randint(0, len(values), size=(BOOTSTRAP_REPLICATES, len(values)))].mean(axis=1)
    interval = np.quantile(estimates, [.025, .975]) * 100
    return differences, {"mean_difference_pp": float(values.mean() * 100),
        "exploratory_95pct_interval_pp": interval.tolist(), "detected_originals": int(len(values)),
        "originals_favoring_inloop": int((values > 0).sum()), "originals_favoring_end": int((values < 0).sum()),
        "originals_tied": int((values == 0).sum()), "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_seed": seed, "resampling_unit": "original record after averaging its three paired seed differences",
        "degenerate_empirical_interval": bool(interval[0] == interval[1]),
        "interval_caution": "Exploratory development-sample interval; unknown host/window dependence is not accounted for. A zero-width interval is not proof of population equivalence."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), "Use a new analysis directory")
    protocol = read(args.run / "protocol.json")
    results = read(args.run / "results.json")
    review = read(args.review)
    manifest = read(args.run / "frozen_followup_manifest.json")
    require(protocol["experiment"] == "frozen_128_development_replication" and
            protocol["status"] == results["status"] == "completed", "Incomplete replication")
    require(not protocol["smoke_check_only"] and not protocol["single_pair_only"] and not protocol["preflight_only"]
            and not protocol["test_partition_evaluated"] and not protocol["new_model_training"], "Not the full fixed development experiment")
    require(review["status"] == "passed" and not review["smoke_check_only"] and
            review["counts"]["final_matrices"] == 30 and review["counts"]["final_vectors"] == 3840,
            "Independent review is missing or incomplete")
    expected = {k: manifest[k] for k in ("selection_seed", "models", "seeds", "steps", "generations", "offspring", "eps")}
    expected["n_dev"] = 128
    require(protocol["settings"] == expected and protocol["generation_runs"] == 18, "Fixed experiment settings changed")
    require(protocol["profile_sha256"] == manifest["profile_sha256"] and
            protocol["frozen_inputs_sha256"] == manifest["inputs_sha256"], "Frozen inputs/profile changed")
    original = array_file(args.run / "selected_inputs.npz")
    frozen = array_file(args.run / "input_evidence/notebook09/followup_inputs.npz")
    for key in ("x_clean", "labels", "csv_rows"):
        np.testing.assert_array_equal(original[key], frozen[key])
    rows = original["csv_rows"]
    require(rows.shape == (128,) and len(np.unique(rows)) == 128 and rows.tolist() == manifest["csv_rows"], "Selected rows changed")
    require(not set(rows.tolist()) & set(manifest["pilot_csv_rows"]), "Pilot overlap")
    comparison = results["comparison"]
    require(len(comparison) == 30 and len({(r["model"], r["seed"], r["method"]) for r in comparison}) == 30,
            "Missing/duplicate method results")
    require(all(r["generation_forward_counts_match_original"] for r in comparison), "Unmatched core generation budgets")
    details, summaries = [], {}
    for model in ("default", "madry"):
        successes, clean_predictions = {}, None
        for method in protocol["methods"]:
            per_seed = []
            for seed in (0, 1, 2):
                data = array_file(args.run / model / ("seed_" + str(seed)) / method / "final.npz")
                np.testing.assert_array_equal(data["csv_rows"], rows)
                np.testing.assert_array_equal(data["x_clean"], original["x_clean"])
                if clean_predictions is None:
                    clean_predictions = data["clean_predictions"]
                np.testing.assert_array_equal(data["clean_predictions"], clean_predictions)
                computed = (clean_predictions == 1) & (data["predictions"] == 0) & np.any(data["x_final"] != data["x_clean"], axis=1)
                np.testing.assert_array_equal(data["newly_evaded"], computed)
                matching = [r for r in comparison if (r["model"], r["seed"], r["method"]) == (model, seed, method)]
                require(len(matching) == 1 and matching[0]["newly_evaded"] == int(computed.sum())
                        and matching[0]["clean_detected"] == int((clean_predictions == 1).sum()), "Summary/count mismatch")
                per_seed.append(computed)
            successes[method] = np.stack(per_seed, axis=1)
        detected = clean_predictions == 1
        differences, primary = paired_effect(successes[PRIMARY_END], successes[PRIMARY_LOOP], detected)
        summaries[model] = {"selected_records": 128, "clean_detected": int(detected.sum()),
            "already_missed": int((~detected).sum()), "primary_comparison": primary,
            "method_new_evasions_by_seed": {m: s.sum(axis=0).tolist() for m, s in successes.items()},
            "method_mean_new_evasion_rate": {m: float(s[detected].mean()) if detected.any() else None for m, s in successes.items()}}
        for i, row in enumerate(rows):
            details.append({"model": model, "csv_row_zero_based": int(row), "initially_detected": bool(detected[i]),
                "end_success_seeds": int(successes[PRIMARY_END][i].sum()),
                "inloop_success_seeds": int(successes[PRIMARY_LOOP][i].sum()),
                "paired_mean_success_difference": float(differences[i])})
    # The independent review derives these counts from retained optimizer logs.
    # Unique values are counted within each original; cross-original duplicates
    # are irrelevant to this measure. Restored blocks are not candidate counts.
    optimizer = []
    for item in review["generation_audits"]:
        n = item["fitness_rows"]
        optimizer.append(dict(item,
            repeated_fitness_vector_fraction=1-item["unique_vectors_summed_per_original"]/n if n else None,
            unchanged_fitness_vector_fraction=item["unchanged_fitness_rows"]/n if n else None,
            restored_profile_blocks_per_fitness_row=item["profile_blocks_restored"]/n if n else None))
    args.out.mkdir(parents=True, exist_ok=False)
    result = {"status": "completed", "analysis": "fixed_128_paired_development_replication",
        "protocol_sha256": hashlib.sha256((args.run / "protocol.json").read_bytes()).hexdigest(),
        "independent_review_sha256": hashlib.sha256(args.review.read_bytes()).hexdigest(),
        "primary_methods": {"end": PRIMARY_END, "inloop": PRIMARY_LOOP}, "models": summaries,
        "optimizer_accounting": optimizer, "evaluation_notes": protocol["evaluation_notes"],
        "no_population_independence_claim": True, "no_equal_total_compute_claim": True,
        "claim_scope": protocol["claim_scope"]}
    with (args.out / "paired_summary.json").open("x") as f:
        json.dump(result, f, indent=2, allow_nan=False); f.write("\n")
    with (args.out / "paired_by_original.csv").open("x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(details[0])); writer.writeheader(); writer.writerows(details)
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
