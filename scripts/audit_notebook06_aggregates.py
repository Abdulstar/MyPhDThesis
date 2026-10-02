"""Flag positive sums with zero maxima in saved notebook-06 representatives.

This post-hoc diagnostic does not alter official acceptance or rerun attacks.
It assumes each named sum/max pair summarizes the same observations. Passing
this necessary-condition check is not proof of traffic realizability.
"""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np


def load(path):
    with np.load(path, allow_pickle=False) as archive:
        return {key: archive[key] for key in archive.files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-run", type=Path, required=True)
    parser.add_argument("--inloop-run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Preserving earlier reviews: --out must be a NEW file")
    baseline, inloop = args.baseline_run, args.inloop_run
    protocol = json.loads((inloop / "protocol.json").read_text())
    baseline_protocol = json.loads((baseline / "protocol.json").read_text())
    assert protocol["status"] == baseline_protocol["status"] == "completed"
    selected_path = baseline / "selected_development_inputs.npz"
    assert hashlib.sha256(selected_path.read_bytes()).hexdigest() == protocol["baseline_selected_inputs_sha256"]
    selected = load(selected_path)
    clean, rows = selected["x_clean"], selected["csv_rows"]
    names = json.loads((baseline / "feature_names.json").read_text())
    lookup = {name: index for index, name in enumerate(names)}
    pairs = [(i, lookup[name.replace("_sum_", "_max_")])
             for i, name in enumerate(names)
             if "_sum_" in name and name.split("_sum_")[0] in ("duration", "bytes_out", "pkts_out")]
    assert len(pairs) == 108 and len(names) == clean.shape[1] == 757
    sum_indices, max_indices = zip(*pairs)

    def flags(x):
        return (x[:, sum_indices] > 0) & (x[:, max_indices] == 0)

    def flag_details(x, record, mask):
        details = []
        for pair_index in np.flatnonzero(mask):
            a, b = pairs[pair_index]
            details.append({"sum_feature": names[a], "max_feature": names[b],
                            "clean_sum": float(clean[record, a]), "clean_max": float(clean[record, b]),
                            "final_sum": float(x[record, a]), "final_max": float(x[record, b]),
                            "introduced_relative_to_clean": bool(not clean_flags[record, pair_index])})
        return details

    clean_flags = flags(clean)
    reports = []
    settings = protocol["settings"]
    for model in settings["models"]:
        for seed in settings["seeds"]:
            prefix = Path(model) / ("seed_" + str(seed))
            original = load(baseline / prefix / "original_final.npz")
            original_success = (original["clean_predictions"] == 1) & (original["predictions"] == 0)
            sources = [
                ("caa_original", baseline / prefix / "original_final.npz", "x_effective"),
                ("caa_budget_end", baseline / prefix / "budget_only/final_union.npz", "x_adv"),
                ("caa_relation_end", baseline / prefix / "relation_and_budget/final_union.npz", "x_adv"),
                ("caa_budget_inloop", inloop / prefix / "caa_budget_inloop/final_results.npz", "x_effective"),
                ("caa_relation_inloop", inloop / prefix / "caa_relation_inloop/final_results.npz", "x_effective"),
            ]
            for method, path, vector_key in sources:
                data = load(path)
                np.testing.assert_array_equal(data["x_clean"], clean)
                np.testing.assert_array_equal(data["csv_rows"], rows)
                np.testing.assert_array_equal(data["clean_predictions"], original["clean_predictions"])
                x = data[vector_key]
                assert x.shape == clean.shape and np.isfinite(x).all()
                final_flags = flags(x)
                flagged = final_flags.any(axis=1)
                success = (data["clean_predictions"] == 1) & (data["predictions"] == 0)
                extra = success & ~original_success
                events = []
                for i in np.flatnonzero(success):
                    changes = [{"feature": names[j], "clean": float(clean[i, j]), "final": float(x[i, j])}
                               for j in np.flatnonzero(x[i] != clean[i])]
                    events.append({"csv_row_zero_based": int(rows[i]),
                                   "extra_evasion_relative_to_original_caa": bool(extra[i]),
                                   "changed_features": changes,
                                   "aggregate_flags": flag_details(x, i, final_flags[i])})
                reports.append({"model": model, "seed": seed, "method": method,
                    "source_npz_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "vector_key": vector_key, "final_records_flagged": int(flagged.sum()),
                    "newly_evaded": int(success.sum()), "evaded_records_flagged": int((success & flagged).sum()),
                    "extra_evasions_relative_to_original_caa": int(extra.sum()),
                    "extra_evasions_flagged": int((extra & flagged).sum()), "evasions": events})
    output = {
        "status": "completed", "analysis_type": "post_hoc_diagnostic_only",
        "official_results_modified": False, "model_rescoring_performed_by_this_script": False,
        "rule": "sum > 0 and max == 0, exact native stored values, in 108 duration/bytes_out/pkts_out pairs",
        "assumption": "Each named sum/max pair summarizes the same observations; verify feature-extractor semantics before making a traffic-level claim.",
        "limitations": "This is one necessary-condition diagnostic, not a complete feasibility test. Unflagged vectors are not established as realizable or malicious. Counts across seeds/methods reuse the same originals.",
        "selected_inputs_sha256": hashlib.sha256(selected_path.read_bytes()).hexdigest(),
        "selected_records": len(rows), "clean_records_flagged": int(clean_flags.any(axis=1).sum()),
        "clean_flags": [{"csv_row_zero_based": int(rows[i]), "flags": flag_details(clean, i, clean_flags[i])}
                        for i in np.flatnonzero(clean_flags.any(axis=1))],
        "runs": reports,
    }
    with args.out.open("x") as stream:
        json.dump(output, stream, indent=2)
        stream.write("\n")
    print("Aggregate diagnostic completed: {} method/seed comparisons, {} clean records flagged".format(
        len(reports), output["clean_records_flagged"]))
    for row in reports:
        if row["newly_evaded"]:
            print(row["model"], row["seed"], row["method"], "flagged evasions",
                  str(row["evaded_records_flagged"]) + "/" + str(row["newly_evaded"]),
                  "flagged extras", str(row["extra_evasions_flagged"]) + "/" + str(row["extra_evasions_relative_to_original_caa"]))


if __name__ == "__main__":
    main()
