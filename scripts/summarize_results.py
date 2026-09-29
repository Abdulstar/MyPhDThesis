"""Write a portable summary CSV from one clean or attack run."""
import argparse
import csv
import json
from pathlib import Path


def summarize(run_dir):
    report = json.loads((run_dir / "results.json").read_text())
    rows = []
    for name, model in report["models"].items():
        c = model["clean"]
        a = model.get("attack", {})
        rows.append({
            "model": name, "test_records": c["n"], "malicious_records": c["malicious"],
            "accuracy_percent": 100 * c["accuracy"], "recall_percent": 100 * c["recall"],
            "false_positive_rate_percent": 100 * c["false_positive_rate"],
            "true_positives": c["tp"], "false_negatives": c["fn"],
            "false_positives": c["fp"], "true_negatives": c["tn"],
            "attack_subset_size": a.get("n_malicious_attacked", ""),
            "new_evasions": a.get("newly_evaded", ""),
            "attack_recall_percent": 100 * a["malicious_recall_after_attack"] if a else "",
        })
    with (run_dir / "summary.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(rows, indent=2))
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    summarize(parser.parse_args().run_dir)
