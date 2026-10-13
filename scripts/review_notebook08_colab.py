"""Review notebook-08 reproduction and an exploratory duration/packet bound.

Usage: python scripts/review_notebook08_colab.py --run-zip USER.zip
  --reference-zip REFERENCE.zip --published-tree TREE.json --dataset CSV --out NEW.json

Requires NumPy and pandas; executes no code from either ZIP. Model/native-checker
outputs are compared with the previously validated reference, not rerun here.
The extra bound is conditional on every contributing connection record having
at least one counted packet. It is a post-hoc diagnostic, not a changed protocol
or packet-realizability proof. Pool availability is not final matrix reselection.
"""
import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import stat
import time
import zipfile

import numpy as np
import pandas as pd

REFERENCE_SHA256 = "693f2991a78faf0258cba31a1fd9b6293c562a0d76794395d54c25b0cb43a857"
COMMIT = "d6d9f0471b9e68b2d323ee1f796613383c9eee2a"
TREE = "a631b440dee2bcf3b6432af2a9dad7d18b96e71a"


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


class Evidence:
    def __init__(self, path):
        self.z = zipfile.ZipFile(path)
        entries = self.z.infolist()
        names = [e.filename for e in entries]
        if len(names) != len(set(names)) or len(names) > 5000 or sum(e.file_size for e in entries) > 1024 ** 3:
            raise ValueError("Duplicate or oversized archive")
        for e in entries:
            p = PurePosixPath(e.filename)
            if p.is_absolute() or ".." in p.parts or "\\" in e.filename or stat.S_ISLNK(e.external_attr >> 16):
                raise ValueError("Unsafe archive path")
            if e.file_size > 128 * 1024 ** 2:
                raise ValueError("Oversized member")
        roots = {n.split("/")[0] for n in names}
        if len(roots) != 1:
            raise ValueError("Expected one session")
        self.root = next(iter(roots)) + "/"
        self.paths = {n[len(self.root):] for n in names}

    def raw(self, path):
        return self.z.read(self.root + path)

    def read(self, path):
        return json.loads(self.raw(path))

    def arrays(self, path):
        data = self.raw(path)
        with zipfile.ZipFile(io.BytesIO(data)) as inner:
            entries = inner.infolist()
            if len(entries) > 128 or sum(e.file_size for e in entries) > 128 * 1024 ** 2:
                raise ValueError("Oversized NumPy archive")
            for entry in entries:
                with inner.open(entry) as f:
                    version = np.lib.format.read_magic(f)
                    if version == (1, 0):
                        shape, _, dtype = np.lib.format.read_array_header_1_0(f)
                    elif version == (2, 0):
                        shape, _, dtype = np.lib.format.read_array_header_2_0(f)
                    else:
                        raise ValueError("Unsupported array header")
                    if dtype.hasobject or math.prod(shape) * dtype.itemsize != entry.file_size - f.tell():
                        raise ValueError("Unsafe or inconsistent array")
        with np.load(io.BytesIO(data), allow_pickle=False) as z:
            return {k: z[k] for k in z.files}


def without_times(obj):
    if isinstance(obj, dict):
        return {k: without_times(v) for k, v in obj.items() if not k.endswith("seconds")}
    if isinstance(obj, list):
        return [without_times(x) for x in obj]
    return obj


class DurationPacketDiagnostic:
    def __init__(self, names):
        self.names = names
        self.suffixes = [n[len("duration_sum"):] for n in names if n.startswith("duration_sum_")]
        assert len(self.suffixes) == 36
        self.positions = {k: [names.index(k + s) for s in self.suffixes]
                          for k in ("duration_sum", "duration_max", "pkts_in_sum", "pkts_out_sum")}

    def quantities(self, x):
        # Promote the stored numbers before multiplication; this does not alter
        # native float32 acceptance or introduce a new native tolerance.
        s, m, pin, pout = [x[..., self.positions[k]].astype(np.float64)
                          for k in ("duration_sum", "duration_max", "pkts_in_sum", "pkts_out_sum")]
        p = pin + pout
        return s, m, p, p * m

    def failed(self, x):
        s, _, _, bound = self.quantities(x)
        return s > bound


def clean_control_audit(evidence, dataset, names, expected_hash):
    assert sha256(dataset) == expected_hash
    paths = sorted(p for p in evidence.paths if p.endswith("/baseline/development_indices.npy"))
    assert paths and len({hashlib.sha256(evidence.raw(p)).hexdigest() for p in paths}) == 1
    dev = np.load(io.BytesIO(evidence.raw(paths[0])), allow_pickle=False)
    assert dev.shape == (28610,) and len(np.unique(dev)) == len(dev)
    split = np.zeros(143046, dtype=bool); split[dev] = True
    selected = evidence.arrays("experiment/selected_inputs.npz")
    diagnostic = DurationPacketDiagnostic(names)
    wanted = sorted({i for indexes in diagnostic.positions.values() for i in indexes})
    columns = [names[i] for i in wanted]
    local = DurationPacketDiagnostic(columns)
    groups = {(s, y, p): {"rows": 0, "flagged_rows": 0, "flagged_buckets": 0}
              for s in (False, True) for y in (0, 1) for p in ("float64", "float32")}
    examples, offset, verified = [], 0, 0
    for frame in pd.read_csv(dataset, usecols=columns + ["is_botnet"], nrows=143046, chunksize=4096):
        labels = frame.pop("is_botnet").to_numpy(np.int64)
        frame = frame[columns]
        end = offset + len(frame)
        selected_positions = np.flatnonzero((selected["csv_rows"] >= offset) & (selected["csv_rows"] < end))
        for precision in ("float64", "float32"):
            x = frame.to_numpy(dtype=precision)
            assert np.isfinite(x).all() and not (x < 0).any()
            bad = local.failed(x)
            for s in (False, True):
                for label in (0, 1):
                    mask = (split[offset:end] == s) & (labels == label)
                    g = groups[(s, label, precision)]
                    g["rows"] += int(mask.sum())
                    g["flagged_rows"] += int(bad[mask].any(-1).sum())
                    g["flagged_buckets"] += int(bad[mask].sum())
            for i in np.flatnonzero(bad.any(-1))[:max(0, 20 - len(examples))]:
                sums, maxima, packets, upper = local.quantities(x[i])
                examples.append({"csv_row_zero_based": offset + int(i), "precision": precision,
                    "buckets": [{"bucket": local.suffixes[j], "duration_sum": float(sums[j]),
                        "duration_max": float(maxima[j]), "packet_count": float(packets[j]),
                        "conditional_duration_upper_bound": float(upper[j]),
                        "violation_margin": float(sums[j] - upper[j])} for j in np.flatnonzero(bad[i])]})
            if precision == "float32":
                np.testing.assert_array_equal(x[selected["csv_rows"][selected_positions] - offset],
                                              selected["x_clean"][selected_positions][:, wanted])
                verified += len(selected_positions)
        offset = end
    assert offset == 143046 and verified == 32
    return {"dataset_sha256": expected_hash, "unperturbed_rows": offset, "test_rows_parsed_or_scored": 0,
            "selected_originals_verified": verified, "groups": [dict(partition="development" if s else "train",
                label=y, precision=p, **g) for (s, y, p), g in groups.items()], "flagged_examples": examples,
            "all_controls_pass": not any(g["flagged_rows"] for g in groups.values()),
            "arithmetic": "Promote parsed float64 or stored float32 values to float64; compare S > (Pin+Pout)*M with no additional tolerance."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run-zip", "reference-zip", "published-tree", "dataset", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError("Preserving earlier reviews: " + str(args.out))
    started = time.perf_counter()
    assert sha256(args.reference_zip) == REFERENCE_SHA256
    run, reference = Evidence(args.run_zip), Evidence(args.reference_zip)
    context = run.read("session_context.json")
    assert context["project_commit"] == COMMIT and not context["project_status"]
    tree = json.loads(args.published_tree.read_text())
    assert tree["sha"] == TREE and not tree["truncated"]
    published = {e["path"]: e["sha"] for e in tree["tree"] if e["type"] == "blob"}
    for path, expected in context["source_sha256"].items():
        blob = run.raw("source_snapshot/" + path)
        assert hashlib.sha256(blob).hexdigest() == expected
        assert hashlib.sha1(b"blob " + str(len(blob)).encode() + b"\0" + blob).hexdigest() == published[path]
    protocol, ref_protocol = run.read("experiment/protocol.json"), reference.read("experiment/protocol.json")
    assert protocol["status"] == "completed" and not protocol["smoke_check_only"] and not protocol["single_pair_only"]
    assert not protocol["test_partition_evaluated"] and not protocol["new_model_training"]
    for key in ("settings", "input_zip_sha256", "parent_protocol_sha256", "profile_sha256", "profile", "methods",
                "code_revision", "data_revision", "model_revision", "python", "numpy", "torch", "device",
                "native_relationship_tolerance", "generation_runs"):
        assert protocol[key] == ref_protocol[key], key
    result, ref_result = run.read("experiment/results.json"), reference.read("experiment/results.json")
    comparison = result["comparison"]
    assert len(comparison) == 30
    assert without_times(comparison) == without_times(ref_result["comparison"])
    assert result["native_original_reference"] == ref_result["native_original_reference"]
    assert result["clean_controls"] == ref_result["clean_controls"]
    assert without_times(run.read("independent_review.json")) == without_times(reference.read("independent_review.json"))
    evidence_paths = sorted(p for p in run.paths if p.startswith("experiment/") and p.endswith(".npz") and "/input_evidence/" not in p)
    ref_paths = sorted(p for p in reference.paths if p.startswith("experiment/") and p.endswith(".npz") and "/input_evidence/" not in p)
    assert evidence_paths == ref_paths
    for path in evidence_paths:
        assert run.raw(path) == reference.raw(path), "Evidence bytes differ: " + path
    audit_paths = sorted(p for p in run.paths if p.startswith("experiment/") and p.endswith("/generation_audit.json") and "/input_evidence/" not in p)
    for path in audit_paths:
        assert without_times(run.read(path)) == without_times(reference.read(path)), path
    assert len(audit_paths) == 12
    for model in protocol["settings"]["models"]:
        for seed in protocol["settings"]["seeds"]:
            prefix = "experiment/{}/seed_{}/".format(model, seed)
            native = run.read(prefix + "original_generation/generation.json")
            for method in ("caa_profile_budget_inloop", "caa_profile_relation_inloop"):
                generation = run.read(prefix + method + "/generation.json")
                for key in ("forward_counts", "moeva_csv_rows", "population_size"):
                    assert generation[key] == native[key]
    names = run.read("experiment/feature_names.json")
    diagnostic = DurationPacketDiagnostic(names)
    hashes = run.read("source_snapshot/baseline/asset_hashes.json")
    controls = clean_control_audit(run, args.dataset, names, hashes["ctu_13_neris.csv"])
    print("Clean duration/packet controls checked:", controls["all_controls_pass"], flush=True)
    catalog = run.read("experiment/rule_catalog.json")
    pairs = {family: [(names.index(c["positive_feature"]), names.index(c["required_positive_feature"]))
                     for c in catalog if c["family"] == family] for family in ("aggregate", "presence")}
    expected_aggregate = {(i, names.index(n.replace("_sum_", "_max_"))) for i, n in enumerate(names)
                         if any(n.startswith(m + "_sum_") for m in ("bytes_in", "bytes_out", "pkts_in", "pkts_out", "duration"))}
    expected_presence = {(i, names.index(f + n[len("duration_sum"):])) for i, n in enumerate(names)
                         if n.startswith("duration_sum_") for f in ("distinct_external_ips", "distinct_src_port", "distinct_dst_port")}
    assert set(pairs["aggregate"]) == expected_aggregate and len(expected_aggregate) == 180
    assert set(pairs["presence"]) == expected_presence and len(expected_presence) == 108
    source_summaries, available, source_entries, decisions = [], {}, 0, 0
    for entry in run.read("experiment/source_manifest.json"):
        path = entry["source"]
        assert hashlib.sha256(run.raw("experiment/" + path)).hexdigest() == entry["source_sha256"]
        d, masks = run.arrays("experiment/" + path), run.arrays("experiment/evaluated_sources/" + path)
        x = d["x_candidates"][:, None] if entry["matrix_geometry"] else d["x_candidates"]
        for family in ("aggregate", "presence"):
            a, b = zip(*pairs[family])
            fresh = (x[..., list(a)] > 0) & (x[..., list(b)] == 0)
            np.testing.assert_array_equal(fresh, masks[family + "_failed"])
            decisions += fresh.size
        feasible = masks["valid"] & masks["within_budget"] & masks["changed"]
        feasible &= ~masks["aggregate_failed"].any(-1) & ~masks["presence_failed"].any(-1)
        bad = diagnostic.failed(x).any(-1)
        eligible = feasible & ~bad & (masks["predictions"] == 0)
        available[path] = set(int(r) for r, hit in zip(d["csv_rows"], eligible.any(-1)) if hit)
        source_summaries.append({"source": path, "entries": int(bad.size),
            "profile_feasible_entries": int(feasible.sum()), "profile_feasible_entries_flagged": int((feasible & bad).sum())})
        source_entries += bad.size
    diagnostic_comparison, cases = [], []
    for row in comparison:
        prefix = "experiment/{}/seed_{}/{}/".format(row["model"], row["seed"], row["method"])
        final = run.arrays(prefix + "final.npz")
        selection = run.read(prefix + "selection.json")
        final_bad = diagnostic.failed(final["x_final"])
        surviving = set().union(*(available[s["path"]] for s in selection["sources"]))
        detected = set(int(r) for r, p in zip(final["csv_rows"], final["clean_predictions"]) if p == 1)
        surviving &= detected
        diagnostic_comparison.append({"model": row["model"], "seed": row["seed"], "method": row["method"],
            "notebook08_final_newly_evaded": row["newly_evaded"],
            "flagged_selected_evasions": int((final_bad.any(-1) & final["newly_evaded"]).sum()),
            "conditional_passing_pool_originals": sorted(surviving),
            "conditional_passing_pool_original_count": len(surviving), "final_matrix_reselection_performed": False})
        for i in np.flatnonzero(final["newly_evaded"]):
            c, x = final["x_clean"][i], final["x_final"][i]
            s, m, p, bound = diagnostic.quantities(x)
            cases.append({"model": row["model"], "seed": row["seed"], "method": row["method"],
                "csv_row_zero_based": int(final["csv_rows"][i]), "candidate_sha256": hashlib.sha256(x.tobytes()).hexdigest(),
                "distance": float(final["distance"][i]),
                "changes": [{"feature": names[j], "original": float(c[j]), "candidate": float(x[j])} for j in np.flatnonzero(x != c)],
                "flagged_buckets": [{"bucket": diagnostic.suffixes[j], "duration_sum": float(s[j]),
                    "duration_max": float(m[j]), "packet_count": float(p[j]), "conditional_duration_upper_bound": float(bound[j]),
                    "minimum_contributing_records": math.ceil(float(s[j] / m[j])) if m[j] > 0 else None,
                    "violation_margin": float(s[j] - bound[j])} for j in np.flatnonzero(final_bad[i])]})
    report = {"status": "reproduction_verified", "date": "2026-10-13", "project_commit": COMMIT,
        "input_zip_sha256": sha256(args.run_zip), "reference_zip_sha256": REFERENCE_SHA256,
        "source_files_verified_against_published_commit": len(context["source_sha256"]),
        "byte_identical_npz_files": len(evidence_paths), "matching_metric_comparisons": len(comparison),
        "matching_inloop_generation_logs_ignoring_times": len(audit_paths), "fresh_rule_decisions": decisions,
        "exported_source_entries": int(source_entries), "comparison": comparison,
        "archived_independent_review": run.read("independent_review.json"),
        "clean_control_diagnostic": controls, "diagnostic_comparison": diagnostic_comparison,
        "selected_evasion_cases": cases, "source_diagnostic_counts": source_summaries,
        "experiment_wall_seconds": protocol["wall_seconds"], "review_wall_seconds": time.perf_counter() - started,
        "diagnostic_status": "Exploratory, post-hoc, conditional. Notebook 08 metrics and acceptance profile are unchanged.",
        "diagnostic_clean_control_gate": "passed" if controls["all_controls_pass"] else "failed",
        "new_hard_filter_adopted": False,
        "derivation": "For N contributing records, duration_sum <= N*duration_max. If every record contributes at least one counted packet, N <= pkts_in_sum+pkts_out_sum.",
        "source": "https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/aggregated_features_bro_logs.py",
        "scope": "ZIP/source integrity, exact reference reproduction, fresh added-rule masks and duration/packet controls. No local model/native-checker rerun; those were run by the archived verified Colab code. Intermediate optimizer vectors are not exported. Conditional pool availability is not a final matrix result.",
        "limitations": ["Exact extractor-to-pinned-CSV reproduction and missing packet-count handling remain to be established.",
            "The inspected extractor maps missing values to zero and does not enforce the one-packet-per-record assumption.",
            "The clean-control gate must be evaluated before adopting the condition. Failed controls must not be silently removed or repaired.",
            "Passing this bound is not packet realizability or preserved malicious behavior.",
            "Same 32 selected malicious development originals and inherited full-feature-row scaler; no final-test claim."]}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x") as f:
        json.dump(report, f, indent=2); f.write("\n")
    print("Reproduction verified; exploratory diagnostic saved:", args.out, flush=True)


if __name__ == "__main__":
    main()
