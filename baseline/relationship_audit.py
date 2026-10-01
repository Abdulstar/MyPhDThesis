"""Audit notebook 03's saved candidates using the unchanged pinned rule engine.

No attacks, model inference, threshold changes, repairs, or training are run.
Python 3.8.20 / NumPy 1.23.5 are installed by scripts/bootstrap.py.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

import numpy as np

from download_assets import CODE_REVISION, DATA_REVISION, sha256


METADATA_NAME = "ctu_13_neris_metadata.csv"
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MASK_NAMES = ("relation_ok", "bounds_ok", "types_ok", "immutable_ok")


def checked_zip(source):
    """Read bounded ZIP members without extracting or executing their contents."""
    z = zipfile.ZipFile(source)
    names = z.namelist()
    if len(names) != len(set(names)):
        z.close()
        raise ValueError("Duplicate ZIP member names.")
    if sum(i.file_size for i in z.infolist()) > MAX_EXPANDED_BYTES:
        z.close()
        raise ValueError("ZIP expanded size exceeds this pilot audit's 256 MiB limit.")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name:
            z.close()
            raise ValueError("Unsafe ZIP member name.")
    bad = z.testzip()
    if bad is not None:
        z.close()
        raise ValueError("ZIP integrity failure: " + bad)
    return z


def load_candidates(data, feature_count):
    with checked_zip(io.BytesIO(data)):
        pass
    with np.load(io.BytesIO(data), allow_pickle=False) as source:
        arrays = {k: source[k] for k in source.files}
    x, clean = arrays["x_candidates"], arrays["x_clean"]
    if x.ndim != 3 or x.shape[2] != feature_count or min(x.shape[:2]) < 1:
        raise ValueError("Unexpected candidate dimensions.")
    n, k, _ = x.shape
    if clean.shape != (n, feature_count) or x.dtype != np.float32 or clean.dtype != np.float32:
        raise ValueError("Expected saved float32 candidate and clean arrays.")
    if not np.isfinite(x).all() or not np.isfinite(clean).all():
        raise ValueError("Nonfinite feature values.")
    for key in MASK_NAMES + ("valid", "within_budget", "fooled", "changed"):
        if arrays[key].shape != (n, k) or arrays[key].dtype != np.bool_:
            raise ValueError("Invalid Boolean array: " + key)
    for key in ("distance", "correct_minus_wrong_score"):
        if arrays[key].shape != (n, k) or not np.isfinite(arrays[key]).all():
            raise ValueError("Invalid objective array: " + key)
    for key in ("csv_rows", "labels"):
        if arrays[key].shape != (n,) or not np.issubdtype(arrays[key].dtype, np.integer):
            raise ValueError("Invalid row or label array: " + key)
    if len(set(arrays["csv_rows"].tolist())) != n or not np.all(arrays["labels"] == 1):
        raise ValueError("Expected distinct malicious input rows.")
    np.testing.assert_array_equal(arrays["changed"], np.any(x != clean[:, None, :], axis=-1))
    np.testing.assert_array_equal(arrays["fooled"], arrays["correct_minus_wrong_score"] <= 0)
    np.testing.assert_array_equal(arrays["valid"], np.logical_and.reduce([arrays[k] for k in MASK_NAMES]))
    return arrays


def precision_counts(native, wider):
    """Candidate-level transitions, not a tolerance-based acceptance policy."""
    a, b = np.any(native > 0, axis=-1), np.any(wider > 0, axis=-1)
    return {
        "native_invalid": int(a.sum()),
        "float64_invalid": int(b.sum()),
        "native_invalid_but_float64_valid": int((a & ~b).sum()),
        "native_valid_but_float64_invalid": int((~a & b).sum()),
    }


def nonzero_stats(values):
    v = np.asarray(values, dtype=np.float64)
    v = v[v > 0]
    if not len(v):
        return {k: None for k in ("min", "median", "p95", "max")}
    return dict(zip(("min", "median", "p95", "max"),
                    [float(x) for x in np.quantile(v, [0, .5, .95, 1])]))


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def write_csv(path, rows):
    if not rows:
        return
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def feature_ids(node):
    name = type(node).__name__
    if name == "Feature":
        return [node.feature_id]
    if name == "Constant":
        return []
    children = node.operands if name == "ManySum" else (
        [node.dividend, node.divisor, node.fill_value] if name == "SafeDivision"
        else [node.left_operand, node.right_operand])
    return list(dict.fromkeys(f for child in children for f in feature_ids(child)))


def expression(node):
    name = type(node).__name__
    if name == "Feature":
        return str(node.feature_id)
    if name == "Constant":
        return str(node.constant)
    if name == "ManySum":
        return "sum(" + ", ".join(expression(n) for n in node.operands) + ")"
    if name == "SafeDivision":
        return "safe_divide({}, {}, zero_divisor_fill={})".format(
            expression(node.dividend), expression(node.divisor), expression(node.fill_value))
    op = "==" if name == "EqualConstraint" else "<="
    if name not in ("EqualConstraint", "LessEqualConstraint"):
        raise ValueError("Unexpected CTU node: " + name)
    return expression(node.left_operand) + " " + op + " " + expression(node.right_operand)


class RuleEngine:
    def __init__(self, repo, metadata_path, names):
        revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"], text=True)
        if revision != CODE_REVISION or dirty:
            raise ValueError("Use a clean pinned upstream checkout; preserve edits in a separate workspace.")
        sys.path.insert(0, str(repo.resolve()))
        import pandas as pd
        from tabularbench.datasets.dataset import CsvDataSource
        from tabularbench.datasets.samples.ctu_13_neris import get_relation_constraints
        from tabularbench.constraints.constraints import get_constraints_from_metadata
        from tabularbench.constraints.constraints_checker import ConstraintChecker
        from tabularbench.constraints.constraints_backend_executor import ConstraintsExecutor
        from tabularbench.constraints.numpy_backend import NumpyBackend
        from tabularbench.constraints.relation_constraint import AndConstraint
        metadata = pd.read_csv(metadata_path)
        metadata = metadata[metadata.feature.isin(names)].reset_index(drop=True)
        if len(names) != 757 or len(set(names)) != len(names) or metadata.feature.tolist() != names:
            raise ValueError("Feature order does not match the pinned 757-column metadata.")
        self.names, self.metadata = names, metadata
        self.rules = get_relation_constraints(CsvDataSource(str(metadata_path)))
        if len(self.rules) != 360:
            raise ValueError("Unexpected CTU relationship count.")
        self.constraints = get_constraints_from_metadata(metadata, self.rules, names)
        self.checker = ConstraintChecker(self.constraints, tolerance=0.0)
        self.execute = lambda node, x: ConstraintsExecutor(node, NumpyBackend(), names).execute(x)
        self.conjunction = AndConstraint(self.rules)
        self.catalog = []
        for j, rule in enumerate(self.rules):
            if j < 2:
                direction = "s" if j == 0 else "d"
                family, units = "byte_balance", "bytes"
                label = "Total protocol bytes == total incoming + outgoing bytes (" + direction + ")"
            elif j < 36:
                family, units, label = "packet_size", "bytes per packet", expression(rule)
            else:
                metric = rule.left_operand.feature_id.rsplit("_", 3)[0]
                family = "ordering_" + metric
                units = {"bytes_out": "bytes", "pkts_out": "packets", "duration": "raw duration units"}[metric]
                label = expression(rule)
            self.catalog.append({
                "rule_id": "r{:03d}".format(j + 1), "upstream_index_zero_based": j,
                "family": family, "units": units, "label": label, "formula": expression(rule),
                "features": feature_ids(rule),
                "eligible_for_upstream_equality_repair": type(rule).__name__ == "EqualConstraint"
                and type(rule.left_operand).__name__ == "Feature",
            })

    def evaluate(self, populations, dtype):
        # Keep each input's original candidate population shape. Reducing sums
        # after flattening all inputs can change float32 summation behavior.
        shape = populations.shape[:2] + (len(self.rules),)
        residual, left, right = [np.empty(shape, dtype=np.float64) for _ in range(3)]
        for i, population in enumerate(populations):
            x = population.astype(dtype, copy=False)
            for j, rule in enumerate(self.rules):
                residual[i, :, j] = self.execute(rule, x)
                left[i, :, j] = self.execute(rule.left_operand, x)
                right[i, :, j] = self.execute(rule.right_operand, x)
            if not np.isfinite(residual[i]).all() or np.any(residual[i] < 0):
                raise ValueError("Nonfinite or negative rule residuals.")
            np.testing.assert_array_equal(np.all(residual[i] <= 0, axis=-1),
                                          self.execute(self.conjunction, x) <= 0)
        return residual, left, right

    def recompute_masks(self, clean, populations):
        parts = {k: [] for k in MASK_NAMES}
        for i, x in enumerate(populations):
            original = clean[i:i + 1]
            parts["relation_ok"].append(self.checker._check_relationship_constraints(x))
            parts["bounds_ok"].append(self.checker._check_boundary_constraints(original, x))
            parts["types_ok"].append(self.checker._check_type_constraints(x))
            parts["immutable_ok"].append(self.checker._check_mutable_constraints(original, x))
        return {k: np.asarray(v, dtype=bool) for k, v in parts.items()}


def audit_stage(engine, arrays, context, out):
    x, clean = arrays["x_candidates"], arrays["x_clean"]
    n, k, _ = x.shape
    r, left, right = engine.evaluate(x, np.float32)
    w, left64, right64 = engine.evaluate(x, np.float64)
    for key, value in engine.recompute_masks(clean, x).items():
        np.testing.assert_array_equal(value, arrays[key], err_msg="Saved checker mismatch: " + key)
    np.testing.assert_array_equal(np.all(r == 0, axis=-1), arrays["relation_ok"])
    clean_r, _, _ = engine.evaluate(clean[:, None, :], np.float32)
    clean_w, _, _ = engine.evaluate(clean[:, None, :], np.float64)
    if np.any(clean_r) or np.any(clean_w):
        raise ValueError("A clean control fails; investigate before interpreting candidate failures.")
    failed, wider_failed = r > 0, w > 0
    valid, within, changed = (arrays[key] for key in ("valid", "within_budget", "changed"))
    summary = dict(context, inputs=n, candidates=n * k, changed_candidates=int(changed.sum()),
                   **precision_counts(r, w))
    summary.update({
        "all_saved_constraint_masks_reproduced": True,
        "clean_control_failures_native": 0, "clean_control_failures_float64": 0,
        "failed_rule_candidate_pairs_native": int(failed.sum()),
        "failed_rule_pairs_cleared_in_float64": int((failed & ~wider_failed).sum()),
        "new_failed_rule_pairs_in_float64": int((~failed & wider_failed).sum()),
        "native_invalid_in_budget": int((failed.any(axis=-1) & within).sum()),
        "changed_candidates_in_budget": int((changed & within).sum()),
        "changed_valid_in_budget": int((changed & valid & within).sum()),
        "rows_with_changed_valid_in_budget": int((changed & valid & within).any(axis=1).sum()),
        "saved_successful_candidates": int((valid & within & arrays["fooled"]).sum()),
        "saved_successful_candidates_failing_float64_relations": int(
            (valid & within & arrays["fooled"] & wider_failed.any(axis=-1)).sum()),
        "over_budget_candidates": int((~within).sum()),
    })
    group_rows, rule_rows, examples = [], [], []
    for family in dict.fromkeys(rule["family"] for rule in engine.catalog):
        indices = [j for j, rule in enumerate(engine.catalog) if rule["family"] == family]
        f, fw = failed[..., indices].any(axis=-1), wider_failed[..., indices].any(axis=-1)
        group_rows.append(dict(context, family=family, candidates=n*k, failing_candidates=int(f.sum()),
                               failing_input_rows=int(f.any(axis=1).sum()),
                               failing_candidates_in_budget=int((f & within).sum()),
                               failing_candidates_float64=int(fw.sum())))
    for j, rule in enumerate(engine.catalog):
        f, fw = failed[..., j], wider_failed[..., j]
        scale = np.maximum(1.0, np.maximum(np.abs(left64[..., j]), np.abs(right64[..., j])))
        # This is descriptive normalization only, not an error bound/tolerance.
        relative = w[..., j] / scale
        stats = dict(context, rule_id=rule["rule_id"], family=rule["family"], label=rule["label"],
                     units=rule["units"], candidates=n*k, failing_candidates=int(f.sum()),
                     failing_input_rows=int(f.any(axis=1).sum()),
                     failing_candidates_in_budget=int((f & within).sum()),
                     failing_candidates_float64=int(fw.sum()),
                     failures_cleared_in_float64=int((f & ~fw).sum()),
                     new_failures_in_float64=int((~f & fw).sum()))
        for prefix, values in (("native_residual", r[..., j]), ("float64_residual", w[..., j]),
                               ("float64_relative_gap", relative),
                               ("native_in_budget_residual", r[..., j][within]),
                               ("float64_in_budget_residual", w[..., j][within])):
            stats.update({prefix + "_" + name: value for name, value in nonzero_stats(values).items()})
        rule_rows.append(stats)
        if np.any(f | fw):
            # Largest native residual, with float64 as tie-breaker only for a
            # rule whose failures were entirely hidden by native arithmetic.
            values = r[..., j] if f.any() else w[..., j]
            i, candidate = np.unravel_index(np.argmax(values), values.shape)
            feature_values = []
            for feature in rule["features"]:
                pos = engine.names.index(feature)
                original, adversarial = float(clean[i, pos]), float(x[i, candidate, pos])
                feature_values.append({"feature": feature, "original": original, "candidate": adversarial,
                                       "delta": adversarial - original,
                                       "mutable": bool(engine.metadata.iloc[pos]["mutable"]),
                                       "type": engine.metadata.iloc[pos]["type"]})
            examples.append(dict(context, rule_id=rule["rule_id"], label=rule["label"], units=rule["units"],
                                 csv_row_zero_based=int(arrays["csv_rows"][i]), candidate_index=int(candidate),
                                 within_budget=bool(within[i, candidate]),
                                 distance_l2_scaled=float(arrays["distance"][i, candidate]),
                                 left_native=float(left[i, candidate, j]), right_native=float(right[i, candidate, j]),
                                 residual_native=float(r[i, candidate, j]),
                                 left_float64=float(left64[i, candidate, j]), right_float64=float(right64[i, candidate, j]),
                                 residual_float64=float(w[i, candidate, j]), feature_values=feature_values))
    out.mkdir(parents=True, exist_ok=False)
    np.savez_compressed(out / "rule_residuals.npz", residual_native=r, residual_float64=w,
                        csv_rows=arrays["csv_rows"], rule_ids=np.array([q["rule_id"] for q in engine.catalog]))
    candidate_rows = []
    for i in range(n):
        for c in range(k):
            native_rules, wider_rules = failed[i, c], wider_failed[i, c]
            candidate_rows.append(dict(context, csv_row_zero_based=int(arrays["csv_rows"][i]), candidate_index=c,
                                       changed=bool(changed[i, c]), within_budget=bool(within[i, c]),
                                       distance_l2_scaled=float(arrays["distance"][i, c]),
                                       fooled_saved=bool(arrays["fooled"][i, c]), valid_native=bool(valid[i, c]),
                                       failed_rules_native=int(native_rules.sum()), failed_rules_float64=int(wider_rules.sum()),
                                       failed_rule_ids_native=";".join(engine.catalog[j]["rule_id"] for j in np.flatnonzero(native_rules))))
    write_csv(out / "candidates.csv", candidate_rows)
    write_json(out / "largest_residual_examples.json", examples)
    return summary, group_rows, rule_rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-zip", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path("vendor/tabularbench"))
    parser.add_argument("--metadata", type=Path, help="Optional already downloaded, pinned metadata CSV")
    parser.add_argument("--out", type=Path, required=True, help="NEW output directory")
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Preserving existing results: choose a NEW --out directory.")
    if platform.python_version() != "3.8.20" or np.__version__ != "1.23.5":
        raise SystemExit("Run with .baseline-env/bin/python after scripts/bootstrap.py for pinned arithmetic.")
    started = time.perf_counter()
    with checked_zip(args.input_zip) as archive:
        members = archive.namelist()
        results_paths = sorted(n for n in members if n.endswith("/results.json") and "/source_snapshot/" not in n)
        stage_paths = sorted(n for n in members if "/diagnostics/" in n and n.endswith("_candidates.npz"))
        if not results_paths or not stage_paths:
            raise ValueError("Upload the full notebook 03 results ZIP containing saved candidate NPZ files.")
        args.out.mkdir(parents=True, exist_ok=False)
        sources = args.out / "sources"
        sources.mkdir()
        metadata_path = sources / METADATA_NAME
        if args.metadata:
            shutil.copy2(args.metadata, metadata_path)
        else:
            url = "https://huggingface.co/datasets/serval-uni-lu/tabularbench/resolve/{}/ctu_13/{}".format(DATA_REVISION, METADATA_NAME)
            with urllib.request.urlopen(url, timeout=120) as source:
                metadata_path.write_bytes(source.read(1024 * 1024))
        expected_hash = json.loads(Path(__file__).with_name("asset_hashes.json").read_text())[METADATA_NAME]
        if sha256(metadata_path) != expected_hash:
            raise ValueError("Pinned metadata SHA-256 mismatch.")
        stages, groups, rules, reported_outcomes, visited = [], [], [], [], set()
        engine, common_names = None, None
        for results_path in results_paths:
            run_path = str(PurePosixPath(results_path).parent)
            result = json.loads(archive.read(results_path))
            if result["code_revision"] != CODE_REVISION or result["data_revision"] != DATA_REVISION:
                raise ValueError("Archive uses another upstream code or data revision.")
            names = json.loads(archive.read(run_path + "/feature_names.json"))
            if engine is None:
                common_names = names
                engine = RuleEngine(args.repo, metadata_path, names)
                write_json(args.out / "rule_catalog.json", engine.catalog)
            elif names != common_names:
                raise ValueError("Feature orders differ between source runs.")
            generation = result["settings"]["generations"]
            for model in result["settings"]["models"]:
                model_prefix = run_path + "/diagnostics/" + model + "/"
                saved_summary = json.loads(archive.read(model_prefix + "stage_summary.json"))
                if saved_summary["thresholds"]["constraints"] != 0.0:
                    raise ValueError("This audit preserves the original zero relationship tolerance.")
                if saved_summary["thresholds"]["distance"] != result["settings"]["eps"]:
                    raise ValueError("Distance thresholds differ inside the source archive.")
                paths = [p for p in stage_paths if p.startswith(model_prefix)]
                expected_stages = [s["stage"] for s in saved_summary["stages"]]
                if [PurePosixPath(p).name.split("_", 1)[1].rsplit("_candidates.npz", 1)[0] for p in paths] != expected_stages:
                    raise ValueError("Candidate stages do not match their source manifest.")
                originals = {}
                for path in paths:
                    visited.add(path)
                    stage = PurePosixPath(path).name.split("_", 1)[1].rsplit("_candidates.npz", 1)[0]
                    data = archive.read(path)
                    arrays = load_candidates(data, len(names))
                    np.testing.assert_array_equal(arrays["within_budget"], arrays["distance"] <= result["settings"]["eps"])
                    for row, original in zip(arrays["csv_rows"], arrays["x_clean"]):
                        row = int(row)
                        if stage == "NoAttack":
                            originals[row] = original.copy()
                        else:
                            np.testing.assert_array_equal(original, originals[row])
                    context = {"source_run": PurePosixPath(run_path).name, "generations": generation, "model": model, "stage": stage}
                    directory = args.out / "stages" / PurePosixPath(run_path).name / model / stage
                    summary, group, per_rule = audit_stage(engine, arrays, context, directory)
                    summary["source_npz_sha256"] = hashlib.sha256(data).hexdigest()
                    stages.append(summary)
                    groups.extend(group)
                    rules.extend(per_rule)
                    print("g{} {} {}: {} / {} fail; float64 clears {} candidates; saved masks match".format(
                        generation, model, stage, summary["native_invalid"], summary["candidates"],
                        summary["native_invalid_but_float64_valid"]), flush=True)
                reported_outcomes.append({"source_run": PurePosixPath(run_path).name, "generations": generation,
                                          "model": model, "reported_new_evasions": result["models"][model]["attack"]["newly_evaded"]})
        if visited != set(stage_paths):
            raise ValueError("Some saved candidate stages were not audited.")
    source_files = ["datasets/samples/ctu_13_neris.py", "constraints/relation_constraint.py",
                    "constraints/constraints_backend_executor.py", "constraints/numpy_backend.py",
                    "constraints/constraints_checker.py", "constraints/constraints.py",
                    "constraints/constraints_fixer.py", "attacks/utils.py", "attacks/capgd/capgd.py"]
    upstream_hashes = {"tabularbench/" + p: sha256(args.repo / "tabularbench" / p) for p in source_files}
    report = {
        "audit": "unchanged_pinned_relationship_rules_on_saved_notebook03_candidates",
        "input_archive": args.input_zip.name, "input_archive_sha256": sha256(args.input_zip),
        "archive_integrity_passed": True, "code_revision": CODE_REVISION, "data_revision": DATA_REVISION,
        "metadata_sha256": expected_hash, "upstream_source_sha256": upstream_hashes,
        "python": platform.python_version(), "numpy": np.__version__, "relationship_tolerance": 0.0,
        "rules": len(engine.rules), "stages_audited": len(stages),
        "equality_rules": sum(type(r).__name__ == "EqualConstraint" for r in engine.rules),
        "equality_rules_eligible_for_upstream_repair": sum(r["eligible_for_upstream_equality_repair"] for r in engine.catalog),
        "model_predictions_rerun": False, "attacks_rerun": False, "candidate_values_changed": False,
        "aggregate": {key: sum(s[key] for s in stages) for key in (
            "candidates", "native_invalid", "float64_invalid", "native_invalid_but_float64_valid",
            "native_valid_but_float64_invalid", "failed_rule_pairs_cleared_in_float64", "new_failed_rule_pairs_in_float64")},
        "stages": stages, "families": groups, "reported_original_outcomes": reported_outcomes,
        "limits": [
            "Stage-output candidates, not every optimizer iteration; candidate counts are not independent input rows.",
            "Float64 reevaluates stored float32 numbers; it cannot restore pre-rounding values or repair features.",
            "A persistent positive residual is an inconsistency in stored features, not by itself an assessment of practical severity.",
            "Relative gap uses residual / max(1, abs(left), abs(right)); it is descriptive, not an error bound or new tolerance.",
            "Failure counts overlap; residual magnitudes across bytes, packets and duration have different units.",
            "Predictions, distance and attack outcomes are read from the archive; all four constraint masks are independently recomputed.",
            "Only metadata and rule code are required; no full dataset/checkpoints or packet traffic are processed.",
            "The compatibility scaler was fitted on all dataset feature rows; a new research experiment needs train-only preprocessing.",
            "The inspected test subset is now exploratory evidence; develop/tune future methods on a separate development partition.",
        ],
        "audit_wall_seconds": time.perf_counter() - started,
    }
    write_csv(args.out / "stage_summary.csv", stages)
    write_csv(args.out / "family_summary.csv", groups)
    write_csv(args.out / "rule_summary.csv", rules)
    write_json(args.out / "audit_report.json", report)
    print("Audit complete: " + str(args.out.resolve()), flush=True)


if __name__ == "__main__":
    main()
