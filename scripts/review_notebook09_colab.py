"""Verify a completed notebook-09b export and rerun its source/data audit.

No code from the uploaded ZIP is executed. Local audit sources must match the
published Git tree before the subprocess starts. Only the original 143046-row
train/development prefix is parsed; whole data files are hashed for integrity.
This is not a model/attack run. Use a fresh --out directory for each review.
"""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import zipfile

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "d6847238ceef2a1a60711416bbf7919d38aa8739"
TREE = "b65a16ec73681cf749e546140cd3b728aae95012"
REFERENCE_SHA256 = "5e87e2bf5d9547c43aa69039a78b5de611965dc9d72e1d16f8c40f4ea76312fa"
PROTOCOL_SHA256 = "ba1bc623a501322bababc601f9c8ec738524714f2e6774d59e1b2338cb8b3d84"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(8 * 1024 ** 2), b""):
            h.update(block)
    return h.hexdigest()


def open_export(path):
    archive = zipfile.ZipFile(path)
    try:
        entries = archive.infolist()
        names = [x.filename for x in entries]
        require(0 < len(entries) <= 1000 and len(set(names)) == len(names), "Invalid ZIP members")
        require(sum(x.file_size for x in entries) <= 200 * 1024 ** 2, "Oversized export")
        for entry in entries:
            p = PurePosixPath(entry.filename)
            require(not p.is_absolute() and ".." not in p.parts and "\\" not in entry.filename,
                    "Unsafe ZIP path")
            require(not stat.S_ISLNK(entry.external_attr >> 16), "ZIP symlink")
        roots = {n.split("/")[0] for n in names}
        require(len(roots) == 1 and all("/" in n for n in names), "Expected one session root")
        require(archive.testzip() is None, "ZIP CRC failure")
        return archive, next(iter(roots)) + "/"
    except Exception:
        archive.close()
        raise


def scientific_report(report):
    value = copy.deepcopy(report)
    # Deliberately ignore only these two fields, not whole environment objects.
    value.pop("wall_seconds")
    value["environment"].pop("python")
    return value


def compare_audit(archive, root, expected):
    paths = sorted(n[len(root):] for n in archive.namelist() if n.startswith(root + "audit/"))
    require(set(paths) == set(expected), "Different audit output inventory")
    hashes = {}
    for path in paths:
        actual = archive.read(root + path)
        reference = expected[path]
        if path == "audit/report.json":
            require(scientific_report(json.loads(actual)) == scientific_report(json.loads(reference)),
                    "Scientific report mismatch")
        else:
            require(actual == reference, f"Output bytes differ: {path}")
        hashes[path] = digest(actual)
    return hashes


def check_test_log(data, count):
    text = data.decode("utf-8")
    names = re.findall(r"^(test_\S+) \([^\n]+\) \.\.\. ok$", text, flags=re.MULTILINE)
    require(len(names) == count and len(set(names)) == count, "Unexpected test results")
    require(re.search(rf"^Ran {count} tests in [0-9.]+s$", text, re.MULTILINE), "Missing test summary")
    require(text.rstrip().endswith("\nOK"), "Tests did not pass")
    return names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-zip", type=Path, required=True)
    parser.add_argument("--reference-zip", type=Path, required=True)
    parser.add_argument("--notebook08-zip", type=Path, required=True)
    parser.add_argument("--published-tree", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--scenario1", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    require(file_hash(args.reference_zip) == REFERENCE_SHA256, "Unrecognized local reference export")
    tree = json.loads(args.published_tree.read_text())
    require(tree["sha"] == TREE and not tree.get("truncated"), "Unexpected published Git tree")
    index = {x["path"]: x for x in tree["tree"] if x["type"] == "blob"}
    archive, root = open_export(args.run_zip)
    reference, refroot = open_export(args.reference_zip)
    try:
        context = json.loads(archive.read(root + "session_context.json"))
        require(context["project_commit"] == COMMIT and context["project_status"] == [], "Wrong or dirty checkout")
        source_hashes = context["source_sha256"]
        reference_context = json.loads(reference.read(refroot + "session_context.json"))
        require(source_hashes == reference_context["source_sha256"] and len(source_hashes) == 14,
                "Different source inventory")
        snapshot_paths = {n[len(root + "source_snapshot/"):] for n in archive.namelist()
                          if n.startswith(root + "source_snapshot/")}
        require(snapshot_paths == set(source_hashes), "Snapshot inventory mismatch")
        for path, expected_hash in source_hashes.items():
            data = archive.read(root + "source_snapshot/" + path)
            require(digest(data) == expected_hash, f"Snapshot digest mismatch: {path}")
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            require(index[path]["sha"] == blob and index[path]["mode"] == "100644", f"Git blob mismatch: {path}")
            require((ROOT / path).read_bytes() == data, f"Local source differs: {path}")

        expected = {n[len(refroot):]: reference.read(n) for n in reference.namelist()
                    if n.startswith(refroot + "audit/")}
        output_hashes = compare_audit(archive, root, expected)
        report = json.loads(archive.read(root + "audit/report.json"))
        refreport = json.loads(expected["audit/report.json"])
        protocol_bytes = archive.read(root + "audit/protocol.json")
        require(digest(protocol_bytes) == PROTOCOL_SHA256, "Protocol changed")
        protocol = json.loads(protocol_bytes)
        require(report["status"] == "completed", "Audit incomplete")
        require(file_hash(args.notebook08_zip) == report["input_zip_sha256"], "Notebook-08 evidence changed")
        require(file_hash(args.dataset) == protocol["benchmark_sha256"], "Benchmark changed")
        require(file_hash(args.scenario1) == protocol["scenario1_sha256"], "Authors' source changed")

        setup_paths = sorted(n for n in archive.namelist() if n.startswith(root + "setup_report_") and n.endswith(".json"))
        require(len(setup_paths) == 1, "Review expects one Colab setup attempt")
        setup = json.loads(archive.read(setup_paths[0]))
        require(setup["status"] == "completed" and setup["method"] == "venv_without_pip_then_host_pip_python",
                "Unexpected bootstrap result")
        require(setup["ensurepip_requested"] is False and setup["target"]["pip_installed_in_target"] is False,
                "Bootstrap no longer avoids ensurepip/target pip")
        require(setup["requirements_sha256"] == source_hashes["baseline/requirements-semantics.txt"],
                "Requirements differ")
        require(setup["target"]["prefix"] != setup["target"]["base_prefix"], "Target is not isolated")
        for key in ("python", "numpy", "pandas"):
            require(setup["target"][key] == report["environment"][key], "Setup/audit version disagreement")
        test_names = {
            "setup": check_test_log(archive.read(root + "setup_tests.log"), 3),
            "measurement": check_test_log(archive.read(root + "tests.log"), 6),
        }

        # Imports and subprocess execution use only the already verified local
        # sources. The user archive remains inert data throughout this review.
        sys.path.insert(0, str(ROOT))
        from scripts.review_notebook08_colab import Evidence
        inputs = Evidence(args.run_zip)
        old = Evidence(args.notebook08_zip)
        try:
            arrays = inputs.arrays("audit/followup_inputs.npz")
            pilot = old.arrays("experiment/selected_inputs.npz")
            require(set(arrays) == {"x_clean", "labels", "csv_rows"}, "Unexpected follow-up arrays")
            ids, x, y = (arrays[k] for k in ("csv_rows", "x_clean", "labels"))
            require(ids.shape == (128,) and ids.dtype.kind in "iu" and len(np.unique(ids)) == 128,
                    "Invalid follow-up IDs")
            require(x.shape == (128, 757) and x.dtype == np.float32 and np.isfinite(x).all(), "Invalid feature vectors")
            require(y.shape == (128,) and y.dtype.kind in "iu" and np.all(y == 1), "Invalid follow-up labels")
            development_paths = sorted(p for p in old.paths if p.endswith("/baseline/development_indices.npy"))
            require(bool(development_paths), "Original development split missing")
            for path in development_paths:
                require(digest(old.raw(path)) == protocol["development_indices_sha256"], "Split changed")
            dev = np.load(io.BytesIO(old.raw(development_paths[0])), allow_pickle=False)
            require(dev.shape == (28610,) and len(np.unique(dev)) == len(dev)
                    and np.all((dev >= 0) & (dev < 143046)), "Invalid development split")
            labels = pd.read_csv(args.dataset, usecols=["is_botnet"], nrows=143046)["is_botnet"].to_numpy()
            require(len(labels) == 143046 and np.isin(labels, [0, 1]).all(), "Invalid source labels")
            malicious = set(dev[labels[dev] == 1].tolist())
            remaining = np.array(sorted(malicious - set(pilot["csv_rows"].tolist())), dtype=np.int64)
            require(len(malicious) == 692 and len(remaining) == 660, "Selection population changed")
            recomputed_ids = np.random.RandomState(protocol["followup"]["selection_seed"]).permutation(remaining)[:128]
            require(np.array_equal(ids, recomputed_ids), "Deterministic sample changed")
            require(set(ids.tolist()) <= malicious and not set(ids.tolist()) & set(pilot["csv_rows"].tolist()),
                    "Sample outside development or overlaps pilot")
            manifest = inputs.read("audit/followup_manifest.json")
            require(manifest["csv_rows"] == ids.tolist() and manifest == report["followup"], "Manifest mismatch")
            require(manifest["inputs_sha256"] == digest(inputs.raw("audit/followup_inputs.npz")), "Inputs digest mismatch")
            require(manifest["rows_sha256"] == digest(ids.astype("<i8").tobytes()), "Ordered row digest mismatch")
        finally:
            inputs.z.close()
            old.z.close()

        rerun = args.out / "recomputed_audit"
        command = [sys.executable, str(ROOT / "baseline/measurement_semantics.py"),
                   "--input-zip", str(args.notebook08_zip.resolve()), "--out", str(rerun.resolve()),
                   "--dataset", str(args.dataset.resolve()), "--scenario1", str(args.scenario1.resolve())]
        with (args.out / "recompute.log").open("x") as log:
            subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
        recomputed = {"audit/" + str(p.relative_to(rerun)): p.read_bytes() for p in rerun.rglob("*") if p.is_file()}
        compare_audit(archive, root, recomputed)
        rerun_report = json.loads(recomputed["audit/report.json"])
        result = {
            "status": "passed",
            "review_date": "2026-10-21",
            "review_script_sha256": file_hash(Path(__file__)),
            "uploaded_zip_sha256": file_hash(args.run_zip),
            "uploaded_session": root.rstrip("/"),
            "archive_members": len(archive.infolist()),
            "archive_crc_verified": True,
            "source_commit": COMMIT, "source_tree": TREE,
            "source_snapshots_verified": len(source_hashes),
            "source_sha256": source_hashes,
            "reference_zip_sha256": REFERENCE_SHA256,
            "audit_files_compared": len(output_hashes),
            "byte_identical_non_report_audit_files": len(output_hashes) - 1,
            "report_ignored_paths": ["environment.python", "wall_seconds"],
            "all_other_report_fields_match_reference_and_fresh_rerun": True,
            "audit_output_sha256": output_hashes,
            "colab_environment": report["environment"],
            "reference_environment": refreport["environment"],
            "recomputed_environment": rerun_report["environment"],
            "colab_setup": {k: setup[k] for k in ("method", "ensurepip_requested", "host_pip", "installed_packages")},
            "target_pip_installed": setup["target"]["pip_installed_in_target"],
            "archived_passing_test_names": test_names,
            "colab_audit_wall_seconds": report["wall_seconds"],
            "fresh_cached_audit_wall_seconds": rerun_report["wall_seconds"],
            "timings_comparable": False,
            "fresh_source_data_audit_executed": True,
            "train_development_rows_rechecked": report["clean_controls"]["rows"],
            "source_bridge": report["source_bridge"],
            "conditional_bound_counterexample_row": 1503,
            "packet_duration_rule_adopted": report["packet_duration_rule_adopted"],
            "followup": {
                "sample_size": 128, "features": 757, "selection_seed": manifest["selection_seed"],
                "selection_recomputed_from_source_labels": True,
                "all_feature_vectors_match_fresh_source_audit": True,
                "all_malicious_development": True, "pilot_overlap": 0,
                "available_malicious_development": 692, "remaining_after_pilot_exclusion": 660,
                "inputs_sha256": manifest["inputs_sha256"], "rows_sha256": manifest["rows_sha256"],
                "profile_sha256": manifest["profile_sha256"],
                "status": manifest["status"], "attacks_executed": manifest["attacks_executed"],
            },
            "model_scoring_performed": False, "test_rows_evaluated": 0,
            "limitations": report["limitations"],
        }
        with (args.out / "review.json").open("x") as f:
            json.dump(result, f, indent=2, allow_nan=False)
            f.write("\n")
        print(json.dumps({"status": result["status"], "verified_sources": len(source_hashes),
                          "compared_audit_files": len(output_hashes), "verified_followup_records": 128,
                          "new_attacks_executed": 0, "review": str(args.out / "review.json")}, indent=2))
    finally:
        archive.close()
        reference.close()


if __name__ == "__main__":
    main()
