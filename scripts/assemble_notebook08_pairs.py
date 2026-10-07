"""Assemble six completed full-budget notebook-08 pairs without rerunning them.

Usage: python scripts/assemble_notebook08_pairs.py PAIR_PARENT NEW_OUTPUT
PAIR_PARENT contains default_seed_0 ... madry_seed_2 and execution.json with
wall_seconds, parallel_workers, and successful model/seed/exit_code records.
Use review_notebook08_evidence.py on the assembled output before reporting it.
"""
import csv
import hashlib
import json
from pathlib import Path
import shutil
import sys


def read(path):
    return json.loads(path.read_text())


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def csv_write(path, records):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    parent, out = [Path(p).resolve() for p in sys.argv[1:]]
    if out.exists():
        raise FileExistsError("Preserving earlier evidence: " + str(out))
    pairs = [(m, s) for m in ("default", "madry") for s in (0, 1, 2)]
    execution = read(parent / "execution.json")
    assert len(execution["pairs"]) == 6
    assert sorted((p["model"], p["seed"]) for p in execution["pairs"]) == sorted(pairs)
    assert all(p["exit_code"] == 0 for p in execution["pairs"])
    assert execution["wall_seconds"] > 0
    common = ["compatibility_scaler.json", "feature_names.json", "selected_inputs.npz", "fixed_profile.json",
              "rule_catalog.json", "native_dependency_blocks.json", "clean_controls.csv", "clean_controls.json"]
    comparison, manifest, native_reference, protocols = [], [], [], []
    first = parent / "default_seed_0"
    reference = read(first / "protocol.json")
    out.mkdir(parents=True, exist_ok=False)
    for name in common:
        shutil.copy2(first / name, out / name)
    shutil.copytree(first / "input_evidence", out / "input_evidence")
    (out / "pair_provenance").mkdir()
    for model, seed in pairs:
        key = model + "_seed_" + str(seed)
        folder = parent / key
        p = read(folder / "protocol.json")
        results = read(folder / "results.json")
        assert p["status"] == results["status"] == "completed"
        assert p["single_pair_only"] and not p["smoke_check_only"] and not p["test_partition_evaluated"]
        assert p["settings"]["models"] == [model] and p["settings"]["seeds"] == [seed]
        assert p["generation_runs"] == 3
        for field in ("input_zip_sha256", "parent_protocol_sha256", "profile_sha256", "profile", "code_revision",
                      "data_revision", "model_revision", "python", "numpy", "torch", "device", "methods",
                      "native_relationship_tolerance", "new_model_training", "cost_note"):
            assert p[field] == reference[field], (key, field)
        assert {k: v for k, v in p["settings"].items() if k not in ("models", "seeds")} == {
            k: v for k, v in reference["settings"].items() if k not in ("models", "seeds")}
        for name in common:
            assert digest(folder / name) == digest(first / name), (key, name)
        assert len(results["comparison"]) == 5 and len(results["native_original_reference"]) == 1
        assert {r["method"] for r in results["comparison"]} == set(p["methods"])
        for r in results["comparison"] + results["native_original_reference"]:
            assert r["model"] == model and r["seed"] == seed
        assert results["clean_controls"] == read(first / "results.json")["clean_controls"]
        sources = read(folder / "source_manifest.json")
        prefix = model + "/seed_" + str(seed) + "/"
        for source in sources:
            assert source["source"].startswith(prefix)
            assert digest(folder / source["source"]) == source["source_sha256"]
        shutil.copytree(folder / model / ("seed_" + str(seed)), out / model / ("seed_" + str(seed)))
        shutil.copytree(folder / "evaluated_sources" / model / ("seed_" + str(seed)),
                        out / "evaluated_sources" / model / ("seed_" + str(seed)))
        shutil.copy2(folder / "protocol.json", out / "pair_provenance" / (key + "_protocol.json"))
        log = parent / (key + ".log")
        if log.is_file():
            shutil.copy2(log, out / "pair_provenance" / log.name)
        comparison.extend(results["comparison"])
        native_reference.extend(results["native_original_reference"])
        manifest.extend(sources)
        protocols.append({"model": model, "seed": seed, "protocol_sha256": digest(folder / "protocol.json"),
                          "results_sha256": digest(folder / "results.json"), "wall_seconds": p["wall_seconds"]})
    assert len({s["source"] for s in manifest}) == len(manifest)
    reference["settings"].update(models=["default", "madry"], seeds=[0, 1, 2])
    reference.update(single_pair_only=False, generation_runs=18, wall_seconds=execution["wall_seconds"],
                     execution_mode="six_independent_full_budget_pairs", parallel_workers=execution["parallel_workers"],
                     timing_is_not_a_speed_comparison=True)
    write(out / "protocol.json", reference)
    write(out / "pair_assembly.json", {"execution": execution, "pairs": protocols,
        "note": "One identical copy of shared input evidence retained; all pair output vectors preserved. Run independent review before reporting."})
    write(out / "source_manifest.json", manifest)
    csv_write(out / "comparison.csv", comparison)
    csv_write(out / "native_original_reference.csv", native_reference)
    write(out / "results.json", {"status": "completed", "comparison": comparison,
        "native_original_reference": native_reference, "clean_controls": read(first / "results.json")["clean_controls"],
        "physical_source_files": len(manifest), "wall_seconds": execution["wall_seconds"]})
    print("Assembled all six pairs. Run independent evidence review:", out)


if __name__ == "__main__":
    main()
