"""Read only the fixed, reviewed notebook-08/09b inputs; never execute ZIP code."""
import hashlib
import io
import json
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.review_notebook08_colab import Evidence, sha256

PILOT_ZIP_SHA256 = "bb1e0d9afe2eb4db9ed6b1a699b72a51d77abc86b27e00745a006daabf98ddd1"
SEMANTICS_ZIP_SHA256 = "e44eb9bf358bc7736e8e072a9b825b4dbc520ba36a7c2c05b50e397703ec076c"
FROZEN_INPUT_SHA256 = "f67408981fb225e2fc5833fdaced74ff852eb268ec4b3af116b5af18b41816c8"
SEMANTICS_PROTOCOL_SHA256 = "ba1bc623a501322bababc601f9c8ec738524714f2e6774d59e1b2338cb8b3d84"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_frozen_inputs(pilot_zip, semantics_zip, destination):
    require(sha256(pilot_zip) == PILOT_ZIP_SHA256, "Upload the reviewed notebook-08 results ZIP")
    require(sha256(semantics_zip) == SEMANTICS_ZIP_SHA256, "Upload the reviewed notebook-09b results ZIP")
    destination.mkdir(parents=True, exist_ok=False)
    pilot, semantics = Evidence(pilot_zip), Evidence(semantics_zip)
    try:
        require(pilot.z.testzip() is None and semantics.z.testzip() is None, "Evidence ZIP CRC failure")
        protocol = semantics.read("audit/protocol.json")
        report = semantics.read("audit/report.json")
        manifest = semantics.read("audit/followup_manifest.json")
        parent = pilot.read("experiment/protocol.json")
        require(hashlib.sha256(semantics.raw("audit/protocol.json")).hexdigest() == SEMANTICS_PROTOCOL_SHA256,
                "Measurement protocol differs")
        require(report["status"] == "completed" and parent["status"] == "completed"
                and parent["experiment"] == "connection_aware_evolutionary_search"
                and parent["generation_runs"] == 18 and not parent["smoke_check_only"]
                and not parent["single_pair_only"], "Expected completed source experiments")
        require(pilot.read("independent_review.json")["status"] == "passed", "Pilot review did not pass")
        require(report["input_zip_sha256"] == PILOT_ZIP_SHA256 and report["followup"] == manifest,
                "Input provenance differs")
        require(manifest["status"] == "inputs_frozen_attacks_not_run" and manifest["attacks_executed"] == 0
                and manifest["predictions_used_for_selection"] is False, "Sample was changed or used")
        require(all(manifest[k] == v for k, v in protocol["followup"].items()), "Follow-up protocol differs")
        frozen_bytes = semantics.raw("audit/followup_inputs.npz")
        require(hashlib.sha256(frozen_bytes).hexdigest() == manifest["inputs_sha256"] == FROZEN_INPUT_SHA256,
                "Frozen input bytes changed")
        selected = semantics.arrays("audit/followup_inputs.npz")
        require(set(selected) == {"x_clean", "labels", "csv_rows"}, "Unexpected selected-input fields")
        x, rows, labels = (selected[k] for k in ("x_clean", "csv_rows", "labels"))
        require(x.shape == (128, 757) and x.dtype == np.float32 and np.isfinite(x).all(), "Invalid feature matrix")
        require(rows.shape == (128,) and rows.dtype == np.int64 and len(np.unique(rows)) == 128,
                "Invalid row identities")
        require(labels.shape == (128,) and np.all(labels == 1), "Expected malicious source labels")
        require(rows.tolist() == manifest["csv_rows"] and
                hashlib.sha256(rows.astype("<i8").tobytes()).hexdigest() == manifest["rows_sha256"], "Rows changed")
        pilot_selected = pilot.arrays("experiment/selected_inputs.npz")
        require(pilot_selected["csv_rows"].tolist() == manifest["pilot_csv_rows"] and
                not set(rows.tolist()) & set(pilot_selected["csv_rows"].tolist()), "Sample overlaps/differs from pilot")
        names_bytes = pilot.raw("experiment/feature_names.json")
        require(hashlib.sha256(names_bytes).hexdigest() == protocol["feature_names_sha256"], "Feature order changed")
        names = json.loads(names_bytes)
        splits = sorted(p for p in pilot.paths if p.endswith("/baseline/development_indices.npy"))
        require(bool(splits), "Development split missing")
        for path in splits:
            require(hashlib.sha256(pilot.raw(path)).hexdigest() == protocol["development_indices_sha256"], "Split changed")
        development_bytes = pilot.raw(splits[0])
        dev = np.load(io.BytesIO(development_bytes), allow_pickle=False)
        require(dev.shape == (28610,) and len(np.unique(dev)) == len(dev)
                and np.all((dev >= 0) & (dev < 143046)) and np.isin(rows, dev).all(), "Non-development sample")
        require(parent["profile_sha256"] == protocol["old_profile_sha256"] == manifest["profile_sha256"], "Profile changed")
        base = destination / "notebook08"
        base.mkdir()
        for output_name, data in {
            "protocol.json": pilot.raw("experiment/protocol.json"),
            "independent_review.json": pilot.raw("independent_review.json"),
            "compatibility_scaler.json": pilot.raw("experiment/compatibility_scaler.json"),
            "feature_names.json": names_bytes, "development_indices.npy": development_bytes,
            "selected_pilot_inputs.npz": pilot.raw("experiment/selected_inputs.npz"),
        }.items():
            with (base / output_name).open("xb") as f:
                f.write(data)
        source = destination / "notebook09"
        source.mkdir()
        for name in ("report.json", "protocol.json", "followup_manifest.json", "followup_inputs.npz"):
            with (source / name).open("xb") as f:
                f.write(semantics.raw("audit/" + name))
        with (source / "session_context.json").open("xb") as f:
            f.write(semantics.raw("session_context.json"))
        return selected, names, manifest, parent, base
    finally:
        pilot.z.close()
        semantics.z.close()
