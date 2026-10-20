"""Reproduce the CTU measurement-semantics audit without loading any model.

Only the train/development prefix is parsed. Synthetic connection-CSV fixtures
exercise the byte-verified upstream extractor; they are not packet replays.
"""
import argparse
import contextlib
import csv
import hashlib
from html.parser import HTMLParser
import importlib.util
import io
import json
from pathlib import Path
import platform
import sys
import time
import types
import urllib.parse
import urllib.request
import uuid

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.review_notebook08_colab import Evidence, sha256

PROTOCOL_PATH = ROOT / "baseline/measurement_semantics_protocol.json"
PORTS = [1, 3, 8, 10, 21, 22, 25, 53, 80, 110, 123, 135, 138, 161, 443, 445, 993, -1]
SUFFIXES = [f"_{d}_{'OTHER' if p == -1 else p}" for p in PORTS for d in ("s", "d")]
METRICS = ["bytes_in", "bytes_out", "pkts_in", "pkts_out", "duration"]
INPUT_HEADER = ["ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port",
                "protocol", "service", "duration", "bytes_outgoing", "bytes_incoming",
                "state", "packets_outgoing", "packets_incoming"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as f:
        json.dump(value, f, indent=2, allow_nan=False)
        f.write("\n")


class DownloadForm(HTMLParser):
    """Only the public file-download form; never login or credential forms."""
    def __init__(self):
        super().__init__()
        self.active = False
        self.action = None
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.active = attrs.get("id") == "download-form"
            if self.active:
                self.action = attrs.get("action")
        if tag == "input" and self.active and attrs.get("type") == "hidden":
            self.fields[attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.active = False


def download_verified(url, destination, expected, limit):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        require(sha256(destination) == expected, f"Existing asset hash mismatch: {destination}")
        return destination
    temporary = destination.with_name(destination.name + ".partial_" + uuid.uuid4().hex)
    try:
        for attempt in range(2):
            with urllib.request.urlopen(url, timeout=60) as response:
                if "text/html" in response.headers.get("Content-Type", ""):
                    require(attempt == 0 and "drive.google.com" == urllib.parse.urlparse(url).hostname,
                            "Expected a data file, received HTML. Use a hash-verified local asset.")
                    form = DownloadForm()
                    form.feed(response.read(100_000).decode("utf-8"))
                    require(form.action == "https://drive.usercontent.google.com/download",
                            "Public download form unavailable; no authentication attempted.")
                    require(form.fields.get("id") == "1ZHGihxd2EJ9NuKbeWkqfoL3QfCEktV_D",
                            "Unexpected Drive file ID")
                    url = form.action + "?" + urllib.parse.urlencode(form.fields)
                    continue
                size = 0
                with temporary.open("xb") as f:
                    for chunk in iter(lambda: response.read(1024 ** 2), b""):
                        size += len(chunk)
                        require(size <= limit, "Asset exceeds download limit")
                        f.write(chunk)
                require(sha256(temporary) == expected, "Downloaded asset hash mismatch")
                require(not destination.exists(), "Destination appeared during download")
                temporary.rename(destination)
                return destination
        raise ValueError("Download did not return the expected data")
    finally:
        temporary.unlink(missing_ok=True)


def load_extractor(protocol):
    source = ROOT / "research_sources/ctu13_2f1624c/aggregated_features_bro_logs.py"
    require(sha256(source) == protocol["extractor_sha256"], "Upstream extractor hash mismatch")
    # Configure the unmodified module for a Neris-style synthetic fixture. The
    # upstream repository's default config selects DDoS, so it is not used here.
    config = types.ModuleType("config")
    for key, value in dict(KNOWN_PORTS=PORTS, OTHER_PORT=-1, INTERNAL="147.32.",
                           WINDOW_SEC=60, isDdos=False, fineGrain=False).items():
        setattr(config, key, value)
    previous = sys.modules.get("config")
    sys.modules["config"] = config
    try:
        spec = importlib.util.spec_from_file_location("ctu_upstream_fixture_extractor", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            del sys.modules["config"]
        else:
            sys.modules["config"] = previous
    return module


def connection(duration="0.665524", outgoing=3288, incoming=0,
               packets_out="-", packets_in="-", source_port=50000, uid="synthetic1"):
    return ["1312962900.1", uid, "147.32.84.42", source_port, "203.0.113.7", 65000,
            "udp", "-", duration, outgoing, incoming, "SF", packets_out, packets_in]


def run_fixture(module, folder, records):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=False)
    with (folder / "input.csv").open("x", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(INPUT_HEADER)
        writer.writerows(records)
    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        module.aggregate_bro_logs(str(folder / "aggregated.csv"), str(folder / "input.csv"),
                                  botnet_ips=(), window=60, ddos=False)
    (folder / "extractor.log").write_text(log.getvalue())
    with (folder / "aggregated.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    require(len(rows) == 1, "Expected one synthetic host/window")
    row = rows[0]
    vector = {name: float(value) for name, value in row.items() if name not in ("label", "internal_ip")}
    total_packets = vector["pkts_in_sum_s_OTHER"] + vector["pkts_out_sum_s_OTHER"]
    s, m = vector["duration_sum_s_OTHER"], vector["duration_max_s_OTHER"]
    return vector, dict(records=len(records), missing_packet_cells=sum(r[i] == "-" for r in records for i in (12, 13)),
                        packet_total=total_packets, duration_sum=s, duration_max=m,
                        conditional_bound_violated=bool(s > total_packets * m),
                        packet_min_out=vector["pkts_out_min_s_OTHER"],
                        distinct_source_ports=vector["distinct_src_port_s_OTHER"],
                        output_sha256=sha256(folder / "aggregated.csv"))


def synthetic_audit(out, protocol):
    module = load_extractor(protocol)
    cases = {
        "missing_packets": [connection()],
        "literal_zero_packets": [connection(packets_out=0, packets_in=0)],
        "complete_packets": [connection(packets_out=3, packets_in=1)],
        "partially_missing_positive_total": [connection("1", 100, packets_out=1, packets_in=0),
                                             connection("1", 100, uid="synthetic2")],
        "partially_missing_passing_bound": [connection("1", 100, packets_out=1, packets_in=0),
                                            connection("0", 100, uid="synthetic2")],
        "leading_all_zero_record": [connection("0", 0, packets_out=0, packets_in=0, source_port=49999),
                                     connection("1", 100, packets_out=1, packets_in=0, uid="synthetic2")],
        "duration_exceeds_window": [connection("120", 100, packets_out=2, packets_in=0)],
    }
    vectors, summaries = {}, {}
    for name, records in cases.items():
        vectors[name], summaries[name] = run_fixture(module, out / "fixtures" / name, records)
    require(vectors["missing_packets"] == vectors["literal_zero_packets"], "Missing/zero collision not reproduced")
    require(summaries["partially_missing_positive_total"]["conditional_bound_violated"], "Partial-missingness witness failed")
    require(not summaries["partially_missing_passing_bound"]["conditional_bound_violated"], "Passing-but-incomplete witness failed")
    require(summaries["leading_all_zero_record"]["packet_min_out"] == 1, "Leading-zero behavior changed")
    require(summaries["leading_all_zero_record"]["distinct_source_ports"] == 2, "Endpoint count witness failed")
    require(summaries["duration_exceeds_window"]["duration_max"] == 120, "Duration/window witness failed")
    return vectors, summaries


def load_evidence(path, protocol):
    evidence = Evidence(path)
    old = evidence.read("experiment/protocol.json")
    require(old["experiment"] == "connection_aware_evolutionary_search" and old["status"] == "completed",
            "Upload completed notebook 08 results")
    require(not old["smoke_check_only"] and not old["single_pair_only"] and old["generation_runs"] == 18,
            "A full notebook 08 run is required")
    require(old["profile_sha256"] == protocol["old_profile_sha256"], "Different notebook 08 profile")
    require(evidence.read("independent_review.json")["status"] == "passed", "Notebook 08 review did not pass")
    names_bytes = evidence.raw("experiment/feature_names.json")
    require(hashlib.sha256(names_bytes).hexdigest() == protocol["feature_names_sha256"], "Feature schema changed")
    names = json.loads(names_bytes)
    selected = evidence.arrays("experiment/selected_inputs.npz")
    require(set(selected) == {"csv_rows", "x_clean", "labels"}, "Unexpected selected-input fields")
    require(selected["x_clean"].shape == (32, 757) and selected["x_clean"].dtype == np.float32,
            "Expected 32 originals with 757 float32 features")
    ids = selected["csv_rows"]
    require(ids.shape == (32,) and ids.dtype.kind in "iu" and len(set(ids.tolist())) == 32, "Invalid pilot IDs")
    require(selected["labels"].shape == (32,) and np.all(selected["labels"] == 1), "Expected malicious pilot labels")
    paths = sorted(p for p in evidence.paths if p.endswith("/baseline/development_indices.npy"))
    require(bool(paths), "Saved development split is missing")
    for member in paths:
        require(hashlib.sha256(evidence.raw(member)).hexdigest() == protocol["development_indices_sha256"],
                "Development index hash mismatch")
    # The bytes are authenticated before NumPy parses this known .npy file.
    dev = np.load(io.BytesIO(evidence.raw(paths[0])), allow_pickle=False)
    require(dev.shape == (28610,) and len(np.unique(dev)) == len(dev), "Invalid development split")
    require(np.all(np.isin(ids, dev)), "Pilot includes a non-development record")
    require(np.all((dev >= 0) & (dev < 143046)), "Development rows outside training prefix")
    return evidence, names, selected, dev


def quantities(frame):
    def family(prefix):
        return frame[[prefix + s for s in SUFFIXES]].to_numpy(np.float64)
    duration, maximum = family("duration_sum"), family("duration_max")
    packets = family("pkts_in_sum") + family("pkts_out_sum")
    byte_total = family("bytes_in_sum") + family("bytes_out_sum")
    metrics = {
        "conditional_duration_packet_bound": duration > packets * maximum,
        "positive_duration_zero_packet_total": (duration > 0) & (packets == 0),
        "positive_bytes_zero_packet_total": (byte_total > 0) & (packets == 0),
        "positive_packets_zero_minimum_either_direction": (packets > 0) & ((family("pkts_in_min") == 0) | (family("pkts_out_min") == 0)),
    }
    current_failure = np.zeros_like(duration, dtype=bool)
    for metric in METRICS:
        current_failure |= (family(metric + "_sum") > 0) & (family(metric + "_max") <= 0)
    for endpoint in ("distinct_external_ips", "distinct_src_port", "distinct_dst_port"):
        current_failure |= (duration > 0) & (family(endpoint) <= 0)
    metrics["unchanged_profile_v1_failure"] = current_failure
    return metrics, duration, maximum, packets


def clean_audit(dataset, names, selected, dev, out):
    split = np.zeros(143046, dtype=bool)
    split[dev] = True
    labels = np.empty(143046, dtype=np.int64)
    groups, flags, candidates = {}, [], {}
    target, matched, offset = None, set(), 0
    for frame in pd.read_csv(dataset, nrows=143046, chunksize=2048):
        require(frame.columns.tolist() == names + ["is_botnet"], "CSV column order changed")
        n = len(frame)
        y = frame["is_botnet"].to_numpy()
        require(np.isin(y, [0, 1]).all(), "Non-binary source labels")
        labels[offset:offset+n] = y
        raw = frame[names]
        require(np.isfinite(raw.to_numpy()).all() and (raw.to_numpy() >= 0).all(), "Nonfinite/negative features")
        x32 = raw.to_numpy(np.float32)
        for position, csv_row in enumerate(selected["csv_rows"]):
            if offset <= csv_row < offset+n:
                require(np.array_equal(x32[csv_row-offset], selected["x_clean"][position]), "Original differs from pinned CSV")
                require(y[csv_row-offset] == selected["labels"][position], "Original label mismatch")
                matched.add(int(csv_row))
        for local in np.flatnonzero(split[offset:offset+n] & (y == 1)):
            candidates[offset+int(local)] = x32[local].copy()
        if offset <= 1503 < offset+n:
            target = {k: float(v) for k, v in frame.iloc[1503-offset].items()}
        for precision in ("float64", "float32"):
            converted = raw if precision == "float64" else pd.DataFrame(x32, columns=names)
            masks, duration, maximum, packets = quantities(converted)
            for is_dev in (False, True):
                for label in (0, 1):
                    take = (split[offset:offset+n] == is_dev) & (y == label)
                    key = ("development" if is_dev else "train", label, precision)
                    group = groups.setdefault(key, {"partition": key[0], "label": label, "precision": precision, "rows": 0})
                    group["rows"] += int(take.sum())
                    for name, mask in masks.items():
                        for unit, count in (("rows", mask[take].any(axis=1).sum()), ("buckets", mask[take].sum())):
                            field = name + "_" + unit
                            group[field] = group.get(field, 0) + int(count)
            for local, bucket in np.argwhere(masks["conditional_duration_packet_bound"]):
                flags.append(dict(csv_row=int(offset+local), partition="development" if split[offset+local] else "train",
                                  label=int(y[local]), precision=precision, bucket=SUFFIXES[bucket],
                                  duration_sum=float(duration[local,bucket]), duration_max=float(maximum[local,bucket]),
                                  packet_total=float(packets[local,bucket]), bound=float(packets[local,bucket]*maximum[local,bucket])))
        offset += n
    require(offset == 143046 and len(matched) == 32 and target is not None, "Incomplete clean audit")
    rows = [groups[k] for k in sorted(groups)]
    pd.DataFrame(rows).to_csv(out / "clean_control_groups.csv", index=False)
    pd.DataFrame(flags, columns=["csv_row", "partition", "label", "precision", "bucket", "duration_sum", "duration_max", "packet_total", "bound"]).to_csv(out / "conditional_bound_flags.csv", index=False)
    write_json(out / "counterexample_benchmark_row.json", target)
    return dict(rows=offset, groups=rows, conditional_bound_flags=flags, pilot_originals_verified=len(matched),
                native_test_rows_parsed_or_scored=0), target, labels, candidates


def source_bridge(source, benchmark, names, out):
    bench_iterator = iter(pd.read_csv(benchmark, nrows=143046, chunksize=2048))
    count = diff64 = diff32 = label_diff = 0
    maximum_difference = 0.0
    target = None
    for raw in pd.read_csv(source, chunksize=2048):
        require(count + len(raw) <= 143046, "Source extends beyond permitted training prefix")
        other = next(bench_iterator).iloc[:len(raw)]
        require(len(other) == len(raw), "Benchmark prefix ended early")
        require(set(raw.columns) == set(names + ["label", "internal_ip"]), "Unexpected original aggregate schema")
        a, b = raw[names].to_numpy(np.float64), other[names].to_numpy(np.float64)
        require(np.isfinite(a).all(), "Nonfinite source values")
        diff64 += int(np.count_nonzero(a != b))
        diff32 += int(np.count_nonzero(a.astype(np.float32) != b.astype(np.float32)))
        maximum_difference = max(maximum_difference, float(np.max(np.abs(a-b))))
        require(raw["label"].isin(["BOTNET", "BACKGROUND"]).all(), "Unrecognized source label")
        label_diff += int(np.count_nonzero((raw["label"] == "BOTNET").to_numpy(np.int64) != other["is_botnet"].to_numpy()))
        if count <= 1503 < count+len(raw):
            local = 1503-count
            target = dict(original_csv_row=1503, internal_ip=str(raw.iloc[local]["internal_ip"]),
                          source_label=str(raw.iloc[local]["label"]), window_timestamp=int(raw.iloc[local]["window_timestamp"]),
                          matching_model_features_float64=int(np.count_nonzero(a[local] == b[local])),
                          matching_model_features_float32=int(np.count_nonzero(a[local].astype(np.float32) == b[local].astype(np.float32))))
            write_json(out / "counterexample_authors_row.json", raw.iloc[local].to_dict())
        count += len(raw)
    require(target is not None and target["matching_model_features_float64"] == len(names), "Counterexample source match failed")
    return dict(original_scenario1_rows=count, model_features=len(names), different_cells_float64=diff64,
                different_cells_float32=diff32, different_labels=label_diff, maximum_absolute_float64_difference=maximum_difference,
                row1503=target, exact_raw_log_reconstruction=False)


def freeze_followup(protocol, selected, candidates, names, out):
    remaining = np.array(sorted(set(candidates) - set(selected["csv_rows"].tolist())), dtype=np.int64)
    specification = protocol["followup"]
    require(len(remaining) >= specification["sample_size"], "Insufficient remaining development cases")
    ids = np.random.RandomState(specification["selection_seed"]).permutation(remaining)[:specification["sample_size"]]
    x = np.stack([candidates[int(i)] for i in ids])
    np.savez_compressed(out / "followup_inputs.npz", x_clean=x, labels=np.ones(len(ids), dtype=np.int64), csv_rows=ids)
    manifest = dict(specification, available_malicious_development=len(candidates),
                    remaining_after_excluding_pilot=len(remaining), csv_rows=ids.tolist(),
                    pilot_csv_rows=selected["csv_rows"].tolist(), inputs_sha256=sha256(out / "followup_inputs.npz"),
                    rows_sha256=hashlib.sha256(ids.astype("<i8").tobytes()).hexdigest(), feature_count=len(names),
                    data_sha256=protocol["benchmark_sha256"], profile_sha256=protocol["old_profile_sha256"],
                    predictions_used_for_selection=False, attacks_executed=0)
    write_json(out / "followup_manifest.json", manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-zip", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--assets", type=Path, default=ROOT / "assets")
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--scenario1", type=Path)
    args = parser.parse_args()
    started = time.perf_counter()
    protocol = json.loads(PROTOCOL_PATH.read_text())
    args.out.mkdir(parents=True, exist_ok=False)
    write_json(args.out / "protocol.json", protocol)
    evidence, names, selected, dev = load_evidence(args.input_zip, protocol)
    try:
        dataset = args.dataset or args.assets / "ctu_13_neris.csv"
        source = args.scenario1 or args.assets / "features_stat_scenario1.csv"
        download_verified(protocol["benchmark_url"], dataset, protocol["benchmark_sha256"], 400*1024**2)
        download_verified(protocol["scenario1_url"], source, protocol["scenario1_sha256"], 160*1024**2)
        print("Verified both dataset assets", flush=True)
        vectors, fixtures = synthetic_audit(args.out, protocol)
        print("Completed seven controlled extractor fixtures", flush=True)
        controls, target, labels, candidates = clean_audit(dataset, names, selected, dev, args.out)
        missing = vectors["missing_packets"]
        collision = {p: bool(np.array_equal(np.array([missing[n] for n in names], dtype=p),
                                           np.array([target[n] for n in names], dtype=p))) for p in ("float64", "float32")}
        require(all(collision.values()), "Synthetic row-1503 feature collision failed")
        print("Completed 143046 training/development controls; no test rows parsed", flush=True)
        bridge = source_bridge(source, dataset, names, args.out)
        require(bridge["different_cells_float32"] == 0 and bridge["different_labels"] == 0,
                "Authors' Scenario 1 differs at model-input precision; retain results and investigate")
        write_json(args.out / "source_bridge.json", bridge)
        require(all(g["unchanged_profile_v1_failure_rows"] == 0 for g in controls["groups"]),
                "Unchanged profile failed controls; do not prepare follow-up")
        followup = freeze_followup(protocol, selected, candidates, names, args.out)
        report = dict(status="completed", audit="measurement_semantics", protocol_sha256=sha256(PROTOCOL_PATH),
                      input_zip_sha256=sha256(args.input_zip), assets={"benchmark":sha256(dataset), "authors_scenario1":sha256(source)},
                      environment={"python":platform.python_version(), "numpy":np.__version__, "pandas":pd.__version__},
                      source_bridge=bridge, fixtures=fixtures, synthetic_row1503_match=collision, clean_controls=controls,
                      packet_duration_rule_adopted=False, missingness_identifiable_from_features=False,
                      notebook08_results_recomputed=False, model_scoring_performed=False, test_rows_evaluated=0,
                      followup=followup, limitations=protocol["limitations"], wall_seconds=time.perf_counter()-started)
        write_json(args.out / "report.json", report)
        print(json.dumps({"status":report["status"], "source_rows":bridge["original_scenario1_rows"],
                          "rule_adopted":False, "next_sample":len(followup["csv_rows"]), "wall_seconds":report["wall_seconds"]}, indent=2))
    finally:
        evidence.z.close()


if __name__ == "__main__":
    main()
