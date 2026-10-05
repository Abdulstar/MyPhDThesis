"""Small, auditable helpers for the notebook-07 saved-pool audit.

The added rule is a necessary aggregate condition, not a packet-validity oracle.
No model, attack, threshold or original benchmark constraint is modified.
"""
import hashlib
import io
import math
from pathlib import Path, PurePosixPath
import stat
import zipfile

import numpy as np


def checked_archive(path, max_bytes=256 * 1024 * 1024, max_members=4000):
    """Bound and validate ZIP contents before reading/extracting; never execute."""
    z = zipfile.ZipFile(path)
    try:
        items = z.infolist()
        if len(items) > max_members or len({i.filename for i in items}) != len(items):
            raise ValueError("Excessive or duplicate ZIP members")
        if sum(i.file_size for i in items) > max_bytes:
            raise ValueError("ZIP expanded size exceeds the audit limit")
        for item in items:
            name = item.filename.rstrip("/")
            p = PurePosixPath(name)
            if (not name or p.is_absolute() or ".." in p.parts or "\\" in name
                    or ":" in name or str(p) != name
                    or stat.S_ISLNK(item.external_attr >> 16)):
                raise ValueError("Unsafe ZIP member: " + item.filename)
        bad = z.testzip()
        if bad is not None:
            raise ValueError("ZIP CRC failure: " + bad)
    except Exception:
        z.close()
        raise
    return z


def unpack_evidence(source, destination):
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError("Preserving earlier evidence: " + str(destination))
    with checked_archive(source) as z:
        # Validate first; extraction is exclusively into a newly created tree.
        destination.mkdir(parents=True, exist_ok=False)
        for info in z.infolist():
            target = destination / info.filename
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as f:
                    f.write(z.read(info))
    matches = [p.parent.parent for p in destination.glob("**/baseline/protocol.json")
               if (p.parent.parent / "inloop/protocol.json").is_file()]
    if len(matches) != 1:
        raise ValueError("Select a notebook-06 ZIP containing one baseline and one inloop run")
    return matches[0]


def load_npz(path):
    """Refuse pickles and dishonest/excessive nested NumPy array dimensions."""
    with checked_archive(path, max_bytes=128 * 1024 * 1024, max_members=128) as z:
        for member in z.infolist():
            if not member.filename.endswith(".npy") or member.is_dir():
                raise ValueError("Unexpected NPZ member")
            with z.open(member) as f:
                version = np.lib.format.read_magic(f)
                if version == (1, 0):
                    shape, _, dtype = np.lib.format.read_array_header_1_0(f)
                elif version == (2, 0):
                    shape, _, dtype = np.lib.format.read_array_header_2_0(f)
                else:
                    raise ValueError("Unsupported NPY format version")
                size = math.prod(shape) * dtype.itemsize
                if dtype.hasobject or size != member.file_size - f.tell():
                    raise ValueError("Unsafe or inconsistent NumPy array header")
    with np.load(path, allow_pickle=False) as f:
        return {k: f[k] for k in f.files}


def aggregate_pairs(names, protocol):
    if len(names) != len(set(names)):
        raise ValueError("Duplicate feature names")
    index = {name: i for i, name in enumerate(names)}
    pairs = []
    for metric in protocol["metrics"]:
        for direction in protocol["directions"]:
            for port in protocol["ports"]:
                a = metric + "_sum_" + direction + "_" + port
                b = metric + "_max_" + direction + "_" + port
                if a not in index or b not in index:
                    raise ValueError("Missing paired aggregate: " + a + " / " + b)
                pairs.append({"pair_id": len(pairs), "metric": metric,
                              "sum_feature": a, "max_feature": b,
                              "sum_index": index[a], "max_index": index[b]})
    if len(pairs) != protocol["expected_pairs"]:
        raise ValueError("Unexpected rule count")
    return pairs


def support_failures(x, pairs):
    """Exactly (sum > 0) & (maximum == 0), with no inferred time/size cap."""
    a = [p["sum_index"] for p in pairs]
    b = [p["max_index"] for p in pairs]
    return (x[..., a] > 0) & (x[..., b] == 0)


def vector_digest(vector):
    return hashlib.sha256(np.ascontiguousarray(vector).tobytes()).hexdigest()


def merge_candidate(pools, position, vector, score, distance, source, local_index,
                    support_ok, predicted_class):
    """Deduplicate within one original record, preserving a stable provenance."""
    digest = vector_digest(vector)
    item = {"vector": vector, "sha256": digest, "score": float(score),
            "distance": float(distance), "source": source, "index": int(local_index),
            "support_ok": bool(support_ok), "prediction": int(predicted_class)}
    old = pools[position].get(digest)
    if old is None or (source, local_index) < (old["source"], old["index"]):
        pools[position][digest] = item


def evasion_options(pools, clean_predictions, require_support):
    result = []
    for i, pool in enumerate(pools):
        options = [c for c in pool.values() if clean_predictions[i] == 1
                   and c["prediction"] == 0 and (c["support_ok"] or not require_support)]
        options.sort(key=lambda c: (c["score"], c["distance"], c["source"], c["index"]))
        result.append(options)
    return result


def select_with_final_gate(clean, options, accept_matrix):
    """Try saved evasions in order; check the complete final matrix each time.

    Population geometry matters to the unchanged float32 native checker. Never
    replace this with flattened-population or singleton checks. Rejections are
    retained in the audit; clean fallback does not count as a new evasion.
    """
    pointers = [0] * len(clean)
    rejected = []
    max_rounds = 1 + sum(len(o) for o in options)
    for _ in range(max_rounds):
        chosen = [o[p] if p < len(o) else None for o, p in zip(options, pointers)]
        x = clean.copy()
        for i, c in enumerate(chosen):
            if c is not None:
                x[i] = c["vector"]
        accepted = np.asarray(accept_matrix(x), dtype=bool)
        if accepted.shape != (len(clean),):
            raise ValueError("Final gate returned the wrong shape")
        if accepted.all():
            return x, chosen, rejected
        for i in np.flatnonzero(~accepted):
            if chosen[i] is None:
                raise ValueError("An unchanged clean control failed the final gate")
            c = chosen[i]
            rejected.append({"input_position": int(i), "sha256": c["sha256"],
                             "source": c["source"], "index": c["index"],
                             "rank_zero_based": pointers[i]})
            pointers[i] += 1
    raise RuntimeError("Final candidate selection failed to terminate")
