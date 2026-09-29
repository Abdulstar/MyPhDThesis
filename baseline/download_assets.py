"""Download only the pinned CTU dataset and two RLN checkpoints."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

CODE_REVISION = "bfb75415a6a31a41ddfeef34478eea1da227d19c"
DATA_REVISION = "49cb6c10f28d17d6e9b70ccac27a7cf6e8a563c8"
MODEL_REVISION = "b6f2ac4ee659505da75b7e517649379334c55ad0"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def assets():
    for name in ["ctu_13_neris.csv", "ctu_13_neris_metadata.csv"]:
        yield name, "https://huggingface.co/datasets/serval-uni-lu/tabularbench/resolve/{}/ctu_13/{}".format(DATA_REVISION, name)
    for training in ["default", "madry"]:
        folder = "torchrln_ctu_13_neris_{}.model".format(training)
        for name in ["args.json", "weights.pt"]:
            local = "{}/{}".format(folder, name)
            remote = "https://huggingface.co/serval-uni-lu/tabularbench/resolve/{}/ctu_13_neris/{}".format(MODEL_REVISION, local)
            yield local, remote


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets", type=Path, default=Path("assets"))
    args = parser.parse_args()
    expected_path = Path(__file__).with_name("asset_hashes.json")
    expected = json.loads(expected_path.read_text()) if expected_path.exists() else {}
    manifest = {}
    for name, url in assets():
        path = args.assets / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            print("Downloading " + name, flush=True)
            tmp = path.with_name(path.name + ".part")
            with urllib.request.urlopen(url, timeout=120) as src, open(tmp, "wb") as dst:
                while True:
                    chunk = src.read(8 * 1024 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
            tmp.replace(path)
        digest = sha256(path)
        if name in expected and digest != expected[name]:
            raise RuntimeError("Hash mismatch: {}. Move this file aside, then download again.".format(path))
        manifest[name] = {"url": url, "sha256": digest, "bytes": path.stat().st_size}
        print("Verified {} ({} bytes)".format(name, path.stat().st_size), flush=True)
    (args.assets / "download_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
