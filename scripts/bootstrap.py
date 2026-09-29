"""Install the pinned CPU baseline separately from Colab's notebook Python."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "baseline"
ENV = ROOT / ".baseline-env"
PYTHON = ENV / "bin/python"
VENDOR = ROOT / "vendor/tabularbench"
UV_VERSION = "0.12.18"
PYTHON_VERSION = "3.8.20"
sys.path.insert(0, str(BASELINE))
from download_assets import CODE_REVISION


def run(args, **kwargs):
    print("+ " + " ".join(str(a) for a in args), flush=True)
    return subprocess.run([str(a) for a in args], check=True, cwd=ROOT, **kwargs)


def main():
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise SystemExit("Use a Linux x86_64 runtime (Google Colab CPU or Ubuntu/WSL2).")
    if not shutil.which("git"):
        raise SystemExit("git is required; it is normally available in Colab.")
    uv_root = ROOT / ".tools/uv"
    uv = uv_root / "bin/uv"
    if not uv.exists():
        # --target leaves the notebook kernel's packages and interpreter alone.
        run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
             "--target", uv_root, "uv==" + UV_VERSION])
    installed_uv = subprocess.check_output([str(uv), "--version"], text=True).split()[1]
    if installed_uv != UV_VERSION:
        raise SystemExit("Unexpected uv version in .tools/uv; move that folder aside and rerun setup.")
    env = os.environ.copy()
    env.update({
        "UV_CACHE_DIR": str(ROOT / ".cache/uv"),
        "UV_PYTHON_INSTALL_DIR": str(ROOT / ".tools/python"),
        "UV_PYTHON_BIN_DIR": str(ROOT / ".tools/python-bin"),
        "UV_PYTHON_PREFERENCE": "only-managed",
        "UV_LINK_MODE": "copy",
    })
    if not (VENDOR / ".git").exists():
        VENDOR.mkdir(parents=True, exist_ok=True)
        if any(VENDOR.iterdir()):
            raise SystemExit("vendor/tabularbench already contains non-git files; move it aside first.")
        run(["git", "init", VENDOR])
        run(["git", "-C", VENDOR, "remote", "add", "origin", "https://github.com/serval-uni-lu/tabularbench.git"])
    # Also handles an interrupted initial fetch without deleting any files.
    head = subprocess.run(["git", "-C", str(VENDOR), "rev-parse", "--verify", "HEAD"], capture_output=True, text=True)
    if head.returncode:
        run(["git", "-C", VENDOR, "fetch", "--depth", "1", "origin", CODE_REVISION])
        run(["git", "-C", VENDOR, "checkout", "--detach", CODE_REVISION])
    else:
        if head.stdout.strip() != CODE_REVISION:
            raise SystemExit("Upstream checkout is at another revision; preserve it and use a new workspace.")
    if subprocess.check_output(["git", "-C", str(VENDOR), "diff", "HEAD", "--"], text=True):
        raise SystemExit("Upstream tracked files changed. Preserve edits and use a clean checkout.")
    run([uv, "python", "install", PYTHON_VERSION], env=env)
    if not PYTHON.exists():
        if ENV.exists() and any(ENV.iterdir()):
            raise SystemExit("Incomplete .baseline-env. Rename it, then rerun setup.")
        run([uv, "venv", "--python", PYTHON_VERSION, ENV], env=env)
    run([PYTHON, "-c", "import sys; assert sys.version_info[:3] == (3, 8, 20), sys.version"], env=env)
    # Resolve everything in one transaction. Separate torch-first installation
    # would temporarily pull different numpy/requests versions from its index.
    run([uv, "pip", "install", "--python", PYTHON, "-r", BASELINE / "requirements-repro.txt",
         "torch @ https://download.pytorch.org/whl/cpu/torch-1.12.1%2Bcpu-cp38-cp38-linux_x86_64.whl",
         "torchvision @ https://download.pytorch.org/whl/cpu/torchvision-0.13.1%2Bcpu-cp38-cp38-linux_x86_64.whl"], env=env)
    run([uv, "pip", "check", "--python", PYTHON], env=env)
    run([PYTHON, "-m", "unittest", "discover", "-s", "tests", "-v"], env=env)
    packages = subprocess.check_output([str(uv), "pip", "freeze", "--python", str(PYTHON)], text=True, env=env)
    report = {
        "baseline_python": PYTHON_VERSION,
        "bootstrap_python": platform.python_version(),
        "uv": installed_uv,
        "platform": platform.platform(),
        "upstream_commit": CODE_REVISION,
        "requirements_sha256": hashlib.sha256((BASELINE / "requirements-repro.txt").read_bytes()).hexdigest(),
        "installed_packages": packages.splitlines(),
    }
    (ROOT / ".cache/setup_report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Setup complete. Baseline Python: " + str(PYTHON), flush=True)


if __name__ == "__main__":
    main()
