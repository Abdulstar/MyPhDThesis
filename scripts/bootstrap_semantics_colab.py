"""Create an isolated audit environment without invoking ensurepip.

Host pip >=22.3 manages the new interpreter through its --python option.
No host packages, existing environments, or previous reports are overwritten.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "baseline/requirements-semantics.txt"


def create_environment(destination):
    destination = Path(destination).absolute()
    destination.mkdir(parents=True, exist_ok=False)
    # The default CLI invokes ensurepip. Explicitly disable that step, including
    # on installations whose ensurepip module is absent or cannot run.
    venv.EnvBuilder(with_pip=False, system_site_packages=False,
                    symlinks=os.name != "nt", clear=False).create(destination)
    return destination / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def run(command, capture=False):
    print("+ " + " ".join(str(x) for x in command), flush=True)
    return subprocess.run([str(x) for x in command], check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        raise SystemExit("Use a new setup report path; the earlier report is preserved.")
    if not (3, 11) <= sys.version_info[:2] <= (3, 13):
        raise SystemExit("The audit requires a Python 3.11–3.13 notebook runtime.")
    pip_version = run([sys.executable, "-m", "pip", "--version"], capture=True).strip()
    match = re.match(r"pip (\d+)\.(\d+)", pip_version)
    if not match or tuple(map(int, match.groups())) < (22, 3):
        raise SystemExit("Host pip >=22.3 is required for --python. Use a current Colab runtime.")
    python = create_environment(args.env)
    target = [sys.executable, "-m", "pip", "--disable-pip-version-check", "--python", python]
    run(target + ["install", "-r", REQUIREMENTS])
    run(target + ["check"])
    installed = run(target + ["freeze"], capture=True).splitlines()
    verification = json.loads(run([python, "-I", "-c", """
import importlib.util, json, sys
from pathlib import Path
import numpy, pandas
root = Path(sys.prefix).resolve()
assert sys.prefix != sys.base_prefix
assert numpy.__version__ == '2.3.5' and pandas.__version__ == '2.2.3'
assert Path(numpy.__file__).resolve().is_relative_to(root)
assert Path(pandas.__file__).resolve().is_relative_to(root)
print(json.dumps(dict(prefix=str(root), base_prefix=sys.base_prefix,
    python=sys.version.split()[0], numpy=numpy.__version__, pandas=pandas.__version__,
    pip_installed_in_target=importlib.util.find_spec('pip') is not None)))
"""], capture=True))
    if Path(verification["prefix"]) != args.env.absolute():
        raise RuntimeError("The interpreter prefix is not the requested environment")
    report = dict(status="completed", method="venv_without_pip_then_host_pip_python",
                  ensurepip_requested=False, host_python=platform.python_version(),
                  host_pip=pip_version, target=verification, installed_packages=installed,
                  requirements_sha256=hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    print("Audit environment ready: " + str(python), flush=True)


if __name__ == "__main__":
    main()
