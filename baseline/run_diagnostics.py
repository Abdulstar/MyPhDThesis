"""Run the original baseline with an observer on CAA's final selector.

Uses the same CLI as run_baseline.py, and requires --attack. Upstream files and
the original baseline runner are unchanged. Observer installation is limited
to this process. Diagnostic timing includes audit computation and file I/O.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

# Also applies the original thread configuration before importing torch/numpy.
import run_baseline
import numpy as np
import torch
from candidate_trace import CandidateTrace, observe_selector
from download_assets import CODE_REVISION


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repo", type=Path, default=Path("vendor/tabularbench"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--models", nargs="+", default=["default", "madry"])
    args, _ = parser.parse_known_args()
    if "--attack" not in sys.argv:
        parser.error("Pass --attack; all other options match run_baseline.py.")
    revision = subprocess.check_output(["git", "-C", str(args.repo), "rev-parse", "HEAD"], text=True).strip()
    if revision != CODE_REVISION or subprocess.check_output(["git", "-C", str(args.repo), "diff", "HEAD", "--"], text=True):
        raise RuntimeError("Diagnostics require the clean, pinned upstream checkout.")
    sys.path.insert(0, str(args.repo.resolve()))
    from tabularbench.attacks.caa import caa
    from tabularbench.constraints.constraints_checker import ConstraintChecker
    original_class = caa.ConstrainedAutoAttack
    names = iter(args.models)

    class ObservedCAA(original_class):
        def __init__(self, *positional, **kwargs):
            super().__init__(*positional, **kwargs)
            name = next(names)
            # This runner intentionally retains the audited native CTU row cut.
            rows = np.load(args.out / "selected_test_indices.npy", allow_pickle=False) + 143046
            stages = ["NoAttack"] + [type(a).__name__ for a in self._autoattack.attacks]
            checker = ConstraintChecker(self.constraints_eval, self.objective_calculator.thresholds["constraints"])
            trace = CandidateTrace(args.out / "diagnostics" / name, rows, stages,
                                   checker, self.objective_calculator.thresholds)
            # Check that logging does not consume random numbers. This is done
            # after selection, so the attack's own RNG use is not intercepted.
            record = trace.record

            def checked_record(*record_args, **record_kwargs):
                numpy_before = np.random.get_state()
                torch_before = torch.get_rng_state().clone()
                record(*record_args, **record_kwargs)
                numpy_after = np.random.get_state()
                assert numpy_before[0] == numpy_after[0]
                np.testing.assert_array_equal(numpy_before[1], numpy_after[1])
                assert numpy_before[2:] == numpy_after[2:]
                assert torch.equal(torch_before, torch.get_rng_state())

            trace.record = checked_record
            observe_selector(self._autoattack.objective_calculator, trace)

    caa.ConstrainedAutoAttack = ObservedCAA
    try:
        run_baseline.main()
    finally:
        caa.ConstrainedAutoAttack = original_class
    (args.out / "diagnostics_manifest.json").write_text(json.dumps({
        "observer": "baseline/candidate_trace.py",
        "upstream_commit": revision,
        "upstream_files_modified": False,
        "original_selector_return_values_preserved": True,
        "observer_numpy_and_torch_rng_preservation_checked": True,
        "stage_outputs_saved": True,
        "every_optimizer_iteration_saved": False,
        "timings_include_diagnostic_overhead": True,
        "diagnostics_constraints_tolerance": 0.0,
        "final_attack_scoring_unchanged": True,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
