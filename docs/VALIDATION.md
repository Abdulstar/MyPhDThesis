# Validation record — 29 September 2026

## Completed

- Created a fresh isolated Python 3.8.20 environment through `scripts/bootstrap.py`; installed CPU PyTorch 1.12.1 and the pinned dependencies. `uv pip check` passed for all 60 packages.
- Validated the notebook against the nbformat schema and compiled every code cell.
- Executed all eight default notebook code cells, sequentially in one Python 3.12.14 namespace on Linux x86_64. The baseline itself ran as a Python 3.8 subprocess, leaving the controlling interpreter unchanged.
- Downloaded the full dataset and both checkpoints through the notebook's download cell; all six SHA-256 hashes passed.
- Reproduced both clean confusion matrices on 55,082 native test records. Standard RLN: TN 54,587, FP 88, FN 9, TP 398. Adversarially trained RLN: TN 54,633, FP 42, FN 11, TP 396.
- Completed the eight-record CAA smoke test for both checkpoints. Both had zero new evasions and returned unchanged inputs. These results verify execution; they do not establish robustness.
- Generated the summary CSV files and confusion-matrix image.
- Created and integrity-checked the results ZIP, including both result sets, logs, provenance and source snapshot, while excluding downloaded assets and the environment.
- Passed three focused tests covering malicious/valid sample selection, metric denominators and invalid/out-of-budget candidate handling.

Machine-readable measurements: [`colab_integration_validation_2026-09-29.json`](../reference_results/colab_integration_validation_2026-09-29.json).

## Boundaries of this validation

The notebook was **not executed in Google's hosted Colab service**. A local Jupyter kernel attempt was blocked by this execution environment's network-interface restrictions, so the exact default code cells were run directly in order instead. This checks the experimental workflow but does not exercise the notebook frontend, the Colab browser-download callback, or Google Drive authorization/copy. Those remain for the first hosted run.

Prepublication execution reused the existing local checkout; it did not clone the then-empty public repository. The installer itself was tested with a fresh environment and upstream checkout. An existing, successfully installed environment was reused when executing the code cells.

The full-budget attack option was left disabled. No retraining, new defensive method, live-traffic experiment, multiple-seed estimate or full published robust-score reproduction was performed.

The notebook keeps heavy optional evaluation off by default and records run settings to make these distinctions visible in the outputs.
