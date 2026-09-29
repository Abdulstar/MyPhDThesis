# Review of the uploaded Colab pilot

The uploaded archive `pilot32_20260929T060849Z_2174bc2f_results_20260929T061041Z_a44172fa.zip` completed the planned 32-record experiment successfully. The recorded project commit is `0ad9419bec662ad2c144a040c525d1f7287a0aa0`, with a clean working tree.

## Verified measurements

Clean evaluation used 55,082 records: 54,675 benign and 407 malicious.

| Measurement | Standard RLN | Adversarially trained RLN |
|---|---:|---:|
| Clean accuracy | 99.8239% | 99.9038% |
| Malicious records detected | 398 / 407 | 396 / 407 |
| Malicious recall | 97.7887% | 97.2973% |
| False alarms | 88 / 54,675 | 42 / 54,675 |
| Attacked malicious records | 32 | 32 |
| Initially detected in this subset | 32 | 32 |
| New evasions | 0 | 0 |
| Returned rows that changed | 0 | 0 |
| Maximum returned scaled L2 distance | 0 | 0 |
| Attack wall time, this run | 24.20 seconds | 21.61 seconds |

The combined evaluation command took 67.44 seconds, excluding setup/download. Main-process peak memory was approximately 4.63 GiB. These are single CPU-run observations, not packet-level latency measurements or a controlled model-speed study.

The adversarially trained checkpoint has fewer false alarms but misses two more malicious records on this clean partition. Higher overall accuracy therefore does not imply higher malicious recall.

## Independent checks

- ZIP integrity passed; all 35 entries were readable.
- All eight source snapshots match both their recorded SHA-256 hashes and the Git blob IDs at the recorded commit.
- The download manifest reports all six pinned asset hashes. The large assets are not embedded in the ZIP, so they were not rehashed from this upload.
- Confusion matrices, positive-class AUROC and average precision were independently recomputed from the saved clean predictions.
- Seed-0 sample selection was reproduced. Both models used the same 32 original CSV rows.
- Both saved adversarial arrays are exactly equal to their clean arrays, with shape 32 × 757. Row IDs, labels and per-record audits agree.
- No traceback or failed/error marker was found in the uploaded execution logs.

Machine-readable evidence is in [the review record](../reference_results/pilot32_colab_review_2026-09-29.json).

## Research interpretation

This establishes a successful Colab execution of the checkpoint baseline and the bounded attack pilot. It does not establish robustness. CAA initializes its output with the original inputs and replaces them only when its selector finds acceptable successful candidates. Consequently, unchanged returned inputs do not reveal what candidates were attempted and rejected internally.

The ZIP cannot distinguish insufficient search, invalid candidates, over-budget candidates, or valid changes that the model still detects. It also provides no successful evasion with which to compare the defenses' adversarial performance. Zero observed evasions is a valid result to preserve; it is not an error to fix by changing the scoring rules.

## Next experiment

Use [notebook 03](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/03_Attack_Diagnostics_32.ipynb). It records attack-stage outputs before CAA's final selection and compares 10 versus 100 evolutionary generations while holding the selected rows, seed, models, gradient steps, offspring and perturbation radius fixed. It keeps the original feature-validity checks and attack scoring.

The checkpoint-compatible scaler still follows the upstream all-feature-rows convention. New training comparisons require train-only preprocessing and separate development/test data. These are CTU feature records, not live packets or requests.

Implementation source: [pinned CAA selector](https://github.com/serval-uni-lu/tabularbench/blob/bfb75415a6a31a41ddfeef34478eea1da227d19c/tabularbench/attacks/caa/caa.py).
