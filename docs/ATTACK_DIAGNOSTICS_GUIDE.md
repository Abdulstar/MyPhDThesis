# Attack diagnostics on the same 32 records

[Open notebook 03 in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/03_Attack_Diagnostics_32.ipynb)

Choose a CPU runtime, leave the defaults unchanged, and select **Runtime → Run all**. Download the final ZIP and share it for review. No changes to notebook 01 or 02 are required. Notebook 03 uses a separate `/content/MyPhDThesis_Diagnostics32` checkout and unique output folders.

## Why this experiment is next

The uploaded pilot produced zero new evasions and unchanged final attack arrays. Its final arrays do not tell us why candidates were rejected. The new observer records the outputs of each CAA stage after that stage returns but before CAA selects successful examples. It does not record every intermediate gradient iterate or every evolutionary generation.

The experiment also compares two search efforts:

| Setting | First run | Second run |
|---|---:|---:|
| Malicious records | Same 32 | Same 32 |
| Evolutionary generations | 10 | 100 |
| Offspring | 50 | 50 |
| Gradient steps | 10 | 10 |
| Scaled L2 radius | 0.5 | 0.5 |
| Seed | 0 | 0 |
| Checkpoints | Standard and adversarial RLN | Same checkpoints |

Only generation count changes between the two runs. The longer run is not guaranteed to find more successful candidates: a finite stochastic optimizer and its final returned population do not provide a monotonic robustness bound. The comparison describes this predefined evaluation setting, not a general robustness guarantee.

## What is recorded

The observer captures three possible stages:

1. **NoAttack:** unchanged-input control. Already-missed examples are not new evasions.
2. **CAPGD:** the constrained gradient attack's returned candidates.
3. **Moeva2:** the evolutionary attack's returned population for records still unresolved.

CAA may stop early or remove successful records before later stages. Original CSV row IDs remain aligned even when two records have identical feature values.

For every returned candidate, the archive stores the original/candidate arrays, row ID, change indicator, scaled distance, score margin and checks for relationships, bounds, feature types and immutable features. The three acceptance conditions are **valid**, **within budget**, and **misclassified**. All three must hold simultaneously.

`invalid`, `over_budget` and `still_detected` counts can overlap. Do not sum them as distinct rejected candidates. The eight `disjoint_objective_buckets` in each `stage_summary.json` partition every stage's candidates exactly. Candidate counts describe optimizer outputs, not independent network attacks, packets or requests.

## Reading the exported files

| File | Purpose |
|---|---|
| `budget_comparison.csv` | Final new evasions and detection for each model/budget |
| `candidate_stage_comparison.csv` | Candidate changes, failures and successes by stage |
| `comparison_checks.json` | Same subset, controlled settings and clean reference checks |
| `diagnostics/<model>/stage_summary.json` | Failure breakdown and disjoint objective combinations |
| `diagnostics/<model>/*_candidates.csv` | One row per observed candidate |
| `diagnostics/<model>/*_candidates.npz` | Candidate arrays and cached objective values |
| `diagnostics_manifest.json` | Observer scope and RNG-preservation checks |

The usual clean predictions, final attack arrays, environment versions, hashes and script snapshots are also included. If execution stops, run the final export cell separately to preserve the partial logs. The larger ZIP can take longer to download than earlier pilots.

## How the observer preserves the baseline

`baseline/run_diagnostics.py` calls the original `run_baseline.py` with the same arguments. Within that process only, it installs an observer on CAA's top-level selector. The original selector runs first and its returned indices are passed back unchanged. The observer uses the already-cached objective evaluations; it does not make additional model predictions or generate candidates. It verifies that its logging preserves NumPy and PyTorch random-number states.

Constraint checks are decomposed using the same pinned checker at the same tolerance, and their conjunction is checked against the selector's cached validity. The original upstream files, attack parameters, feature scaling and success rules are unchanged. An assertion stops the run if candidate alignment or validity bookkeeping disagrees.

Recording has computation, compression and I/O overhead. The reported attack wall times include this overhead and must not be used as inference latency, packet throughput, or a direct speed comparison against notebook 02.

## What the findings will determine

If the observer finds changed but invalid candidates, inspect their failed constraints and the attack's feasibility handling. If valid changes exceed the distance budget, they remain failures at radius 0.5. If changed, valid, in-budget candidates remain detected, record that limited result. If accepted evasions appear, compare the models on the same rows before expanding the evaluation.

Do not relax constraints or enlarge the radius merely to force a successful attack. Different attacker capabilities or budgets are separate research conditions that need justification. This diagnostic does not train the proposed defense, and it does not turn feature-space evidence into a live-traffic result.

The pinned CPU environment is retained. GPU support and a leakage-controlled training protocol remain separate later tasks. See the [pilot review](COLAB_PILOT32_REVIEW_2026-09-29.md) for the preceding measurements.

## Local validation and initial findings

All six default code cells completed locally in approximately 244 seconds, using cached setup/assets. Both generation budgets were run for both models. Five unit checks passed and the exported archive passed its integrity check. This was sequential code-cell execution in one local Python namespace; hosted Colab, its browser download callback and optional Drive authorization were not exercised.

| Evolutionary generations | Standard RLN: new evasions | Adversarial RLN: new evasions |
|---|---:|---:|
| 10 | 0 / 32 | 0 / 32 |
| 100 | 1 / 32 | 0 / 32 |

At 10 generations, the final attack arrays matched the uploaded Colab pilot exactly. CAPGD changed all 32 rows for each model, but all 32 candidates failed relationship constraints; they passed the distance, bound, type and immutable-feature checks. The evolutionary stage returned only four changed, valid, in-budget candidates per model, and none evaded detection.

At 100 generations, the standard model's evolutionary stage returned 25 successful candidates, all for **one original record**. These are one newly evaded record, not 25 independent evasions. Final detection on the malicious subset was 31/32 (96.875%) for the standard model and 32/32 (100%) for the adversarially trained model. The final predictions, feature validity and scaled distances were independently recomputed from the saved arrays, scaler and checkpoints.

This establishes a feature-valid evasion under this search setting and shows that the earlier zero-evasion result depended on search effort. It does not establish real-traffic realizability, a general defense ranking, or a statistically reliable advantage from one paired 32-record subset and one seed. Exact stage counts and validation details are in [the local validation record](../reference_results/diagnostics32_local_validation_2026-09-29.json). Run the notebook in Colab to obtain an independent execution record in your working environment.
