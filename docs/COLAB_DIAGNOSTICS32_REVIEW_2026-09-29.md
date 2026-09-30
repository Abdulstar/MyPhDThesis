# Review of notebook 03's uploaded Colab results

The uploaded archive `diagnostics32_20260929T132256Z_f142b528_results_20260929T133337Z_79f17a41.zip` completed both search budgets for both checkpoints. The recorded project commit is `cae62372e7805160a2e9c7a593734c210773df4c`, with a clean working tree. This is the user's hosted Colab run, distinct from the earlier local validation.

## Main result

All four clean confusion matrices match the reference. The attack comparison used the same 32 malicious records, seed 0, 10 gradient steps, 50 offspring and scaled L2 radius 0.5. Only evolutionary generation count changed between the two budgets.

| Generations | Model | New evasions among initially detected records | Malicious recall after attack on this subset |
|---|---|---:|---:|
| 10 | Standard RLN | 0 / 32 | 100% |
| 10 | Adversarially trained RLN | 0 / 32 | 100% |
| 100 | Standard RLN | 1 / 32 (3.125%) | 96.875% |
| 100 | Adversarially trained RLN | 0 / 32 | 100% |

The newly evaded record is original CSV row **152745** (zero-based), the same record found in local validation. Its scaled L2 distance recomputes to **0.1582525969**, below the fixed 0.5 limit. The saved constraint checks mark it valid; the final attack audit records a malicious-to-benign prediction change. The final array exactly matches the candidate selected from the evolutionary stage.

These recall values concern the 32 attacked malicious records, not all 55,082 test records, all malicious traffic, or live packets. A one-record difference in one small paired subset and one seed does not establish a general or statistically reliable defense advantage. No new defense has been trained in this experiment.

## What the candidate diagnostics show

For each model and budget, CAPGD returned 32 changed candidates. All 32 failed relationship constraints. None failed the bound, type or immutable-feature checks, and all were inside the distance budget. The standard model misclassified one of these invalid candidates, which correctly did not count as a successful evasion.

At 100 generations, the evolutionary stage returned 6,592 candidates for each model:

| Candidate measurement | Standard RLN | Adversarially trained RLN |
|---|---:|---:|
| Changed candidates | 3,745 | 4,817 |
| Changed, valid and within budget | 43 | 52 |
| Candidates classified incorrectly before validity/budget filtering | 3,294 | 3,646 |
| Successful candidates satisfying all conditions | 11 | 0 |
| Original records with a successful candidate | 1 | 0 |
| Original records with any changed, valid, in-budget stage-output candidate | 2 / 32 | 1 / 32 |

The 11 successful candidates refer to **one original record**, not 11 independent evasions. Failure reasons overlap. Most candidates being classified incorrectly is not sufficient: they must also satisfy the feature constraints and perturbation budget. Changed, feasible candidate coverage should be reported alongside new-evasion rates when extending this evaluation.

Only two standard-model records and one adversarial-model record had any changed, valid, in-budget candidate among the saved 100-generation stage outputs. This is a reason to investigate feasible candidate generation before interpreting the zero-evasion cases as strong protection. It is not a claim that no feasible changes exist for the other records: the observer does not retain every internal optimizer iteration.

## Agreement with the earlier local run

The final evasion counts and the identity of the evaded record agree. The search traces are not identical. For example, the local standard-model evolutionary stage had 25 successful candidates at 100 generations, versus 11 in Colab; its selected perturbation had distance 0.1665994525, versus 0.1582525969 in Colab.

All ten recorded source snapshots match the GitHub commit and the earlier local validation hashes. This is therefore an outcome replication, not bitwise reproduction of the optimizer's candidates. The cause of the intermediate differences has not been isolated. Preserve environment records and quantify repeatability instead of assuming that a fixed seed guarantees identical searches across environments.

## Checks performed in this review

- ZIP integrity passed for all 88 entries; no traceback or failed/error log marker was found.
- All ten source snapshots matched their SHA-256 values and Git blob IDs at the recorded commit.
- All six reported asset hashes matched the pinned manifest. Source dataset/checkpoint files are not embedded in this archive and were not rehashed from the upload.
- Clean confusion matrices, positive-class AUROC and average precision were recomputed from saved prediction files.
- Seed-0 sample selection was reproduced. Row IDs, feature ordering and the saved scaler agree across budgets.
- All 12 stage summaries were checked against the saved candidate arrays, including changes, cached score decisions, constraint-mask conjunctions, selected indices and disjoint failure buckets.
- Scaled distances were independently recomputed using the saved scaler and the pinned min-max scaling formula.
- Final adversarial arrays were reconstructed from the selected stage candidates and matched the saved final arrays exactly.

This review checks the saved constraint and prediction outputs for consistency; it does not rerun the checkpoint models or feature-constraint rules against separately downloaded assets. The scientific claim remains limited to the supplied feature representation and checks. Feature validity does not demonstrate realizable network traffic that retains malicious functionality.

Machine-readable evidence is in [the review record](../reference_results/diagnostics32_colab_review_2026-09-29.json).

## Recommended next research step

First inspect **which individual feature relationships fail and the sizes of those violations**, using the candidates already saved by notebook 03. Distinguish substantive dependency violations from numerical residuals before changing an attack or its tolerance. Keep the present scoring rules as the recorded baseline; a revised tolerance or feasible-generation method would be a separately documented condition.

Then extend the fixed protocol to all 407 eligible malicious test records with multiple predefined attack seeds, retaining the same records for both models and reporting already-missed records separately from new evasions. Record both feasible candidate coverage and attack success, and assess repeatability. This broader evaluation should precede claims about defense rankings.

Before training the proposed method, establish train-only preprocessing and separate development/test data. The present pretrained-checkpoint compatibility scaler uses all feature rows to match the audited upstream loader. These pilot test rows should not become the data used to tune the proposed defense.

The combined evaluation commands took 119.88 seconds at 10 generations and 458.99 seconds at 100 generations, excluding setup/download. These timings include diagnostics and disk I/O and are not inference-speed benchmarks.
