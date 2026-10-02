# Notebook 05: local development results

The full default experiment completed on 1 October 2026 and its saved evidence was independently checked on 2 October. Conservative block rollback greatly increased coverage by changed, valid, in-budget candidates, but **did not find additional evasions**. This is a useful repair comparator and a negative result for stronger evasion, not an improved IDS or a completed PhD contribution.

Run [notebook 05 in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/05_Development_Consistency_Repair.ipynb) with a CPU runtime and **Runtime → Run all**. No previous ZIP upload is required. The [implementation guide](DEVELOPMENT_REPAIR_GUIDE.md) explains the fixed protocol and exported evidence.

## Fixed experiment

- 32 constraint-valid malicious records selected from the official upstream validation partition; selection seed 0; no model-prediction filtering.
- Two existing RLN checkpoints: standard (`default`) and adversarially trained (`madry`).
- Attack seeds 0, 1 and 2; identical selected records throughout.
- Original CAA: 10 gradient steps, 100 evolutionary generations, 50 offspring, scaled L2 radius 0.5, original constraints and zero relationship tolerance.
- Original CAA ran once per model/seed. Both repair methods processed the same saved stage outputs after generation finished, retained validated original evasions and reported extra computation separately.

Both models detected 28 of the 32 selected records before attack. The other four were already missed and are excluded from the new-evasion denominator. Original CAA's early stopping gave those four no later-stage attack candidates.

## Results by seed

Coverage counts distinct original records with at least one **changed, valid, in-budget** candidate in the method's union with the original pool. A clean fallback does not count. Each three-number entry below lists seeds 0, 1 and 2; these are repeated searches on the same inputs, not three independent data samples.

| Model | Method | Coverage out of 32, seeds 0 / 1 / 2 | New evasions out of 28, seeds 0 / 1 / 2 |
|---|---|---|---|
| Standard RLN | Original CAA | 2 / 2 / 1 | 1 / 1 / 1 |
| Standard RLN | Budget-only rollback | 27 / 28 / 28 | 1 / 1 / 1 |
| Standard RLN | Relationship + budget rollback | 28 / 28 / 28 | 1 / 1 / 1 |
| Adversarially trained RLN | Original CAA | 1 / 2 / 3 | 0 / 0 / 0 |
| Adversarially trained RLN | Budget-only rollback | 28 / 28 / 28 | 0 / 0 / 0 |
| Adversarially trained RLN | Relationship + budget rollback | 28 / 28 / 28 | 0 / 0 / 0 |

New-evasion rates were 3.57% for standard RLN and 0% for adversarially trained RLN under all three methods and all three seeds. Selected-subset malicious recall after attack was respectively 27/32 (84.375%) and 28/32 (87.5%). These are not full-dataset accuracy scores or proof of robustness.

Relationship + budget rollback produced zero constraint-invalid candidates in its saved pools for all six runs. Invalid candidates remained in the budget-only pools and were excluded from acceptance. Relationship repair also produced more distinct feasible changes, even where record coverage was the same:

| Model | Original unique feasible changes, seeds 0 / 1 / 2 | Budget-only union | Relationship + budget union |
|---|---|---|---|
| Standard RLN | 50 / 33 / 31 | 314 / 343 / 361 | 697 / 769 / 892 |
| Adversarially trained RLN | 14 / 21 / 12 | 429 / 358 / 445 | 845 / 953 / 1128 |

Vectors are deduplicated separately for each original record before these counts are summed. They do not increase the statistical sample size. Most of the record-coverage improvement was already achieved by the budget-only control; this limits what can be attributed specifically to relationship repair.

## Cost and validation

The six original attacks took approximately 81–84 seconds each on this local CPU environment, including candidate tracing. Mean additional processing time was approximately 1.21–1.24 seconds for budget-only rollback and 2.02–2.05 seconds for relationship + budget rollback, depending on model. The complete experiment cell took about nine minutes. These are local pipeline timings, include evidence-writing overhead and do not predict Colab runtime or IDS server throughput.

Validation included:

- All 16 project tests, including seven new repair and final-acceptance tests.
- Exact execution of all six notebook code cells, in order, with the default settings in a local Python namespace; schema and ZIP integrity checks.
- Independent rechecking of 18 original stage files (34,968 candidate entries) and 36 repaired stage files (69,936 entries), using the pinned constraints and scaler.
- Checks that every repaired coordinate came from the corresponding proposed or original value, source-pool hashes matched across methods, and record-level coverage and evasion counts matched saved arrays.
- Fresh model scoring of 7,534 unique changed-feasible vectors across repaired stage files and all 576 final representatives across the 18 comparisons.
- Verification that earlier tracked project files remained unchanged and an existing output directory was refused.

The hosted Colab browser and its download dialog were not exercised here. The generated results ZIP passed its integrity check and contains the full original and repaired arrays, masks, predictions, source snapshots and logs. The [machine-readable reference](../reference_results/development_repair_local_validation_2026-10-02.json) records the archive SHA-256, tested source hashes, complete per-run metrics and validation scope.

## Research decision supported by this result

Keep this simple rollback method as a comparator. It can turn many infeasible proposals into feasible changes, but it does not yet demonstrate stronger attacks or improved defense. A suitable next development question is whether generating changes within consistent feature groups, rather than repairing only final stage outputs, finds more valid evasions for a measured computational budget. That is a future hypothesis, not a result from this notebook.

Before judging the intended defense contribution, define the attacker capabilities and valid perturbations, develop the attack and training procedure on development data, then freeze an independent evaluation protocol. New model training should use train-only preprocessing. This checkpoint-compatibility diagnostic fits its scaler on all dataset feature rows and inherits upstream checkpoint training history; it is not a leakage-free final evaluation. Constraint-valid feature aggregates do not establish packet realizability or preserved malicious functionality.
