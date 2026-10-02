# Colab notebook 05 results review — 2 October 2026

The uploaded Colab experiment completed successfully with the planned settings. Conservative relationship and budget rollback increased coverage by valid, changed candidates, but **found no additional evasions**. This supports the earlier local run's main conclusion, while preserving the differences between the two runs.

This review concerns the uploaded archive `development_repair_20261002T042520Z_3f469117_results_20261002T044827Z_690324d6.zip`, SHA-256 `25ef47869bc744a709c679ce32a33156d14a0759e68df13b171f126322309a32`. It does not replace the [earlier local findings](DEVELOPMENT_REPAIR_FINDINGS_2026-10-02.md). Complete metrics and verification evidence are in the [new reference JSON](../reference_results/development_repair_colab_review_2026-10-02.json).

## What was run

The archive records a clean checkout of project commit `395709672500e00e636382871c118a1a15dff2b6`. All 18 exported source snapshots match that published version. All six dataset/checkpoint hashes match the pins, and the installed package lists match the local validation environment. The Colab notebook kernel was Python 3.13.15; the experiment correctly ran in its separate Python 3.8.20, NumPy 1.23.5, PyTorch 1.12.1 CPU environment. The setup log records all 16 tests passing.

The experiment used 32 constraint-valid malicious records from the official validation partition, selection seed 0, attack seeds 0/1/2, both RLN checkpoints, 10 gradient steps, 100 evolutionary generations, 50 offspring and scaled L2 radius 0.5. The original relationship tolerance remained zero. Selected inputs, split indices and compatibility scaler are identical to the local run. No native test rows were attacked or scored.

Each model/seed generated one original CAA pool. Budget-only and relationship + budget rollback used that same pool after attack generation and retained valid original evasions. Additional time and model evaluations were measured; total computation is not equal across methods.

## Results

Both models initially detected 28 of the 32 selected malicious records. Four were already missed and are excluded from the new-evasion denominator. The original attack stopped processing those four after its clean-input check, so later stages supplied candidates for 28 records.

Coverage counts original records with at least one **changed, valid, in-budget** candidate in the method's union with the original pool. Restoring a candidate to its clean input does not count. Triples below list seeds 0, 1 and 2.

| Model | Method | Coverage out of 32, seeds 0 / 1 / 2 | New evasions out of 28, seeds 0 / 1 / 2 |
|---|---|---|---|
| Standard RLN | Original CAA | 2 / 3 / 4 | 1 / 1 / 1 |
| Standard RLN | Budget-only rollback | 26 / 27 / 28 | 1 / 1 / 1 |
| Standard RLN | Relationship + budget rollback | 28 / 28 / 28 | 1 / 1 / 1 |
| Adversarially trained RLN | Original CAA | 1 / 1 / 2 | 0 / 0 / 0 |
| Adversarially trained RLN | Budget-only rollback | 28 / 28 / 28 | 0 / 0 / 0 |
| Adversarially trained RLN | Relationship + budget rollback | 28 / 28 / 28 | 0 / 0 / 0 |

The standard RLN's new-evasion rate was 1/28 (3.57%) under every method and seed. The same original record, zero-based CSV row 117132, was newly evaded in each case. The adversarially trained RLN had 0/28 new evasions. Repeated successes on the same record are not three independent successes.

After attack, malicious recall on this selected subset was 27/32 (84.375%) for standard RLN and 28/32 (87.5%) for adversarially trained RLN. These are not full-dataset accuracy values. No model was trained or improved in this experiment.

Relationship + budget rollback produced zero constraint-invalid candidates in all six saved method pools. Budget-only rollback left some relationship-invalid candidates, which were excluded from acceptance. It nevertheless accounted for most of the record-coverage improvement. Relationship checks contributed two further covered records for standard RLN seed 0 and one for seed 1; coverage was otherwise equal to the budget-only control.

Relationship repair produced more distinct feasible changes per original record:

| Model | Original unique feasible changes, seeds 0 / 1 / 2 | Budget-only union | Relationship + budget union |
|---|---|---|---|
| Standard RLN | 16 / 38 / 14 | 280 / 300 / 377 | 693 / 719 / 976 |
| Adversarially trained RLN | 11 / 23 / 16 | 382 / 355 / 419 | 865 / 1112 / 1178 |

These counts are sums after deduplicating vectors separately for each original record. More candidates do not increase the number of independent data samples, and these feasible changes did not produce additional evasion.

## Timing

The full experiment took 1306.95 seconds, approximately 21.8 minutes, excluding the preceding setup and download cells. Individual original CAA runs took approximately 194–206 seconds including tracing. Mean added processing time was 3.52 seconds for standard RLN and 3.15 seconds for adversarially trained RLN with budget-only rollback, versus 4.47 and 5.66 seconds with relationship + budget rollback. Added time includes checking, prediction and evidence writing. These are Colab pipeline timings, not IDS server throughput measurements.

## Evidence checks and differences from the local run

The review checked archive integrity and safe paths, source snapshots, pinned assets, settings, row selection and summary consistency. It independently rechecked 18 raw stage files containing 34,968 candidate entries and 36 repaired stage files containing 69,936 entries. Every saved constraint component, validity decision, budget decision and changed/unchanged flag matched recomputation. Repairs used only the corresponding candidate or clean coordinate values. Source-pool hashes agreed across comparison methods, and saved record-level coverage and evasion counts matched the arrays.

The review also rescored 7,656 unique changed-feasible vectors across repaired stage files and all 576 final representatives. All saved class decisions matched. Across 15,481 scored repaired-candidate entries, 211 malicious-probability values were not bitwise identical to local rescoring; the maximum absolute difference was approximately `1.78814e-7`. Probability differences were recorded separately. No attack threshold, relationship tolerance, distance limit or classification acceptance rule was relaxed for this review.

Exact attack-output reproduction across environments was not achieved. The six clean-input candidate arrays matched exactly, but all 12 CAPGD/Moeva2 stage arrays differed between the local and Colab runs despite matching code, package versions, inputs and seeds. Original and budget-only coverage counts consequently differ. This review has not isolated the cause of those generation differences; small rescoring differences alone do not prove a cause. Preserve both runs, and do not describe them as bitwise reproductions or combine them as independent data samples.

The decision-relevant outcomes agree: relationship + budget coverage was 28/32 in every run, and repair added no evasions for either model. Zero observed evasions against one model on this small subset does not establish general robustness.

## What this means for the PhD work

The validated finding is that conservative repair can increase the availability of feasible feature changes. It has not yet demonstrated stronger adversarial examples or improved IDS accuracy. Keep original CAA, budget-only rollback and relationship + budget rollback as comparison methods.

A next development hypothesis is: **Can searching within consistent feature groups produce additional valid evasions under a measured computational budget?** Define the permitted attacker changes before implementing that search, keep the present records as development data, and count original inputs rather than repeated candidates. A defensible comparison should report valid new evasions, changed-valid coverage, additional model evaluations and elapsed time; the budget-only control remains necessary. Candidate selection or repair inside optimization would be a new experiment, not a reinterpretation of this one.

That future method would still require independent evaluation and a novelty review before making a PhD contribution claim. Later defense training should use train-only preprocessing and a frozen final evaluation protocol. The present compatibility scaler uses all feature rows to match frozen upstream checkpoints, and their training history is inherited. Benchmark feature validity does not prove packet realizability or preservation of malicious functionality.

## Rechecking the saved arrays

The new audit helper reads saved evidence and uses the pinned local checker and models; it does not generate attacks. It is scoped to notebook 05's default 32-record, two-model, three-seed experiment. Prepare the existing pinned environment and assets, safely extract the results ZIP, then run:

```bash
.baseline-env/bin/python scripts/review_notebook05_evidence.py \
  . /path/to/extracted/comparison_20261002T042626Z_d7d3df3d \
  /path/to/new_evidence_review.json
```

Choose a new output filename to preserve previous reviews. Probability differences from the reviewing machine are recorded; validity, budget and class decisions must match exactly.
