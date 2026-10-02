# Repair during search: local development findings — 2 October 2026

Notebook 06 is implemented and the default experiment completed. Repair during search found a few additional **native-checker-valid feature-space evasions** against the standard RLN. It found no new evasions against the adversarially trained RLN. Relationship repair was not consistently better than budget-only repair. Some extra evasions exploit aggregate combinations that deserve separate scrutiny, so this does not establish a realizable traffic attack, improved IDS accuracy or a novel PhD contribution.

## What was compared

The fresh original CAA, two end-only controls, and two in-search variants used the same 32 malicious development records. Both frozen checkpoints initially detected 28 and already missed 4. Selection did not filter by prediction. Attack seeds were 0, 1 and 2, with 10 gradient steps, 100 evolutionary generations, 50 offspring, scaled L2 radius 0.5 and the unchanged zero-tolerance native checker.

The in-search methods apply the existing block rollback before evolutionary fitness evaluation and write the repaired coordinates into the population. Every sampling, mutation, crossover, selection and objective setting otherwise stays pinned. This is a method-placement/control experiment, with no model retraining.

## New evasions among the 28 initially detected records

Each cell lists seeds **0 / 1 / 2**. These are counts per seed, not independent samples to add together.

| Method | Standard RLN | Adversarially trained RLN |
|---|---|---|
| Original CAA | 1 / 1 / 1 | 0 / 0 / 0 |
| Budget repair at end | 1 / 1 / 1 | 0 / 0 / 0 |
| Relationship + budget repair at end | 1 / 1 / 1 | 0 / 0 / 0 |
| Budget repair during search | 1 / 1 / 3 | 0 / 0 / 0 |
| Relationship + budget repair during search | 2 / 1 / 2 | 0 / 0 / 0 |

One, two and three new evasions correspond to 3.57%, 7.14% and 10.71% of the 28 initially detected inputs. These are attack success rates on a small malicious subset, **not full-dataset accuracy**. No benign traffic was evaluated for false-positive rate.

The in-search counts above are standalone results. In this run the separately recorded union with original CAA did not add further evasions. In general that union requires both attacks and cannot be advertised as a matched-total-compute method. All original CAA success records in this experiment refer to zero-based CSV row 117132; additional in-search successes involve rows 131302 and 134407.

## Native validity does not establish traffic realizability

A post-hoc diagnostic checks the 108 duration, outgoing-byte and outgoing-packet sum/max pairs for `sum > 0` while `max == 0`. If each pair summarizes the same observations, that combination is inconsistent. Feature-extractor semantics still need to be verified before making a traffic-level claim. This diagnostic was **not** added to official acceptance or used to change the reported attack results.

None of the 32 clean selected records was flagged. Across the in-search methods and seeds there were 4 additional-evasion occurrences relative to original CAA; 3 were flagged. These occurrences reuse two additional original records. Both additional relationship-repair evasions were flagged. Budget-only seed 2 also found an additional evasion that this particular diagnostic did not flag; passing one necessary-condition check does not establish realizability or retained malicious functionality.

For example, standard RLN / seed 0 / relationship repair evades row 131302 by changing `duration_sum_s_443` from 0 to 141178.875 and `duration_sum_d_OTHER` from 0 to 143144.15625, while their corresponding minima and maxima remain zero. It passes the native checker at scaled L2 distance approximately 0.35568014. The upstream rules enforce `max <= sum`, `min <= sum` and `min <= max`; those inequalities do not reject this case. Do not infer duration units from this report.

The same issue can occur in the baseline. Flagged successful final representatives, shown as **flagged / successful** for seeds 0 / 1 / 2:

| Method | Seed 0 | Seed 1 | Seed 2 |
|---|---|---|---|
| Original CAA | 0/1 | 1/1 | 1/1 |
| Budget repair at end | 1/1 | 0/1 | 1/1 |
| Relationship + budget repair at end | 1/1 | 1/1 | 1/1 |
| Budget repair during search | 1/1 | 1/1 | 1/3 |
| Relationship + budget repair during search | 2/2 | 1/1 | 2/2 |

The diagnostic covers the reported final representative, not every possible successful candidate in each pool. It is not a complete physical or adversarial-capability model. The full JSON preserves changed feature names/values and row identifiers for review.

## Coverage and search behavior

Changed-valid coverage counts originals with a changed, native-valid, in-budget candidate in saved final stage-output pools, out of 32. Clean fallbacks do not count. End-only rows retain the original candidate pool, as in notebook 05; in-search rows use the new trajectory's own pool.

| Method | Standard RLN: seeds 0 / 1 / 2 | Adversarially trained RLN: seeds 0 / 1 / 2 |
|---|---|---|
| Original CAA | 2 / 2 / 1 | 1 / 2 / 3 |
| Budget repair at end | 27 / 28 / 28 | 28 / 28 / 28 |
| Relationship + budget repair at end | 28 / 28 / 28 | 28 / 28 / 28 |
| Budget repair during search | 1 / 1 / 3 | 1 / 1 / 1 |
| Relationship + budget repair during search | 2 / 1 / 2 | 1 / 1 / 1 |

High end-only coverage did not increase evasion. Moving conservative repair into search sharply reduced final-pool coverage in this run. Generation logs also show substantial repetition of unchanged inputs:

- Budget repair during search: 43.6%–45.0% of evolutionary objective rows were unchanged clean inputs.
- Relationship + budget repair during search: 76.3%–77.4% of evolutionary objective rows were unchanged clean inputs.

These observations motivate examining diversity and constraint semantics before expanding this method. They do not by themselves establish why particular attacks succeeded or failed.

## Compute and time

Every original and modified search used exactly 3,139 core model-forward calls covering 150,896 rows, including 23 gradient-enabled forwards covering 644 rows. Each of the 28 evolutionary inputs received 5,156 objective-model rows: 206 initial candidates plus 99 batches of 50 offspring. Repair/evaluation population digests agree, and all counters were checked at runtime and in the saved-evidence review. Duplicate and clean evaluations remain charged to this budget.

Mean core generation seconds over three seeds on this local CPU environment:

| Search | Standard RLN | Adversarially trained RLN |
|---|---:|---:|
| Original CAA | 74.9 | 74.7 |
| Budget repair during search | 144.4 | 144.8 |
| Relationship + budget repair during search | 170.0 | 175.1 |

Repair added substantial CPU work. Timings include tracing, checks and evidence writing; they are neither IDS inference latency nor a controlled hardware benchmark. End-only prediction costs, final scoring and union checks are recorded separately and are outside the matched core attack budget. The complete baseline-plus-variants CLI experiment took about 39.9 minutes here; Colab duration can differ.

## Validation and scope

- All 20 project tests passed, including actual two-generation population repair and repaired-genotype fitness checks.
- All six notebook code cells ran locally with a smaller 4-record, one-seed, two-generation configuration, including setup, both models, result tables and ZIP export. Notebook schema and export CRC passed. Hosted Colab and its download dialog were not tested.
- The separate default CLI run completed all 18 CAA searches and all 30 comparison rows.
- Saved baseline and modified final-stage arrays were independently checked using the pinned model/checker. Final representatives were rescored; logged masks, distances, coverage, evasion counts, input membership and core query budgets agreed.
- Intermediate generation counters and digests were checked for consistency; every intermediate vector was not archived or independently reconstructed.
- All previously tracked project files stayed unchanged. New source was frozen and hashed for the experiment.

Python 3.8.20, NumPy 1.23.5 and CPU torch 1.12.1 remain pinned. The baseline project commit was `dffc1fae5bb9af7554f669cc29dfe4304ec89926`. Upstream code, data and model revisions plus all six asset hashes are recorded in the [machine-readable validation](../reference_results/inloop_repair_local_validation_2026-10-02.json).

The native test partition was excluded from attack selection/scoring, but the compatibility scaler still uses all feature rows to reproduce the existing checkpoints. Checkpoint training history is inherited. This is not a leakage-free final evaluation. Seeds reuse the same small selected development sample and give search variability, not independent population confidence. No real packets were replayed, no network simulator was validated, and no new IDS was trained. Cross-machine bitwise trajectories are not assumed; baseline and variants must be paired within one environment.

## Run and review

Open [notebook 06 in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/06_Repair_During_Search.ipynb), choose CPU and select **Runtime → Run all**. Keep the defaults. It runs its own fresh baseline; no previous ZIP upload is needed. Download the new ZIP and share it. The [guide](INLOOP_REPAIR_GUIDE.md) explains the protocol and partial-export procedure.

The next research decision should start with the flagged feature changes: establish the actual extractor semantics and attacker capabilities before designing stronger constraints or interpreting a feature-space evasion as a network attack. Preserve the native-checker baseline and report any stronger semantic evaluation separately. A larger held-out experiment and a novelty review are still needed before claiming a contribution.

For an independent saved-result review, run these from the project root with a newly extracted completed session:

```bash
.baseline-env/bin/python scripts/review_notebook06_evidence.py \
  . SESSION/baseline SESSION/inloop new_evidence_review.json
.baseline-env/bin/python scripts/audit_notebook06_aggregates.py \
  --baseline-run SESSION/baseline --inloop-run SESSION/inloop \
  --out new_aggregate_review.json
```

Completed local evidence archive: `repair_during_search_local_validation_20261002T135030Z.zip`. SHA-256: `691871e958a8eaa7cfc245be7b0a4390c0781c3dabac877bf57c70f941fbd1e4`. The archive contains raw saved stage arrays, final representatives, generation logs, source snapshots, fresh verification results and the separate aggregate diagnostic; no dataset or environment is bundled.
