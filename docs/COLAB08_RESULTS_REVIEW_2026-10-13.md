# Notebook 08: Colab results review — 13 October 2026

**The Colab experiment successfully reproduces the reference. The extra evasion remains a result under notebook 08's fixed feature conditions; its traffic realizability remains unresolved. A new packet/duration diagnostic also flags an authentic training record, so it has not been adopted as a hard validity rule.**

The uploaded run completed all 18 generation runs and the separate evidence review. Its 33 setup tests passed. The experiment itself took 2,285.97 seconds, approximately 38.10 minutes; this is a workflow runtime, not a method speed claim.

## Reproduction checks

| Check | Result |
|---|---|
| Project revision | `d6d9f0471b9e68b2d323ee1f796613383c9eee2a`; clean checkout |
| Source snapshots | All 37 match their recorded SHA256 and the published GitHub blobs |
| Comparison rows | All 30 reproduce the reference, excluding timing fields |
| NumPy evidence | All 247 files are byte-for-byte identical to the saved reference |
| Exported source entries | 175,416 across 108 physical sources |
| Final matrices | 30 matrices, 960 final vectors |
| Added-rule decisions | 50,519,808 independently recomputed in this review |
| In-loop generation logs | All 12 match the reference after excluding timings |
| Core attack budgets | Match fresh native CAA for each model/seed pair |

The archived Colab review freshly recomputed native validity, distances and frozen-model predictions. This review verified its published implementation, exact reference evidence and added-rule masks. It did not rerun the model or native checker locally. Intermediate optimizer vectors were not exported; their matching logs and repair/evaluation digests do not constitute independent reconstruction of those vectors.

Colab's notebook kernel was Python 3.12.6. The experiment correctly used the separate pinned Python 3.8.20 / NumPy 1.23.5 / PyTorch 1.12.1+cpu environment. No model was trained and no test-partition records were evaluated.

## Notebook 08 results, unchanged

Each number below is the number of newly evaded originals for the indicated seed. Each model initially detected **28 of the 32 selected malicious development records**; the four existing misses are excluded from new evasions. The three seeds reuse the same originals.

| Method | Default model: seeds 0 / 1 / 2 | Madry model: seeds 0 / 1 / 2 |
|---|---|---|
| Native CAA with the common final filter | 1 / 1 / 0 | 0 / 0 / 0 |
| Budget/profile repair afterward | 1 / 1 / 1 | 0 / 0 / 0 |
| Relationship/profile repair afterward | 1 / 1 / 1 | 0 / 0 / 0 |
| Budget/profile repair inside MOEVA | 1 / 1 / 1 | 0 / 0 / 0 |
| Relationship/profile repair inside MOEVA | 2 / 1 / 1 | 0 / 0 / 0 |

One evasion is 1/28 = 3.57%; two are 2/28 = 7.14%. These are attack-evasion rates for this selected malicious pilot, not overall IDS accuracy or false-positive rates. The extra evasion appears only for the default model at seed 0. Its count was not improved over end repair at seeds 1 and 2. No new evasion of the Madry checkpoint was observed in this pilot; that does not establish complete robustness.

## A new concern with the extra evasion

The additional original is zero-based CSV row **131302**. Its selected vector has scaled L2 distance `0.33002832531929016` and SHA256 `d63213db5ec1c4fb191012ff003e36bdeb3830f441468b90edf8407e2b60b644`.

| Changed feature | Original | Candidate |
|---|---:|---:|
| `duration_min_s_25` | 0 | 0.1795309484 |
| `duration_max_s_25` | 3.0180590153 | 2.9518923759 |
| `duration_sum_s_80` | 103.6017532349 | 34,344.640625 |
| `duration_max_s_80` | 75.2999954224 | 489.6778869629 |

For the candidate's `s_80` bucket, the packet sums are unchanged: 18 incoming + 22 outgoing = **40 packets**. The duration sum divided by its maximum is about 70.14. Consequently, those duration statistics require **at least 71 contributing records**.

For nonnegative durations from the same N contributing records:

`duration_sum <= N * duration_max`

If every contributing record has at least one counted packet, then:

`N <= pkts_in_sum + pkts_out_sum`

Together these imply the conditional bound:

`duration_sum <= (pkts_in_sum + pkts_out_sum) * duration_max`

For this candidate, the right side is `19,587.115478515625`, while the duration sum is `34,344.640625`, a gap of `14,757.525146484375`. This is a substantial discrepancy under the stated assumption, not a small numerical-boundary issue.

The [pinned aggregation implementation](https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/aggregated_features_bro_logs.py) updates packet and duration aggregates for each processed record in the same bucket. However, it also replaces missing values with zero and does not enforce the assumption that each record has a positive packet count. Exact reproduction of the pinned feature CSV from that source has not been established. This mathematical diagnostic must therefore remain conditional.

No duration-unit conversion or collection-window cap was assumed. The sum and maximum use the same stored units, which cancel in the record-count ratio. Grouping records by start time does not by itself justify capping every duration at the aggregation-window length.

## The clean-data counterexample prevents adopting the new bound

The pinned dataset was downloaded and its SHA256 verified as `37a8a8502183f1f2681b429a8f2ba6d1c1e36c75aa7ef463255275a79bd07575`. All **143,046 native training/development records** were checked in parsed float64 and model-input float32. Only that prefix was parsed. No test records were evaluated.

The proposed bound flags **one benign training record**, zero-based CSV row **1503**, in both precisions. No other training/development row is flagged. All 32 selected pilot originals pass.

| Row 1503, bucket `s_OTHER` | Stored value |
|---|---:|
| Duration sum | 0.665524 |
| Duration maximum | 0.665524 |
| Incoming packet sum | 0 |
| Outgoing packet sum | 0 |
| Outgoing byte sum | 3,288 |
| UDP byte aggregate | 3,288 |
| Distinct external IPs / source ports / destination ports | 1 / 1 / 1 |

This record already contains positive duration and bytes with zero counted packets. It is not an adversarially generated example, and the discrepancy persists in float64 and float32. Its presence does not identify the cause: missing measurements, preprocessing behavior or another data-generation issue require investigation.

**Decision: the clean-control acceptance check failed. The proposed bound is not added to notebook 08, the control is not removed, and the extra evasion is not retrospectively declared invalid.** Changing the condition to exempt zero-count rows without establishing the underlying measurement semantics would not resolve partially missing counts in nonzero buckets.

## Exploratory saved-pool diagnostic

For transparency, the conditional bound was also evaluated on all exported candidates. It flags 10 of the 15 selected evasion instances across methods/seeds, including row 131302. These instances reuse the same two original records, so 15 is not a count of independent attacks or traffic samples.

The following numbers describe **initially detected originals with at least one saved candidate passing the old profile and this conditional bound**. They are candidate-pool availability counts, not final reselected attack results. Native masks and predictions are the byte-identical verified evidence; no new attack generation or final matrix reselection was performed.

| Method | Conditional pool availability, default seeds 0 / 1 / 2 |
|---|---|
| Native CAA with common filter | 1 / 1 / 0 |
| Budget/profile repair afterward | 1 / 1 / 1 |
| Relationship/profile repair afterward | 1 / 1 / 1 |
| Budget/profile repair inside MOEVA | 0 / 0 / 1 |
| Relationship/profile repair inside MOEVA | 1 / 0 / 1 |

Every surviving original is row **117132**; the additional row **131302** has no passing saved alternative under this diagnostic. Madry has zero passing evasions throughout. Some flagged selected vectors have passing alternatives, which is why rejecting only the selected vector would misstate pool availability.

Because the clean-control check failed, this table is a sensitivity analysis under an unestablished assumption. It is not a replacement for the notebook 08 table or a new robustness claim.

## Next research step

Notebook 08 does not need another identical run. The implementation and Colab reproduction are established. The next bounded task is a **data-semantics and threat-model audit**:

1. Trace the meaning of zero/missing packet counts through the source extraction and preprocessing, starting with the benign row-1503 counterexample. Establish whether the exact raw-to-feature mapping can be recovered. Do not infer the cause from the aggregated row alone.
2. Derive a documented feasibility model from that evidence, including how unknown measurements are represented and handled. Keep a fixed rule specification, clean-control tests and counterexamples. Do not tune exceptions simply to retain or remove particular evasions.
3. Once those assumptions are defensible, freeze the revised protocol and compare candidate generation on a larger development sample using paired originals and matching budgets. If raw provenance cannot support traffic-level claims, explicitly scope the study to feature-space feasibility and reproducibility.

The extra case is worth investigating, but it is not yet proof of a consistent or realizable attack improvement. Neither this review nor notebook 08 establishes a new IDS defense or improved IDS accuracy. Novelty would require a literature comparison beyond this experiment. The inherited scaler fitted on all feature rows also remains a limitation for any later final-test claim.

## Reproduce this review

The new [review script](../scripts/review_notebook08_colab.py) accepts the Colab ZIP, saved reference ZIP, the recursive Git tree for the published revision, the pinned dataset CSV and a new JSON output path. It executes no code from either archive. Its checks intentionally target this exact notebook-08 reference. A mismatch raises an error instead of silently treating a different run as the same reproduction.

The [machine-readable review](../reference_results/notebook08_colab_review_2026-10-13.json) contains source verification, comparisons, clean-control groups, the counterexample, selected candidate changes, and conditional pool counts.

Input ZIP SHA256: `bb1e0d9afe2eb4db9ed6b1a699b72a51d77abc86b27e00745a006daabf98ddd1`.

Reference ZIP SHA256: `693f2991a78faf0258cba31a1fd9b6293c562a0d76794395d54c25b0cb43a857`.

All earlier repository files and both original ZIPs are preserved.
