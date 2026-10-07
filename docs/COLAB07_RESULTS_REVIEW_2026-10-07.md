# Colab notebook 07 review — 7 October 2026

**The Colab run completed successfully and reproduced the earlier notebook 07 findings.** Inspection of the last additional evasion reveals another unsupported feature combination: positive duration in two buckets with zero recorded endpoints. A separately labeled exploratory check rejects that candidate and finds no passing saved alternative for its original record.

This is a follow-up to the existing audit. Notebook 07's rule, results and files remain unchanged. The new diagnostic is post-hoc development analysis, not a final robustness evaluation.

## Uploaded run and verification

Archive: `traffic_consistency_20261007T050655Z_79b2765e_results_20261007T051132Z_93f60f61.zip`.

SHA256: `ce4f13b7f14035105e6f23660905949c6442831962ba736d6211da32d677c0d9`.

- Archive integrity passed: 676 entries, 9,356,606 compressed bytes, 49,375,828 expanded bytes.
- The 29 source-snapshot files match their recorded hashes and GitHub commit `dcd13baffa31a731066e4a3ffd4a6a30f5327faa`. The uploaded checkout was clean; its setup log records all 26 tests passing.
- The audit used isolated Python 3.8.20, NumPy 1.23.5 and PyTorch 1.12.1+cpu. The Colab notebook kernel was Python 3.13.16. The audit itself took 123.12 seconds, excluding setup and downloads.
- A fresh local replay reproduced all 30 comparison rows, clean-control counts, native masks, distance arrays, rule flags and predicted classes. All 60 final-vector archives are byte-identical.
- Source probability arrays differ slightly across machines: 5,852 entries across 86 files, maximum absolute difference `3.0994415283203125e-06`. No predicted class or selected final vector changed. The smallest distance from probability 0.5 among differing entries was approximately 0.00212. Native validity tolerance remained zero.
- An independent review checked 120 physical source files containing 175,800 vector entries, recomputed 31,644,000 sum/maximum decisions, reconstructed per-original pool availability and freshly checked/scored 1,920 final vectors.

The dataset's native test rows were not parsed or evaluated. The inherited compatibility scaler still uses all feature rows, so these results do not constitute a leakage-free independent test.

## Confirmed notebook 07 result

All **143,046 unmodified training/development records** pass the original added sum/maximum rule in both parsed float64 and model float32. Both models initially detect 28 of the selected 32 malicious originals; four are already missed. New evasion uses the 28 initially detected originals as its denominator.

For the standard model, newly evaded originals under notebook 07's rule are:

| Method | Seed 0 | Seed 1 | Seed 2 |
|---|---:|---:|---:|
| Original CAA | 1 | 1 | 1 |
| Budget end repair | 1 | 1 | 1 |
| Relationship + budget end repair | 1 | 1 | 1 |
| Budget in-loop repair | 1 | 1 | 2 |
| Relationship + budget in-loop repair | 1 | 1 | 1 |

The adversarially trained `madry` model has zero new evasions for every method/seed in this limited search. This does not establish general robustness.

## Inspection of the remaining extra evasion

Original CSV row **134407**, standard model, budget in-loop repair, seed 2:

| Changed feature | Original | Candidate |
|---|---:|---:|
| `duration_sum_s_443` | 0 | 10930.1298828125 |
| `duration_max_s_443` | 0 | 2191.09130859375 |
| `duration_sum_d_OTHER` | 0 | 22768.142578125 |
| `duration_max_d_OTHER` | 0 | 4878.5986328125 |

These are raw feature units; no duration-unit or window-size assumption is needed for this inspection. These four values are the only changed features. The candidate's scaled-L2 distance is approximately 0.24476, within the inherited 0.5 budget. Its saved malicious-class score is approximately 0.002364 and the frozen model predicts benign.

In both affected buckets, all packet, byte and protocol-byte aggregates remain zero. More decisively, **distinct external IPs, distinct source ports and distinct destination ports all remain zero**. Those six endpoint-count fields are immutable under the pinned benchmark metadata; the duration fields are mutable.

The [inspected extractor](https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/aggregated_features_bro_logs.py) updates duration and all three endpoint sets for each processed connection in the same bucket. Under that update logic, positive accumulated duration cannot coexist with empty endpoint sets. This is an inconsistency with the inspected extractor, rather than proof that the frozen model was evaded by realizable traffic. Exact reproduction of the pinned benchmark CSV from this extractor has not been established.

Candidate SHA256: `c5d3d1d6793cf66de2c4e895f773c316ecd054ad60aae3e9472cd75211120e1f`.

## Separate exploratory duration/endpoint check

The follow-up diagnostic requires each bucket with positive `duration_sum` to have positive distinct external-IP, source-port and destination-port counts. It checks 36 buckets × 3 implications = **108 conditions**. Distinct counts are not treated as numbers of connections, and no duration cap is introduced.

This condition was selected after inspecting the survivor and recorded before scanning all clean controls and saved pools. **All 143,046 clean training/development records pass it in both precisions**, with zero flagged rows. All 32 selected originals pass too. This supports further investigation of the condition, not a claim of complete physical validity.

All 120 saved source files were scanned. The diagnostic applies the new condition after notebook 07's existing native validity, budget, changed-input and sum/maximum filters. Evasions are deduplicated within each original record, and already-missed originals are excluded. The reproduced pre-filter pool counts match notebook 07 for every method and original.

| Standard model method | Notebook 07 pool availability, seeds 0 / 1 / 2 | After exploratory duration/endpoint check |
|---|---:|---:|
| Original CAA | 1 / 1 / 1 | 1 / 1 / 0 |
| Budget end repair | 1 / 1 / 1 | 1 / 1 / 0 |
| Relationship + budget end repair | 1 / 1 / 1 | 1 / 1 / 1 |
| Budget in-loop repair | 1 / 1 / 2 | 1 / 1 / 0 |
| Relationship + budget in-loop repair | 1 / 1 / 1 | 0 / 1 / 1 |

These are **records with a passing saved pool evasion**, before a new complete final-matrix selection; they are not newly reported end-to-end attack results. All remaining originals in this diagnostic are row 117132. Row 134407 had one unique notebook-07-passing evasion in the relevant pool and has zero after the new condition. The `madry` pools remain at zero.

Changing the feasibility definition also changes baseline availability, so relative method performance must be reevaluated consistently. The table does not prove that one method is superior or that no valid attack can be generated by a stronger search.

## Next experiment

1. Specify a versioned feasibility profile containing the justified aggregate and connection-presence conditions, including their extractor provenance and known limitations. Preserve the original benchmark definition for a separate comparison.
2. Apply the same profile to candidate generation and final selection for every compared method. Record rejected candidates, unique feasible changes, successful evasions, query counts and repair overhead.
3. Repeat the paired development experiment with fixed inputs, seeds and generation budgets. Inspect surviving feature changes before scaling or using generated samples for IDS retraining. Freeze the protocol before an independent evaluation.

The useful research finding is that an apparent attack improvement can depend on incomplete feasibility checks. Establishing novelty and a general method still requires literature comparison and broader evaluation.

The new diagnostic can be reproduced from a completed, verified notebook 07 audit directory:

```bash
.baseline-env/bin/python scripts/inspect_notebook07_duration_support.py \
  --audit-run runs/your_notebook07_session/audit \
  --out runs/duration_support_new_run
```

It refuses an existing output directory. It generates no attacks, performs no model training or new inference, and preserves the earlier results. Structured evidence is in [the new review JSON](../reference_results/traffic_consistency_colab_review_2026-10-07.json).
