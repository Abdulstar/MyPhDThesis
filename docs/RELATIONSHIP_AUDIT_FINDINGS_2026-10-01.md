# Relationship audit of the uploaded notebook 03 results

**The rejected candidates contain inconsistent feature values. Their rejection is not explained by switching rule arithmetic from float32 to float64.** The audit reproduced every saved constraint decision using the official pinned checker, then inspected all 360 relationships separately.

Source archive: `diagnostics32_20260929T132256Z_f142b528_results_20260929T133337Z_79f17a41.zip`.

SHA-256: `7d5ab5c586585a61c3267d37792bf12f7dc2fc0ccd6be857cabd57e5961c618f`.

The source run used project commit `cae62372e7805160a2e9c7a593734c210773df4c`, pinned upstream `bfb75415a6a31a41ddfeef34478eea1da227d19c`, and the same 32 malicious CTU feature records for both models and search budgets. This is the user's saved Colab experiment, audited locally without rerunning attacks or model inference.

## What was verified

- All 12 saved stages were audited: two generation budgets × two models × three stages.
- The 26,624 stage-output candidates contained 7,252 relationship-invalid candidates. These totals include repeated controls and multiple candidates for each original record; they are not independent samples.
- Every relationship, bounds, type and immutable-feature mask matched the original saved mask exactly. The latter three checks passed for every candidate.
- The saved clean originals passed every relationship in both arithmetic modes.
- Float64 changed **zero individual rule pass/fail decisions and zero whole-candidate decisions**. Residual magnitudes can still differ between arithmetic modes.
- The existing successful standard-model candidate also passed the float64 relationship check. Original reported new evasions remain 0/32 for both models at 10 generations, and 1/32 standard versus 0/32 adversarially trained at 100 generations.

Float64 here reevaluates the stored float32 numbers. It does not reconstruct higher-precision values from before candidate generation or storage. This result does not rule out every possible earlier numerical effect.

## Failures at 100 generations

| Model | Stage | Candidates | Relationship-invalid | Invalid and within L2 budget | Original rows with a changed, valid, in-budget candidate |
|---|---|---:|---:|---:|---:|
| Standard RLN | CAPGD | 32 | 32 | 32 | 0/32 |
| Adversarial RLN | CAPGD | 32 | 32 | 32 | 0/32 |
| Standard RLN | Moeva2 | 6,592 | 2,985 | 115 | 2/32 |
| Adversarial RLN | Moeva2 | 6,592 | 4,014 | 26 | 1/32 |

All CAPGD candidates fail both byte-balance equalities. Each also has at least one outgoing-byte ordering, outgoing-packet ordering and duration ordering failure. Packet-size failures affect 17 standard-model and 16 adversarial-model CAPGD candidates. These categories overlap.

For standard-model CAPGD, the source-side byte-total residual ranges from **1,413,484 to 320,389,312 bytes**; the destination-side residual ranges from **6,605,712 to 2,123,472,128 bytes**. Such discrepancies cannot be characterized as tiny residuals around zero.

One concrete example is original CSV row **158426**, CAPGD candidate 0, for both models:

| Feature | Original | Candidate |
|---|---:|---:|
| `bytes_out_max_d_443` | 0 | 449,001,760 |
| `bytes_out_sum_d_443` | 0 | 0 |

The maximum cannot exceed the sum under rule `r121`. Its residual is 449,001,760 bytes in both arithmetic modes. Its saved scaled L2 distance is approximately **0.221595**, inside the 0.5 budget. This illustrates why the distance and per-feature bounds are insufficient without cross-feature relationship checks.

## The evolutionary stage needs a different emphasis

At 100 generations, duration ordering fails for 2,782 standard-model and 3,822 adversarial-model candidates across all saved Moeva2 outputs. The frequent `duration_min_s_138 ≤ duration_max_s_138` failure occurs in 1,784 and 2,283 candidates respectively. These gaps also persist in float64.

However, many of those candidates already exceed the distance budget. Within the fixed budget, the family-level counts are:

| Failing family | Standard RLN | Adversarial RLN |
|---|---:|---:|
| Byte balance | 5 | 7 |
| Packet size | 0 | 0 |
| Outgoing-byte ordering | 17 | 2 |
| Outgoing-packet ordering | 64 | 0 |
| Duration ordering | 50 | 19 |

These counts overlap and therefore must not be added to estimate distinct invalid candidates. For the standard model, `pkts_out_min_s_80 ≤ pkts_out_max_s_80` alone fails for **42 in-budget candidates**. Prioritizing only the most frequent rule across all outputs would miss this practical distinction.

The standard model has 43 changed-valid-in-budget Moeva2 candidates, drawn from only two original rows; the adversarial model has 52, all from one original row. Increasing candidate counts alone therefore does not establish broad attack coverage.

## A verified limitation in the upstream repair helper

The pinned [CTU rule definitions](https://github.com/serval-uni-lu/tabularbench/blob/bfb75415a6a31a41ddfeef34478eea1da227d19c/tabularbench/datasets/samples/ctu_13_neris.py) express both byte equalities with sums on each side. The pinned [`fix_equality_constraints` helper](https://github.com/serval-uni-lu/tabularbench/blob/bfb75415a6a31a41ddfeef34478eea1da227d19c/tabularbench/attacks/utils.py) selects equalities only when their left operand is a single `Feature`.

Consequently, **zero of CTU's two equalities qualify for that repair helper**, even when its repair flags are enabled. This is a source-level fact. It is not proof that it is the sole cause of the failed search, and it does not address the separate inequality failures. Constraint penalties used during optimization can still attempt to enforce these relationships.

## Recommended next experiment

Develop and evaluate a candidate-generation or repair method that maintains the dependencies between totals, minima, maxima and protocol byte counts. Keep the pinned implementation as the comparison baseline in a separate new notebook.

1. **Specify the allowed changes on development data.** Identify mutable source features and dependent aggregates, respecting the original immutable fields and dynamic lower bounds. Do not simply assign a different value to a forbidden field to satisfy an equation.
2. **Implement a bounded consistency method.** Maintain integer counts, byte balances and minimum/maximum/sum ordering, then recheck all original constraints and the same scaled L2 budget. Track repair failures explicitly. A repaired candidate may cease to fool the model, so recompute its prediction before scoring it.
3. **Compare under a fixed protocol.** Use the same records, model checkpoints and threat model; report changed-valid-in-budget coverage, invalid candidate rate, evasion among initially detected malicious records, perturbation size and computation cost. Include multiple seeds and comparable search effort. Compare a simple repair with the proposed method to establish what the additional method contributes.

Choose and tune the method on a separate development partition. The current inspected test subset is exploratory; it should not become the hyperparameter-selection set for a later claimed test result. New defense training should additionally use train-only preprocessing and a frozen evaluation protocol.

This is a concrete implementation lead, not yet an established novel contribution or evidence of general defense superiority. No tolerance relaxation is justified by this audit, and no live-traffic realizability claim follows from valid feature vectors.

## Reproduce and inspect

Use [notebook 04](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/04_Relationship_Audit.ipynb) and the [run guide](RELATIONSHIP_AUDIT_GUIDE.md). Machine-readable findings and local notebook validation are recorded in [the reference JSON](../reference_results/relationship_audit_2026-10-01.json).

Validation used the original pinned Python/NumPy environment, numerical regression tests that can detect both cleared and newly exposed float32 failures, and execution of the new notebook's code cells locally in order. Hosted Colab upload/download dialogs were not exercised during this local validation. Earlier tracked files and notebooks were preserved.
