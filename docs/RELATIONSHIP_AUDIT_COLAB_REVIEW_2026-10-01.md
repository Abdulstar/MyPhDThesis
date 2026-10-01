# Notebook 04: review of the uploaded Colab results

**The Colab audit completed successfully and reproduces the local findings.** Every saved native and float64 relationship residual was independently recomputed and matched exactly. No rerun of notebook 03 or 04 is needed for this source experiment.

Reviewed archive: `relationship_audit_20261001T075804Z_ca471628_results_20261001T080054Z_4b741113.zip`.

SHA-256: `a51218cfd825b98132033a1b02973fe313873026e6f4ac4e197899570ce48a83`.

The run used clean project commit `0abbc95505c38519e566b37d0328bf835c43ebe5`. The notebook host was Python 3.13.15, while the isolated audit correctly used Python 3.8.20 and NumPy 1.23.5. The setup log records all nine tests passing and the audit log records successful completion.

## Verification

- The outer ZIP and its embedded notebook 03 ZIP passed integrity checks. The embedded source archive is byte-for-byte the same experiment previously reviewed.
- All 14 source snapshots match their declared SHA-256 hashes and the files in the published Git commit. The audit implementation, test and notebook hashes also match the local validation record.
- The metadata hash matches the pinned asset. Reported upstream source hashes match the reference.
- All fields in `audit_report.json` match the prior reference, except elapsed audit time. Timing is diagnostic runtime, not an IDS inference-speed measurement.
- Independent direct NumPy expressions reproduced every native and float64 residual in all 12 stages. No code from either uploaded ZIP was executed during this review.
- All four constraint masks were independently recomputed from the saved feature arrays and pinned metadata: relationships, bounds, types and immutable features.
- All 26,624 candidate CSV records, 4,320 rule-summary rows, 60 family-summary rows and 1,500 feature-value examples were checked against the underlying arrays. Quantile summaries were checked numerically; all residual-array values matched exactly.

Machine-readable verification is in [the new review JSON](../reference_results/relationship_audit_colab_review_2026-10-01.json). The rule definitions, earlier detailed findings and concrete byte-total examples remain in [the original findings document](RELATIONSHIP_AUDIT_FINDINGS_2026-10-01.md).

## Confirmed results

Across the two budgets and models, 7,252 of the 26,624 saved candidates fail relationship checks. Higher-precision arithmetic changes **zero individual rule decisions and zero whole-candidate decisions**. This confirms inconsistencies in the stored feature values; float64 cannot reconstruct information lost before those values were saved.

For the 100-generation experiment:

| Measure | Standard RLN | Adversarially trained RLN |
|---|---:|---:|
| CAPGD candidates rejected by relationships | 32/32 | 32/32 |
| Moeva2 candidates rejected by relationships | 2,985/6,592 | 4,014/6,592 |
| Changed, valid, in-budget Moeva2 candidates | 43 | 52 |
| Original records covered by those feasible changes | 2/32 | 1/32 |
| Original reported new evasions | 1/32 | 0/32 |

The standard-model feasible changes cover original CSV rows 152745 and 187815; the adversarial-model feasible changes cover only row 152745. The 11 successful standard-model candidates belong to one original record and therefore count as one evasion.

The unchanged evasion counts describe the same saved notebook 03 experiment. Notebook 04 did not generate a new attack run, evaluate a new seed, or demonstrate an improved defense. Candidate counts include unchanged and repeated values; they are not counts of independent network requests.

## Next experiment

The next step is to compare the original attack with a clearly specified method for generating or repairing mutually consistent features. This remains evaluation groundwork for the intended IDS defense research.

Use a separate development partition to design the method. Keep the original model checkpoints and compatibility preprocessing fixed for this diagnostic comparison, preserve the declared feature constraints and scaled L2 budget, and account for repair computation in the search-cost comparison. After any repair, recompute all constraints, distance and the model prediction before counting a success.

Measure **coverage of original records with changed, valid, in-budget candidates** alongside valid evasion rate, failure reasons and computation cost. A simple repair should be a comparator for any more elaborate proposed method. No improvement should be claimed merely because a threshold was loosened or because more duplicate candidates were generated.

Once the attack evaluation has adequate coverage, compare defense training under a frozen protocol with train-only preprocessing and held-out evaluation. A stronger valid attack can lower the currently reported robust detection rate; measuring that accurately is a necessary step before assessing whether the new defense improves it.

This upload validates the audit workflow. It does not yet establish a novel contribution, general defense superiority, or live-traffic realizability.
