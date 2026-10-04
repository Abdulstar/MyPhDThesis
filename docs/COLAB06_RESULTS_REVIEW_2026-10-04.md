# Notebook 06: uploaded Colab results review — 4 October 2026

**The uploaded experiment completed successfully, and independent saved-evidence checks passed.** Its 30 final representative NPZ archives are byte-for-byte identical to the corresponding archives recorded in the earlier local validation. The same small increase in feature-space evasion is reproduced, together with the same aggregate-consistency concerns. This is useful reproducibility evidence for the current development experiment; the IDS checkpoints remain frozen.

## Experiment and results

The run used the published notebook 06 at commit `cc724b288d2a9144165fc6a7e40fc642a488dc1c` with no recorded project changes. It completed 18 CAA searches: two RLN checkpoints on CTU-13 Neris aggregate features, three seeds, and original/budget-repair/relationship-repair search variants. The two end-only controls reuse each original CAA run, giving 30 comparison rows in total.

The same 32 malicious development records were selected without prediction filtering. Each model detected 28 and already missed four. New evasion rates therefore use **28 initially detected records** as their denominator. Settings were seeds 0/1/2, 10 gradient steps, 100 generations, 50 offspring, scaled L2 radius 0.5 and zero relationship tolerance.

Each table entry gives **new evasions for seeds 0 / 1 / 2**:

| Method | Standard RLN | Adversarially trained RLN |
|---|---|---|
| Original CAA | 1 / 1 / 1 | 0 / 0 / 0 |
| Budget repair at end | 1 / 1 / 1 | 0 / 0 / 0 |
| Relationship + budget repair at end | 1 / 1 / 1 | 0 / 0 / 0 |
| Budget repair during search | 1 / 1 / 3 | 0 / 0 / 0 |
| Relationship + budget repair during search | 2 / 1 / 2 | 0 / 0 / 0 |

One, two and three evasions correspond to 3.57%, 7.14% and 10.71% of the 28 initially detected records. These are attack success rates on a malicious subset. They are not full-dataset accuracy, and no benign-subset false-positive rate was measured. Seeds reuse the same records and cannot be added into a larger independent sample.

Budget-only and relationship repair each average 1.67 new evasions across these three seeds, compared with 1 for original CAA. Relationship repair is not consistently superior to the budget-only control. The separately computed union with original CAA adds no extra evasion in this run. Such a union generally requires both attacks and has additional cost.

## Why these results do not yet establish realistic traffic attacks

The separate aggregate diagnostic checks 108 duration, outgoing-byte and outgoing-packet sum/max pairs. A positive sum with a zero maximum is inconsistent **if both statistics summarize the same observations**. The actual feature-extractor semantics still need verification. This check was applied after the run and did not change the benchmark's published acceptance rules or reported results.

None of the 32 clean inputs was flagged. The additional standard-model evasion occurrences relative to original CAA were:

| In-search repair | Seed | Zero-based CSV row | Positive sum / zero maximum flagged |
|---|---:|---:|---|
| Relationship + budget | 0 | 131302 | Yes |
| Budget | 2 | 131302 | Yes |
| Budget | 2 | 134407 | No |
| Relationship + budget | 2 | 134407 | Yes |

Thus three of four additional-evasion occurrences are flagged, involving two original records across methods/seeds. Both additional relationship-repair evasions are flagged. The remaining budget-only example also lacks packet-level validation; passing this single diagnostic does not establish realizability or retained malicious behavior.

For example, relationship repair at seed 0 evades row 131302 with `duration_sum_s_443 = 141178.875` and `duration_sum_d_OTHER = 143144.15625`, starting from zero, while the corresponding maxima remain zero. The native checker accepts the vector at scaled L2 distance about 0.35568014. Its sum/min/max inequalities do not exclude this combination. Duration units are not established by this review.

This issue is also present in original CAA: its successful standard-model representative is flagged in seeds 1 and 2. It is not a weakness unique to the added repair methods. The diagnostic covers each method's reported final representative, rather than every possible successful vector in its candidate pool. Full feature changes and flags are preserved in the JSON review.

## Coverage and computational cost

End-only relationship repair covered 28/32 originals with changed, valid, in-budget candidates for both models at every seed, but did not increase evasion. In-search coverage was only 1–3/32 for the standard model and 1/32 for the adversarially trained model. Conservative repair therefore restricts the final candidate pool in this experiment.

Generation diagnostics reproduce the earlier local counts: approximately 44%–45% of budget-repair objective evaluations and 76%–77% of relationship-repair evaluations were unchanged clean vectors. Repetition and clean fallbacks still consume the model-evaluation budget.

All original and modified searches used exactly **150,896 core model-forward rows in 3,139 calls**, including 644 gradient-enabled rows in 23 calls. Initial NoAttack/CAPGD stage arrays and masks matched within this run. Each of the 28 evolutionary inputs used 5,156 objective-model rows. Extra repair work, postprocessing and union checks are separate from this matched core model-query budget.

Mean generation time in seconds across the uploaded run's three seeds:

| Search | Standard RLN | Adversarially trained RLN |
|---|---:|---:|
| Original CAA | 48.5 | 46.9 |
| Budget repair during search | 87.0 | 88.1 |
| Relationship + budget repair during search | 102.1 | 101.4 |

The full baseline-plus-variants computation took about **24.1 minutes**, excluding setup/export. Repair during search was slower in this environment. These timings include tracing and validation and are not IDS deployment latency or throughput measurements. Python 3.8.20, NumPy 1.23.5 and CPU torch 1.12.1 remain pinned; this workflow does not use GPU acceleration.

## Verification performed

- ZIP CRC, extraction paths and recorded completion states passed.
- All 24 source snapshots matched both their recorded SHA-256 hashes and the published Git blob hashes at the recorded commit.
- All six dataset/model asset hashes matched locally and in the uploaded download manifest. The pinned upstream checkout was unchanged.
- The uploaded setup log records 20 passing tests.
- The saved baseline evidence review checked 18 raw and 36 repaired stage files, and independently rescored 576 exported final representatives.
- The saved in-search review checked 36 stage files with 69,936 candidate entries, independently rescored 768 exported final representatives, and checked 33,600 generation batches covering 1,732,416 logged objective-model rows.
- All checked class decisions, feasibility masks, distance budgets, per-record counts and matched core model-query counters agreed. The baseline rescoring comparison found zero differences in its 15,031 cached feasible-candidate probability entries.
- The selected-input archive and all 30 final representative NPZ archives matched the earlier local validation by SHA-256. Non-time comparison metrics and the summarized generation counts also matched.

No attacks were rerun for this review. Intermediate generation counters/digests were checked for consistency; every intermediate population was not independently reconstructed. Final-archive identity does not establish universal determinism across future machines or runs.

## Research interpretation and next step

The experiment supports a narrow finding: repair placement changes search behavior and can expose additional native-checker-valid feature-space evasions at the same core model-query budget. It also exposes a gap between benchmark acceptance and the intended meaning of network aggregates. Neither a new defense nor a novel contribution has been established.

The next experiment should begin by verifying the feature-extraction definitions and attacker capabilities. Check whether the flagged statistics can come from the same traffic window and whether the clean training/development data satisfy any proposed additional rule. Preserve the original benchmark evaluation and preregister a separate, stronger semantic evaluation before adapting the generator. Compare original CAA, budget-only and relationship controls again under that declared protocol. Do not silently remove inconvenient successes or claim packet feasibility from feature checks alone.

After this validity question is resolved, broaden the development sample and plan a held-out defense evaluation with benign traffic, false-positive rates and independent attacks. The present compatibility scaler uses all feature rows for frozen-checkpoint compatibility, and checkpoint training history is inherited. Although native test records were excluded from attack selection/scoring, this is not a leakage-free final test. A new training/evaluation protocol and a literature novelty check are still required for a PhD contribution.

You do not need to rerun notebook 06 for this review. Keep the uploaded ZIP as the evidence for this run. Earlier documents and notebooks remain unchanged.

## Evidence

- Source ZIP: `repair_during_search_20261004T040929Z_eb3c376b_results_20261004T043401Z_9e5af4fb.zip`.
- SHA-256: `0e1d546e01628c46c065a5dc99070f68dac3b51593c49ad37862126d45a922c8`.
- [Machine-readable review](../reference_results/inloop_repair_colab_review_2026-10-04.json).
- [Notebook 06 protocol](INLOOP_REPAIR_GUIDE.md).
- [Earlier local findings](INLOOP_REPAIR_FINDINGS_2026-10-02.md).

The existing `scripts/review_notebook05_evidence.py`, `scripts/review_notebook06_evidence.py` and `scripts/audit_notebook06_aggregates.py` reproduce the saved-evidence checks with the pinned assets and a new output filename. The input ZIP and original outputs were not modified.
