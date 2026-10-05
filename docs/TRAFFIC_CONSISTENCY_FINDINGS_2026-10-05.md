# Notebook 07 validation: 5 October 2026

The added sum/maximum rule removes three of the four extra in-loop evasion occurrences from notebook 06. One additional occurrence remains. Original CAA still has one evaded original in every seed after searching its saved pools for passing alternatives. This narrows the development finding; it does not demonstrate improved IDS accuracy or traffic realizability.

Input: `repair_during_search_20261004T040929Z_eb3c376b_results_20261004T043401Z_9e5af4fb.zip`.

Input SHA256: `0e1d546e01628c46c065a5dc99070f68dac3b51593c49ad37862126d45a922c8`.

This is a local replay of the user's Colab-generated evidence using the pinned CPU environment. No attacks were regenerated. The rule and its source limitations are described in [the notebook 07 guide](TRAFFIC_CONSISTENCY_GUIDE.md). Earlier files were preserved.

## Clean-control result

All 143,046 native training/development records pass all 180 positive-sum/positive-maximum checks in both parsed float64 and model float32. No nonfinite or negative features were found in these controls. All 32 selected originals match the pinned CSV and native development split.

| Partition | Benign | Malicious | Flagged by the added rule |
|---|---:|---:|---:|
| Training | 111,666 | 2,770 | 0 |
| Development | 27,918 | 692 | 0 |

Native test records were not parsed or evaluated. Asset hashing checks the complete data file for integrity. The earlier frozen compatibility scaler used all feature rows; that inherited limitation remains.

## Attack comparison

Both models initially detect 28 of the 32 malicious originals and already miss four. Each cell below gives newly evaded originals for attack seeds **0 / 1 / 2**. The denominator is 28 initially detected originals per seed.

| Standard model method | Notebook 06 result | Fresh native pool selection | With the added rule |
|---|---:|---:|---:|
| Original CAA | 1 / 1 / 1 | 1 / 1 / 1 | 1 / 1 / 1 |
| Budget end repair | 1 / 1 / 1 | 1 / 1 / 1 | 1 / 1 / 1 |
| Relationship + budget end repair | 1 / 1 / 1 | 1 / 1 / 1 | 1 / 1 / 1 |
| Budget in-loop repair | 1 / 1 / 3 | 1 / 1 / 3 | 1 / 1 / 2 |
| Relationship + budget in-loop repair | 2 / 1 / 2 | 2 / 1 / 2 | 1 / 1 / 1 |

The adversarially trained `madry` model has **0 / 0 / 0** new evasions for every method under both audit policies. This limited unsuccessful search does not establish general robustness.

The four extra occurrences concern only two distinct original records:

| Zero-based CSV row | Method / seed | After the added rule |
|---:|---|---|
| 131302 | Relationship in-loop / 0 | No passing saved evasion |
| 131302 | Budget in-loop / 2 | No passing saved evasion |
| 134407 | Budget in-loop / 2 | One passing saved evasion remains |
| 134407 | Relationship in-loop / 2 | No passing saved evasion |

The original CAA success is row 117132. Fifteen earlier selected evasion occurrences across the standard-model methods/seeds fail the added rule. Twelve have a passing alternative in their method's saved sources; three do not. Thus rejecting only the earlier chosen vectors would overstate the loss of attack success. These are repeated search occurrences, not 15 independent traffic records.

## Validation coverage

- Checked 90 physical stage-source files containing 174,840 candidate entries and 30 effective-final source files containing 960 vectors. Duplicate vectors remain in these entry counts.
- Reproduced native stage masks, distances, queried predictions and all 30 published evasion counts with the frozen models and scaler.
- Re-evaluated both selection policies for every model/seed/method. All final selections pass their stated gates; no final-matrix rejection was required on this archive.
- An independent review recomputed all 31,644,000 added-rule pair decisions, reconstructed per-original pool availability, and freshly checked/scored all 60 final matrices containing 1,920 vectors.
- The 26 project tests pass, including six new tests for aggregate coverage, alternative recovery, deduplication, final-gate fallback and archive handling.

The first full audit took about 55 seconds on the local validation machine, excluding environment setup/download. This is not a Colab speed guarantee or an attack runtime comparison. Counts and detailed results are recorded in [the validation JSON](../reference_results/traffic_consistency_validation_2026-10-05.json).

## Research implication

The relationship-repair variant's extra successes do not survive this necessary condition in the saved pools. Budget-only in-loop repair retains one extra original in one seed: 2/28 versus 1/28 for original CAA in that seed. This tiny development difference is insufficient for a general effectiveness claim.

The next step is to inspect the surviving row 134407 candidate and establish which further semantic conditions can be justified from the actual feature pipeline. Any extended constraints should be checked against clean development controls before a larger, frozen evaluation. Do not call the surviving vector packet-realizable, or the audit a new IDS defense. Retain these negative results as evidence for why a defensible threat model matters.
