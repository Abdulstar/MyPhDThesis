# Notebook 08: local validation findings — 7 October 2026

The full paired development experiment completed. All 33 project tests passed. A separate review freshly rechecked all exported native masks, rule masks, distances and model classes, verified final selections, and checked matching core evaluation budgets. Earlier documents, notebooks and results are preserved.

## Observed evasions

Each entry is **newly evaded / 28 initially detected malicious originals**. Both models initially missed four of the 32 selected originals. Seeds reuse the same originals; these are not independent traffic samples. All five methods use the identical strengthened final filter.

| Method | Default seeds 0 / 1 / 2 | Madry seeds 0 / 1 / 2 |
|---|---|---|
| Native CAA + common filter | 1 / 1 / 0 | 0 / 0 / 0 |
| Budget/profile repair afterward | 1 / 1 / 1 | 0 / 0 / 0 |
| Relationship/profile repair afterward | 1 / 1 / 1 | 0 / 0 / 0 |
| Budget/profile repair inside MOEVA | 1 / 1 / 1 | 0 / 0 / 0 |
| Relationship/profile repair inside MOEVA | 2 / 1 / 1 | 0 / 0 / 0 |

These are evasion counts, not overall accuracy or false-positive rates. One evasion is 3.57% of the 28 initially detected inputs; two are 7.14%. The native returned CAA result before the added profile is retained separately in the reference JSON and evidence archive.

## Interpretation

The relationship-aware in-loop variant found an additional default-model evasion at seed 0. It did not improve the count over end repair at seeds 1 and 2. End repair and budget-only in-loop repair also recovered an evasion at seed 2 that the filtered native pool did not supply. The evidence supports investigating the extra case; it does not establish a consistent advantage across seeds, broad attack superiority or an improved IDS.

All observed evasions across methods concern these original CSV row IDs: **117132, 131302**. The additional seed-0 relationship-aware case is row **131302**; it changes four duration features in already populated buckets. This differs from the earlier duration-only proposal in empty buckets, but packet realizability and retained malicious behavior remain unverified. Large duration changes also require further semantic investigation; the collection-window/unit mapping to the pinned CSV has not been established sufficiently to impose an arbitrary cap.

## Validity and cost checks

- All 143,046 unperturbed native training/development controls passed the 180 aggregate and 108 endpoint checks in both float64 and float32. No test rows were parsed or scored.
- Every in-loop MOEVA fitness population passed the new profile before model evaluation. Repair wrote into the actual genotype, and repair/evaluation hashes matched. Native relationship repair additionally required every scored population to pass the full native checker. Budget-only search retained native relationship penalties.
- All 12 in-loop generation runs matched their fresh native counterpart’s core forward/gradient counts, pre-MOEVA arrays, original IDs and MOEVA population dimensions. Each attacked original used 5,156 MOEVA fitness rows: 206 initial candidates + 99 generations × 50 offspring. Each full run attacked 28 initially detected originals.
- Each generation run used 150,896 core forward rows (including 144,368 MOEVA fitness rows), 3,139 forward calls, and 644 gradient-enabled forward rows in 23 calls. Post-selection/verification costs were additional. Three pairs ran concurrently during local validation; timings are not a method speed comparison.
- CAPGD inner steps stayed native. The added repair operates inside MOEVA; the in-loop CAA outer selector and all reported final outputs also apply the profile.

Independent review totals: **108 source files**, **175,416 exported source entries**, **30 final matrices**, and **1,732,416 logged in-loop fitness rows**. Intermediate optimizer vectors were not exported; their logs/digests were cross-checked, not independently reconstructed. Maximum fresh-versus-saved malicious-score difference: `0.0`.

## Search diversity

| Model | Seed | In-loop repair | Unique vectors / fitness rows | Unchanged fitness rows |
|---|---:|---|---:|---:|
| default | 0 | Budget | 64332 / 144368 | 76240 |
| default | 0 | Relationship | 10243 / 144368 | 131375 |
| default | 1 | Budget | 62705 / 144368 | 79534 |
| default | 1 | Relationship | 10112 / 144368 | 131887 |
| default | 2 | Budget | 62785 / 144368 | 79308 |
| default | 2 | Relationship | 10521 / 144368 | 131491 |
| madry | 0 | Budget | 64225 / 144368 | 78055 |
| madry | 0 | Relationship | 10021 / 144368 | 132154 |
| madry | 1 | Budget | 62747 / 144368 | 79494 |
| madry | 1 | Relationship | 10152 / 144368 | 131135 |
| madry | 2 | Budget | 62982 / 144368 | 79257 |
| madry | 2 | Relationship | 10351 / 144368 | 131053 |

Unique vectors are counted within each original and then summed. Repeated and unchanged vectors still consume the attack budget. These counts show the cost of conservative rollback; they do not by themselves establish faster or better search.

## Validation scope

The full experiment was executed as six explicit `--pair` runs, using three concurrent CPU workers, then assembled with provenance/input checks and independently reviewed. An earlier sequential notebook run was interrupted during the first pair; its partial output was preserved and excluded from the completed comparison. The 33-test suite, notebook syntax/schema, local setup, noninteractive input handling, review, display and export were exercised. Browser upload/download interaction still needs the user’s Colab run.

The validation used the pinned isolated Python 3.8.20 / NumPy 1.23.5 / CPU PyTorch 1.12.1 environment. The working implementation was uncommitted during validation; exact source hashes are in the reference JSON and archive. Publishing must preserve those implementation bytes.

## What to do next

1. Run [notebook 08 in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/08_Connection_Aware_Search.ipynb) on CPU with the completed notebook 07 ZIP. Keep both ZIPs.
2. Compare the exported final counts, candidate identities, rule masks and budget checks with this local reference. Tiny floating-point score differences can occur; record any decision changes rather than hiding them.
3. Inspect the extra row-131302 candidate’s traffic semantics and the concentration of repeated/unchanged proposals before deciding on a larger development study. A candidate generator that respects dependencies directly is a research hypothesis to assess, not an established contribution.

The 32 malicious development originals, rules motivated by earlier observations, and inherited scaler fitted on all feature rows prevent a leakage-free final-test claim. A later locked evaluation must be designed separately. No IDS training, packet replay, real-world accuracy improvement, or novelty claim is established here.

Files: [Colab guide](CONNECTION_AWARE_SEARCH_GUIDE.md) · [Machine-readable reference](../reference_results/notebook08_connection_search_validation_2026-10-07.json).

Evidence archive: `Notebook08_Connection_Search_Validation_2026-10-07.zip`; SHA256 `693f2991a78faf0258cba31a1fd9b6293c562a0d76794395d54c25b0cb43a857`.
