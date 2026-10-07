# Notebook 08: connection-aware search

[Open notebook 08 in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/08_Connection_Aware_Search.ipynb).

Use **Runtime → Change runtime type → CPU**, then **Runtime → Run all**. Upload the completed **notebook 07 results ZIP** when prompted. Keep that input ZIP and all previous results. Download and share the new ZIP produced at the end. No Raspberry Pi, traffic generator or GPU is needed for this experiment.

## Research question

On the fixed CTU-13 Neris development pilot, does enforcing necessary aggregate/connection conditions during evolutionary search recover more valid evasions than filtering or repairing candidates after search, at matching core model-evaluation counts?

This evaluates attack feasibility against two frozen TORCHRLN IDS checkpoints. It does not train a new IDS. It is a development experiment, not a claim of novel attack design or real-world robustness.

## Why this follows notebook 07

Notebook 07 exposed a candidate that changed only duration in two buckets with no recorded external IPs or source/destination ports. Its extra evasion survived the sum/maximum check but failed this additional necessary endpoint-presence condition. Filtering old outputs cannot tell us whether enforcing that condition during generation would find different feasible candidates. Notebook 08 runs a fresh paired comparison to answer that narrower question.

The versioned profile in `baseline/connection_profile_v1.json` is fixed before these new runs. It contains:

1. **180 aggregate checks:** for bytes in/out, packets in/out and duration, a positive sum requires a positive maximum in the same port/direction bucket.
2. **108 endpoint checks:** a positive duration sum requires positive distinct external-IP, source-port and destination-port counts in that bucket.

All native bounds, feature types, immutable features, 360 native relationships, zero relationship tolerance and scaled L2 budget 0.5 remain in the final gate. No maximum duration or assumed collection-window length is introduced.

The necessary conditions are informed by the [pinned aggregation source](https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/aggregated_features_bro_logs.py). The extractor updates aggregate and endpoint sets for processed connections. This is source-informed justification; exact byte-level reproduction of the pinned CSV from that extractor has not been established. The `tcp/udp/icmp_sum` features accumulate bytes, not connection counts.

Before attack generation, the runner checks every one of the 143,046 native training/development records, separately by partition and class, in float64 and float32. Any violation stops the experiment and preserves the evidence. Do not remove failed controls or tune the profile to make the run finish.

## What the five methods mean

| Method | Generation | Added repair | Common final filter |
|---|---|---|---|
| `caa_filter` | Native CAA | None | Yes |
| `caa_profile_budget_end` | Same native CAA run | Basic features, budget and profile after generation | Yes |
| `caa_profile_relation_end` | Same native CAA run | Native relationships, basic features, budget and profile after generation | Yes |
| `caa_profile_budget_inloop` | Fresh CAA with modified MOEVA repair | Basic features, budget and profile before MOEVA fitness | Yes |
| `caa_profile_relation_inloop` | Fresh CAA with modified MOEVA repair | Native relationships, basic features, budget and profile before MOEVA fitness | Yes |

Budget-only variants retain the native relationship penalty during search; their final selected candidates must still pass all native relationships. The native returned result is separately saved in `native_original_reference.csv`. The main `caa_filter` comparison uses the same new final-selection procedure as the other four methods, so it need not equal that native returned result.

The new rollback extends the existing dependency-block repair. When an added condition fails, it restores the implicated mutable block to that record's own original values. Endpoint counts are immutable: the repair never invents new endpoint observations to justify duration. It does not consult model predictions, labels or random draws. Conservative rollback can collapse many proposals into repeated or clean vectors; the logs retain these counts.

Hard repair runs before every **MOEVA** fitness evaluation and writes the repaired values into the optimizer's actual genotype. Matching hashes verify that those repaired values are the ones scored. **CAPGD inner gradient iterations remain unchanged.** In-loop CAA's outer stage selector and the common final selector also require both added conditions. Do not describe this as repair inside every CAPGD step.

## Fixed comparison and cost accounting

The experiment restores the same 32 selected malicious development originals and frozen compatibility scaler from the notebook 07 ZIP. It uses both `default` and `madry` checkpoints, seeds 0/1/2, 10 CAPGD steps, 100 MOEVA generations and 50 offspring. It makes 18 fresh CAA generation runs; the two end-repair methods reuse each native run.

For each in-loop run, the implementation requires identical pre-MOEVA candidate arrays/masks and original IDs, MOEVA input IDs and population dimensions, and complete core model-forward counts, including gradient-enabled forwards. It stops if these differ. The pinned algorithm's actual population has 206 members; its 100-generation fitness budget is `206 + 99 × 50 = 5,156` rows per attacked original. Repeated/clean vectors still consume that budget. Initially missed inputs are removed by native CAA, so they do not enter the evolutionary run.

These are **matching core attack counts**, not matching total queries or wall time. Final filtering, rescoring and verification incur extra work. `generation.json` separates core generation from returned-matrix export. `comparison.csv` records incremental postprocessing cost in this shared workflow; caching and reuse mean these are not standalone method runtime measurements. Generation timing includes instrumentation. Do not use these timings to claim a speed improvement.

All saved stage pools and the generation's effective returned matrix are eligible sources. End-repair methods additionally include repaired versions of the native stage pools. Each in-loop method uses only its own sources. The final selector deduplicates within each original, ranks passing evasions by malicious score/distance/stable provenance, and checks the assembled final matrix. If a candidate fails that matrix-level check, it tries the next candidate before falling back to the unchanged original. This matters because the native float32 relationship evaluation is sensitive to array geometry; flattening native constraint checks would change acceptance.

## Reading the results

| Field | Meaning |
|---|---|
| `clean_detected` | Selected malicious originals initially detected by this model |
| `already_missed` | Selected malicious originals missed before any attack |
| `covered_records` | Originals with at least one changed candidate passing all final feature/budget conditions |
| `pool_evaded_records` | Initially detected originals with at least one passing, misclassified pool candidate |
| `newly_evaded` | Initially detected originals with an evasion that also passes the final matrix check |
| `new_evasion_rate` | `newly_evaded / clean_detected` |
| `unique_profile_feasible` | Changed passing candidates, deduplicated within each original |

The full pilot has 32 malicious originals; both frozen models initially detect 28 and miss four. The four existing misses cannot count as new evasions. Three attack seeds reuse those same originals; summing seed results does not create 84 independent examples. There are no benign evaluation examples in this attack pilot, so it cannot estimate overall accuracy or false-positive rate.

Raw `CandidateTrace` summaries describe native checks. Added-profile stage counts are in `profile_stage_selection.json`; use `comparison.csv` and final vectors for the strengthened comparison.

## Environment and reproducibility

The notebook installs Python 3.8.20 / NumPy 1.23.5 / PyTorch 1.12.1+cpu in an isolated environment. It does not downgrade the Colab kernel. A GPU runtime can execute it, but computation remains on CPU intentionally. The code/data/checkpoints retain the pinned revisions and SHA256 asset checks used in earlier notebooks. The native upstream source is not patched.

The runner parses only the training/development prefix and rechecks original CSV values, feature order, labels and native split membership. Full asset bytes are hashed for integrity. The earlier frozen compatibility scaler was fitted using all feature rows; this inherited limitation remains, even though notebook 08 neither refits it nor evaluates the test partition. A later leakage-free evaluation must be designed separately.

Every session, export and experiment directory is new. Existing Git checkouts are preserved rather than pulled or reset automatically. If an older checkout lacks notebook 08, start a fresh Colab runtime or use a new `ROOT` path. Never delete previous evidence just to rerun.

Local full run:

```bash
.baseline-env/bin/python baseline/run_connection_search.py --input-zip /absolute/path/notebook07_results.zip --out /absolute/path/new_experiment
.baseline-env/bin/python scripts/review_notebook08_evidence.py /absolute/path/new_experiment /absolute/path/new_review.json
```

For implementation troubleshooting only, `--smoke` runs four originals, one model/seed and three MOEVA generations. Its protocol marks `smoke_check_only: true`. Never report its output as the full research experiment.

For independent execution on a larger CPU machine, `--pair default 0` runs one full-budget model/seed pair and records `single_pair_only: true`. A single pair is not the full experiment. The optional `scripts/assemble_notebook08_pairs.py` assembles all six completed pairs after checking matching provenance and common inputs; its docstring describes the required execution manifest. Independently review the assembled evidence before reporting it. The Colab notebook's default remains one complete sequential run. Timings from concurrent pair execution are not a method speed comparison.

## Evidence and interpretation

The new ZIP contains input evidence, the fixed profile/rule catalog, clean-control audit, source snapshots, setup logs, stage pools, source validity masks, final matrices, per-original provenance, generation budgets and a separate review. It excludes full dataset files and model weights.

The independent review recomputes native validity in the original population geometry, all added rule masks, distances and model classes for every exported source. It independently reconstructs deduplicated pool counts and checks final-vector provenance. It also cross-checks intermediate repair/fitness logs and matching digests. Intermediate optimizer vectors are not exported, so the review does not independently reconstruct every intermediate generation. The runtime assertions and targeted tests check repair-before-fitness behavior.

If the run stops, run the last export cell to save partial logs and share the ZIP. Do not disable a failed assertion, loosen tolerance or change the profile to obtain a favorable result.

Passing these necessary conditions does not prove that packets can realize the features or that malicious behavior survives. More valid evasions would support a narrow attack-search finding on this development pilot. Equal or fewer evasions must also be retained. Neither outcome by itself demonstrates an improved IDS, a novel PhD contribution, real-world accuracy or complete robustness. Before scaling up, inspect surviving candidates and the repair's loss of diversity, then decide whether there is enough evidence to justify a larger development study.
