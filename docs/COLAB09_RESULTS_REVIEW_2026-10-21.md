# Notebook 09b: completed Colab run reviewed

Review date: 2026-10-21. **Status: passed.**

The uploaded run completed the measurement-semantics audit and froze 128 inputs
for the next development experiment. The Colab environment fix worked. This
run produced no new model predictions, attack outcomes, or IDS accuracy result.

## What was checked

| Check | Result |
| --- | --- |
| ZIP integrity | All 51 members passed CRC and archive-path checks |
| Published source | All 14 snapshots match the recorded SHA-256 values, Git blobs, and local sources |
| Colab setup | Completed without requesting `ensurepip`; target environment has no installed pip |
| Uploaded tests | 3 setup regression tests and 6 measurement tests passed |
| Audit outputs | All 29 non-report files are byte-identical to the prior reference and a fresh local audit |
| Report | Every field matches both runs except Python version and elapsed audit time |
| Dataset controls | 143,046 train/development records rechecked; no native test records parsed or scored |
| Follow-up sample | 128 unique malicious development records, 757 features each, zero pilot overlap |
| New attacks executed | 0 |

Colab used Python **3.13.16**, NumPy **2.3.5**, and pandas **2.2.3**. The local
reference and fresh rerun used Python 3.12.14 with the same NumPy/pandas versions.
The Colab audit took about 28.02 seconds, including asset acquisition/checking;
the fresh local audit used cached assets and took about 9.47 seconds. These are
different workloads/environments, not a speed comparison.

The Python 3.13 result validates this NumPy/pandas audit. It does not validate
the older model/attack dependencies on Python 3.13. Keep that experiment in its
separate, pinned Python 3.8.20 environment.

## Research interpretation

The authors' Scenario 1 aggregate file and the benchmark agree across **77,183
rows and 757 model features at float32 precision**, with zero label differences.
There are 79 tiny float64 cell differences (maximum absolute difference about
3.64e-12). This establishes the aggregate-file correspondence checked here; it
does not recover the original packet capture or exact raw-log pipeline.

The proposed diagnostic

`duration_sum > (pkts_in_sum + pkts_out_sum) * duration_max`

flags one existing, unmodified train/development record: zero-based CSV row
1503, labeled 0 in the benchmark and `BACKGROUND` in the authors' aggregate
file. All 757 features of that row match exactly in both precisions. A
`BACKGROUND` label is not independent verification that traffic is benign.

Seven controlled extractor examples reproduce missing-value/zero collisions,
partial missingness, initialization behavior, and durations longer than the
aggregation window. They show why packet completeness cannot be inferred from
these aggregate features. They do **not** establish which mechanism produced
the historical row, or demonstrate feasible packets or preserved attack behavior.

**Decision: preserve profile v1 unchanged.** Do not turn the packet/duration
diagnostic into a universal hard constraint or add an outcome-driven exemption.
The existing profile passes all audited train/development controls, which is
compatibility evidence rather than a proof of physical realizability.

## The next experiment is ready to be implemented

The sample selection was independently recomputed from the original development
indices and source labels. There are 692 malicious development records; excluding
all 32 pilot originals leaves 660. A fixed permutation with seed `20261013`
selects 128. The order, labels, and float32 feature vectors match the export and
fresh source audit exactly. No predictions or attack outcomes selected them.

The next notebook should consume **both** the completed notebook-08 export
(frozen scaler, original split and prior evidence) and this notebook-09b export
(frozen inputs and protocol). Keep both ZIPs. Notebook 09b does not need another
run. This review adds no notebook 10 and starts no attacks.

The already fixed comparison is:

1. Evaluate the frozen `default` and `madry` TORCHRLN models separately on these
   same 128 originals. Retain existing clean misses and report the initially
   detected denominator for each model.
2. Run seeds 0, 1, and 2 with the unchanged profile, CAPGD 10 steps, MOEVA 100
   generations/50 offspring, and scaled L2 budget 0.5.
3. Compare relationship/profile repair inside MOEVA against relationship/profile
   repair after native CAA as the primary comparison. Preserve the three
   secondary methods frozen in the manifest.
4. Match core attack budgets and initial states. Report extra repair/selection
   queries and time separately, and retain the native checker's matrix geometry.
5. Report per-original outcomes, coverage, rollback/duplicate rates and all
   seeds. Average paired seed differences within each original before exploratory
   record-level resampling; do not treat repeated seeds as independent samples.

These are development records already inspected by the clean-control audit,
not an untouched test set. Unknown host/window correlations limit record-level
intervals. The inherited all-feature-row scaler fit remains a limitation. The
study's scope is feature-space robustness under explicit constraints, not
real-world IDS accuracy or confirmed packet-level evasion.

## Evidence and reproduction

- Source commit: `d6847238ceef2a1a60711416bbf7919d38aa8739`.
- Source tree: `b65a16ec73681cf749e546140cd3b728aae95012`.
- Uploaded ZIP: `measurement_semantics_20261021T012235Z_08cdf07d_results_20261021T012400Z_59feb8d4.zip`.
- Uploaded SHA-256: `e44eb9bf358bc7736e8e072a9b825b4dbc520ba36a7c2c05b50e397703ec076c`.
- Follow-up inputs SHA-256: `f67408981fb225e2fc5833fdaced74ff852eb268ec4b3af116b5af18b41816c8`.
- Ordered row IDs SHA-256: `7d6230d364dd302f7a367adba184eeafc24ae7fd06b6266b156ae395ff0e2128`.
- Machine-readable review: [notebook09_colab_review_2026-10-21.json](../reference_results/notebook09_colab_review_2026-10-21.json).
- Review script: [review_notebook09_colab.py](../scripts/review_notebook09_colab.py).

The script executes only locally verified published sources, never code from
the uploaded ZIP. It authenticates both dataset assets, compares archived
outputs with the prior local reference, independently recomputes the selection,
and reruns the source/data audit. Reproducing this exact review additionally
requires the retained local reference export identified in the JSON report;
the user does not need to run this review script to continue.

```bash
python scripts/review_notebook09_colab.py \
  --run-zip COLAB09B_RESULTS.zip \
  --reference-zip RETAINED_LOCAL09B_REFERENCE.zip \
  --notebook08-zip COLAB08_RESULTS.zip \
  --published-tree PUBLISHED_GIT_TREE.json \
  --dataset assets/ctu_13_neris.csv \
  --scenario1 assets/features_stat_scenario1.csv \
  --out NEW_REVIEW_DIRECTORY
```

This publication adds a review script, this document, and a JSON report. Earlier
notebooks, results, protocols, and proposal documents are preserved.
