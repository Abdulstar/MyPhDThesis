# Notebook 07: traffic consistency audit

[Open notebook 07 in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/07_Traffic_Consistency_Audit.ipynb).

Choose a CPU runtime, select **Runtime → Run all**, and upload your completed notebook 06 results ZIP when prompted. Leave the settings unchanged. Download the new ZIP at the end and share it for review. Earlier files and results are preserved. If a cell fails, run the final export cell to save the partial evidence and logs.

This notebook needs the complete notebook 06 archive containing both `baseline` and `inloop`, not a screenshot or a CSV alone. If the archive is already on Colab, enter its absolute path in `INPUT_ZIP`. A fresh runtime downloads approximately 348 MB of aggregate feature data plus two small checkpoints. Python 3.8.20, NumPy 1.23.5 and CPU PyTorch 1.12.1 are installed separately from the notebook kernel. GPU access is not needed. The audit reuses saved candidates; it does not rerun the 18 attacks.

## Research question for this audit

Do the reported feature-space evasions remain available when candidates must also satisfy a documented necessary aggregate condition?

The added rule rejects an aggregate **only when its sum is positive and its maximum is zero**. It covers incoming/outgoing bytes, incoming/outgoing packets and duration, for 18 port buckets and both endpoint roles: **180 sum/maximum pairs**. No tolerance is added and the native 360 relationships remain unchanged. This rule was motivated by notebook 06's exploratory findings. The protocol was fixed before the notebook 07 clean-control scan, but this remains a post-hoc development audit.

## Evidence for the rule

The upstream researchers' [realistic adversarial hardening repository](https://github.com/serval-uni-lu/realistic_adversarial_hardening) links the [CTU feature extractor](https://github.com/tongun/ctu13-botnet-detection). [TabularBench's dataset documentation](https://serval-uni-lu.github.io/tabularbench/doc/datasets.html) describes the engineered CTU representation and its research lineage.

Inspected extractor revision: `2f1624ce0f06055901edfc90219d5072d8d04895`.

| Source | What it establishes |
|---|---|
| [Aggregation code](https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/aggregated_features_bro_logs.py) | Each sum and maximum are updated from the same observations. Empty buckets and missing `-` values use zero. |
| [Configuration](https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/config.py) | The 18 port buckets, including `OTHER`; a configurable aggregation window. |
| [Extraction driver](https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/extract_features.py) | Multiple window sizes are supported, so a fixed duration cap is not justified here. |
| [Combination code](https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/read_combined_features.py) | Numeric conversion and benign/botnet label handling. |

In this extractor, aggregation is by internal host, time window, destination-port bucket and endpoint role. `_s_` means the internal host originates the connection; `_d_` means it receives it. These suffixes are distinct from the incoming/outgoing measurement families. Protocol `tcp_sum`, `udp_sum` and `icmp_sum` fields accumulate bytes, not connection counts. The rule uses no protocol-count inference or duration unit conversion.

This is relevant source lineage, not a byte-for-byte reconstruction of the benchmark CSV. The exact pinned CSV's generation window and complete preprocessing history have not been independently reproduced. The notebook checks the proposed necessary condition against actual clean records instead of assuming that the lineage settles every feature detail. Passing this condition is insufficient to establish realizable traffic or preserved malicious behavior.

## What is checked

1. **Provenance:** ZIP integrity, bounded safe extraction, pinned assets and upstream code, feature order, frozen scaler, completed baseline/in-loop pairing, and selected originals.
2. **Clean controls:** all 143,046 native training-prefix records, split into 114,436 training and 28,610 development records using the upstream stratified split. Results are separated by benign/malicious class and parsed float64/model float32. Native test rows are not parsed or scored. Hashing the full asset reads its bytes solely for integrity verification.
3. **Saved sources:** all three final-stage populations per attack, all end-only repaired populations, and each method's effective final output. Both the original checker and the model are rerun. Candidates that were not exported during intermediate optimizer iterations cannot be audited.
4. **Selection:** within each original record, deduplicate native-valid, changed, in-budget vectors. Rank successful evasions by malicious probability, distance and stable provenance. Select once under native rules and once with the additional rule. Recheck the complete final matrix and try the next candidate if that gate rejects one. Otherwise retain the original input.

Native relationship checks preserve each saved population's original shape. Flattening candidates for these checks can change float32 summation behavior. Final 32-row matrices are therefore checked separately. The original zero tolerance and scaled-L2 budget are retained.

The clean-control audit reports violations without deleting observations or tuning the rule. If one of the selected originals violates it, the paired candidate comparison stops with its evidence preserved.

## Which candidate pools are compared

| Method | Sources included |
|---|---|
| Original CAA | Its three raw stage populations and effective final output |
| Budget end repair | Original CAA sources plus three budget-repaired populations and its final output |
| Relationship + budget end repair | Original CAA sources plus three relationship/budget-repaired populations and its final output |
| Budget in-loop repair | Its own three stage populations and effective final output |
| Relationship + budget in-loop repair | Its own three stage populations and effective final output |

The in-loop `x_union` output is excluded because it additionally uses a separate original attack. Physical source files shared between methods are checked once. Candidate-entry totals include duplicate vectors; unique feasible totals are deduplicated within each original record. Repeated seeds are not independent samples of network traffic.

## Read the outputs

| File or column | Meaning |
|---|---|
| `clean_controls.csv` | Control counts and rule violations by partition, class and precision |
| `clean_flagged_records.csv` | Every flagged clean control; header only when none fail |
| `comparison.csv` | One row per model, seed and method |
| `published_newly_evaded` | Notebook 06 result, reproduced by fresh inference |
| `published_evasions_flagged` | Earlier selected evasions that fail the added rule |
| `native_final_newly_evaded` | New selection from all saved sources, under the original rules |
| `native_plus_support_final_newly_evaded` | Same selection with the additional rule |
| `flagged_published_evasions_with_passing_alternative` | Earlier flagged evasions recovered with another saved vector |
| `*_pool_evaded_records` | Records with an eligible evasion before the complete final-matrix gate |
| `*_final_gate_rejections` | Candidates rejected when assembled into that final matrix |
| `records.csv` | Per-original counts, selection hashes and recovery indicators |
| `source_audits/` and `source_manifest.json` | Fresh masks, probabilities, distances, rule flags and source hashes |
| `native_final.npz`, `native_plus_support_final.npz` | Selected final vectors for each policy |
| `*_selection.json` | Candidate provenance and any final-gate rejections |

The ZIP also includes the original extracted evidence, the exact audit source snapshot, environment report and logs. It excludes the large dataset and model assets. New evasion is measured among initially detected malicious records. It is not accuracy over benign and malicious traffic. A clean fallback never counts as an evasion or changed-valid coverage.

## Limits and next decision

The frozen models and scaler are inherited. The earlier compatibility scaler used all feature rows; this audit does not remove that limitation or create an independent final test. All attack comparisons reuse 32 selected malicious development originals. Results across attack seeds describe repeated search on those originals.

If an apparent improvement disappears, record that finding and inspect why the optimizer exploited an incomplete feasibility definition. If an improvement survives, inspect its exact feature changes and remaining semantic constraints before scaling the experiment. Passing one aggregate condition is not evidence of a deployable IDS, packet realizability, retained attack functionality, or a novel PhD contribution.

For a local run from the repository:

```bash
python scripts/bootstrap.py
.baseline-env/bin/python baseline/download_assets.py
.baseline-env/bin/python baseline/run_traffic_consistency_audit.py \
  --input-zip /absolute/path/to/notebook06_results.zip \
  --out runs/traffic_consistency_new_run
```

The output directory must not already exist. Every run creates new evidence; the audit does not rewrite earlier experiments.
