# Notebook 09 — measurement semantics and the next development sample

Open [09_Measurement_Semantics_Audit.ipynb](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/09_Measurement_Semantics_Audit.ipynb) in Colab, select a **CPU runtime**, choose **Runtime → Run all**, and upload your completed **Notebook 08 results ZIP** when prompted. Share the new ZIP that downloads at the end.

This notebook investigates the packet-count issue found in the Notebook 08 review. It also prepares 128 additional malicious development records for the next experiment. It **does not run those attacks**, retrain an IDS, rerun Notebook 08, or estimate real-world IDS accuracy.

## What happens

1. A new repository checkout and uniquely named session are created. Existing notebooks and result folders are preserved.
2. A small isolated environment installs NumPy 2.3.5 and pandas 2.2.3. It uses the notebook's Python interpreter (supported: Python 3.11–3.13) and leaves kernel packages unchanged. PyTorch and model checkpoints are unnecessary.
3. The uploaded archive's completed Notebook 08 protocol, fixed profile, feature schema and saved development split are checked. No code or serialized model from the archive is executed.
4. Two public CSV assets are downloaded and checked by SHA256: the benchmark (348,439,863 bytes) and the authors' Scenario 1 aggregates (123,264,347 bytes). Allow approximately **472 MB** for these downloads. Subsequent processing is lightweight; network speed will usually dominate a fresh run.
5. Seven synthetic connection-CSV fixtures are passed through the unmodified, pinned upstream aggregation code. Six focused tests verify the relevant counterexamples.
6. All 143,046 native training/development records are audited in float64 and float32. Only that benchmark prefix is parsed; full files are hashed for integrity. Native test records are not evaluated.
7. The original Scenario 1 table is compared with its corresponding benchmark prefix. Row 1503's original label, host and window timestamp are retained in the evidence.
8. A deterministic sample of 128 malicious development records is selected from the 660 remaining after excluding all 32 pilot originals. No model prediction or attack outcome influences selection.

A GPU provides no benefit to this CSV/source audit. This environment is separate from the Python 3.8/PyTorch environment used for the frozen-model experiments.

## How to read the result

Expected reference findings are documented in [MEASUREMENT_SEMANTICS_FINDINGS_2026-10-21.md](MEASUREMENT_SEMANTICS_FINDINGS_2026-10-21.md).

- `status: completed` means the audit and sample preparation finished.
- `packet_duration_rule_adopted: false` is the intended research decision, not a program failure.
- `source_bridge.different_cells_float32: 0` confirms agreement with the authors' aggregates at the model's input precision.
- `conditional_bound_flags.csv` retains the authentic row-1503 counterexample in both precisions.
- `followup_manifest.json` records `attacks_executed: 0`. The 128-row file is an input artifact, not a result.

The column `positive_packets_zero_minimum_either_direction` is descriptive. A zero directional minimum can be an ordinary observation; it is **not** an estimated missing-data rate. Likewise, a positive packet total or a passing duration bound does not establish complete measurements.

## Research decision

Keep Notebook 08's profile v1 and reported results unchanged. Do not add

`duration_sum <= (pkts_in_sum + pkts_out_sum) * duration_max`

as a universal rule, and do not exempt zero-total buckets simply to clear the control. The extractor allows missing counts to become zeros, including within nonzero-total buckets. The cause of the original row's zero counts remains unresolved.

The next attack comparison will therefore concern **feature-space robustness under an explicit, fixed constraint profile**. A passing feature vector does not establish packet realizability or preserved malicious behavior.

## Frozen next experiment

The new protocol and manifest specify the following development experiment; this notebook prepares its inputs only.

| Item | Specification |
|---|---|
| Records | 128 additional malicious development originals; exclude the 32 pilot rows |
| Selection | NumPy RandomState seed 20261013; labels and saved split only |
| Models | The same frozen `default` and `madry` TORCHRLN checkpoints |
| Attack seeds | 0, 1, 2 |
| Core budget | 10 CAPGD steps; 100 MOEVA generations; 50 offspring; scaled L2 epsilon 0.5 |
| Primary comparison | Relationship/profile repair inside MOEVA versus after native CAA |
| Secondary comparisons | Native CAA with common filter; budget/profile end repair; budget/profile in-loop repair |
| Main outcome | Paired newly evaded originals among each model's initially detected records |
| Additional outcomes | Candidate coverage, rollback/duplicate rates, model queries and measured runtime |

Each original is the analysis unit. Summarize seed outcomes within each original before comparing methods. Do not count three seeds as three independent traffic samples. Any bootstrap interval over records is exploratory and does not resolve unknown host/window correlations. Report both models and all seeds, including negative results. Matching core attack budgets does not imply equal total queries or wall time.

These are additional **development** cases. They have already participated in clean-control audits and are not an untouched test set. The inherited scaler fitted on all feature rows remains a limitation. No packet-level, accuracy-improvement, defense or novelty claim follows from this preparation.

## Output files

The new session includes the source snapshot, environment/runtime logs, fixture inputs and aggregates, `report.json`, `source_bridge.json`, control CSVs, the original counterexample, `followup_inputs.npz`, and `followup_manifest.json`. Large CSV assets and the uploaded Notebook 08 archive are excluded from the export; their hashes are recorded.

If a cell fails, run the final export cell separately and share the partial ZIP. The absence of a completed report must not be interpreted as a successful experiment. A mismatching downloaded or cached asset is rejected; it is not silently substituted or overwritten.

For an existing local dataset, set `PHD_DATASET` and `PHD_SCENARIO1` to its absolute paths before running. `PHD_INPUT_ZIP` supplies the completed 08 ZIP. `PHD_NO_DOWNLOAD=1` disables the browser download of the result ZIP. The script itself can be run as:

```bash
python baseline/measurement_semantics.py \
  --input-zip /absolute/path/notebook08_results.zip \
  --dataset /absolute/path/ctu_13_neris.csv \
  --scenario1 /absolute/path/features_stat_scenario1.csv \
  --out /absolute/path/new_audit_directory
```

The output directory must not already exist.
