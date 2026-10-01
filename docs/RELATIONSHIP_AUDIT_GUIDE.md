# Notebook 04: audit the saved feature relationships

Open [04_Relationship_Audit.ipynb in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/04_Relationship_Audit.ipynb).

1. Choose a **CPU runtime** and select **Runtime → Run all**.
2. When prompted, upload the complete notebook 03 results ZIP: `diagnostics32_..._results_....zip`.
3. Wait for setup and the audit to finish. The notebook displays its summaries and downloads a **new audit ZIP**. Share that ZIP for review.

If the input ZIP is already in Colab, put its full path in `INPUT_ZIP` before running. Leave the other defaults unchanged. The default workspace is `/content/MyPhDThesis_RelationshipAudit`; old workspaces and notebooks are preserved. Optional Drive copying is disabled by default.

The original uploaded experiment has already been audited locally; [the findings](RELATIONSHIP_AUDIT_FINDINGS_2026-10-01.md) are available now. Running notebook 04 reproduces this audit in your environment. It does not require a new attack run or model training.

## What the audit checks

The script reads the original float32 candidate arrays and applies the official rule objects, NumPy backend and constraint checker at the same pinned upstream revision. It verifies metadata SHA-256, feature order, archive integrity, labels, array dimensions and saved mask consistency. It then independently recomputes **relationship, bounds, type and immutable-feature masks** and requires exact agreement with the saved masks.

Each of the 360 relationships has a stable audit ID (`r001`–`r360`), an upstream zero-based index, a readable formula, its feature names and units. The rule families are:

| Family | Rules | Meaning |
|---|---:|---|
| Byte balance | 2 | Total protocol bytes equal incoming plus outgoing bytes, for `s` and `d` |
| Packet size | 34 | Outgoing bytes / outgoing packets ≤ 1500 for the enumerated ports |
| Byte ordering | 108 | Outgoing-byte minimum ≤ maximum ≤ sum, including minimum ≤ sum |
| Packet ordering | 108 | The same checks for outgoing packet counts |
| Duration ordering | 108 | The same checks for duration features |

The packet-size rules retain upstream semantics: `OTHER` is excluded and zero packet count uses a division fill value of zero. Passing these benchmark rules is not proof that a feature vector can be produced by real packets.

For a comparison `a ≤ b`, a positive residual measures the excess; for `a == b`, it measures the absolute difference. The original zero relationship tolerance is preserved. Residuals in bytes, packets and duration should not be ranked together by raw magnitude.

## How numerical effects are assessed

The same official rule expressions are evaluated twice:

- **Native:** on the saved float32 values, preserving each original row's candidate-population shape and upstream arithmetic.
- **Float64 diagnostic:** on exactly those stored numbers promoted to float64.

Both clean controls and attack candidates are checked. The report counts failures that disappear, persist, or appear when the arithmetic changes. It reports these transitions at both the individual-rule and whole-candidate levels. A candidate remains invalid if any of its other rules still fails.

Promoting a stored float32 value cannot restore information lost before it was saved. A persistent gap is an inconsistency in the stored values; its practical severity still depends on units and context. Relative gaps are descriptive (`residual / max(1, abs(left), abs(right))`), not a tolerance or a numerical error bound. No baseline result is rescored under an alternative acceptance policy.

## Reading the exported files

| File | Purpose |
|---|---|
| `audit_report.json` | Provenance, verification results, stage/family summaries and limitations |
| `stage_summary.csv` | Invalid candidates, precision transitions, budget failures and changed-valid coverage |
| `family_summary.csv` | Relationship-family failures, with separate counts inside the distance budget |
| `rule_catalog.json` | All 360 rule definitions and features |
| `rule_summary.csv` | Per-rule failure counts and native/float64 residual quantiles, including in-budget ranges |
| `stages/.../candidates.csv` | Candidate-to-original-row mapping and failed rule IDs |
| `stages/.../rule_residuals.npz` | Full native/float64 residual matrices; axes are input row, candidate, rule |
| `stages/.../largest_residual_examples.json` | Largest residual for each failing rule, original/candidate feature values and budget status |
| `input_.../diagnostics32_....zip` | Exact source experiment, retained inside the new export |
| `source_snapshot/`, logs and setup record | Code and environment used for this audit |

Failure counts across rules overlap. Candidate counts can include duplicates and unchanged originals; they are not numbers of independent attacks or requests. Example files select the largest residual across all candidates, so always inspect `within_budget`. Original prediction outputs and distances are reused from the source ZIP; no model predictions are rerun here.

## Dependencies and local execution

The same isolated Python 3.8.20 / NumPy 1.23.5 / CPU PyTorch environment is used. Fresh setup installs the existing pinned dependency set. After setup, only the approximately **38 KB metadata CSV** is downloaded. The 348 MB feature dataset and model checkpoints are not required. A GPU does not accelerate this rule audit.

From the repository root:

```bash
python scripts/bootstrap.py
.baseline-env/bin/python baseline/relationship_audit.py \
  --input-zip /path/to/diagnostics32_results.zip \
  --out runs/relationship_audit_new
```

An optional `--metadata /path/to/ctu_13_neris_metadata.csv` reuses an existing metadata file after hash verification. `--out` must be a new directory. The notebook creates unique session, input, audit and export paths, including when a cell is repeated.

If setup or auditing fails, run the final export cell separately and share the partial ZIP. If the wrong ZIP was uploaded, rerun the upload cell with notebook 03's full results archive. No uploaded scripts are executed, and pickled NumPy arrays are rejected.

## Research boundary

This is a reproducibility and attack-validity diagnostic. A subsequent method should improve the generation of consistent, changed candidates while retaining immutable features, bounds, integer constraints and the fixed perturbation budget. Every proposed repair must be rechecked against all constraints; repairing one feature can break another rule or exceed the budget.

Use a separate development partition to design and tune that method. These already inspected test rows are exploratory evidence. New model training also needs train-only preprocessing; the current compatibility scaler follows the upstream checkpoint loader and uses all dataset feature rows.

This audit is not a packet replay experiment, a robustness certificate, or an established thesis contribution by itself.
