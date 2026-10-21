# Notebook 10: the fixed 128-record development experiment

Open [notebook 10 in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/10_Frozen_128_Development_Replication.ipynb).
Choose a CPU runtime, leave `RUN_MODE` as `full`, and select **Runtime → Run all**.
When prompted, select both completed result ZIPs together:

- Notebook 08: `connection_search_20261013T064148Z_af4a1a10_results_20261013T072031Z_cf72eb9f.zip`.
- Notebook 09b: `measurement_semantics_20261021T012235Z_08cdf07d_results_20261021T012400Z_59feb8d4.zip`.

The notebook recognizes these files by their reviewed hashes, not their names.
After completion, download and share the new `frozen_followup128_...zip`.
Earlier files are preserved. If a cell fails, run the final export cell to save
partial evidence and share that ZIP; do not adjust constraints or remove rows.

## Question and fixed comparison

Does relationship/profile repair during MOEVA produce more valid new evasions
than the same repair applied after native CAA, on 128 additional malicious
development originals at the same core attack budget?

This is a replication beyond the 32-record pilot, using the sample frozen before
attack outcomes in notebook 09b. It is not an untouched final test. It does not
train a new IDS, change the defense, establish attack novelty, or demonstrate
packet-level realizability.

| Component | Fixed setting |
| --- | --- |
| Sample | 128 malicious development originals; excludes all 32 pilot originals |
| Selection | Seed 20261013; native development labels only; no prediction-based selection |
| IDS models | Existing default and adversarially trained (`madry`) TORCHRLN checkpoints |
| Features | 757: 756 aggregates and `window_timestamp` |
| Repeated attack seeds | 0, 1, 2 on the same originals |
| Attack budget | CAPGD 10 steps; MOEVA 100 generations, 50 offspring; scaled L2 epsilon 0.5 |
| Primary comparison | `caa_profile_relation_inloop` versus `caa_profile_relation_end` |
| Secondary methods | `caa_filter`, `caa_profile_budget_end`, `caa_profile_budget_inloop` |
| Constraints | Original native constraints/tolerance plus unchanged profile v1 |
| Environment | Python 3.8.20, NumPy 1.23.5, PyTorch 1.12.1+cpu |

The packet/duration diagnostic investigated in notebook 09b is not adopted as a
hard rule. Missingness and the exact historical raw-log pipeline remain unknown.
The inherited frozen scaler was originally fitted on all benchmark feature
rows; this limitation is retained and must be disclosed.

## What the notebook does

1. Creates a new project/session directory and records source hashes and runtime
   context. It reads only selected data/provenance members from the two ZIPs.
2. Uses the existing isolated `uv` bootstrap, which avoids the Colab
   `python -m venv`/`ensurepip` failure. The notebook kernel is unchanged.
3. Verifies the exact code/data/model revisions, profile, scaler, sample and
   development split. Rechecks 143,046 train/development controls and all 128
   original vectors. It hashes whole data files but parses no native test rows.
4. Scores both frozen models before attacks. A local preflight found 122
   detections and six existing misses for each model on these 128 malicious
   records. This is a sample-specific detection count, not overall accuracy.
5. Runs 18 fresh attack generations and produces 30 final method comparisons.
   It reuses notebook 08's unchanged generation, rollback, pool evaluation, and
   final-selection functions. Before-MOEVA arrays, stage membership and core
   forward budgets must match; a mismatch stops the run.
6. Uses the existing independent evidence reviewer to recompute all exported
   vector masks, distances, predictions, pool counts and selection provenance.
   Optimizer logs/digests are checked; unexported intermediate vectors are not
   independently reconstructed.
7. Produces paired per-original analysis and a new export ZIP.

No GPU is used by this pinned CPU comparison. Switching device/package versions
would require a separately validated experiment. The larger full run takes more
work than the pilot; wall time depends on the runtime. It should not be compared
as a speed result with the earlier run on a different machine.

## How to read the results

`newly_evaded` counts initially detected malicious originals for which a changed,
valid representative is finally selected. Divide it by `clean_detected`, not
by all traffic and not by the number of generated candidates. Existing clean
misses remain in the evidence but do not count as new evasions.

The primary effect is computed per model. For every original, subtract end-repair
success from in-search-repair success for each matched seed, average those three
differences within that original, then average across initially detected
originals. The result is reported in percentage points. Positive favors repair
during MOEVA; negative favors repair afterward. Regressions are retained.

The exploratory 95% percentile interval resamples originals after that seed
average (10,000 replicates, fixed analysis seed 20261021). Seeds are not treated
as independent traffic samples. Unknown host/window dependence remains; a
zero-width empirical interval does not demonstrate population equivalence.

Coverage, repeated optimizer vectors, unchanged optimizer vectors, restored
blocks, queries and time are also retained. More coverage alone is not a better
attack. Restored blocks per evaluated row is not a fraction of repaired
candidates. Shared end-method generation/evaluation means incremental cost
fields are not standalone method runtimes or equal-total-compute comparisons.

## Output files and modes

- `experiment/preflight.json`: baseline detections on all 128 frozen records.
- `experiment/comparison.csv`: all five methods for both models and all seeds.
- `experiment/.../final.npz`: selected vectors and per-original decisions.
- `experiment/.../generation_audit.json`: repair/evaluation accounting.
- `independent_review.json`: independent evidence checks.
- `paired_analysis/paired_by_original.csv`: seed-averaged paired outcomes.
- `paired_analysis/paired_summary.json`: model-specific effects, exploratory
  intervals and optimizer accounting.

`preflight` mode runs only checks and original-model predictions; it runs no
attacks. `smoke` mode uses the first four frozen records, one model/seed and
reduced budgets. It checks implementation only. Neither can be summarized as
the full experiment. The production notebook defaults to `full`.

Local validation is documented in
[notebook10_implementation_validation_2026-10-21.json](../reference_results/notebook10_implementation_validation_2026-10-21.json).
It distinguishes setup, full-sample preflight and reduced implementation checks
from the full research experiment, which is left for the Colab run.
