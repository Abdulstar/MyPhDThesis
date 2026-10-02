# Notebook 06: repair during evolutionary search

Open [06_Repair_During_Search.ipynb in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/06_Repair_During_Search.ipynb), choose a **CPU runtime**, then select **Runtime → Run all**. Keep the default settings for the planned experiment. Download the new ZIP at the end and share it for review.

No previous ZIP upload is needed. Notebook 06 runs a fresh notebook-05 baseline in the same environment, then runs two new variants. The default requires **18 complete CAA runs**: two models × three seeds × three search variants. It also checks candidates during each generation, so expect a longer run than notebook 05. Keep the session connected. A GPU does not accelerate this pinned CPU implementation.

## Research question

Does moving the existing conservative repair inside evolutionary search find additional valid evasions, compared with repairing only final stage outputs, when the core attack model-evaluation budget is held fixed?

Notebook 05 established that end-only repair increases changed-valid coverage without additional evasion on the inspected development subset. This experiment changes when repair happens. It does not introduce a new IDS, retrain checkpoints or establish novelty.

## Five comparison rows per model and seed

| Method | Procedure |
|---|---|
| `caa_original` | Fresh, unmodified pinned CAA. |
| `caa_budget_end` | Notebook-05 budget-only rollback of that CAA's saved outputs; retain valid original evasions. |
| `caa_relation_end` | Notebook-05 relationship + budget rollback of the same outputs; retain valid original evasions. |
| `caa_budget_inloop` | CAA with budget-only rollback applied to every MOEVA initial/offspring population before fitness evaluation. |
| `caa_relation_inloop` | CAA with relationship + budget rollback applied at that same point. |

The budget-only in-search control separates effects of the radius restriction from relationship checking. The end-only methods share one original attack run; the in-search methods create new search trajectories. They do not reuse the original trajectory's final candidate pool.

## What changes inside the algorithm

MOEVA's pinned sampling, mixed-variable crossover, mutation, selection, three objective functions, population sizes, seed, generation count and duplicate policy remain unchanged. The new subclass connects the existing block rollback to pymoo 0.5.0's initialization and mating repair hooks. The repaired mutable coordinates are written back into the actual population before objective evaluation. This matters because selection and later offspring must use the repaired values.

For relationship repair, the existing dependency blocks are restored when their rules fail, and high-cost blocks are restored until the original scaled L2 budget is met. The full official checker verifies the result. A block-level numerical rejection at the final full check reverts that candidate to its own clean input and is recorded. Such a fallback is never counted as changed coverage. Budget-only repair leaves relationship violations available to the original constraint objective.

All output coordinates come from either the proposed candidate or its own clean record. The method can discard useful mutations, collapse offspring to repeated vectors, and restrict exploration. Logging records those outcomes; a successful execution does not mean an improved attack.

## Fixed development protocol and compute controls

- Same 32 constraint-valid malicious development records, selection seed 0, without model-prediction filtering.
- Same standard and adversarially trained RLN checkpoints and attack seeds 0, 1, 2.
- Same 10 gradient steps, 100 evolutionary generations, 50 offspring, scaled L2 radius 0.5 and zero relationship tolerance.
- Native test records are excluded from selection and model scoring. Existing compatibility preprocessing and checkpoint-history limitations remain.
- No early stopping on a newly found evasion inside MOEVA. Duplicate and clean evaluations still count toward the budget.

The runner requires exact equality of the fresh baseline and modified runs' NoAttack/CAPGD input arrays, candidate arrays and acceptance masks. It also requires equality of all core attack forward-call and forward-row counters, including gradient-enabled forwards. If a control fails, the experiment stops instead of presenting an unmatched comparison. Run the baseline and variants in the same environment; an older archive from another machine is unsuitable for these strict controls.

For each MOEVA input, its audit checks `initial population size + (generations − 1) × offspring` objective-model evaluations. The pinned default population has 206 candidates, giving 5,156 objective-model rows per MOEVA input at the default budget. The stored population digest before fitness must match the one recorded by repair. Complete per-generation counts and digests are saved, together with counts of distinct evaluated vectors and clean fallbacks.

Equal model-evaluation counts do **not** imply equal wall time or total computation. In-search repair adds CPU work. Timings include validation, hashing, candidate tracing and evidence writing; they are not server throughput measurements. End-only repair adds its own model predictions, shown separately. Final representative scoring and the optional union check are also outside the matched core attack budget.

## Metrics and interpretation

`covered_records` counts distinct originals with at least one changed, valid, in-budget candidate in the reported final stage-output pools. It does not count every feasible vector ever evaluated during optimization. Clean fallbacks do not count. Per-generation feasibility is a separate diagnostic.

`newly_evaded` is the number of initially detected records evaded by the reported method. For in-search variants it is the **standalone** result, so a weaker search can lose an original CAA success. `union_newly_evaded` additionally retains original CAA successes; that union requires both search runs and is not an equal-total-compute attack. End-only methods already retain validated original successes, as in notebook 05.

Already missed records are reported separately. Malicious-subset recall is not full-dataset accuracy. Means and sample standard deviations across seeds describe search variation on the same inputs; they are not population confidence intervals.

- Additional valid evasions at the matched core query budget would support further investigation of repair during search; inspect extra CPU time and end-only scoring cost too.
- Higher feasibility without additional evasion is a feasibility result, not evidence of stronger attacks or improved defense.
- Repeated or clean offspring and lost standalone successes reveal overly conservative repair or reduced search diversity. Preserve that negative result before designing another method.

Any subsequent IDS training experiment still needs its own training procedure, train-only preprocessing, stronger independent evaluation and novelty review. Constraint-valid CTU feature aggregates do not prove packet realizability or preservation of malicious functionality.

## Exported evidence

The ZIP contains a fresh `baseline` run, the new `inloop` comparison, settings, source snapshots, setup/download logs and the pinned asset manifest. The dataset and environment are excluded.

| Output | Meaning |
|---|---|
| `inloop/protocol.json` | Settings, source-baseline hashes, required comparison controls and completion status |
| `inloop/comparison.csv` | Five methods per model/seed: coverage, standalone/union evasion, generation forwards and cost |
| `inloop/seed_summary.csv` | Descriptive seed means and sample standard deviations |
| `<model>/seed_<seed>/<method>/generation_audit.json` | Per-input and per-generation repair/evaluation counts and population digests |
| `.../raw_pool/` | Saved NoAttack, CAPGD and final MOEVA output arrays and their acceptance masks |
| `.../final_results.npz` | Returned, effective standalone and union representatives, predictions and distances |
| `.../records.csv` | Original-record coverage, distinct feasible changes and standalone/union evasion |
| `.../results.json` | Control assertions, original/modified forward counters and detailed results |

If a cell fails, run the final export cell separately and share the partial ZIP and logs. A partial run is not a completed result. Every new session and export has a unique name; the CLI refuses an existing output directory.

## Local execution

```bash
python scripts/bootstrap.py
.baseline-env/bin/python baseline/download_assets.py --assets assets
.baseline-env/bin/python baseline/run_development_repair.py \
  --n-dev 32 --seeds 0 1 2 --steps 10 --generations 100 --offspring 50 \
  --eps 0.5 --out runs/new_inloop_session/baseline
.baseline-env/bin/python baseline/run_inloop_repair.py \
  --baseline-run runs/new_inloop_session/baseline \
  --out runs/new_inloop_session/inloop
```

For a smaller smoke check, explicitly reduce the baseline's records, models, seeds, steps and generations. The in-search runner inherits those settings exactly. Label such results as a smoke experiment.
