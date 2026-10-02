# Notebook 05: development comparison of candidate consistency repair

Open [05_Development_Consistency_Repair.ipynb in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/05_Development_Consistency_Repair.ipynb).

1. Choose a **CPU runtime** and select **Runtime → Run all**.
2. Leave the default settings unchanged for the planned experiment.
3. Keep the session connected while all six original attack runs finish. Progress appears after each model, seed and repair method.
4. Download the new results ZIP at the end and share it for review.

No previous results ZIP needs to be uploaded. The notebook obtains the pinned dataset and checkpoints itself. A fresh checkout downloads approximately 348 MB of feature data plus the small model files, and installs the existing isolated environment. The default workspace is `/content/MyPhDThesis_DevelopmentRepair`. Existing notebooks, workspaces and exports are preserved.

## Research purpose and fixed protocol

The previous audits found very limited coverage of original records by changed, constraint-valid, in-budget candidates. This experiment tests whether a simple conservative repair improves that coverage, and whether the resulting valid changes also increase evasion. Its purpose is to establish a repair baseline and improve attack evaluation before developing the IDS defense.

| Setting | Default |
|---|---|
| Dataset | Pinned CTU-13 Neris aggregate feature records; 757 features |
| Development partition | Official upstream validation split, from rows before native test start 143046 |
| Selection | 32 constraint-valid malicious development records; selection seed 0; no prediction filtering |
| Models | Existing standard RLN and adversarially trained RLN checkpoints |
| Attack seeds | 0, 1, 2 on the same selected records |
| Original attack | Unmodified pinned CAA, including CAPGD and Moeva2 |
| Search budget per model/seed | 10 gradient steps, 100 evolutionary generations, 50 offspring |
| Distance | Original scaled L2 radius 0.5 |
| Relationship tolerance | Original zero tolerance |
| Device | Existing pinned CPU pipeline |

The official splitter uses random state 1319 to divide the original training prefix into 114,436 training rows and 28,610 validation rows. The native 55,082 test rows are excluded from attack selection and model scoring in this notebook. The compatibility scaler still uses all feature rows to match the existing checkpoints; this diagnostic is therefore not a leakage-free final evaluation. The checkpoint training history is inherited, and the validation subset should be treated as development data.

The defaults are fixed before interpreting this experiment. Changes to records, seeds or search budgets define a different development run and are recorded in its protocol. The earlier inspected test subset is not used to tune the repair.

## The three comparisons

| Method | Procedure |
|---|---|
| `original` | Run the original CAA and retain its original outputs and final result. |
| `budget_only` | Basic feature checks and whole-block budget rollback, without a relationship-repair pass. Add validated repaired evasions to the original result. |
| `relation_and_budget` | Basic checks, restoration of blocks that fail relationships, then whole-block budget rollback. Add validated repaired evasions to the original result. |

Each original CAA run is performed **once**. Its exact stage-output arrays are reused by both postprocessors. Repair does not affect upstream generation, optimizer steps, original selection or random-number state. All repairs occur after the original run has finished.

The budget-only control helps distinguish the effect of relationship checks from the effect of discarding large perturbations. The two augmented methods keep valid original evasions. Any improvement in their final evasion count is evaluated along with their extra time and model evaluations; this is a paired-input comparison, not a claim of equal total compute.

## What block rollback does

Mutable features appearing in the same relationship are connected. Transitive connections form dependency blocks, while immutable features are fixed anchors. The pinned CTU rules yield **40 blocks**: two large blocks of 159 features, 36 duration triples, and two `OTHER` packet-count triples. A mutable feature without a relationship would form a singleton block.

For each original record and its candidate population:

1. Restore immutable coordinates to the original record.
2. If a feature violates the upstream bounds or type check, restore its complete dependency block to the original values.
3. In `relation_and_budget`, evaluate each block's upstream relationships at tolerance zero. Restore any failing block in that candidate.
4. Compute block costs in the original scaled L2 geometry. If over budget, restore blocks from greatest cost to least; break ties by feature order. Recheck the exact float32 distance after each rollback rank.
5. Independently recheck every original constraint and the distance budget. Recompute the model prediction for changed feasible candidates, sharing prediction calls only for exact duplicate vectors.

Every output coordinate is either its candidate value or its own original value. The repair uses no class labels, model scores, random choices, new feature values or relaxed thresholds. A final selected representative is checked and scored again; if it cannot provide a valid evasion, the existing validated original CAA result is retained.

This is deliberately a simple, conservative baseline. It can discard useful changes, especially in the large byte/protocol/packet blocks. It is not a nearest feasible projection, an optimal search or a novelty claim. A stronger method can later be compared against it.

## Reading the metrics correctly

The main coverage measure is the number of **distinct original records** for which at least one candidate is changed, valid and within the fixed budget. Coverage is reported for the method's pool and for its union with the original pool. Restoring a candidate completely to its clean original never counts as changed coverage.

New-evasion rate uses only records detected before attack as its denominator. Already missed records are reported separately. Final malicious recall is confined to this selected malicious subset; it is not full-dataset accuracy.

CAA stops searching an input after finding a successful candidate, including a clean input already classified as benign. Such early stopping is preserved. Inspect the initially detected count alongside coverage; the repair never receives later-stage candidates for records already removed by the original selector.

Candidate counts include repeated and unchanged vectors. The export also records exact-vector deduplicated feasible candidate counts per original record. Three attack seeds measure variation of the search on the same selected inputs; their mean and sample standard deviation do not constitute population confidence intervals.

| File | Contents |
|---|---|
| `protocol.json` | Settings, pins, method scope, limitations and completion status |
| `split_manifest.json` | Official split details, selection policy, row IDs and disjointness checks |
| `development_indices.npy` | All official validation row IDs |
| `selected_development_inputs.npz` | Selected originals, labels and row IDs |
| `repair_blocks.json` | Exact feature blocks and upstream relationship indices |
| `comparison.csv` | Model × seed × method coverage, evasion, candidate counts and added cost |
| `seed_summary.csv` | Mean and sample standard deviation across attack seeds |
| `*_development_clean_predictions.csv` | Full validation-partition clean predictions and labels |
| `<model>/seed_<seed>/raw_pool/` | Unchanged stage outputs from the original CAA run |
| `<model>/seed_<seed>/<method>/records.csv` | Record-level coverage, deduplication, final prediction and distance |
| `<model>/seed_<seed>/<method>/<stage>/repaired_candidates.npz` | Repaired arrays, complete acceptance masks, rollback counts and rescored predictions |
| `<model>/seed_<seed>/<method>/final_union.npz` | Final representatives for an augmented method |
| `<model>/seed_<seed>/results.json` | Detailed stage counts, timing and model-forward counts |

In repaired NPZ files, `predicted_class = -1` means an invalid/out-of-budget candidate was not scored. A missing malicious score can also mean a clean fallback reused its known clean prediction. Acceptance always requires the full validity and budget masks. Raw model scores are never reused for a changed repaired candidate.

## Cost and practical limits

The output separates original attack-generation time, repair computation, constraint/distance checking, model scoring and final selection checking. Total added postprocessing time also includes evidence writing and I/O. Main-process forward hooks count both gradient and inference forwards through the model wrapper; these are model-row evaluations, not network requests. Baseline attack time includes the candidate observer and its I/O.

The pinned attack implementation and dependencies remain on CPU, even if a GPU is allocated. Three seeds for both models require six original attack runs, so notebook 05 takes substantially longer than the archive-only notebook 04 audit. These timings are experimental pipeline costs, not server inference latency or a throughput benchmark.

Valid benchmark features are not sufficient to prove that packets can realize them or that malicious functionality is preserved. This work uses recorded feature aggregates and existing classifiers. Later defense training needs train-only preprocessing, suitable independent evaluation data and a frozen protocol.

## How the result informs the next research step

- **Coverage rises and evasion rises:** the repaired pool exposes additional valid weaknesses under this feature-space benchmark. Check the extra computation before claiming an attack advantage.
- **Coverage rises but evasion does not:** repair improves feasibility, but this does not yet demonstrate stronger evasion. Investigate search within consistent feature groups instead of treating coverage as the final research objective.
- **Most candidates revert to clean:** the repair is too conservative for those outputs. Report this openly; unchanged fallbacks do not establish robustness.
- **Neither coverage nor evasion improves:** retain the negative result and reconsider the generation method on development data.

The intended defense contribution comes later: train and evaluate an IDS using suitable valid adversarial examples and compare it with the preserved baselines. This notebook tests the evaluation foundation needed to assess that contribution fairly.

## Local execution and failures

```bash
python scripts/bootstrap.py
.baseline-env/bin/python baseline/download_assets.py --assets assets
.baseline-env/bin/python baseline/run_development_repair.py \
  --n-dev 32 --seeds 0 1 2 --steps 10 --generations 100 --offspring 50 \
  --eps 0.5 --out runs/development_repair_new
```

For an implementation smoke check, explicitly reduce `--n-dev`, `--steps` and `--generations`; label those results as a smaller smoke run. Never overwrite an existing output directory. If a Colab cell fails, run the final export cell separately and share the partial ZIP and logs.
