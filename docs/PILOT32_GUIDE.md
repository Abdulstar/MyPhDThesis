# Next experiment: a paired 32-record robustness pilot

[Open notebook 02 in Google Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/02_Robustness_Pilot_32.ipynb)

1. Open the link above, preferably in a fresh Colab runtime.
2. Choose a **CPU** runtime (hardware accelerator: None). An already allocated GPU runtime can also run this notebook, but its GPU is not used.
3. Leave the default settings unchanged and choose **Runtime → Run all**.
4. Download the results ZIP from the final cell and share it for review.

No code copying, GitHub token or Raspberry Pi is required. Notebook 01 and the previous documents are unchanged. Notebook 02 clones into `/content/MyPhDThesis_Pilot32`, separately from notebook 01's checkout, and creates unique result folders. It does not reset, pull over or delete an existing checkout. For future updates, save your results and use a fresh runtime to obtain the latest code.

## What runs

| Setting | Pilot value |
|---|---|
| Checkpoints | Standard RLN and supplied adversarially trained RLN |
| Clean evaluation | All 55,082 records in the native test partition |
| Attack subset | The same 32 constraint-valid malicious records for both models |
| Selection | Seed 0, independent of either model's predictions |
| Attack | Pinned upstream Constrained Adaptive Attack (CAA) |
| Gradient steps | 10 |
| Evolutionary generations | 10 |
| Offspring | 50 |
| Perturbation budget | L2 radius 0.5 after the compatible feature scaling |
| Device | CPU, two configured PyTorch threads |
| Environment | Isolated Python 3.8.20 and PyTorch 1.12.1+cpu |

The pilot evaluates pretrained checkpoints; it does not train the proposed method. It increases both sample coverage and search effort relative to the eight-record smoke test. Consequently, differences between those runs cannot be attributed to just one of these changes. A later controlled study should hold the selected rows fixed when varying search budgets.

## What the ZIP contains

- Full clean predictions and model metrics, including recall and false-positive rate.
- Selected original CSV row IDs, per-model candidate arrays and row-level attack audits.
- `pilot_diagnostics.csv`: returned changed rows, valid changes, already-missed records, new evasions, detection after attack and attack wall times.
- `pilot_checks.json`: clean reference checks and verification that both models used the same subset.
- Logs, asset hashes, environment/package versions, source snapshots and hardware information.

The large dataset and Python environment are excluded. An optional `SAVE_TO_DRIVE` setting copies the ZIP to `My Drive/MyPhDThesis/results` after authorization. If a run fails, execute the export cell separately and share its partial archive. The notebook's expected reference counts are checks, not results substituted for observed measurements.

## How to read the attack result

**New evasion rate** is newly evaded malicious records divided by the records that the model originally detected in this subset. A record already missed before the attack is not a new success. Invalid or over-budget candidates fall back to the original prediction when scoring.

CAA can return an unchanged original when it finds no acceptable successful candidate. Therefore, 32 valid returned candidates do not mean 32 successful attacks. Use the changed-row and new-evasion counts. Zero new evasions in a small, finite search is not proof of robustness.

This is feature-space evaluation of recorded CTU-Neris aggregates. It is not a test of 32 packets or live requests. A feature-valid change is not necessarily realizable traffic that preserves malicious functionality. The current compatibility scaler follows the upstream all-feature-rows convention; new training comparisons need train-only preprocessing and a separate development/test protocol.

## GPU decision for this stage

Access to a Colab GPU may help later with neural-network training and larger gradient computations. It does not automatically accelerate data parsing, NumPy constraint checks or evolutionary search. This pilot keeps the already verified CPU environment and logs any allocated GPU without claiming to use it.

A source audit of pinned TabularBench commit `bfb75415a6a31a41ddfeef34478eea1da227d19c` found that the CAPGD path constructs `ind_to_fool` on the model device and subsequently passes that tensor to `numpy.setdiff1d`. Direct NumPy conversion of a CUDA tensor requires a CPU transfer. The path also constructs a CPU tensor from `adv1` before indexed assignment. These operations require a CUDA compatibility audit before enabling the complete attack on GPU; changing only `force_device` is insufficient. These are source-level findings, not an observed GPU execution failure in this project.

The model wrapper supports a device choice, and PyTorch offers a CUDA 11.6 build for version 1.12.1. Neither fact establishes that the complete pinned attack works on a particular Colab GPU. No CUDA speedup or CPU/GPU result agreement has been measured here. A future GPU port should use a separately recorded environment, explicit device fixes and paired CPU/GPU checks before being used for thesis comparisons.

Sources:

- [Pinned CAPGD implementation](https://github.com/serval-uni-lu/tabularbench/blob/bfb75415a6a31a41ddfeef34478eea1da227d19c/tabularbench/attacks/capgd/capgd.py#L595-L652)
- [Pinned model device selection](https://github.com/serval-uni-lu/tabularbench/blob/bfb75415a6a31a41ddfeef34478eea1da227d19c/tabularbench/models/torch_models.py#L134-L146)
- [Official PyTorch previous-version installation instructions](https://pytorch.org/get-started/previous-versions/#v1121)

## Command-line equivalent

After the existing setup and downloads, choose a new output path:

```bash
.baseline-env/bin/python baseline/run_baseline.py --out runs/pilot32_new_run --attack --n-attack 32 --steps 10 --generations 10 --offspring 50 --eps 0.5 --seed 0
.baseline-env/bin/python scripts/summarize_results.py runs/pilot32_new_run
```

The notebook adds provenance, returned-change diagnostics and ZIP export around these commands. Its settings intentionally stop at the bounded pilot; the full 407-record, larger-budget run is not started automatically.

## Validation before publication

All six default notebook code cells were executed locally in one Python 3.12 namespace using the pinned Python 3.8 CPU environment. Both clean confusion matrices matched the reference, both models attacked the same 32 selected rows, and the exported archive passed its integrity check. Each model returned unchanged rows with zero new evasions at this budget. This validates execution, not a robustness claim.

The local run reused downloaded assets and an installed environment. Hosted Colab, its browser download callback and optional Drive authorization were not exercised in this test; no GPU was available. The existing notebook 01 had already been run successfully by the user on hosted Colab. Exact settings, source hashes, timings and limitations for this new local test are in [the pilot validation record](../reference_results/pilot32_local_validation_2026-09-29.json).
