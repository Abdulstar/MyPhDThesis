# My PhD Thesis — Proposal A

**Capability Aware Adversarial Training for Network Intrusion Detection**

[![Open the baseline in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/01_Baseline_Reproduction.ipynb)

## Start here

1. Click **Open in Colab** above.
2. Connect to a **CPU** runtime (hardware accelerator: None).
3. Choose **Runtime → Run all**, or run the cells from top to bottom.
4. Review the two-model comparison and download the results ZIP from the last cell.

No GitHub token, Raspberry Pi or GPU is needed for this public-repository baseline. The notebook installs a separate Python **3.8.20** environment with CPU PyTorch **1.12.1**, so it does not replace Colab's notebook interpreter or its scientific packages. Setup takes longer than subsequent inference runs.

The default notebook downloads about 348 MB of CTU-13 Neris features and two small pretrained RLN checkpoints. It evaluates the native test partition and runs an eight-record constrained-attack smoke test. Larger attack runs are **off by default**.

## Expected clean baseline

Previously verified on Linux CPU, before this Colab integration; these are reference measurements, not a new defense result.

| Model | Accuracy | Malicious detected | False alarms |
|---|---:|---:|---:|
| Standard RLN | 99.8239% | 398 / 407 | 88 / 54,675 |
| Adversarially trained RLN | 99.9038% | 396 / 407 | 42 / 54,675 |

Test data: 55,082 records, including 407 malicious records. The reference JSON is in [`reference_results/`](reference_results/). An always-benign classifier scores 99.2611% accuracy here; compare recall and false-positive rate as well as accuracy.

## Research interpretation

This first milestone verifies checkpoint behavior on the **recorded CTU feature representation**. It does not replay packets or establish real-world IDS performance. Numerical feature constraints do not prove that a host can realize a perturbation while preserving its malicious purpose.

The checkpoint loader follows upstream's all-data feature-scaling convention for compatibility. Before comparing a new training method, establish train-only preprocessing, separate development/calibration data and a sealed test set. The source audit also documents an upstream selection-argument mismatch that this runner bypasses by explicitly selecting malicious records.

The default eight-record attack run is a software smoke test. In the original reference run it found no new evasions and returned unchanged inputs; this does not establish robustness. The repository's full published constrained-attack scores have not yet been reproduced.

See [the Colab guide](docs/COLAB_GUIDE.md), [research plan](docs/NEXT_EXPERIMENTS.md), [source audit](docs/SOURCE_AUDIT_2026-09-29.md) and [validation record](docs/VALIDATION.md).

## Results and persistence

Each notebook session creates a new timestamped experiment folder. Individual runs also use unique names, preserving previous results. The final cell packages the results, provenance and executed script snapshot for download. An optional checkbox copies the ZIP to `My Drive/MyPhDThesis/results` after you authorize a Drive mount.

Colab runtime files are temporary. Saving the notebook to GitHub does not save its downloaded assets, environment or experiment outputs. Download or copy the results ZIP before the runtime ends. GitHub stores code and small reference results; large downloads and generated runs are excluded by `.gitignore`.

## Local Linux alternative

From the repository root:

```bash
python3 scripts/bootstrap.py
.baseline-env/bin/python baseline/download_assets.py
.baseline-env/bin/python baseline/run_baseline.py --out runs/my_first_clean_run
.baseline-env/bin/python baseline/run_baseline.py --out runs/my_first_smoke_run --attack --n-attack 8
```

Use a new output path for every run. Approximately 4.7 GiB peak main-process RAM was measured in the original baseline; allow additional memory for worker processes and the notebook.

## Sources

- [TabularBench (2024)](https://arxiv.org/abs/2408.07579)
- [Constrained Adaptive Attack (2024)](https://arxiv.org/abs/2406.00775)
- [Upstream code](https://github.com/serval-uni-lu/tabularbench)
- [Dataset](https://huggingface.co/datasets/serval-uni-lu/tabularbench)
- [Pretrained models](https://huggingface.co/serval-uni-lu/tabularbench)
- [Official Colab FAQ](https://research.google.com/colaboratory/faq.html)

Upstream code, dataset and model revisions are pinned in `baseline/download_assets.py`; individual asset hashes are in `baseline/asset_hashes.json`. Source downloads retain their respective upstream licenses. RLN is an existing architecture supplied by the benchmark, not a model introduced by this thesis.
