# Run the baseline in Google Colab

1. Open [01_Baseline_Reproduction.ipynb](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/01_Baseline_Reproduction.ipynb).
2. Connect to a CPU runtime. If you selected a GPU, change the hardware accelerator to **None**; this first notebook deliberately uses CPU.
3. Leave the initial settings unchanged: clean evaluation and an eight-record smoke test are enabled; full-budget evaluation and Google Drive mounting are disabled.
4. Run cells top to bottom, or choose **Runtime → Run all**.
5. Read the clean-score table, confusion matrices and attack audit.
6. Download the ZIP produced by the last cell. Optionally enable `SAVE_TO_DRIVE` and authorize a Drive mount to copy the ZIP to `My Drive/MyPhDThesis/results`.

## What each stage does

| Stage | Operation | Output |
|---|---|---|
| Project | Clone the public repository, or preserve an existing checkout | Commit, source hashes, new experiment folder |
| Setup | Install a separate Python 3.8.20 CPU environment | Pinned dependency versions and setup log |
| Download | Retrieve the exact dataset and two checkpoints | SHA-256-verified files and manifest |
| Clean evaluation | Score all 55,082 native test records | Predictions, confusion matrices, recall, false alarms and accuracy |
| Smoke test | Run CAA on eight malicious records for each model | Candidate validity, scaled distances and new evasion counts |
| Export | Archive this session's outputs and source snapshot | Downloadable ZIP, optional Drive copy |

The notebook's Python controls the experiment and displays results. Baseline scripts run through `.baseline-env/bin/python`; installing PyTorch 1.12 directly into a current Colab notebook is unnecessary. No runtime restart is required.

## Reading the results

- **Recall:** detected malicious records / malicious records.
- **False-positive rate:** false alarms / benign records.
- **New evasion rate:** accepted new evasions / initially detected malicious records in the attack subset.
- **Attack recall:** detection after accepted perturbations, using the original prediction if a returned candidate is invalid or over budget.

The clean reference is 398/407 detected and 88 false alarms for standard RLN, versus 396/407 detected and 42 false alarms for adversarially trained RLN. These are default decision-rule results, not a comparison at a common false-positive target.

The eight-record check originally returned no new evasions. An unchanged input can be a valid returned candidate; this does not mean a successful nonzero attack was generated or that the model is robust. Use the candidate audits and explicit denominators.

The checkpoint compatibility scaler uses all feature rows, matching the audited upstream loader. New training comparisons must use a separately designed protocol with train-only preprocessing and development-only model/threshold selection.

## Working in later sessions

Colab runtime storage is temporary. Every fresh runtime needs setup and downloads again. In the same runtime, cached code, packages and valid assets are reused. Each run gets a fresh output directory, including when you repeat a cell. The notebook does not automatically reset or update an existing checkout, preserving any edits; the session records its commit and working-tree status.

To use newly published GitHub code after editing, save your results first and start in a fresh Colab runtime. Your notebook copy and the repository checkout are separate: the notebook imports the code cloned into `/content/MyPhDThesis`.

## Troubleshooting

| Symptom | Action |
|---|---|
| Network timeout during setup/download | Rerun the failed cell; completed assets are hash-checked and reused. An incomplete `.part` download restarts. |
| Dataset hash mismatch | Preserve the suspect file under another name, then rerun the download cell. Do not disable hash checks. |
| RAM exhaustion | Close other large notebooks/processes or use a runtime with more available RAM. The original main process used about 4.7 GiB plus worker/kernel overhead. |
| Baseline count mismatch | Keep the logs and check dataset hashes, code revision, feature order and preprocessing; do not tune on test labels. |
| Download does not start | Open Colab's Files panel and download the ZIP from `/content/MyPhDThesis/exports`. |
| Runtime disconnected | Restore code from GitHub and rerun. Outputs survive only if downloaded or copied to Drive. |
| Existing output directory from the CLI | Give `--out` a new path. The notebook does this automatically. |
| GitHub repository becomes private later | This public-clone workflow will need explicit authentication; do not put a token into the notebook or repository. |

## Optional larger evaluation

After verifying the baseline, change `RUN_FULL_BUDGET` to true in cell 1 and run the notebook again. That run uses all eligible malicious records and the larger search settings. Its runtime has not been established. The result needs a protocol audit before it can be called a reproduction of the published constrained-attack score.

Sources: [Colab FAQ](https://research.google.com/colaboratory/faq.html), [uv Python management](https://docs.astral.sh/uv/guides/install-python/), [TabularBench](https://github.com/serval-uni-lu/tabularbench).
