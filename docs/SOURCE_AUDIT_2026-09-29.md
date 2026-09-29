# Source audit and reproduction choices

Historical audit from the 29 September starter pack. In this repository, the same baseline scripts live under `baseline/`; current installation and notebook validation are documented in `COLAB_GUIDE.md` and `VALIDATION.md`. Mentions of the original ZIP and its runs describe the earlier artifact.

Checked 29 September 2026. Findings apply to code commit `bfb75415a6a31a41ddfeef34478eea1da227d19c`, not necessarily to the exact code used for every published experiment.

## Asset loading

`tabularbench/datasets/samples/ctu_13_neris.py` points to dataset paths under `ctu_13_neris/`. At the pinned Hugging Face dataset revision, the actual directory is `ctu_13/`. `download_assets.py` retrieves the observed paths directly. The model repository uses `ctu_13_neris/`, which is retained for model downloads.

Upstream `requirements.txt` lacks `huggingface-hub`, although the project imports it and `pyproject.toml` lists it. The tested lock includes `huggingface-hub==0.26.2`.

No arbitrary repository-wide model download is needed. This pack uses only two `args.json` files and two `weights.pt` files.

## Attack selection

`benchmark/subset_utils.py` declares the arguments after `model` as `filter_correct, filter_class`. `benchmark/benchmark.py` passes `bms.filter_class, bms.filter_correct` positionally. With defaults 1 and False, the called function treats the request as “correctly classified records of class False/0.” This differs from an intended malicious-class evasion evaluation.

The starter runner selects `y_test == 1` explicitly and records every selected CSV row index. It checks original records against the complete metadata constraints and uses the same selection for both models, independent of predictions. All 407 malicious records passed these checks in the verified run. The upstream helper's relationship-only filter and its pandas indexing branch are bypassed.

This observed code-path issue is not evidence that the published table was produced by this helper call.

## Preprocessing, split and checkpoint compatibility

`benchmark/benchmark.py` fits its scaler on all feature rows. The two selected checkpoint folders do not include a separate scaler JSON. The starter runner therefore follows the all-data fitting convention to check supplied checkpoint behavior. It removes only `is_botnet`, preserves feature order and fits a min-max TabScaler on float32 inputs.

The native CTU splitter assigns CSV rows from zero-based index 143046 onward to test, with the earlier rows partitioned into training and validation. The starter evaluates the entire native test section. It does not invent a temporal or independent-session interpretation of this row cut.

`tasks/train_model.py` fits a scaler on all rows and supplies `x_test, y_test` to `model.fit` as validation inputs. Do not use this helper unchanged for new claims about held-out performance. New controlled comparisons require train-only preprocessing, development-only fitting/selection/calibration and a sealed test set.

The checkpoint-compatibility run includes `window_timestamp`, exactly as the current representation does. Its scientific suitability must be checked separately in the research protocol.

## Constraint semantics

The runner imports the original CTU relationship constraints and metadata bounds/types/mutability. It adds no new timing, padding or host-operation assumptions. `get_constraints_from_metadata` reads `min`, `max`, `type` and `mutable`; separate `dyn_min`/`dyn_max` columns are not applied by that function at this revision. Do not equate those unused flags with enforced operational restrictions.

Validity is evaluated at tolerance 0 using the upstream checker (including its built-in floating-point allowance for bounds). Distances are L2 after the fitted scaler. Invalid or over-budget final candidates cannot count as new evasions.

The original CAA implementation, its CAPGD/MOEVA components and its model interface are unchanged. Thread/process limits and `n_jobs=1` keep the pilot manageable on a CPU. Numerical feature validity does not demonstrate realizable packets or preservation of a malicious objective.

## Metric conventions

Clean predictions use the checkpoint's class-score argmax, matching the upstream decision rule. No threshold is selected on test labels.

The upstream metric path one-hot encodes labels and passes both predicted class columns to `roc_auc_score`, which averages the per-column AUCs. The conventional binary positive-class AUC can differ because float32 softmax saturation creates different ties in the two columns. The runner reports both conventions explicitly.

Both checkpoint runs match these repository table values to its printed precision:

| Model | Accuracy | Precision | Recall | Two-column macro AUC |
|---|---:|---:|---:|---:|
| Standard RLN | 0.998239 | 0.818930 | 0.977887 | 0.990569 |
| Adversarially trained RLN | 0.999038 | 0.904110 | 0.972973 | 0.989847 |

`1 - mdc` is stored with an explicit malicious-subset name, not described as full-test accuracy. Already missed malicious examples are separated from new evasion among initially detected examples. Final returned-candidate validity is not internal proposal yield.

## Execution status

Executed: full native clean evaluation for both checkpoints; eight-record CAA smoke test for both; three focused selection/metric tests; Python compilation and shell syntax checks. The second verified run also records main-process peak RSS and wall time. `setup_cpu.sh` assembles the same installation commands used here; the packaged bootstrap itself was syntax-checked, not re-executed in a second clean machine.

Not executed: the 32-record expanded pilot, the all-malicious full-budget command, model retraining, any new defense, live traffic generation, cross-dataset testing or multiple-seed statistical evaluation. A small smoke test with zero evasions cannot establish robustness.

The ZIP contains the final verified run only. Earlier intermediate runs were retained in the working area but are not needed to reproduce this final pack.
