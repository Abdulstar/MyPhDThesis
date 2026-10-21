# Notebook 09b — Colab environment setup fix

Use [Notebook 09b in Colab](https://colab.research.google.com/github/Abdulstar/MyPhDThesis/blob/main/notebooks/09b_Measurement_Semantics_Colab_Fix.ipynb). Select a **CPU runtime**, choose **Runtime → Run all**, and upload the same completed **Notebook 08 results ZIP**. Share the new ZIP downloaded at the end.

The error reported in the first Notebook 09 was in `venv`'s `ensurepip` step, before the data audit started. The traceback identifies the failing step but does not establish the underlying cause inside `ensurepip`. The local validation environment supported that step; it did not reproduce the Colab failure.

The new setup explicitly creates a virtual environment with `with_pip=False`. The existing notebook interpreter's pip then installs the unchanged audit requirements into the new interpreter using `--python`. This is a [documented pip workflow for environments without pip](https://pip.pypa.io/en/stable/topics/python-option/) and avoids invoking `ensurepip`. The host needs pip 22.3 or newer, checked before installation.

The bootstrap verifies the new environment's prefix, dependency versions, dependency consistency, and that NumPy and pandas load from that environment. It does not install or upgrade packages in the notebook kernel. Python 3.11–3.13 and the existing NumPy 2.3.5 / pandas 2.2.3 requirements are retained.

Each setup-cell attempt uses a new environment folder and setup report. If a log name already exists, a uniquely named log is created. A failed or partially created earlier environment is preserved. Earlier notebooks, guides, results, and the research protocol are unchanged.

Three focused regression tests reproduce a blocked `ensurepip` setup, show that the new creation method works while that step is blocked, and verify that existing environment folders are not overwritten. The six existing measurement-semantics tests also run. The new notebook's local validation includes dependency installation into the pip-free environment, the full audit, and results ZIP export. This is local validation, not a claim that a remote Colab session was executed.

The scientific procedure remains the same as [Notebook 09's audit guide](MEASUREMENT_SEMANTICS_GUIDE.md): investigate the packet-count ambiguity, verify the source-table match, audit 143,046 train/development rows, and prepare 128 additional development inputs. No attack, model, threshold or validity rule is changed. The larger attack experiment is not executed by this notebook.

Open the **09b** link above rather than rerunning the old setup cell. Upload the completed 08 results, not a partial 09 export. A successful run reports `status: completed`; `packet_duration_rule_adopted: false` remains the intended research decision.
