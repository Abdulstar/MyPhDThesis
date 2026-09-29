# Research milestones after the notebook works

Direction: **Capability Aware Adversarial Training for Network Intrusion Detection**.

## Milestone 1 — establish the baseline

Reproduce the supplied checkpoints' clean confusion matrices, then expand constrained-attack evaluation. Record sample IDs, valid-candidate counts, budgets and seeds. Reconcile the original sampling, repetitions and aggregation before claiming reproduction of the paper's robust result.

The current notebook completes the clean check and the small execution test. It does not train a new defense.

## Milestone 2 — define the research protocol

1. Separate fitting, development/threshold calibration and final testing; group related records where supported by provenance.
2. Fit preprocessing on training data only. Preserve the original checkpoint-compatibility experiment as a separate reference.
3. Investigate the timestamp feature's shortcut potential with an explicit ablation and appropriate split. The native row cut alone does not prove temporal independence.
4. Predeclare a false-positive target and choose thresholds on development data, then report actual test false-positive rate.
5. Retain one neural backbone for controlled training comparisons. Later add a tree reference and additional compatible data setting.

## Three linked studies

| Research question | Objective and your implementation work | Intended evidence |
|---|---|---|
| RQ1: How do robustness estimates and defense rankings change across attacker capabilities and budgets? | Define supported actions, recompute dependent features, check validity and measure both defenses under the same scenarios. | A new characterization of capability sensitivity with justified assumptions. |
| RQ2: Can capability-aware training improve the weakest-group detection rate while meeting a predefined false-alarm target? | Implement the proposed weighting/benign-protection rule and compare it with clean training, standard adversarial training, uniform mixing, worst-example training and group DRO. | Matched-compute comparisons, adaptive evaluation, multiple training seeds and ablations that isolate the proposed mechanism. |
| RQ3: How does protection transfer to capability combinations and budgets absent from training? | Hold out conditions, freeze model-selection rules and thresholds, and compare source-only selection criteria. | Evidence explaining transfer conditions and limits, later confirmed in a second compatible setting. |

Adaptive weighting and group DRO are established approaches. A novel contribution is not guaranteed by adding weights or obtaining a small accuracy increase. The method needs a distinct, justified mechanism or substantial new finding that survives fair comparisons.

Start capability development with one demonstrably supported operation family, such as bounded timing changes. Map an operation to actual feature dependencies before implementing it. Feature-valid perturbations, realizable traffic and host actions preserving malicious function are different evidence levels. Label results accordingly.

Your research outputs are the protocol/findings, learning method and transfer analysis. The notebook supports reproducible experiments; it is not itself the thesis contribution.
