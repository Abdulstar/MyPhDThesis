"""Metrics with explicit denominators; independent of TabularBench."""
import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score


def clean_metrics(y, probabilities):
    prediction = probabilities.argmax(axis=1)
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    return {
        "n": int(len(y)), "benign": int(tn + fp), "malicious": int(tp + fn),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "accuracy": float((tp + tn) / len(y)),
        "recall": float(tp / (tp + fn)),
        "false_positive_rate": float(fp / (tn + fp)),
        "precision": float(tp / (tp + fp)) if tp + fp else 0.0,
        "auroc_positive_class": float(roc_auc_score(y, probabilities[:, 1])),
        "auroc_upstream_two_column_macro": float(roc_auc_score(np.eye(2)[y], probabilities)),
        "average_precision": float(average_precision_score(y, probabilities[:, 1])),
        "majority_class_accuracy": float((tn + fp) / len(y)),
    }


def select_malicious(y, clean_valid, n, seed):
    eligible = np.flatnonzero((y == 1) & clean_valid)
    if not len(eligible):
        raise ValueError("No constraint-valid malicious test records.")
    if n > 0 and n < len(eligible):
        eligible = np.random.RandomState(seed).choice(eligible, n, replace=False)
    return np.sort(eligible)


def attack_metrics(clean_predictions, adversarial_predictions, valid, distance_ok):
    """All selected records have true label 1. Invalid candidates fall back to clean."""
    accepted = valid & distance_ok
    final = np.where(accepted, adversarial_predictions, clean_predictions)
    initially_detected = clean_predictions == 1
    newly_evaded = initially_detected & (final == 0)
    return {
        "n_malicious_attacked": int(len(final)),
        "clean_detected": int(initially_detected.sum()),
        "already_missed_before_attack": int((~initially_detected).sum()),
        "returned_candidates_valid_and_in_budget": int(accepted.sum()),
        "newly_evaded": int(newly_evaded.sum()),
        "new_evasion_rate_among_initially_detected": float(newly_evaded.sum() / initially_detected.sum()) if initially_detected.any() else None,
        "malicious_recall_after_attack": float((final == 1).mean()),
        "clean_recall_on_same_subset": float(initially_detected.mean()),
    }
