"""Versioned aggregate/endpoint checks and conservative block rollback.

The added checks are necessary feature conditions, not traffic-realizability
proofs. Native constraints and their zero tolerance are preserved.
"""
import json
from pathlib import Path

import numpy as np

from consistency_repair import BlockRollbackRepair


class ConnectionProfile:
    def __init__(self, names, config=None):
        self.config = config or json.loads(Path(__file__).with_name("connection_profile_v1.json").read_text())
        self.names = list(names)
        pos = {n: i for i, n in enumerate(names)}
        if len(pos) != len(names):
            raise ValueError("Duplicate feature names")
        self.aggregate, self.presence = [], []
        for metric in self.config["metrics"]:
            for direction in self.config["directions"]:
                for port in self.config["ports"]:
                    suffix = "_" + direction + "_" + port
                    self.aggregate.append((pos[metric + "_sum" + suffix], pos[metric + "_max" + suffix]))
        for direction in self.config["directions"]:
            for port in self.config["ports"]:
                suffix = "_" + direction + "_" + port
                for family in ("distinct_external_ips", "distinct_src_port", "distinct_dst_port"):
                    self.presence.append((pos["duration_sum" + suffix], pos[family + suffix]))
        if len(self.aggregate) != self.config["aggregate_pairs"] or len(self.presence) != self.config["duration_endpoint_pairs"]:
            raise ValueError("Profile feature schema mismatch")

    def failures(self, x):
        def check(pairs):
            return ((x[..., [a for a, b in pairs]] > 0)
                    & (x[..., [b for a, b in pairs]] == 0))
        return {"aggregate": check(self.aggregate), "presence": check(self.presence)}

    def ok(self, x):
        parts = self.failures(x)
        return ~parts["aggregate"].any(axis=-1) & ~parts["presence"].any(axis=-1)

    def catalog(self):
        return [{"family": family, "positive_feature": self.names[a], "required_positive_feature": self.names[b]}
                for family, pairs in [("aggregate", self.aggregate), ("presence", self.presence)] for a, b in pairs]


class ConnectionRollback(BlockRollbackRepair):
    def __init__(self, constraints, preprocess, epsilon, profile):
        super().__init__(constraints, preprocess, epsilon)
        self.profile = profile
        owner = {int(f): b for b, block in enumerate(self.blocks) for f in block}
        self.rule_blocks = []
        for a, b in profile.aggregate + profile.presence:
            blocks = sorted({owner[i] for i in (a, b) if self.mutable[i]})
            # In this CTU schema each implication touches at most one native
            # mutable component. Future schemas need an explicit merged graph.
            if len(blocks) > 1:
                raise ValueError("Added rule spans native blocks; merge dependencies before using this schema")
            self.rule_blocks.append(blocks[0] if blocks else -1)
        self.last_profile_audit = None

    def repair_population(self, clean, candidates, repair_relations=True):
        if not self.profile.ok(clean).all():
            raise ValueError("Own original violates the fixed profile; do not silently replace or filter it")
        work, audit = super().repair_population(clean, candidates, repair_relations)
        parts = self.profile.failures(work)
        failed = np.concatenate([parts["aggregate"], parts["presence"]], axis=-1)
        restored = np.zeros(len(work), dtype=np.int32)
        for block_id in sorted(set(self.rule_blocks)):
            selected_rules = np.flatnonzero(np.asarray(self.rule_blocks) == block_id)
            bad = np.flatnonzero(failed[:, selected_rules].any(axis=1))
            if not len(bad):
                continue
            if block_id < 0:
                raise ValueError("Immutable-only added condition failed after immutable restoration")
            block = self.blocks[block_id]
            work[np.ix_(bad, block)] = clean[:, block]
            restored[bad] += 1
        if not self.profile.ok(work).all():
            raise AssertionError("Added-profile rollback did not establish the fixed conditions")
        distance = np.linalg.norm(self.preprocess(work) - self.preprocess(clean), axis=1)
        if np.any(distance > self.epsilon):
            raise AssertionError("Profile rollback exceeded the fixed budget")
        if not np.all((work == candidates) | (work == clean)):
            raise AssertionError("Repair invented feature values")
        audit.update(profile_blocks_restored=restored,
            aggregate_failures_before_profile=parts["aggregate"].sum(axis=-1),
            presence_failures_before_profile=parts["presence"].sum(axis=-1),
            changed_vs_raw=np.any(work != candidates, axis=1),
            changed_vs_clean=np.any(work != clean, axis=1), distance_after_profile=distance)
        self.last_profile_audit = audit
        return work, audit


def observe_profile_selector(calculator, trace, profile):
    """Keep native cached masks; add a gate before CAA accepts a stage output."""
    from tabularbench.attacks.objective_calculator import select_k_best
    original = calculator.get_successful_attacks_indexes
    selector_rows = []

    def observed(x_clean, y_clean, x_adv, *args, **kwargs):
        original(x_clean, y_clean, x_adv, *args, **kwargs)
        metric_name = kwargs.get("preferred_metrics", args[0] if args else "misclassification")
        order = kwargs.get("order", args[1] if len(args) > 1 else "asc")
        count = kwargs.get("max_inputs", args[2] if len(args) > 2 else -1)
        count = x_adv.shape[1] if count == -1 else count
        metric = getattr(calculator.objectives_eval, metric_name)
        if order == "desc":
            metric = -metric
        added_ok = profile.ok(x_adv)
        native = calculator.objectives_respected.mdc
        selected = select_k_best(metric, native & added_ok, count)
        selector_rows.append({"stage_index": len(selector_rows), "inputs": len(x_clean),
            "native_success_candidates": int(native.sum()),
            "profile_success_candidates": int((native & added_ok).sum()),
            "selected_input_indices": selected[0].tolist(), "selected_candidate_indices": selected[1].tolist()})
        trace.record(x_clean, y_clean, x_adv, calculator.objectives_eval, calculator.objectives_respected, selected)
        return selected

    calculator.get_successful_attacks_indexes = observed
    return selector_rows
