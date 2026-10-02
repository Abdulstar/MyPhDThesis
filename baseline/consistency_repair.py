"""Conservative block rollback for a paired, feature-space attack experiment.

Each output coordinate is either the proposed value or its own clean value.
No model scores, labels, random draws or threshold changes enter the repair.
This is a simple repair baseline, not an optimal projection or novelty claim.
"""
import numpy as np

from relationship_audit import feature_ids


class BlockRollbackRepair:
    def __init__(self, constraints, preprocess, epsilon):
        from tabularbench.constraints.constraints import get_feature_min_max
        from tabularbench.constraints.constraints_backend_executor import ConstraintsExecutor
        from tabularbench.constraints.numpy_backend import NumpyBackend
        from tabularbench.constraints.relation_constraint import AndConstraint
        self.constraints = constraints
        self.preprocess = preprocess
        self.epsilon = float(epsilon)
        if self.epsilon <= 0:
            raise ValueError("epsilon must be positive")
        self.feature_min_max = get_feature_min_max
        self.names = list(constraints.feature_names)
        self.mutable = np.asarray(constraints.mutable_features, dtype=bool)
        self.integer = np.asarray(constraints.feature_types) != "real"
        position = {name: i for i, name in enumerate(self.names)}
        parent = list(range(len(self.names)))

        def find(a):
            while parent[a] != a:
                parent[a] = parent[parent[a]]
                a = parent[a]
            return a

        rule_features = []
        for rule in constraints.relation_constraints:
            ids = [position[f] if isinstance(f, str) else int(f) for f in feature_ids(rule)]
            ids = sorted(set(i for i in ids if self.mutable[i]))
            rule_features.append(ids)
            for i in ids[1:]:
                parent[find(i)] = find(ids[0])
        components = {}
        for i in np.flatnonzero(self.mutable):
            components.setdefault(find(int(i)), []).append(int(i))
        self.blocks = [np.asarray(ids, dtype=int) for ids in sorted(components.values(), key=lambda a: a[0])]
        owner = {int(f): b for b, block in enumerate(self.blocks) for f in block}
        self.block_rules = [[] for _ in self.blocks]
        self.immutable_only_rules = []
        for j, ids in enumerate(rule_features):
            if ids:
                assert len({owner[i] for i in ids}) == 1
                self.block_rules[owner[ids[0]]].append(j)
            else:
                self.immutable_only_rules.append(j)
        self.executors = []
        for ids in self.block_rules:
            rules = [constraints.relation_constraints[j] for j in ids]
            node = AndConstraint(rules) if len(rules) > 1 else (rules[0] if rules else None)
            self.executors.append(None if node is None else ConstraintsExecutor(node, NumpyBackend(), self.names))

    def description(self):
        return {
            "algorithm": "restore dependency blocks to their own clean values",
            "relationship_tolerance": 0.0,
            "budget_order": "descending original block squared scaled L2 cost; feature-order tie break",
            "budget_recheck": "exact float32 scaled L2 after each rollback rank",
            "model_scores_used_by_repair": False,
            "blocks": [{"block_id": b, "features": [self.names[i] for i in block],
                        "rule_indices_zero_based": self.block_rules[b]} for b, block in enumerate(self.blocks)],
            "immutable_only_rule_indices": self.immutable_only_rules,
        }

    def repair_population(self, clean, candidates, repair_relations=True):
        """One original [1,F] and its population [K,F]; inputs are never mutated.

        Requires a separable numeric scaler preserving feature order, as in the
        pinned all-numeric CTU min-max scaler. Final acceptance is the caller's
        unchanged upstream checker plus the original scaled L2 budget.
        """
        original = np.asarray(clean)
        proposed = np.asarray(candidates)
        if original.shape != (1, len(self.names)) or proposed.ndim != 2 or proposed.shape[1] != len(self.names):
            raise ValueError("Expected one original and its candidate population")
        if original.dtype != np.float32 or proposed.dtype != np.float32:
            raise ValueError("Use the saved/native float32 feature representation")
        if not np.isfinite(original).all() or not np.isfinite(proposed).all():
            raise ValueError("Nonfinite source values; do not silently repair an invalid run")
        work = proposed.copy()
        k = len(work)
        audit = {name: np.zeros(k, dtype=np.int32) for name in
                 ["immutable_features_restored", "basic_blocks_restored", "relation_blocks_restored", "budget_blocks_restored"]}
        audit["immutable_features_restored"] = (work[:, ~self.mutable] != original[:, ~self.mutable]).sum(1)
        work[:, ~self.mutable] = original[:, ~self.mutable]
        low, high = self.feature_min_max(self.constraints, original)
        tiny = np.finfo(np.float32).eps
        bad_features = (work < low - tiny) | (work > high + tiny)
        bad_features[:, self.integer] |= work[:, self.integer] != np.round(work[:, self.integer])
        for b, block in enumerate(self.blocks):
            bad = np.flatnonzero(bad_features[:, block].any(1))
            if len(bad):
                work[np.ix_(bad, block)] = original[:, block]
                audit["basic_blocks_restored"][bad] += 1
        if repair_relations:
            for block, executor in zip(self.blocks, self.executors):
                if executor is None:
                    continue
                residual = np.asarray(executor.execute(work))
                bad = np.flatnonzero((residual > 0) | ~np.isfinite(residual))
                if len(bad):
                    work[np.ix_(bad, block)] = original[:, block]
                    audit["relation_blocks_restored"][bad] += 1

        transformed_original = np.asarray(self.preprocess(original))
        delta = np.asarray(self.preprocess(work)) - transformed_original
        if delta.shape != work.shape or delta.dtype != np.float32:
            raise ValueError("Repair requires the pinned separable float32 numeric geometry")
        audit["distance_before_budget"] = np.linalg.norm(delta, axis=1)
        if self.blocks:
            costs = np.stack([np.sum(delta[:, block].astype(np.float64)**2, axis=1) for block in self.blocks], axis=1)
            order = np.argsort(-costs, axis=1, kind="stable")
            for rank in range(len(self.blocks)):
                over = np.linalg.norm(delta, axis=1) > self.epsilon
                if not over.any():
                    break
                for b in np.unique(order[over, rank]):
                    selected = np.flatnonzero(over & (order[:, rank] == b))
                    block = self.blocks[int(b)]
                    work[np.ix_(selected, block)] = original[:, block]
                    delta[np.ix_(selected, block)] = 0
                    audit["budget_blocks_restored"][selected] += 1
        distance = np.linalg.norm(np.asarray(self.preprocess(work)) - transformed_original, axis=1)
        if np.any(distance > self.epsilon):
            raise AssertionError("Rollback failed to satisfy the fixed distance budget")
        np.testing.assert_array_equal(distance, np.linalg.norm(delta, axis=1))
        if not np.all((work == proposed) | (work == original)):
            raise AssertionError("Rollback introduced a value other than original or proposed")
        audit["distance_after_budget"] = distance
        audit["changed_vs_raw"] = np.any(work != proposed, axis=1)
        audit["changed_vs_clean"] = np.any(work != original, axis=1)
        return work, audit


def pool_summary(changed, valid, within, fooled):
    """Counts candidates; coverage and evasion denominators stay record based."""
    changed, valid, within, fooled = [np.asarray(a, dtype=bool) for a in (changed, valid, within, fooled)]
    feasible_change = changed & valid & within
    success = valid & within & fooled
    return {
        "candidates": int(valid.size), "changed_candidates": int(changed.sum()),
        "unchanged_candidates": int((~changed).sum()), "invalid_candidates": int((~valid).sum()),
        "over_budget_candidates": int((~within).sum()),
        "changed_valid_in_budget": int(feasible_change.sum()),
        "successful_candidates": int(success.sum()),
    }, feasible_change.any(1), success.any(1)
