"""Paired development-only comparison of CAA with conservative block rollback.

The attack runs once per model/seed. Two postprocessors share its exact saved
stage-output pool. No repair influences upstream generation or CAA selection.
"""
import os
for _key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "LOKY_MAX_CPU_COUNT"):
    os.environ[_key] = "2"

import argparse
import gc
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import torch

from candidate_trace import CandidateTrace, observe_selector
from consistency_repair import BlockRollbackRepair, pool_summary
from download_assets import CODE_REVISION, DATA_REVISION, MODEL_REVISION, sha256
from metrics import attack_metrics, clean_metrics
from relationship_audit import write_csv, write_json


class ForwardCounter:
    """Count main-process wrapper forwards, including gradient attack forwards."""
    def __init__(self, model):
        self.counts = {k: 0 for k in ["forward_calls", "forward_rows", "grad_enabled_forward_calls", "grad_enabled_forward_rows"]}
        self.handle = model.register_forward_pre_hook(self.record)

    def record(self, module, args):
        rows = int(args[0].shape[0])
        self.counts["forward_calls"] += 1
        self.counts["forward_rows"] += rows
        if torch.is_grad_enabled():
            self.counts["grad_enabled_forward_calls"] += 1
            self.counts["grad_enabled_forward_rows"] += rows

    def snapshot(self):
        return dict(self.counts)

    def since(self, before):
        return {k: v - before[k] for k, v in self.counts.items()}


def measured_pool(clean, population, checker, scaler, epsilon):
    parts = {k: [] for k in ["relation_ok", "bounds_ok", "types_ok", "immutable_ok"]}
    distances = []
    for i, candidates in enumerate(population):
        original = clean[i:i+1]
        parts["relation_ok"].append(checker._check_relationship_constraints(candidates))
        parts["bounds_ok"].append(checker._check_boundary_constraints(original, candidates))
        parts["types_ok"].append(checker._check_type_constraints(candidates))
        parts["immutable_ok"].append(checker._check_mutable_constraints(original, candidates))
        distances.append(np.linalg.norm(scaler.transform(candidates) - scaler.transform(original), axis=1))
    out = {k: np.asarray(v, dtype=bool) for k,v in parts.items()}
    out["valid"] = np.logical_and.reduce(list(out.values()))
    out["distance"] = np.asarray(distances)
    out["within_budget"] = out["distance"] <= epsilon
    out["changed"] = np.any(population != clean[:, None, :], axis=-1)
    return out


def final_gate(clean, proposed, baseline, baseline_prediction, model, checker, scaler, epsilon):
    """Validate the selected representative again; keep the baseline otherwise."""
    valid = checker.check_constraints(clean, proposed).astype(bool)
    distance = np.linalg.norm(scaler.transform(proposed) - scaler.transform(clean), axis=1)
    prediction = model.predict_proba(proposed).argmax(1)
    take = valid & (distance <= epsilon) & (prediction == 0)
    final = np.where(take[:, None], proposed, baseline).astype(np.float32)
    final_prediction = np.where(take, prediction, baseline_prediction)
    # Same final-batch checker as the original baseline. No invalid or
    # out-of-budget representative can be counted as an evasion.
    final_valid = checker.check_constraints(clean, final).astype(bool)
    final_distance = np.linalg.norm(scaler.transform(final) - scaler.transform(clean), axis=1)
    if not final_valid.all() or np.any(final_distance > epsilon):
        raise AssertionError("Final representatives fail the unchanged acceptance rules")
    return final, final_prediction, final_distance, int((~take & np.any(proposed != baseline, axis=1)).sum())


class PoolAccumulator:
    def __init__(self, rows, clean_predictions, baseline, baseline_prediction, baseline_distance):
        self.rows = rows
        self.lookup = {int(row): i for i, row in enumerate(rows)}
        self.detected = clean_predictions == 1
        self.covered = np.zeros(len(rows), dtype=bool)
        self.success = np.zeros(len(rows), dtype=bool)
        self.unique = [set() for _ in rows]
        self.totals = {k: 0 for k in ["candidates", "changed_candidates", "unchanged_candidates", "invalid_candidates",
                                     "over_budget_candidates", "changed_valid_in_budget", "successful_candidates"]}
        self.best = baseline.copy()
        self.best_distance = np.where(baseline_prediction == 0, baseline_distance, np.inf)
        self.best_source = np.full(len(rows), "original_CAA", dtype=object)

    def update(self, stage, rows, population, masks):
        totals, covered, success = pool_summary(masks["changed"], masks["valid"], masks["within_budget"], masks["fooled"])
        for key,val in totals.items():
            self.totals[key] += val
        feasible = masks["changed"] & masks["valid"] & masks["within_budget"]
        accepted = masks["valid"] & masks["within_budget"] & masks["fooled"]
        for local,row in enumerate(rows):
            global_id = self.lookup[int(row)]
            self.covered[global_id] |= covered[local]
            self.success[global_id] |= success[local]
            for c in np.flatnonzero(feasible[local]):
                self.unique[global_id].add(hashlib.sha256(population[local,c].tobytes()).hexdigest())
            if accepted[local].any():
                distance = np.where(accepted[local], masks["distance"][local], np.inf)
                c = int(np.argmin(distance))
                if distance[c] < self.best_distance[global_id]:
                    self.best[global_id] = population[local,c]
                    self.best_distance[global_id] = distance[c]
                    self.best_source[global_id] = stage + ":" + str(c)


def postprocess(source_dir, target_dir, method, repair, checker, scaler, model,
                counter, epsilon, rows, clean_predictions, baseline, baseline_prediction, baseline_distance):
    target_dir.mkdir(parents=True, exist_ok=False)
    accumulator = PoolAccumulator(rows, clean_predictions, baseline, baseline_prediction, baseline_distance)
    started = time.perf_counter()
    before = counter.snapshot()
    timing = {k: 0.0 for k in ["repair_compute_seconds", "constraint_and_distance_seconds", "prediction_seconds"]}
    query_rows, stage_reports = 0, []
    for path in sorted(source_dir.glob("*_candidates.npz")):
        with np.load(path, allow_pickle=False) as loaded:
            source = {k: loaded[k] for k in loaded.files}
        stage = path.stem.split("_", 1)[1].rsplit("_candidates", 1)[0]
        population = source["x_candidates"]
        if method == "original":
            masks = source
            new_population = population
            repair_details = None
        else:
            new_population = np.empty_like(population)
            details = []
            start = time.perf_counter()
            for i, candidates in enumerate(population):
                fixed, audit = repair.repair_population(source["x_clean"][i:i+1], candidates,
                                                        repair_relations=(method == "relation_and_budget"))
                new_population[i] = fixed
                details.append(audit)
            timing["repair_compute_seconds"] += time.perf_counter() - start
            repair_details = {k: np.stack([d[k] for d in details]) for k in details[0]}
            start = time.perf_counter()
            masks = measured_pool(source["x_clean"], new_population, checker, scaler, epsilon)
            timing["constraint_and_distance_seconds"] += time.perf_counter() - start
            # Clean fallbacks reuse known clean predictions. Every changed,
            # feasible candidate is rescored; exact duplicates share a call.
            prediction = np.full(masks["valid"].shape, -1, dtype=np.int64)
            score = np.full(prediction.shape, np.nan, dtype=np.float64)
            for i,row in enumerate(source["csv_rows"]):
                unchanged = ~masks["changed"][i]
                prediction[i, unchanged] = clean_predictions[accumulator.lookup[int(row)]]
            query = masks["changed"] & masks["valid"] & masks["within_budget"]
            start = time.perf_counter()
            if query.any():
                unique, inverse = np.unique(new_population[query], axis=0, return_inverse=True)
                probabilities = model.predict_proba(unique)
                if probabilities.shape != (len(unique), 2) or not np.isfinite(probabilities).all():
                    raise AssertionError("Invalid model probabilities")
                prediction[query] = probabilities.argmax(1)[inverse]
                score[query] = probabilities[:,1][inverse]
                query_rows += len(unique)
            timing["prediction_seconds"] += time.perf_counter() - start
            masks["fooled"] = prediction == 0
            stage_out = target_dir / stage
            stage_out.mkdir()
            np.savez_compressed(stage_out / "repaired_candidates.npz", x_clean=source["x_clean"],
                                x_candidates=new_population, csv_rows=source["csv_rows"], labels=source["labels"],
                                predicted_class=prediction, score_malicious=score, prediction_query_mask=query,
                                **masks, **{"repair_"+k:v for k,v in repair_details.items()})
        accumulator.update(stage, source["csv_rows"], new_population, masks)
        summary, _, _ = pool_summary(masks["changed"], masks["valid"], masks["within_budget"], masks["fooled"])
        summary.update({"stage": stage, "source_npz_sha256": sha256(path),
                        "constraint_failures_overlapping": {k: int((~masks[k]).sum()) for k in
                                                            ["relation_ok", "bounds_ok", "types_ok", "immutable_ok"]}})
        if repair_details is not None:
            summary["candidates_altered_by_repair"] = int(repair_details["changed_vs_raw"].sum())
            summary["fully_reverted_changed_candidates"] = int((source["changed"] & ~masks["changed"]).sum())
            summary["blocks_restored"] = {key: int(repair_details[key].sum()) for key in
                                          ["basic_blocks_restored", "relation_blocks_restored", "budget_blocks_restored"]}
        stage_reports.append(summary)
    costs = dict(timing, unique_changed_feasible_rows_scored=query_rows,
                 postprocess_wall_seconds=time.perf_counter()-started, forward_counts=counter.since(before))
    write_json(target_dir / "stage_summary.json", {"method": method, "stages": stage_reports, "costs": costs})
    return accumulator, costs, stage_reports


def seed_aggregate(comparison):
    out = []
    for model,method in sorted({(r["model"],r["method"]) for r in comparison}):
        group = [r for r in comparison if r["model"]==model and r["method"]==method]
        result = {"model":model,"method":method,"runs":len(group)}
        for key in ["union_coverage_fraction", "new_evasion_rate_among_initially_detected", "newly_evaded", "added_wall_seconds"]:
            values = [r[key] for r in group if r[key] is not None]
            result[key+"_mean"] = statistics.mean(values) if values else None
            result[key+"_sample_std"] = statistics.stdev(values) if len(values)>1 else None
        out.append(result)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path("vendor/tabularbench"))
    p.add_argument("--assets", type=Path, default=Path("assets"))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--n-dev", type=int, default=32)
    p.add_argument("--selection-seed", type=int, default=0)
    p.add_argument("--seeds", type=int, nargs="+", default=[0,1,2])
    p.add_argument("--models", nargs="+", choices=["default","madry"], default=["default","madry"])
    p.add_argument("--steps", type=int, default=10)
    p.add_argument("--generations", type=int, default=100)
    p.add_argument("--offspring", type=int, default=50)
    p.add_argument("--eps", type=float, default=.5)
    args = p.parse_args()
    if args.out.exists(): p.error("Preserving earlier results: --out must be a NEW directory")
    if min(args.n_dev,args.steps,args.generations,args.offspring)<1 or args.eps<=0:
        p.error("Counts and epsilon must be positive")
    if min(args.seeds+[args.selection_seed])<0 or len(set(args.seeds))!=len(args.seeds) or len(set(args.models))!=len(args.models):
        p.error("Use distinct nonnegative attack seeds and distinct models")
    if platform.python_version() != "3.8.20" or np.__version__ != "1.23.5" or torch.__version__ != "1.12.1+cpu":
        raise RuntimeError("Run with the existing pinned .baseline-env/bin/python")
    revision = subprocess.check_output(["git","-C",str(args.repo),"rev-parse","HEAD"],text=True).strip()
    if revision != CODE_REVISION or subprocess.check_output(["git","-C",str(args.repo),"diff","HEAD","--"],text=True):
        raise RuntimeError("Use the clean pinned upstream checkout")
    sys.path.insert(0,str(args.repo.resolve()))
    from tabularbench.models.tab_scaler import TabScaler
    from tabularbench.models.tabsurvey.mlp_rln import TORCHRLN
    from tabularbench.datasets.dataset import CsvDataSource
    from tabularbench.datasets.samples.ctu_13_neris import Ctu13Splitter, get_relation_constraints
    from tabularbench.constraints.constraints import get_constraints_from_metadata
    from tabularbench.constraints.constraints_checker import ConstraintChecker
    from tabularbench.attacks.caa.caa import ConstrainedAutoAttack
    torch.set_num_threads(2)
    args.out.mkdir(parents=True,exist_ok=False)
    started = time.perf_counter()
    settings = {k:str(v) if isinstance(v,Path) else v for k,v in vars(args).items()}
    protocol = {
        "experiment":"development_candidate_consistency_comparison", "status":"running", "settings":settings,
        "code_revision":CODE_REVISION, "data_revision":DATA_REVISION,"model_revision":MODEL_REVISION,
        "python":platform.python_version(),"numpy":np.__version__,"torch":torch.__version__,"device":"cpu",
        "relationship_tolerance":0.0,"attack_generation_shared_between_methods":True,
        "repair_inside_optimizer":False,"new_model_training":False,"test_partition_evaluated":False,
        "scaler_fitted_on_all_feature_rows_for_checkpoint_compatibility":True,
        "equal_total_compute_claim":False,
        "methods":["original","budget_only","relation_and_budget"],
        "limitations":[
            "Development pilot on a fixed selected subset; seed variation is not independent population uncertainty.",
            "Original upstream validation rows are used; checkpoint training history is inherited, not retrained here.",
            "The compatibility scaler uses all dataset feature rows. This is not a leakage-free final evaluation.",
            "Repair only processes original CAA stage outputs, not every optimizer iteration, and does not guide search.",
            "Both repaired methods retain original valid evasions; their additional computation and model forwards are reported.",
            "A reverted clean input is not changed-valid coverage or a new evasion.",
            "Feature-space benchmark validity does not establish packet realizability or attack-functionality preservation.",
            "Block rollback is a simple repair baseline; no novelty, optimality or general defense advantage is asserted.",
        ]}
    write_json(args.out/"protocol.json",protocol)
    hashes = json.loads(Path(__file__).with_name("asset_hashes.json").read_text())
    for name,expected in hashes.items():
        if sha256(args.assets/name) != expected: raise RuntimeError("Pinned asset hash mismatch: "+name)
    print("Loading pinned feature data and official validation split...",flush=True)
    data = pd.read_csv(args.assets/"ctu_13_neris.csv",low_memory=False)
    labels = data.pop("is_botnet").to_numpy(dtype=np.int64)
    names = data.columns.tolist()
    values = data.to_numpy(dtype=np.float32)
    del data; gc.collect()
    metadata = pd.read_csv(args.assets/"ctu_13_neris_metadata.csv")
    metadata = metadata[metadata.feature.isin(names)].reset_index(drop=True)
    if metadata.feature.tolist()!=names or len(names)!=757: raise ValueError("Unexpected CTU feature order")
    scaler = TabScaler(num_scaler="min_max",one_hot_encode=True)
    scaler.fit(torch.from_numpy(values),x_type=metadata["type"])
    if scaler.cat_idx or scaler.num_idx != list(range(len(names))):
        raise ValueError("Block geometry requires this all-numeric, order-preserving scaler")
    scaler.get_scaler_data().save(str(args.out/"compatibility_scaler.json"))
    class LoadedDatasetView:
        def get_x_y(self): return values,labels
    splits = Ctu13Splitter().get_splits(LoadedDatasetView())
    dev_rows = np.asarray(splits["val"],dtype=np.int64)
    if np.intersect1d(dev_rows,splits["test"]).size or dev_rows.max()>=143046:
        raise AssertionError("Development/test row overlap")
    x_dev,y_dev = values[dev_rows].copy(),labels[dev_rows].copy()
    del values; gc.collect()
    constraints = get_constraints_from_metadata(metadata,get_relation_constraints(CsvDataSource(str(args.assets/"ctu_13_neris_metadata.csv"))),names)
    checker = ConstraintChecker(constraints,0.0)
    malicious = np.flatnonzero(y_dev==1)
    valid = checker.check_constraints(x_dev[malicious],x_dev[malicious]).astype(bool)
    # A one-candidate population and a multi-candidate population can have
    # different float32 reduction order. Require valid originals in both.
    for i in np.flatnonzero(valid):
        original = x_dev[malicious[i]:malicious[i]+1]
        valid[i] &= bool(checker.check_constraints(original,original)[0])
    eligible = malicious[valid]
    if len(eligible)<args.n_dev:
        raise ValueError("Only {} eligible development records; reduce --n-dev explicitly".format(len(eligible)))
    selected = np.random.RandomState(args.selection_seed).choice(eligible,args.n_dev,replace=False)
    selected = selected[np.argsort(dev_rows[selected])]
    rows = dev_rows[selected]
    clean, y = x_dev[selected].copy(),y_dev[selected].copy()
    np.save(args.out/"development_indices.npy",dev_rows)
    np.save(args.out/"selected_development_csv_rows.npy",rows)
    np.savez_compressed(args.out/"selected_development_inputs.npz",x_clean=clean,labels=y,csv_rows=rows)
    write_json(args.out/"feature_names.json",names)
    split_record = {"splitter":"pinned Ctu13Splitter; validation from native training prefix", "split_random_state":1319,
        "train_rows":len(splits["train"]),"development_rows":len(dev_rows),"native_test_rows":len(splits["test"]),
        "development_malicious":len(malicious),"eligible_malicious":len(eligible),"selected":len(rows),
        "selection_seed":args.selection_seed,"prediction_filter_used":False,"selected_csv_rows_zero_based":rows.tolist(),
        "selected_rows_all_in_official_validation":bool(np.isin(rows,dev_rows).all()),
        "selected_rows_disjoint_from_native_test":bool(not np.isin(rows,splits["test"]).any()),
        "split_indices_sha256":{key:hashlib.sha256(np.asarray(value,dtype="<i8").tobytes()).hexdigest() for key,value in splits.items()}}
    write_json(args.out/"split_manifest.json",split_record)
    repair = BlockRollbackRepair(constraints,scaler.transform,args.eps)
    write_json(args.out/"repair_blocks.json",repair.description())
    print("Selected {} validation malicious records; {} dependency blocks; no test-row scoring.".format(len(rows),len(repair.blocks)),flush=True)
    comparison,run_reports,clean_reports = [],[],{}
    for model_name in args.models:
        print("Loading RLN "+model_name,flush=True)
        model = TORCHRLN.load_class(str(args.assets/("torchrln_ctu_13_neris_"+model_name+".model")),
                                   x_metadata=metadata,scaler=scaler,force_device="cpu")
        counter = ForwardCounter(model.wrapper_model)
        dev_probabilities = model.predict_proba(x_dev)
        clean_reports[model_name] = clean_metrics(y_dev,dev_probabilities)
        pd.DataFrame({"csv_row_zero_based":dev_rows,"label":y_dev,"prediction":dev_probabilities.argmax(1),
                      "score_malicious":dev_probabilities[:,1]}).to_csv(args.out/(model_name+"_development_clean_predictions.csv"),index=False)
        clean_predictions = model.predict_proba(clean).argmax(1)
        for seed in args.seeds:
            run_dir = args.out/model_name/("seed_"+str(seed))
            run_dir.mkdir(parents=True,exist_ok=False)
            np.random.seed(seed); torch.manual_seed(seed)
            attack = ConstrainedAutoAttack(constraints=constraints,constraints_eval=constraints,scaler=scaler,
                model=model.wrapper_model,model_objective=model.predict_proba,n_jobs=1,
                fix_equality_constraints_end=True,fix_equality_constraints_iter=True,norm="L2",eps=args.eps,
                seed=seed,steps=args.steps,n_gen=args.generations,n_offsprings=args.offspring,verbose=False,n_classes=2)
            trace = CandidateTrace(run_dir/"raw_pool",rows,["NoAttack"]+[type(a).__name__ for a in attack._autoattack.attacks],
                                   checker,attack.objective_calculator.thresholds)
            original_record = trace.record
            def checked_record(*a,**kw):
                state = np.random.get_state(); torch_state = torch.get_rng_state().clone()
                original_record(*a,**kw)
                after = np.random.get_state()
                assert state[0]==after[0] and state[2:]==after[2:]
                np.testing.assert_array_equal(state[1],after[1]); assert torch.equal(torch_state,torch.get_rng_state())
            trace.record = checked_record
            observe_selector(attack._autoattack.objective_calculator,trace)
            before = counter.snapshot(); start = time.perf_counter()
            print("{} seed {}: original CAA, {} generations".format(model_name,seed,args.generations),flush=True)
            returned = attack(clean,y)
            attack_seconds = time.perf_counter()-start
            attack_counts = counter.since(before)
            # Original final scoring uses the same rules as earlier notebooks.
            original_valid = checker.check_constraints(clean,returned).astype(bool)
            original_distance = np.linalg.norm(scaler.transform(returned)-scaler.transform(clean),axis=1)
            original_predictions = model.predict_proba(returned).argmax(1)
            keep = original_valid & (original_distance<=args.eps)
            baseline = np.where(keep[:,None],returned,clean).astype(np.float32)
            baseline_predictions = np.where(keep,original_predictions,clean_predictions)
            baseline_distance = np.where(keep,original_distance,0)
            original_metrics = attack_metrics(clean_predictions,original_predictions,original_valid,original_distance<=args.eps)
            np.savez_compressed(run_dir/"original_final.npz",x_clean=clean,x_returned=returned,x_effective=baseline,
                                csv_rows=rows,labels=y,clean_predictions=clean_predictions,predictions=baseline_predictions,
                                returned_valid=original_valid,returned_distance=original_distance)
            per_method,original_accumulator = {},None
            for method in ["original","budget_only","relation_and_budget"]:
                accumulator,costs,stages = postprocess(run_dir/"raw_pool",run_dir/method,method,repair,checker,scaler,
                    model,counter,args.eps,rows,clean_predictions,baseline,baseline_predictions,baseline_distance)
                if method=="original":
                    original_accumulator = accumulator
                    final,final_predictions,distances = baseline,baseline_predictions,baseline_distance
                    metrics = original_metrics
                    final_seconds,final_counts,rejected = 0.0,{k:0 for k in counter.counts},0
                else:
                    before = counter.snapshot(); start = time.perf_counter()
                    final,final_predictions,distances,rejected = final_gate(clean,accumulator.best,baseline,baseline_predictions,
                                                                          model,checker,scaler,args.eps)
                    final_seconds,final_counts = time.perf_counter()-start,counter.since(before)
                    metrics = attack_metrics(clean_predictions,final_predictions,np.ones(len(rows),dtype=bool),distances<=args.eps)
                    np.savez_compressed(run_dir/method/"final_union.npz",x_clean=clean,x_adv=final,csv_rows=rows,labels=y,
                                        clean_predictions=clean_predictions,predictions=final_predictions,distance=distances)
                union_covered = original_accumulator.covered | accumulator.covered
                unique_union = [a | b for a,b in zip(original_accumulator.unique,accumulator.unique)]
                records = [{"csv_row_zero_based":int(row),"clean_prediction":int(clean_predictions[i]),
                            "covered_by_original_pool":bool(original_accumulator.covered[i]),
                            "covered_by_method_pool":bool(accumulator.covered[i]),"covered_by_union":bool(union_covered[i]),
                            "unique_changed_feasible_candidates_union":len(unique_union[i]),
                            "final_prediction":int(final_predictions[i]),"newly_evaded":bool(clean_predictions[i]==1 and final_predictions[i]==0),
                            "final_distance_l2_scaled":float(distances[i])} for i,row in enumerate(rows)]
                write_csv(run_dir/method/"records.csv",records)
                added_seconds = 0.0 if method=="original" else costs["postprocess_wall_seconds"]+final_seconds
                result = {"model":model_name,"seed":seed,"method":method,"n_selected":len(rows),
                          **metrics, **{"pool_"+k:v for k,v in accumulator.totals.items()},
                          "method_pool_covered_records":int(accumulator.covered.sum()),
                          "union_covered_records":int(union_covered.sum()),"union_coverage_fraction":float(union_covered.mean()),
                          "additional_covered_records":int((union_covered & ~original_accumulator.covered).sum()),
                          "initially_detected_covered_records_union":int((union_covered & (clean_predictions==1)).sum()),
                          "unique_changed_feasible_candidates_union":sum(len(s) for s in unique_union),
                          "baseline_attack_seconds_with_trace":attack_seconds,"added_wall_seconds":added_seconds,
                          "baseline_attack_forward_rows":attack_counts["forward_rows"],
                          "added_prediction_forward_rows":costs["forward_counts"]["forward_rows"]+final_counts["forward_rows"],
                          "final_selection_rejections":rejected}
                if method != "original" and result["newly_evaded"]<original_metrics["newly_evaded"]:
                    raise AssertionError("Augmented method lost a validated original evasion")
                comparison.append(result)
                per_method[method] = {"summary":result,"costs":costs,"final_gate_seconds":final_seconds,
                                      "final_gate_forward_counts":final_counts,"stages":stages}
                print("  {}: coverage {}/{}, new evasions {}/{}".format(method,result["union_covered_records"],len(rows),
                      result["newly_evaded"],result["clean_detected"]),flush=True)
            run_report = {"model":model_name,"seed":seed,"attack_seconds_with_trace":attack_seconds,
                          "attack_forward_counts":attack_counts,"observer_rng_preservation_checked":True,
                          "upstream_selector_unchanged":True,"methods":per_method}
            write_json(run_dir/"results.json",run_report)
            run_reports.append({"model":model_name,"seed":seed,"results":str((run_dir/"results.json").relative_to(args.out))})
            write_csv(args.out/"comparison.csv",comparison)
            write_csv(args.out/"seed_summary.csv",seed_aggregate(comparison))
            write_json(args.out/"results.json",{"status":"running","clean_development":clean_reports,"runs":run_reports,"comparison":comparison})
            del attack,trace; gc.collect()
        counter.handle.remove()
        del model; gc.collect()
    protocol.update(status="completed",wall_seconds=time.perf_counter()-started)
    write_json(args.out/"protocol.json",protocol)
    write_json(args.out/"results.json",{"status":"completed","clean_development":clean_reports,"runs":run_reports,
                                        "comparison":comparison,"seed_summary":seed_aggregate(comparison)})
    print("Development comparison complete: "+str(args.out.resolve()),flush=True)


if __name__ == "__main__":
    main()
