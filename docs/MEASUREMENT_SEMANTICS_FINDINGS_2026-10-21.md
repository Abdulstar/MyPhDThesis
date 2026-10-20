# Measurement-semantics findings — 21 October 2026

**The row-1503 packet-count anomaly is present in the authors' original aggregate file. It was not introduced by our attack generator. Its underlying connection-log cause remains unknown.** The proposed packet/duration bound is not adopted, and Notebook 08's results and validity profile remain unchanged.

This investigation began on 13 October after reviewing the user's completed Notebook 08 run. The new audit protocol was finalized on 21 October. This is a development investigation motivated by observed cases, not a preregistered independent test.

## A stronger provenance bridge

The [original FENCE repository's README](https://github.com/achernikova/cybersecurity_evasion/blob/52a2ab95e05c535a15da226a1541ade69ed64ca1/README.md) links `features_stat_scenario1.csv`. We retrieved this aggregate table and fixed its SHA256 as `b5e61c1e541f59106bb672289e7977beec2558d2313b104270bf3b2d820b4e89` (123,264,347 bytes).

Its 77,183 rows correspond in order to the start of the pinned benchmark table. All labels agree, and all **77,183 × 757 model-input values agree after conversion to float32**. In float64, only 79 values differ; the largest absolute difference is approximately `3.64e-12`. This is not byte-for-byte equivalence of the two CSVs.

The actual baseline has **757 input features**: 756 aggregates plus `window_timestamp`. The original source table additionally has `internal_ip`; this field is absent from the benchmark. The preserved timestamp alone does not uniquely identify a host's contributing connections.

Zero-based row 1503 matches all 757 numeric model features exactly even in float64:

| Original Scenario 1 field | Value |
|---|---|
| Original label | `BACKGROUND` (mapped to benchmark label 0) |
| Internal host | `147.32.86.229` |
| Window timestamp | `1312962900` — 2011-08-10 07:55:00 UTC |
| Bucket | `s_OTHER` |
| Duration sum / minimum / maximum | `0.665524` / `0.665524` / `0.665524` |
| Incoming and outgoing packet aggregates | All zero |
| Outgoing byte sum / minimum / maximum | `3288` / `3288` / `3288` |
| UDP byte aggregate | `3288` |
| Distinct external IPs / source ports / destination ports | `1 / 1 / 1` |

This is an unmodified dataset control, not an adversarial example. “Label 0” here describes the benchmark label; the source's `BACKGROUND` label should not be upgraded to a claim that the traffic was independently verified benign.

This bridge locates the anomaly upstream of our benchmark use. It does **not** reconstruct the connection log or show whether the original packet fields were literal zeros, missing values, incorrectly converted fields, or affected by another collection behavior. We did not recover the historical logger version/configuration, the exact log-to-CSV conversion, or a row-to-connection-UID mapping. The current source-file link is not an immutable data release; the recorded content hash is required for reproduction.

## What the extractor proves

The [pinned aggregation source](https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/aggregated_features_bro_logs.py) converts `-` to zero before numerical aggregation. No missingness indicator is exported. Seven controlled fixtures exercise this unmodified implementation, with explicit harness configuration.

| Fixture | Observed consequence |
|---|---|
| Missing packet fields | Positive duration/bytes can coexist with zero counted packets |
| Literal-zero packet fields | Produces the same aggregate vector as the missing-field fixture |
| Complete packet fields | The example satisfies the conditional duration bound |
| One measured and one missing-count record | Packet total is positive, yet the bound fails: duration sum 2, maximum 1, packet total 1 |
| Missing counts on a zero-duration record | The bound passes despite incomplete packet measurements |
| An all-zero record before a positive record | The stored packet minimum can be 1 even though an earlier contributing record had zero; endpoint sets still retain both source ports |
| Duration 120 in a 60-second fixture window | Grouping by start time does not cap connection duration at the window length |

The missing-field and literal-zero fixtures each reproduce **all 757 numeric features of row 1503** in float64 and float32. Their host and UID are deliberately synthetic. This establishes an ambiguity in the feature representation, not the historical cause of that row or the physical plausibility of literal-zero packet records.

The leading-zero result follows from the extractor's minimum reinitialization when the entire aggregate state is zero. Consequently, inferring a count of *all* contributing records from positive aggregate minima also needs care; it is not added as another validity rule.

[Zeek's versioned field documentation](https://docs.zeek.org/en/v6.2.1/scripts/base/protocols/conn/main.zeek.html) describes originator/responder packet counts as optional and dependent on the connection-size analyzer. That documents a possible measurement distinction, not the historical configuration or cause of this dataset's anomaly.

## Clean-control audit and decision

All **143,046 native training/development records** were checked in parsed float64 and in float32 promoted to float64 before arithmetic. No additional tolerance was fitted.

- The conditional packet/duration bound flags only row 1503, in both precisions.
- Positive duration or bytes with zero total packets likewise occurs only in this row.
- All 32 pilot originals match the pinned CSV.
- All training/development records pass the unchanged Notebook 08 profile v1.
- No native test records are parsed or scored, and no model is loaded.

The inference `number of contributing records <= total counted packets` requires at least one counted packet per contributing record. The controlled partial-missingness example shows why a nonzero bucket total does not establish that premise. A passing bound also does not establish complete measurements.

**Decision:** retain the conditional bound as a diagnostic only. Do not remove row 1503, relabel it, replace its counts, or add a zero-total exception. Do not retroactively declare Notebook 08's extra evasion invalid. Missingness remains unknown from the benchmark features.

## Next experiment prepared

The new workflow freezes 128 additional malicious development records from the 660 remaining after excluding the original 32. Selection uses only labels and the saved split, with seed `20261013`; no predictions or attack outcomes are used. The CSV-row sequence SHA256 is `7d6230d364dd302f7a367adba184eeafc24ae7fd06b6266b156ae395ff0e2128` (little-endian int64 bytes in selected order).

The primary planned comparison is relationship/profile repair inside MOEVA versus after native CAA, using the same two frozen checkpoints, three seeds and core budgets. The five-method comparison and unchanged validity profile are specified in the [guide](MEASUREMENT_SEMANTICS_GUIDE.md) and machine-readable protocol. This audit does **not** execute these new attacks or establish improved evasion.

The defensible scope is feature-space robustness under explicitly listed necessary conditions. Packet feasibility, malicious functionality and real-world IDS accuracy require separate evidence. The inherited all-row scaler fit, selection from development data, and unknown host/window dependence remain limitations. A novelty or publication claim requires a separate literature assessment.

Six focused tests cover the extractor counterexamples. The full workflow was also run against the user's completed Notebook 08 archive, the two hash-verified data assets and the 143,046-row control prefix; the new reference JSON records the measured results and runtime. The local tests do not imply that Colab itself was remotely executed.
