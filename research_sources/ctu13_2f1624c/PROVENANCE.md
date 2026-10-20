# CTU aggregation source for controlled fixtures

`aggregated_features_bro_logs.py` is an unmodified copy of
[Talha Ongun's implementation](https://github.com/tongun/ctu13-botnet-detection/blob/2f1624ce0f06055901edfc90219d5072d8d04895/src/aggregated_features_bro_logs.py).
Its MIT license is included alongside it.

- Commit: `2f1624ce0f06055901edfc90219d5072d8d04895`
- Git blob: `6919babf3e4d2d59b14e98908eee0242c9ac7001`
- SHA256: `0e99f052f697524212f40df0d9892880ee1a488e1ba97f5690754964b71ee934`

The audit harness supplies an explicit `config` module: the original 18 ports,
internal prefix `147.32.`, a 60-second fixture window and `ddos=False`.
The upstream default configuration selects DDoS; it is not silently treated as
the Neris benchmark configuration. This harness setting does not establish the
window, logger version or conversion used to build the benchmark.

Fixtures are synthetic connection-CSV records. They exercise missing-value
conversion and aggregation only. They do not send packets, prove actual traffic
feasibility, identify the cause of a particular logger value, or preserve botnet
functionality.

The original Scenario 1 feature file is linked by the
[FENCE authors' pinned README](https://github.com/achernikova/cybersecurity_evasion/blob/52a2ab95e05c535a15da226a1541ade69ed64ca1/README.md).
It is downloaded separately and verified against SHA256
`b5e61c1e541f59106bb672289e7977beec2558d2313b104270bf3b2d820b4e89`.
This is an aggregated feature table, not the connection-log input to the
extractor. Its host/window fields improve provenance but do not identify the
contributing connection UIDs or missing measurements.
