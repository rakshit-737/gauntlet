# GAUNTLET

**Threat-informed purple-team coverage scoring: rank ATT&CK techniques by what real actors do, replay real recorded attacks through your Sigma rules, and get a measured coverage matrix, the cheapest gaps to close, and a CI regression gate.**

GAUNTLET closes the loop **CTI → prioritized emulation plan → telemetry → detections → coverage → ranked gaps → regression gate** using only public data: MITRE ATT&CK v19.2, SigmaHQ r2026-07-01, OTRF Security-Datasets and the Atomic Red Team index.

- [Getting started](getting-started.md): install, offline commands, download the data, run the benchmark.
- [Benchmarks](benchmarks.md): coverage with 95% intervals, the prioritization research question, prediction.
- [Coverage explorer demo](demo/index.html): an interactive static view of the committed results.
- [Architecture](architecture.md), [Datasets](DATASETS.md), [Threat model](threat-model.md), [Limitations](limitations.md).

!!! warning "Lab-only"
    GAUNTLET **never executes attack techniques**. It reads recorded logs and prints Atomic Red Team test names marked DRY RUN. See [Security](security.md).
