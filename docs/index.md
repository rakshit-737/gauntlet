# GAUNTLET

**GAUNTLET measures ATT&CK detection coverage instead of inferring it from rule tags.** It replays four recording sets from two public sources (OTRF, Splunk attack_data) and live, event-labelled auditd telemetry through unmodified SigmaHQ rules. Tag-claimed coverage overstates measured coverage by **20 points on OTRF** (100% claimed at family level vs 80.0% [67.6, 88.4] measured, exact McNemar p = 0.001, 11 discordant techniques all in one direction), and by **58-77 points on Splunk attack_data and OTRF compound campaigns** for the full SigmaHQ release package (sigma-all; 38-64 points for sigma-full; the compound sample is 13 techniques).

It also ranks techniques by what real ATT&CK groups do (CTI prioritization), turns gaps into the cheapest rules to add, and gates CI on coverage regressions. It uses only public data.

<div class="grid cards" markdown>

-   **80.0%** [67.6, 88.4]

    ---
    OTRF techniques with an on-target SigmaHQ detection (55 techniques, 98 recordings). 58.2% are *fully* detected.

-   **+20 to +77 pts**

    ---
    Tag-claimed minus measured coverage across OTRF, OTRF compound, Splunk Windows and Splunk Linux.

-   **75%** live

    ---
    Live auditd telemetry on a CI runner: SigmaHQ (with low-level and hunting rules) detects 3 of 4 discovery techniques. The release package detects 0. Splunk replays of the same techniques detect 0.

-   **-75.5 steps** [-85.0, -65.8]

    ---
    CTI ordering vs breadth-first: emulations needed to reach 80% of a held-out ransomware actor's techniques.

</div>

[![Coverage explorer](assets/demo.png)](demo/index.html)

## Try it in 60 seconds

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install "git+https://github.com/rakshit-737/gauntlet@v1.1.0"
gauntlet plan --profile ransomware --top 10       # CTI-prioritized emulation plan (offline)
gauntlet predict --observed T1566.001,T1059.001 -k 5
```

The distribution name `gauntlet` on PyPI belongs to an unrelated project, so do not run `pip install gauntlet`. Install from this repository. Use v1.1.0 or later; the v1.0.0 wheel and image predate the rules-path and bench-output fixes.

<div class="grid cards" markdown>

-   [**How it works**](how-it-works.md)

    ---
    The loop from CTI to the regression gate, with real outputs.

-   [**Evaluation**](evaluation.md)

    ---
    Methodology, every result table, CIs, live telemetry and published comparisons.

-   [**Reproduce**](reproduce.md)

    ---
    Exact commands, expected numbers and runtimes.

-   [**Coverage explorer**](demo/index.html)

    ---
    Interactive view of the committed results.

</div>

!!! warning "Lab-only"
    The `gauntlet` package never executes attack techniques. It reads recorded logs and prints Atomic Red Team test names marked DRY RUN. One CI job runs an allowlist of benign discovery commands (`whoami`, `id`, `uname -a`, ...) on an ephemeral GitHub runner to collect auditd telemetry ([ADR 0005](adr/0005-benign-live-emulation.md)). See [Security](security.md).
