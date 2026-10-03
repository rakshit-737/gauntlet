# GAUNTLET

**GAUNTLET measures ATT&CK detection coverage instead of inferring it from rule tags.** It replays four recording sets from two public providers (OTRF and Splunk attack_data) and live, event-labelled auditd telemetry through unmodified SigmaHQ rules. On OTRF, tag-claimed coverage overstates measured coverage by **20.0 points** (95% Wilson [11.6, 32.4]): every one of the 55 recorded techniques has a tagged rule at family level, but only 80.0% [67.6, 88.4] are detected. On Splunk attack_data and the OTRF compound campaigns the SigmaHQ release package (medium and above, `sigma-all`) overstates by **59.0 to 76.9 points** (38.5 to 63.6 with the full tag's low-level and hunting rules, `sigma-full`; the compound sample is 13 techniques). As a control, the Sigma evaluator fires on all 197 SigmaHQ regression samples it runs ([98.1, 100.0]).

To our knowledge this is the first measured, interval-bounded gap between tag-claimed and replay-measured SigmaHQ coverage on public recordings plus live telemetry; [Virkud et al. (USENIX Security 2024)](https://www.usenix.org/conference/usenixsecurity24/presentation/virkud) argue from rule analysis that technique tags do not imply coverage of real threats.

It also ranks techniques by what real ATT&CK groups do (CTI prioritization), turns gaps into the cheapest rules to add, and gates CI on coverage regressions. It uses only public data. Numbers come from `benchmark` run [37094883465](https://github.com/rakshit-737/gauntlet/actions/runs/37094883465) and `live-telemetry` run [37092465944](https://github.com/rakshit-737/gauntlet/actions/runs/37092465944) ([Evaluation](evaluation.md)).

<div class="grid cards" markdown>

-   **80.0%** [67.6, 88.4]

    ---
    OTRF techniques with an on-target SigmaHQ detection (55 techniques, 98 recordings; 95% Wilson). 58.2% [45.0, 70.3] are *fully* detected.

-   **+20.0 to +76.9 pts**

    ---
    Tag-claimed minus measured coverage across OTRF, OTRF compound, Splunk Windows and Splunk Linux (release package). Smallest: OTRF 20.0 [11.6, 32.4]; largest: OTRF compound 76.9 [49.7, 91.8].

-   **3 of 4** live techniques

    ---
    Live auditd telemetry on a CI runner, n = 4 (95% Wilson [30.1, 95.4]; run 37092465944, identical outcomes on 4 runs): SigmaHQ with low-level and hunting rules detects 3 of 4 discovery techniques; the release package detects 0. None of 12 Splunk replays of the same techniques is detected.

-   **-75.5 steps** [-85.0, -65.8]

    ---
    CTI ordering vs breadth-first: emulations needed to reach 80% of a held-out ransomware actor's techniques (paired bootstrap over 18 held-out groups).

</div>

[![Coverage explorer](assets/demo.png)](demo/index.html)

## Try it in 60 seconds

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install "git+https://github.com/rakshit-737/gauntlet@v1.1.0"
gauntlet plan --profile ransomware --top 10       # CTI-prioritized emulation plan (offline)
gauntlet predict --observed T1566.001,T1059.001 -k 5
```

GAUNTLET is not published on PyPI: install from the v1.1.0 tag or the release wheel. The name `gauntlet` on PyPI belongs to an unrelated project, so do not run `pip install gauntlet`. Use v1.1.0 or later; the v1.0.0 wheel and image predate the rules-path and bench-output fixes.

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
