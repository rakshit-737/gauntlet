# ADR 0005 - Benign live emulation in CI for live telemetry

- Status: accepted
- Date: 2026-10-02

## Context

Replayed recordings (OTRF, Splunk attack_data) are labelled per recording and, for Splunk's
Linux auditd extracts, often lack the records rules need (no `EXECVE`). To measure how
detections behave on *complete, event-labelled* telemetry, GAUNTLET needs telemetry it
generates itself.

## Decision

- One GitHub Actions workflow (`live-telemetry.yml`) runs `scripts/live_emulate.py` on an
  **ephemeral GitHub-hosted ubuntu-24.04 runner** (weekly and on demand). Nothing runs locally.
- The script runs a fixed **allowlist** of read-only discovery commands: `whoami`, `id`,
  `uname -a`, `hostname`, `cat /etc/os-release`, `ps -ef`, `crontab -l`, `ls -la /etc/cron.d`.
  Fixed argv, `shell=False`, timeout, unprivileged runner user. It refuses to start unless
  `GITHUB_ACTIONS=true` and `RUNNER_ENVIRONMENT=github-hosted`, and refuses to run as root.
- No credential access, persistence, privilege escalation, file modification or network
  activity. `sudo` is used only to install/configure auditd and read its log.
- Network access in the job happens only before emulation (pip, pinned rule/recording downloads).
- A unit test pins the allowlist to approved binaries; CODEOWNERS covers the script.
- The **package** (`gauntlet/`) still never executes anything: `gauntlet live` only parses
  the audit log and the labels the script wrote.

## Consequences

Live coverage is limited to benign discovery behaviour; it measures whether rules fire on
real, complete telemetry, not whether they catch real attackers. ADR 0004 is amended
accordingly.
