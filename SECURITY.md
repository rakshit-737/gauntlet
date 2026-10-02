# Security Policy

## Intended use
GAUNTLET is a **defensive** detection-engineering and purple-team training tool. The package replays recorded public telemetry (OTRF, Splunk attack_data) through Sigma rules and never executes techniques. Network access is limited to `scripts/download_data.py`, which fetches pinned, checksum-verified files from GitHub. The only execution of anything technique-like is the `live-telemetry` CI job, which runs an allowlist of benign read-only discovery commands (`whoami`, `id`, `uname -a`, ...) on an ephemeral GitHub-hosted runner ([ADR 0005](https://github.com/rakshit-737/gauntlet/blob/main/docs/adr/0005-benign-live-emulation.md)). There are no exploits or payloads.

Rules for contributions and any future emulation backend:
- Emulation may run **only** inside an isolated lab range that you own, on an internal network with no egress.
- Never run it against third-party, production, or shared systems.
- Do not add real payloads, credential-dumping tools, C2 frameworks or live malware to this repository. Integrations with Caldera or Atomic Red Team must call those projects and stay confined to the range.

## Reporting a vulnerability
Report issues privately via GitHub private vulnerability reporting ("Report a vulnerability" on the Security tab of this repository). Do not open a public issue. Please include reproduction steps. You should get an acknowledgement within 7 days.

## Supported versions
Only the latest `main` is supported.
