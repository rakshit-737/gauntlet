# Security Policy

## Intended use
GAUNTLET is a **defensive** detection-engineering and purple-team training tool. The current release generates synthetic telemetry only. It contains no exploits, no payloads, and no code that executes techniques or contacts external hosts.

Rules for contributions and any future emulation backend:
- Emulation may run **only** inside an isolated lab range that you own, on an internal network with no egress.
- Never run it against third-party, production, or shared systems.
- Do not add real payloads, credential-dumping tools, C2 frameworks or live malware to this repository. Integrations with Caldera or Atomic Red Team must call those projects and stay confined to the range.

## Reporting a vulnerability
Report issues privately through GitHub Security Advisories on this repository, or by email to the maintainer. Do not open a public issue. Please include reproduction steps. You should get an acknowledgement within 7 days.

## Supported versions
Only the latest `main` is supported.
