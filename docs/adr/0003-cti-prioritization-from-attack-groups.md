# ADR 0003 - Derive prioritization weights from ATT&CK group procedures

- Status: accepted (v0.2.0)
- Date: 2026-09-26

## Context

The spec asks for technique prevalence from CTI (e.g. Red Canary Threat
Detection Report). The MVP used hand-typed weights. The Red Canary report
publishes a top-10 list and narrative per year, not a machine-readable
per-technique frequency table with a licence suitable for redistribution.

## Decision

Use MITRE ATT&CK Enterprise (STIX 2.1, pinned v19.2) as the CTI source:

- **prevalence(T)** = share of ATT&CK groups with a documented procedure for T
  (group -> software -> technique links included; parent credited for sub-technique use)
- **profiles** are *sets of real groups*, chosen reproducibly by regex over group
  descriptions (`ransomware`, `espionage`, `financial`, `cloud`) or explicitly
  (`--profile APT29,G0007`)
- **relevance(T | profile)** = share of profile groups using T
- default score = relevance x normalised prevalence; alternatives are kept as
  strategies and compared empirically (leave-one-group-out)

## Consequences

- Fully reproducible and redistributable (derived JSON shipped in the package).
- ATT&CK procedure examples measure *reporting*, not true frequency: they are
  biased toward well-studied actors and older tradecraft. This bias is stated in
  the README limitations.
- Leave-one-group-out evaluation avoids the circularity of scoring a ranking
  with the same weights that produced it.
