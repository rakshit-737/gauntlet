# ADR 0004 - Safety boundary: GAUNTLET never executes attack techniques

- Status: accepted
- Date: 2026-09-26

## Decision

- The package contains **no code path that executes a technique**. The real-data
  path reads recorded logs; the simulated path emits inert event dicts.
- `gauntlet manifest` only prints Atomic Red Team test names/GUIDs, marked DRY RUN,
  for an operator to run inside an isolated, no-egress range they own.
- Datasets are logs, YAML rules, STIX JSON and a CSV index. No binaries, no
  payloads, no exploit code are downloaded or committed.
- `range/docker-compose.yml` uses an `internal: true` network, `cap_drop: [ALL]`
  and read-only containers.

## Consequences

Coverage is limited to techniques someone has already recorded; that is an
accepted trade-off for a project anyone can run safely.
