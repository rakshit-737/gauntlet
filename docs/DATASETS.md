# Dataset card

All data is public, pinned (commit, release tag or versioned file name), fetched by
`scripts/download_data.py`, and verified against `scripts/checksums.sha256`.
Nothing below is committed to git except the small derived files listed at the end.

| Source | Pinned ref | Size | Licence | Used for |
|---|---|---:|---|---|
| [MITRE ATT&CK Enterprise](https://github.com/mitre-attack/attack-stix-data) (STIX 2.1) | `enterprise-attack-19.2.json` | ~54 MB | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) (royalty-free, attribution required) | techniques, tactics, groups, software, procedure-based prevalence, threat profiles |
| [SigmaHQ rules](https://github.com/SigmaHQ/sigma) | release `r2026-07-01`, `sigma_all_rules.zip` | ~3 MB | [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) | detection rule sets under test |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (Mordor) | commit `d9d40ef1` | ~60 MB (Windows atomic host recordings + metadata) | MIT | real recorded attack telemetry, ATT&CK-labelled ground truth |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) Windows index CSV | commit `388942ad` | 0.24 MB | MIT | emulation universe, dry-run manifests |

## OTRF Security-Datasets details

- Only `datasets/atomic/_metadata/SDWIN-*.yaml` entries and their **Host** files
  are fetched (network PCAP-derived files are skipped).
- Each recording is a zip of JSON-lines Windows events (Sysmon, Security,
  PowerShell/Operational, Windows PowerShell, System, ...), captured in the OTRF
  "shire" lab while one technique was executed (mostly with Empire, Covenant,
  Mimikatz, Impacket, or native binaries).
- Ground truth: `attack_mappings` in the metadata (technique + sub-technique).
- Caveat: recordings contain background lab activity and preparatory steps;
  some mappings are at technique level where rules tag sub-techniques (and
  vice versa), hence GAUNTLET reports both *family* and *exact-ID* coverage.
- Caveat: on Windows hosts with Defender real-time protection, a few recordings
  that contain attack-tool strings can be quarantined after download. The
  downloader reports them as `UNREADABLE` and the benchmark skips them; the
  count used is printed in `results/results.json` (`recordings`).

## Citations

- MITRE ATT&CK(R) - Strom, B. et al. *MITRE ATT&CK: Design and Philosophy*, MITRE, 2018/2020.
- Rodriguez, R. and Rodriguez, J. *Security Datasets (formerly Mordor)*, Open Threat Research Forge, https://securitydatasets.com
- SigmaHQ contributors. *Sigma - Generic Signature Format for SIEM Systems*, https://github.com/SigmaHQ/sigma
- Red Canary. *Atomic Red Team*, https://github.com/redcanaryco/atomic-red-team

## Derived files committed to the repo

| File | Derived from | Size |
|---|---|---:|
| `gauntlet/data/attack_kb.json` | ATT&CK v19.2 (names, tactics, platforms, group/software technique sets, 3-sentence group descriptions) | < 1 MB |
| `gauntlet/data/art_windows.json` | ART Windows index (test names, GUIDs, executor) | ~160 KB |
| `results/*.json`, `results/*.md`, `results/*.png` | benchmark outputs | small |

Regenerate the first two with `python -m gauntlet kb` after downloading.
