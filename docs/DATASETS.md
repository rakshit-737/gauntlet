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
| OTRF Security-Datasets *compound* LSASS campaigns (`--only mordor-compound`) | commit `d9d40ef1` | ~22 MB | MIT | multi-technique recordings |
| [Splunk attack_data](https://github.com/splunk/attack_data) (`--only splunk`) | commit `b4573ed3`, manifest `scripts/splunk_attack_data.json` | ~39 MB (552 recordings, 662 files) | Apache-2.0 | Windows XML event logs, Sysmon for Linux and auditd recordings |
| SigmaHQ tag checkout (`git clone --branch r2026-07-01`) | tag `r2026-07-01` | ~30 MB | DRL 1.1 | `sigma-full`: adds low/informational and threat-hunting rules |
| [CTID Top ATT&CK Techniques](https://github.com/center-for-threat-informed-defense/top-attack-techniques) `Techniques.json` (`--only published`) | commit `87cc589e` | 3.8 MB | Apache-2.0 | published `has_sigma` flags |
| [RedGap](https://github.com/befnoz/redgap) `docs/benchmarks/coverage.json` (`--only published`) | commit `a9bcbf2c` | 45 KB | MIT | published per-technique Linux detection outcomes |
| Live auditd telemetry | generated per run by the `live-telemetry` workflow | ~150 KB | - | event-labelled telemetry (artefact only; derived result committed) |

## Splunk attack_data selection

The manifest keeps every recording under `datasets/attack_techniques/` whose files are Windows XML event logs (`XmlWinEventLog*`), Sysmon for Linux or auditd, **all of at most 2 MB**, with a `mitre_technique` label. It covers 1,236 YAML files at the pinned commit, of which 552 recordings qualify. Each file is verified against its git-LFS sha256 oid. The size cap biases the selection towards short recordings. The labels come from the dataset YAML and apply to the whole recording. Files are routed by sourcetype: 16 manifest entries mix Linux and Windows files, and each part is scored with its own platform's rules (`<id>@linux`, `<id>@windows`). Splunk's Linux auditd extracts are pre-filtered: none of the 8 auditd recordings of the live-job techniques contains an `EXECVE` record (see `results/LIVE.md`), which limits what process-creation rules can see.

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
  downloader records them in `.av-skipped.json` and the benchmark lists them in
  `results/results.json` (`skipped_recordings`). The published results come from
  a Linux CI runner, where only `SDWIN-230718150800` (no host file at the pinned
  commit) is skipped.

## Citations

- MITRE ATT&CK(R) - Strom, B. et al. *MITRE ATT&CK: Design and Philosophy*, MITRE, 2018/2020. <https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf>
- Rodriguez, R. and Rodriguez, J. *Security Datasets (formerly Mordor)*, Open Threat Research Forge. <https://securitydatasets.com>
- SigmaHQ contributors. *Sigma - Generic Signature Format for SIEM Systems*. <https://github.com/SigmaHQ/sigma>
- Red Canary. *Atomic Red Team*. <https://github.com/redcanaryco/atomic-red-team>
- Splunk Threat Research Team. *attack_data*. <https://github.com/splunk/attack_data>
- Center for Threat-Informed Defense. *Top ATT&CK Techniques*. <https://github.com/center-for-threat-informed-defense/top-attack-techniques>
- befnoz. *RedGap*: benign Linux lab and Sigma silent-rule report; `docs/benchmarks/coverage.json` at commit `a9bcbf2c`. <https://github.com/befnoz/redgap>

Related research (not datasets, cited for the claim GAUNTLET tests):

- Virkud, A., Inam, M. A., Riddle, A., Liu, J., Wang, G. and Bates, A. *How does Endpoint Detection use the MITRE ATT&CK Framework?* 33rd USENIX Security Symposium, 2024. <https://www.usenix.org/conference/usenixsecurity24/presentation/virkud>
- Uetz, R., Herzog, M., Hackländer, L., Schwarz, S. and Henze, M. *You Cannot Escape Me: Detecting Evasions of SIEM Rules in Enterprise Networks.* 33rd USENIX Security Symposium, 2024. <https://arxiv.org/abs/2311.10197>

## Derived files committed to the repo

| File | Derived from | Size |
|---|---|---:|
| `gauntlet/data/attack_kb.json` | ATT&CK v19.2 (names, tactics, platforms, group/software technique sets, 3-sentence group descriptions) | < 1 MB |
| `gauntlet/data/art_windows.json` | ART Windows index (test names, GUIDs, executor) | ~160 KB |
| `results/*.json`, `results/*.md`, `results/*.png` | `benchmark` and `live-telemetry` workflow artefacts, committed unedited (each file names its run id) | small |

Regenerate the first two with `python -m gauntlet kb` after downloading.
