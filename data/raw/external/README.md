# External Data Sources

External datasets used by this project are not committed to the repository by default. They should be obtained from their original sources and placed in the directories shown below.

Processed outputs derived from these datasets are retained in the repository where appropriate for reproducibility and evaluation.

| Dataset | Provider | Purpose | Expected Location | Format | Retrieved |
|---|---|---|---|---|---|
| CISA Known Exploited Vulnerabilities (KEV) | CISA | Known-exploitation evidence | `data/raw/external/cisa_kev/` | CSV | 2026-08 |
| EPSS | FIRST | Exploitation-likelihood evidence | `data/raw/external/epss/` | CSV.GZ | 2026-08-07 |
| National Vulnerability Database (NVD) | NIST | CVE, CVSS, CWE and description enrichment | `data/raw/external/nvd/` | JSON | 2026-08 |
| CVE2ATT&CK | Public labelled dataset | Training and evaluation of CVE-to-MITRE ATT&CK classification | `data/raw/external/cve2attack/` | CSV | 2026-08 |
| DARPA 2000 LLDOS 1.0 | MIT Lincoln Laboratory | Multi-stage campaign validation | `data/raw/external/darpa2000/lldos_1/` | XML | 2026-08 |
| MulVAL 3-host | MulVAL | Structural attack-graph validation | `data/raw/external/mulval/3host/` | Prolog | 2026-08 |
| NOMS 2022 supplementary material | Published supplementary dataset | Held-out CVE-to-ATT&CK validation | `data/raw/external/noms2022_attack_paths/` | Mixed | 2026-08 |

## Expected Files

### CISA KEV

```text
data/raw/external/cisa_kev/
└── known_exploited_vulnerabilities.csv