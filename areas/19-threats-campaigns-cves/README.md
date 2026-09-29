# 19-threats-campaigns-cves

Specific malware, APTs and CVEs.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| apache-text4shell | [TheMuntu/Wazuh-Detection](https://github.com/TheMuntu/Wazuh-Detection) | 1 | 0 | yes | yes | `linux-apache` | 33% of 3 techniques | — | NONE | 2024-11-01 | — |
| cl-sta-1087 | [Dinas-Kominfo-Kota-Tangerang/cl-sta-1087-malware-rules](https://github.com/Dinas-Kominfo-Kota-Tangerang/cl-sta-1087-malware-rules) | 12 | 0 | no | no | `linux-apache`, `win-sysmon` | 100% of 9 techniques | — | MIT | 2026-03-31 | — |
| cve-2026-31431-copy-fail | [mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4](https://github.com/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4) | 8 | 0 | yes | yes | `linux-auditd` | 100% of 1 techniques | — | MIT | 2026-05-04 | — |
| cve-2026-43284-dirty-frag | [mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4](https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4) | 9 | 0 | yes | yes | `linux-auditd` | 50% of 2 techniques | — | MIT | 2026-05-17 | — |
| hoaxshell | [TheMuntu/Wazuh-Detection](https://github.com/TheMuntu/Wazuh-Detection) | 4 | 0 | yes | yes | `win-sysmon` | 100% of 1 techniques | — | NONE | 2024-11-01 | — |
| judol-gambling-seo | [bayusky/wazuh-custom-rules-and-decoders](https://github.com/bayusky/wazuh-custom-rules-and-decoders) | 2 | 0 | yes | yes | — | 67% of 3 techniques | 1 ok (0 containment) | GPL-2.0 | 2026-03-07 | — |
| raspberry-robin-worms | [TheMuntu/Wazuh-Detection](https://github.com/TheMuntu/Wazuh-Detection) | 6 | 0 | yes | yes | `win-sysmon` | 40% of 5 techniques | — | NONE | 2024-11-01 | — |
| redline-infostealer | [TheMuntu/Wazuh-Detection](https://github.com/TheMuntu/Wazuh-Detection) | 5 | 0 | yes | yes | `win-sysmon` | 80% of 5 techniques | — | NONE | 2024-11-01 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
