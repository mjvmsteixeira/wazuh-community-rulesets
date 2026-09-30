# 18-compliance-frameworks

Framework-mapped packs: NIST CSF 2.0, CJIS, ENS (RD 311/2022).

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| cjis | [TristanGNS/wazuh-cjis-rules](https://github.com/TristanGNS/wazuh-cjis-rules) | 133 | 0 | yes | no | to be defined | no MITRE | — | MIT | 2025-06-24 | — |
| conducting-primary-account-number-scan-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 1 | 0 | yes | yes | `pack-conducting-primary-account-number-scan-with-wazuh` | no MITRE | 1 broken | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| ens-rd311-2022 | [fredycibersec/ENS-Wazuh-integration](https://github.com/fredycibersec/ENS-Wazuh-integration) | 25 | 0 | yes | yes | `linux-auditd` | no MITRE | — | GPL-2.0 | 2026-08-19 | 2 |
| nist-csf-2.0 | [Sbharadwaj05/Wazuh-NIST-Rules-Set](https://github.com/Sbharadwaj05/Wazuh-NIST-Rules-Set) | 54 | 6 | yes | yes | `linux-apache`, `linux-auditd`, `linux-nginx`, `pack-nist-csf-2-0`, `win-sysmon`; manager: remote syslog; to be defined | 76% of 41 techniques | — | Apache-2.0 | 2026-08-26 | 106 |
| wazuh-for-cmmc-compliance | [wazuh.com/blog](https://wazuh.com/blog/) | 1 | 0 | yes | yes | default | 100% of 1 techniques | 1 ok (1 containment), 1 destructive without allowlist | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
