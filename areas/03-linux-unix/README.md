# 03-linux-unix

Linux/BSD: auditd, Sysmon for Linux, LKRG, journald, LPE, reverse shells.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| auditd-cis-attck | [BernaldoPenasAntelo/Linux-MITRE_ATT-CK-Wazuh-Rules](https://github.com/BernaldoPenasAntelo/Linux-MITRE_ATT-CK-Wazuh-Rules) | 127 | 74 | no | no | `linux-auditd`; to be defined | 78% of 9 techniques | — | GPL-3.0 | 2021-04-08 | — |
| auditd | [mdnahidmondol/wazuh-AuditD-Sysmon-rules](https://github.com/mdnahidmondol/wazuh-AuditD-Sysmon-rules) | 2 | 0 | yes | yes | `linux-auditd` | no MITRE | — | NONE | 2021-09-26 | — |
| detection-engineering | [Jeremy-Burgos/wazuh-detection-engineering](https://github.com/Jeremy-Burgos/wazuh-detection-engineering) | 24 | 2 | no | no | `linux-auditd`; to be defined | 100% of 6 techniques | 1 ok (0 containment), 1 broken | MIT | 2026-04-10 | — |
| freebsd | [alonsobsd/wazuh-freebsd-ruleset](https://github.com/alonsobsd/wazuh-freebsd-ruleset) | 10 | 4 | yes | yes | to be defined | 100% of 2 techniques | — | BSD | 2026-01-11 | — |
| journald | [phastier/wazuh](https://github.com/phastier/wazuh) | 14 | 24 | yes | yes | to be defined | no MITRE | — | NONE | 2026-09-02 | — |
| linux-attck | [captainobvious-sec/wazuh-field-notes](https://github.com/captainobvious-sec/wazuh-field-notes) | 40 | 0 | yes | yes | `linux-auditd`, `pack-linux-attck` | 63% of 35 techniques | — | MIT | 2026-09-14 | — |
| linux-custom | [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) | 0 | 2 | yes | yes | to be defined | no MITRE | — | NONE | 2025-05-31 | — |
| lkrg | [adampielak/wazuh-lkrg](https://github.com/adampielak/wazuh-lkrg) | 10 | 0 | yes | yes | — | no MITRE | — | NONE | 2026-06-16 | — |
| offense-lab-linux | [0xbad53c/wazuh-detection-rules](https://github.com/0xbad53c/wazuh-detection-rules) | 107 | 0 | no | no | `linux-auditd` | no MITRE | — | NONE | 2022-02-13 | — |
| sysmon-linux-auditd | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 76 | 91 | yes | yes | `linux-auditd`; to be defined | 52% of 33 techniques | 2 ok (0 containment) | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| sysmon-linux | [0xbad53c/ossec-sysmon-for-linux-decoder](https://github.com/0xbad53c/ossec-sysmon-for-linux-decoder) | 0 | 58 | yes | yes | to be defined | no MITRE | — | GPL-3.0 | 2021-12-05 | — |
| sysmon-linux | [n00bsteam/Wazuh-Extended](https://github.com/n00bsteam/Wazuh-Extended) | 24 | 58 | yes | yes | to be defined | no MITRE | — | NONE | 2023-04-25 | — |
| wazuh-blog-pack | [adampielak/wazuh-scripts-resource](https://github.com/adampielak/wazuh-scripts-resource) | 43 | 15 | no | yes (2 warnings) | `linux-auditd`, `linux-suricata`, `pack-wazuh-blog-pack` | 88% of 17 techniques | 1 broken | NONE | 2026-06-27 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
