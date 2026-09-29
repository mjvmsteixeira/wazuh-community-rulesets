# 01-windows-endpoint

Windows: Sysmon, EventChannel, PowerShell, Sigma-generated rules.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| attck-mapped | [BernaldoPenasAntelo/Windows-MITRE_ATT-CK-Wazuh-Rules](https://github.com/BernaldoPenasAntelo/Windows-MITRE_ATT-CK-Wazuh-Rules) | 322 | 0 | no | yes (1 warning) | `win-sysmon` | no MITRE | — | GPL-3.0 | 2021-01-22 | — |
| offense-lab-windows | [0xbad53c/wazuh-detection-rules](https://github.com/0xbad53c/wazuh-detection-rules) | 78 | 0 | yes | yes | `pack-offense-lab-windows`, `win-sysmon`, `win-terminalservices-localsessionmanager` | no MITRE | — | NONE | 2022-02-13 | — |
| sigma-generated | [SanWieb/sigWah](https://github.com/SanWieb/sigWah) | 1392 | 0 | no | no | `win-sysmon` | 50% of 109 techniques | — | GPL-3.0 | 2020-06-08 | — |
| sigma-generated | [n00bsteam/Wazuh-Extended](https://github.com/n00bsteam/Wazuh-Extended) | 1337 | 0 | yes | yes | `win-sysmon` | 52% of 248 techniques | — | NONE | 2023-04-25 | — |
| sysmon-eventchannel | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 1245 | 0 | no | yes (2 warnings) | `pack-sysmon-eventchannel`, `win-powershell`, `win-sysmon`; to be defined | 52% of 174 techniques | 3 ok (0 containment) | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| sysmon-ion-storm | [n0rthl1ght/wazuh_info_collection](https://github.com/n0rthl1ght/wazuh_info_collection) | 322 | 0 | no | yes (4 warnings) | `win-sysmon`; manager: integration custom-telegram | 57% of 98 techniques | 1 broken | NONE | 2023-01-15 | — |
| sysmon-modular | [fusuyfusuy/wazuh_local_rules](https://github.com/fusuyfusuy/wazuh_local_rules) | 235 | 0 | no | yes (1 warning) | `pack-sysmon-modular`, `win-defender`, `win-smbclient`, `win-smbserver`, `win-sysmon`, `win-terminalservices-localsessionmanager`, `win-terminalservices-remoteconnectionmanager` | 52% of 84 techniques | — | NONE | 2021-08-06 | — |
| sysmon-sigma | [sametsazak/sysmon](https://github.com/sametsazak/sysmon) | 63 | 0 | yes | yes | `win-sysmon` | no MITRE | — | GPL-3.0 | 2021-07-22 | — |
| sysmon | [mdnahidmondol/wazuh-AuditD-Sysmon-rules](https://github.com/mdnahidmondol/wazuh-AuditD-Sysmon-rules) | 19 | 0 | yes | yes | `win-sysmon` | no MITRE | — | NONE | 2021-09-26 | — |
| wazuh-blog-pack | [adampielak/wazuh-scripts-resource](https://github.com/adampielak/wazuh-scripts-resource) | 81 | 3 | no | yes (2 warnings) | `pack-wazuh-blog-pack`, `win-firewall`, `win-powershell`, `win-sysmon`; manager: integration virustotal; to be defined | 57% of 21 techniques | 2 broken, 1 destructive without allowlist | NONE | 2026-06-27 | — |
| windows-ad | [captainobvious-sec/wazuh-field-notes](https://github.com/captainobvious-sec/wazuh-field-notes) | 179 | 0 | yes | yes | `win-powershell`, `win-sysmon` | 57% of 74 techniques | — | MIT | 2026-09-14 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
