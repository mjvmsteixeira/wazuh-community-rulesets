# 21-wazuh-platform-ops

Manager health, exclusions/tuning, active response, inventory, agents.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| active-response | [bayusky/wazuh-custom-rules-and-decoders](https://github.com/bayusky/wazuh-custom-rules-and-decoders) | 2 | 0 | yes | yes | — | no MITRE | — | GPL-2.0 | 2026-03-07 | — |
| afinacao-ruido | [phastier/wazuh](https://github.com/phastier/wazuh) | 29 | 8 | no | yes (14 warnings) | `linux-apache`, `pack-afinacao-ruido`; manager: remote syslog | 80% of 5 techniques | — | NONE | 2026-09-02 | — |
| detect-new-agents | [wazuh/integrations](https://github.com/wazuh/integrations) | 1 | 0 | yes | yes | `pack-detect-new-agents`; manager: localfile /var/ossec/logs/new_agents.json | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| orangebox | [OrangeBox-Labs/Wazuh](https://github.com/OrangeBox-Labs/Wazuh) | 9 | 0 | yes | yes | — | no MITRE | — | NONE | 2026-09-29 | — |
| silent-agent-monitoring | [wazuh/integrations](https://github.com/wazuh/integrations) | 3 | 0 | yes | yes | manager: integration custom-server-telegram; to be defined | no MITRE | 1 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| socfortress-ops | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 243 | 2 | no | yes (54 warnings) | `osquery`, `win-defender`, `win-powershell`, `win-sysmon`; to be defined | 67% of 3 techniques | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
