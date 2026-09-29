# 90-misc

Very specific cases (games, local ERPs, internal policies).

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| minecraft | [hrHVN/Wazuh_games](https://github.com/hrHVN/Wazuh_games) | 1 | 4 | yes | yes | `pack-minecraft`; manager: localfile /var/ossec/logs/active-responses.log | no MITRE | — | NONE | 2025-08-17 | — |
| politicas-internas | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 8 | 0 | no | yes (4 warnings) | `pack-politicas-internas`; manager: integration custom-telegram, integration custom-vkteams | 100% of 2 techniques | 2 ok (0 containment) | NONE | 2026-06-16 | — |
| politicas-internas | [bret99/wazuh_custom_rules](https://github.com/bret99/wazuh_custom_rules) | 21 | 0 | no | no | `linux-auditd`, `pack-politicas-internas`; manager: integration custom-telegram, integration custom-vkteams | 50% of 6 techniques | 2 ok (0 containment) | MIT | 2026-08-05 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
