# 08-ndr-ids

Suricata, Zeek, Maltrail, Packetbeat, commercial NDR, honeypots, scans.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| armis | [wazuh/integrations](https://github.com/wazuh/integrations) | 15 | 0 | yes | yes | — | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| crowdsec | [od55/wazuh-local-ruleset](https://github.com/od55/wazuh-local-ruleset) | 0 | 2 | yes | yes | to be defined | no MITRE | — | NONE | 2026-01-28 | — |
| darktrace | [fredycibersec/wazuh-stuff](https://github.com/fredycibersec/wazuh-stuff) | 10 | 7 | yes | yes | `pack-darktrace` | 50% of 2 techniques | — | MIT | 2025-06-09 | — |
| flowtriq | [wazuh/integrations](https://github.com/wazuh/integrations) | 12 | 12 | yes | yes | to be defined | 100% of 2 techniques | — | AGPL-3.0 | 2026-09-11 | — |
| lumu | [wazuh/integrations](https://github.com/wazuh/integrations) | 5 | 1 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| maltrail | [MikhailKasimov/maltrail-wazuh-decoder-and-rules](https://github.com/MikhailKasimov/maltrail-wazuh-decoder-and-rules) | 5 | 2 | yes | yes | to be defined | 0% of 1 techniques | — | GPL-2.0 | 2025-04-12 | — |
| maltrail | [hawkteam404/Wazuh](https://github.com/hawkteam404/Wazuh) | 5 | 0 | no | no | — | 0% of 1 techniques | — | NONE | 2025-09-30 | — |
| monitoring-dhcp-starvation-attack-with-suricata-and-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 1 | 0 | yes | yes (2 warnings) | `linux-suricata` | 100% of 1 techniques | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| network-security-monitoring-with-wazuh-and-zeek | [wazuh.com/blog](https://wazuh.com/blog/) | 8 | 47 | yes | yes | `pack-network-security-monitoring-with-wazuh-and-zeek` | no MITRE | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| nids-honeypot | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 22 | 2 | yes | yes | `linux-suricata`, `pack-nids-honeypot` | 50% of 2 techniques | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| nta | [od55/wazuh-local-ruleset](https://github.com/od55/wazuh-local-ruleset) | 0 | 1 | yes | yes | to be defined | no MITRE | — | NONE | 2026-01-28 | — |
| responding-to-network-attacks-with-suricata-and-wazuh-xdr | [wazuh.com/blog](https://wazuh.com/blog/) | 2 | 3 | yes | yes (4 warnings) | `linux-suricata` | 100% of 2 techniques | 1 ok (1 containment) | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| trend-micro-ddi | [wazuh/integrations](https://github.com/wazuh/integrations) | 12 | 20 | yes | no | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| zeek | [mellomatcha/wazuh](https://github.com/mellomatcha/wazuh) | 58 | 15 | yes | yes | to be defined | no MITRE | — | NONE | 2026-02-11 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
