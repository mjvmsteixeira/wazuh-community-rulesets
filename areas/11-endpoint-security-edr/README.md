# 11-endpoint-security-edr

Commercial EDR/AV/XDR, YARA, Osquery, EPM.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| admin-by-request-epm | [wazuh/integrations](https://github.com/wazuh/integrations) | 16 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| bitdefender-gravityzone | [wazuh/integrations](https://github.com/wazuh/integrations) | 11 | 40 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| cortex-xdr | [femontanher/cortex-xdr-wazuh-api-integration](https://github.com/femontanher/cortex-xdr-wazuh-api-integration) | 4 | 6 | yes | yes | manager: localfile /var/ossec/logs/cortex_xdr/alerts.json | no MITRE | — | NONE | 2026-03-24 | — |
| cortex | [wazuh/integrations](https://github.com/wazuh/integrations) | 6 | 16 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| crowdstrike | [calvinanglo/corpsec-ops-platform](https://github.com/calvinanglo/corpsec-ops-platform) | 20 | 0 | yes | no | to be defined | 100% of 4 techniques | — | NONE | 2026-05-02 | — |
| edr-av | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 93 | 2 | yes | yes | `pack-edr-av` | 52% of 31 techniques | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| edr | [calvinanglo/corpsec-ops-platform](https://github.com/calvinanglo/corpsec-ops-platform) | 13 | 0 | yes | yes | `win-sysmon` | 77% of 13 techniques | — | NONE | 2026-05-02 | — |
| eset | [bayusky/wazuh-custom-rules-and-decoders](https://github.com/bayusky/wazuh-custom-rules-and-decoders) | 1261 | 0 | yes | yes | to be defined | 54% of 273 techniques | — | GPL-2.0 | 2026-03-07 | — |
| kaspersky-ksc | [tread-lightly/KSC_decoders_and_rules_for_Wazuh](https://github.com/tread-lightly/KSC_decoders_and_rules_for_Wazuh) | 60 | 19 | yes | yes | to be defined | 55% of 11 techniques | — | NONE | 2024-08-16 | — |
| kaspersky | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 1 | 3 | yes | yes | to be defined | no MITRE | — | NONE | 2026-06-16 | — |
| kaspersky | [fredycibersec/wazuh-stuff](https://github.com/fredycibersec/wazuh-stuff) | 11 | 29 | yes | yes | `pack-kaspersky` | 67% of 3 techniques | — | MIT | 2025-06-09 | — |
| ms-defender | [fredycibersec/wazuh-stuff](https://github.com/fredycibersec/wazuh-stuff) | 10 | 20 | no | yes (3 warnings) | `win-defender` | no MITRE | — | MIT | 2025-06-09 | — |
| orangebox | [OrangeBox-Labs/Wazuh](https://github.com/OrangeBox-Labs/Wazuh) | 4 | 2 | yes | yes | to be defined | 100% of 1 techniques | 1 ok (0 containment) | NONE | 2026-09-29 | — |
| rapid7 | [wazuh/integrations](https://github.com/wazuh/integrations) | 1 | 2 | yes | yes | `pack-rapid7` | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| sentinelone | [pfuz/wazuh-ruleset](https://github.com/pfuz/wazuh-ruleset) | 5 | 0 | yes | yes | to be defined | no MITRE | — | NONE | 2025-01-24 | — |
| sophos-central | [michelep/wazuh-rules-sophos-cloud](https://github.com/michelep/wazuh-rules-sophos-cloud) | 4 | 0 | yes | yes | to be defined | no MITRE | — | NONE | 2021-11-17 | — |
| sophos-central | [wazuh/integrations](https://github.com/wazuh/integrations) | 3 | 0 | yes | yes | `pack-sophos-central` | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| suspicious-processes | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 1 | 0 | yes | yes | to be defined | no MITRE | — | NONE | 2026-06-16 | — |
| trend-micro | [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) | 0 | 7 | yes | yes | to be defined | no MITRE | — | NONE | 2025-05-31 | — |
| withsecure | [fredycibersec/wazuh-stuff](https://github.com/fredycibersec/wazuh-stuff) | 12 | 19 | yes | yes | to be defined | 86% of 7 techniques | — | MIT | 2025-06-09 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
