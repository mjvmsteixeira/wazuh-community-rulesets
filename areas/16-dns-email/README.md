# 16-dns-email

DNS (Pi-hole, Technitium), email and phishing (Mimecast, Zimbra, Abnormal, Sublime).

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| abnormal-security | [wazuh/integrations](https://github.com/wazuh/integrations) | 14 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| bind | [od55/wazuh-local-ruleset](https://github.com/od55/wazuh-local-ruleset) | 0 | 11 | yes | yes | to be defined | no MITRE | — | NONE | 2026-01-28 | — |
| detecting-dns-spoofing-attacks-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 7 | 47 | no | yes (2 warnings) | `pack-detecting-dns-spoofing-attacks-with-wazuh` | 50% of 2 techniques | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| detecting-dns-tunneling-attacks-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 8 | 6 | yes | yes | `pack-detecting-dns-tunneling-attacks-with-wazuh` | no MITRE | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| detecting-phishing-attacks-with-wazuh-and-shuffle | [wazuh.com/blog](https://wazuh.com/blog/) | 5 | 0 | no | yes (6 warnings) | manager: integration shuffle, integration slack, module office365; to be defined | no MITRE | 2 ok (0 containment) | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| email-phishing | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 2 | 0 | yes | yes | — | no MITRE | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| how-to-send-email-notifications-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 3 | 0 | no | no | `linux-apache`, `pack-how-to-send-email-notifications-with-wazuh` | no MITRE | 1 broken | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| integrating-mimecast-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 16 | 69 | yes | yes | `pack-integrating-mimecast-with-wazuh` | 67% of 9 techniques | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| orangebox | [OrangeBox-Labs/Wazuh](https://github.com/OrangeBox-Labs/Wazuh) | 2 | 0 | yes | yes | to be defined | 100% of 1 techniques | 1 ok (1 containment) | NONE | 2026-09-29 | — |
| pi-hole | [Tomo-9925/wazuh-pi-hole-decoder-and-rules](https://github.com/Tomo-9925/wazuh-pi-hole-decoder-and-rules) | 3 | 6 | yes | no | `pack-pi-hole` | 67% of 3 techniques | — | NONE | 2025-06-11 | — |
| stalwart-mail | [lulzkiller666/Custom-Wazuh-decoders-and-rules](https://github.com/lulzkiller666/Custom-Wazuh-decoders-and-rules) | 15 | 13 | yes | yes | to be defined | no MITRE | — | NONE | 2025-09-07 | — |
| technitium-dns | [wazuh/integrations](https://github.com/wazuh/integrations) | 9 | 0 | no | yes (1 warning) | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| trend-micro-email | [Maverick000011/wazuh-custom-decoders](https://github.com/Maverick000011/wazuh-custom-decoders) | 0 | 11 | yes | yes | to be defined | no MITRE | — | NONE | 2026-09-02 | — |
| zimbra | [Lordkaly/wazuh-collection](https://github.com/Lordkaly/wazuh-collection) | 10 | 18 | yes | yes | `pack-zimbra` | no MITRE | — | GPL-3.0 | 2025-02-06 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
