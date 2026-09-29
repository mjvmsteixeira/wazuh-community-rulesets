# 16-dns-email

DNS (Pi-hole, Technitium), email and phishing (Mimecast, Zimbra, Abnormal, Sublime).

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| abnormal-security | [wazuh/integrations](https://github.com/wazuh/integrations) | 14 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| bind | [od55/wazuh-local-ruleset](https://github.com/od55/wazuh-local-ruleset) | 0 | 11 | yes | yes | to be defined | no MITRE | — | NONE | 2026-01-28 | — |
| email-phishing | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 2 | 0 | yes | yes | — | no MITRE | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| orangebox | [OrangeBox-Labs/Wazuh](https://github.com/OrangeBox-Labs/Wazuh) | 2 | 0 | yes | yes | to be defined | 100% of 1 techniques | 1 ok (1 containment) | NONE | 2026-09-29 | — |
| pi-hole | [Tomo-9925/wazuh-pi-hole-decoder-and-rules](https://github.com/Tomo-9925/wazuh-pi-hole-decoder-and-rules) | 3 | 6 | yes | no | `pack-pi-hole` | 67% of 3 techniques | — | NONE | 2025-06-11 | — |
| stalwart-mail | [lulzkiller666/Custom-Wazuh-decoders-and-rules](https://github.com/lulzkiller666/Custom-Wazuh-decoders-and-rules) | 15 | 13 | yes | yes | to be defined | no MITRE | — | NONE | 2025-09-07 | — |
| technitium-dns | [wazuh/integrations](https://github.com/wazuh/integrations) | 9 | 0 | no | yes (1 warning) | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| trend-micro-email | [Maverick000011/wazuh-custom-decoders](https://github.com/Maverick000011/wazuh-custom-decoders) | 0 | 11 | yes | yes | to be defined | no MITRE | — | NONE | 2026-09-02 | — |
| wazuh-blog-pack | [adampielak/wazuh-scripts-resource](https://github.com/adampielak/wazuh-scripts-resource) | 15 | 53 | no | yes (3 warnings) | `pack-wazuh-blog-pack` | 50% of 2 techniques | — | NONE | 2026-06-27 | — |
| zimbra | [Lordkaly/wazuh-collection](https://github.com/Lordkaly/wazuh-collection) | 10 | 18 | yes | yes | `pack-zimbra` | no MITRE | — | GPL-3.0 | 2025-02-06 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
