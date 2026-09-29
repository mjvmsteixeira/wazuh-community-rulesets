# 09-web-apps-waf

Web attacks, WAF, proxies/LB, web and collaboration apps.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| akamai | [wazuh/integrations](https://github.com/wazuh/integrations) | 6 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| barracuda-waf | [wazuh/integrations](https://github.com/wazuh/integrations) | 1 | 5 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| barracuda | [pfuz/wazuh-ruleset](https://github.com/pfuz/wazuh-ruleset) | 4 | 15 | yes | yes | to be defined | no MITRE | — | NONE | 2025-01-24 | — |
| bitrix | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 6 | 12 | yes | no | `pack-bitrix` | no MITRE | — | NONE | 2026-06-16 | — |
| caddy | [NucleiAv/caddy-detection-rules](https://github.com/NucleiAv/caddy-detection-rules) | 29 | 2 | yes | yes | `pack-caddy` | 60% of 15 techniques | — | GPL-3.0 | 2026-07-03 | 1 |
| caddy | [tread-lightly/Caddy_decoders_for_Wazuh](https://github.com/tread-lightly/Caddy_decoders_for_Wazuh) | 0 | 5 | yes | yes | to be defined | no MITRE | — | NONE | 2024-07-23 | — |
| confluence | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 3 | 0 | yes | yes | — | 50% of 4 techniques | — | NONE | 2026-06-16 | — |
| directum | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 5 | 0 | yes | yes | `pack-directum` | 50% of 4 techniques | — | NONE | 2026-06-16 | — |
| envoy | [chrisandoryan/Wazoy](https://github.com/chrisandoryan/Wazoy) | 2 | 4 | yes | yes | `pack-envoy` | no MITRE | — | NONE | 2024-08-10 | — |
| filezilla-sftp | [navein-kumar/wazuh-filezilla-sftp-rules](https://github.com/navein-kumar/wazuh-filezilla-sftp-rules) | 7 | 1 | yes | yes | — | no MITRE | — | NONE | 2022-03-12 | — |
| haproxy | [bayusky/wazuh-custom-rules-and-decoders](https://github.com/bayusky/wazuh-custom-rules-and-decoders) | 33 | 10 | yes | yes | `pack-haproxy` | 70% of 10 techniques | 1 ok (0 containment) | GPL-2.0 | 2026-03-07 | — |
| jira | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 3 | 0 | no | yes (1 warning) | `pack-jira` | 50% of 4 techniques | — | NONE | 2026-06-16 | — |
| modsecurity | [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) | 0 | 21 | yes | yes | to be defined | no MITRE | — | NONE | 2025-05-31 | — |
| modsecurity | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 1 | 0 | yes | yes | `linux-apache` | no MITRE | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| orangebox | [OrangeBox-Labs/Wazuh](https://github.com/OrangeBox-Labs/Wazuh) | 10 | 0 | yes | yes | `linux-apache` | 60% of 5 techniques | 4 ok (4 containment) | NONE | 2026-09-29 | — |
| skudonet | [dzoelfi/skudonet-wazuh-decoders](https://github.com/dzoelfi/skudonet-wazuh-decoders) | 1 | 9 | yes | yes | to be defined | no MITRE | — | GPL-2.0 | 2024-12-26 | — |
| web-accesslog | [phastier/wazuh](https://github.com/phastier/wazuh) | 2 | 3 | yes | yes | to be defined | 100% of 1 techniques | — | NONE | 2026-09-02 | — |
| web-attacks | [0xbad53c/wazuh-detection-rules](https://github.com/0xbad53c/wazuh-detection-rules) | 5 | 0 | yes | yes | `linux-apache` | no MITRE | — | NONE | 2022-02-13 | — |
| web-attacks | [MORGADO01/wazuh-detection-rules](https://github.com/MORGADO01/wazuh-detection-rules) | 18 | 0 | yes | yes | `linux-apache`, `linux-nginx` | 55% of 11 techniques | — | NONE | 2026-07-28 | — |
| web-attacks | [wirekits/wazuh-rules](https://github.com/wirekits/wazuh-rules) | 160 | 0 | yes | no | `linux-apache` | 73% of 11 techniques | — | NONE | 2026-06-06 | — |
| webshell | [TheMuntu/Wazuh-Detection](https://github.com/TheMuntu/Wazuh-Detection) | 8 | 1 | yes | yes | `linux-auditd`, `win-sysmon` | 60% of 5 techniques | — | NONE | 2024-11-01 | — |
| webshell | [bayusky/wazuh-custom-rules-and-decoders](https://github.com/bayusky/wazuh-custom-rules-and-decoders) | 8 | 0 | yes | yes | `linux-auditd`, `win-sysmon` | 60% of 5 techniques | 1 ok (1 containment), 1 destructive without allowlist | GPL-2.0 | 2026-03-07 | — |
| wpscan | [bayusky/wazuh-custom-rules-and-decoders](https://github.com/bayusky/wazuh-custom-rules-and-decoders) | 2 | 0 | no | yes (2 warnings) | `linux-apache` | 100% of 1 techniques | 1 ok (0 containment) | GPL-2.0 | 2026-03-07 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
