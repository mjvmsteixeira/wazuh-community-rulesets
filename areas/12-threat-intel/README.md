# 12-threat-intel

MISP, OpenCTI, AbuseIPDB, VirusTotal, OTX, SOCRadar, GTI, domain reputation.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| abuseipdb | [wazuh/integrations](https://github.com/wazuh/integrations) | 10 | 0 | yes | yes | manager: integration custom-abuseipdb; to be defined | no MITRE | 3 ok (0 containment), 1 broken | AGPL-3.0 | 2026-09-11 | — |
| alienvault-otx | [wazuh/integrations](https://github.com/wazuh/integrations) | 14 | 0 | yes | yes | manager: integration custom-alienvault; to be defined | no MITRE | 1 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| criminalip | [shahidakhter786/wazuh-criminalip-integration](https://github.com/shahidakhter786/wazuh-criminalip-integration) | 21 | 0 | yes | yes | manager: integration custom-criminalip; to be defined | no MITRE | 1 broken | MIT | 2024-08-20 | — |
| google-threat-intelligence | [wazuh/integrations](https://github.com/wazuh/integrations) | 6 | 0 | yes | yes | `pack-google-threat-intelligence`; manager: integration custom-gti | no MITRE | 1 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| malware-ip | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 6 | 0 | no | yes (6 warnings) | default | no MITRE | — | NONE | 2026-06-16 | — |
| misp | [MISP/wazuh-integration](https://github.com/MISP/wazuh-integration) | 6 | 0 | no | yes (1 warning) | manager: integration None; to be defined | no MITRE | 2 ok (0 containment) | NONE | 2025-10-06 | — |
| misp | [bayusky/wazuh-custom-rules-and-decoders](https://github.com/bayusky/wazuh-custom-rules-and-decoders) | 4 | 0 | yes | yes | — | no MITRE | 2 ok (2 containment), 2 destructive without allowlist | GPL-2.0 | 2026-03-07 | — |
| misp | [wazuh/integrations](https://github.com/wazuh/integrations) | 38 | 0 | yes | yes | `win-sysmon`; manager: integration custom-misp-ips.py, integration custom-misp.py; to be defined | no MITRE | 2 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| opencti-retrohunt | [federicofantini/Wazuh-TI](https://github.com/federicofantini/Wazuh-TI) | 21 | 0 | no | yes (14 warnings) | `linux-suricata`, `win-sysmon`; manager: localfile /var/ossec/logs/opencti_retrohunt_events.json | no MITRE | — | GPL-3.0 | 2026-09-25 | — |
| opencti | [bayusky/wazuh-custom-rules-and-decoders](https://github.com/bayusky/wazuh-custom-rules-and-decoders) | 3 | 0 | yes | yes | — | no MITRE | — | GPL-2.0 | 2026-03-07 | — |
| opencti | [hawkteam404/Wazuh](https://github.com/hawkteam404/Wazuh) | 7 | 0 | yes | yes | to be defined | no MITRE | — | NONE | 2025-09-30 | — |
| orangebox | [OrangeBox-Labs/Wazuh](https://github.com/OrangeBox-Labs/Wazuh) | 5 | 0 | no | yes (4 warnings) | default | 100% of 2 techniques | 1 ok (1 containment) | NONE | 2026-09-29 | — |
| socradar | [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) | 0 | 3 | yes | yes | to be defined | no MITRE | — | NONE | 2025-05-31 | — |
| socradar | [wazuh/integrations](https://github.com/wazuh/integrations) | 22 | 2 | no | yes (7 warnings) | `pack-socradar`; manager: integration custom-socradar; to be defined | no MITRE | 1 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| ti-enrichment | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 23 | 0 | yes | yes | manager: integration custom-dnsstats, integration custom-misp, integration custom-opencti; to be defined | 50% of 2 techniques | 1 ok (0 containment) | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| virustotal-ip | [wazuh/integrations](https://github.com/wazuh/integrations) | 3 | 0 | yes | yes | manager: integration custom-virustotal_ip, integration virustotal | no MITRE | 3 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
