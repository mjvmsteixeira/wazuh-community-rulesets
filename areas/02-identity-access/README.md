# 02-identity-access

Active Directory, Entra ID, Okta, Duo, Auth0, Authentik, password vaults.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| 1password | [wazuh/integrations](https://github.com/wazuh/integrations) | 11 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| active-directory | [JM2K69/WAZUH-Sentinel-AD](https://github.com/JM2K69/WAZUH-Sentinel-AD) | 47 | 0 | yes | yes | `win-sysmon`; to be defined | 48% of 33 techniques | — | MIT | 2025-06-18 | — |
| active-directory | [LeeHoang26/ad-kerberos-attack-detection-soar](https://github.com/LeeHoang26/ad-kerberos-attack-detection-soar) | 3 | 0 | yes | yes | manager: integration custom-soar.py | 33% of 3 techniques | 1 ok (1 containment) | NONE | 2026-09-12 | — |
| active-directory | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 1 | 0 | no | no | — | no MITRE | — | NONE | 2026-06-16 | — |
| active-directory | [mellomatcha/wazuh](https://github.com/mellomatcha/wazuh) | 4 | 0 | yes | no | default | 67% of 3 techniques | — | NONE | 2026-02-11 | — |
| active-directory | [wazuh/integrations](https://github.com/wazuh/integrations) | 1 | 0 | yes | yes | default | 0% of 1 techniques | — | AGPL-3.0 | 2026-09-11 | — |
| ad-duo-pingcastle | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 19 | 0 | no | yes (2 warnings) | to be defined | no MITRE | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| aruba-clearpass | [parlakbarann/wazuh-custom-network-decoders](https://github.com/parlakbarann/wazuh-custom-network-decoders) | 0 | 45 | yes | yes | to be defined | no MITRE | — | NONE | 2025-12-13 | — |
| auth0 | [wazuh/integrations](https://github.com/wazuh/integrations) | 3 | 0 | yes | yes | `pack-auth0` | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| authentik | [phastier/wazuh](https://github.com/phastier/wazuh) | 26 | 2 | yes | yes | to be defined | 100% of 5 techniques | — | NONE | 2026-09-02 | — |
| authentik | [wazuh/integrations](https://github.com/wazuh/integrations) | 5 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| beyondinsight-password-safe | [wazuh/integrations](https://github.com/wazuh/integrations) | 6 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| beyondtrust | [pfuz/wazuh-ruleset](https://github.com/pfuz/wazuh-ruleset) | 6 | 23 | yes | yes | to be defined | no MITRE | — | NONE | 2025-01-24 | — |
| bitwarden | [timohissink/vault-event-monitor](https://github.com/timohissink/vault-event-monitor) | 45 | 0 | yes | yes | to be defined | 100% of 1 techniques | — | MIT | 2026-07-31 | — |
| entra-id | [yunusmrcoban/wazuh-custom](https://github.com/yunusmrcoban/wazuh-custom) | 6 | 13 | yes | yes | to be defined | no MITRE | — | NONE | 2025-10-21 | — |
| keycloak | [stephane-segning/keycloak-wazuh-siem](https://github.com/stephane-segning/keycloak-wazuh-siem) | 18 | 1 | no | yes (1 warning) | `osquery`, `pack-keycloak`; manager: localfile /var/ossec/logs/active-responses.log, wodle cis-cat; to be defined | 100% of 5 techniques | — | NONE | 2025-05-23 | — |
| mfa | [od55/wazuh-local-ruleset](https://github.com/od55/wazuh-local-ruleset) | 0 | 22 | yes | yes | to be defined | no MITRE | — | NONE | 2026-01-28 | — |
| nps | [od55/wazuh-local-ruleset](https://github.com/od55/wazuh-local-ruleset) | 0 | 2 | yes | yes | to be defined | no MITRE | — | NONE | 2026-01-28 | — |
| okta | [calvinanglo/corpsec-ops-platform](https://github.com/calvinanglo/corpsec-ops-platform) | 17 | 0 | yes | no | to be defined | 80% of 10 techniques | — | NONE | 2026-05-02 | — |
| okta | [moizl599/wazuh_okta-integration](https://github.com/moizl599/wazuh_okta-integration) | 17 | 0 | yes | yes | to be defined | no MITRE | — | NONE | 2023-09-26 | — |
| okta | [wazuh/integrations](https://github.com/wazuh/integrations) | 9 | 75 | yes | yes | — | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| onepassword | [calvinanglo/corpsec-ops-platform](https://github.com/calvinanglo/corpsec-ops-platform) | 14 | 0 | yes | no | to be defined | 100% of 5 techniques | — | NONE | 2026-05-02 | — |
| openbao | [bayusky/wazuh-custom-rules-and-decoders](https://github.com/bayusky/wazuh-custom-rules-and-decoders) | 9 | 0 | yes | yes | to be defined | no MITRE | — | GPL-2.0 | 2026-03-07 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
