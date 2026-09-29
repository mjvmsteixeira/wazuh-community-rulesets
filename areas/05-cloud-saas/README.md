# 05-cloud-saas

AWS, Azure, Google Workspace, Microsoft 365, Yandex, OCI, enterprise SaaS.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| activemq | [wazuh/integrations](https://github.com/wazuh/integrations) | 16 | 1 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| airflow | [wazuh/integrations](https://github.com/wazuh/integrations) | 19 | 1 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| atlassian-bitbucket | [wazuh/integrations](https://github.com/wazuh/integrations) | 14 | 0 | yes | yes | — | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| aws-bedrock | [wazuh/integrations](https://github.com/wazuh/integrations) | 5 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| aws-mq | [wazuh/integrations](https://github.com/wazuh/integrations) | 7 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| aws | [wazuh/integrations](https://github.com/wazuh/integrations) | 52 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| azure-application-insights | [wazuh/integrations](https://github.com/wazuh/integrations) | 4 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| azure-devops | [yunusmrcoban/wazuh-custom](https://github.com/yunusmrcoban/wazuh-custom) | 15 | 0 | yes | yes | to be defined | no MITRE | — | NONE | 2025-10-21 | — |
| azure-frontdoor | [wazuh/integrations](https://github.com/wazuh/integrations) | 5 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| azure-functions | [wazuh/integrations](https://github.com/wazuh/integrations) | 4 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| azure-metrics | [wazuh/integrations](https://github.com/wazuh/integrations) | 9 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| azure | [wazuh/integrations](https://github.com/wazuh/integrations) | 17 | 0 | yes | yes | to be defined | no MITRE | 1 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| corpsec-gws-intune | [calvinanglo/corpsec-ops-platform](https://github.com/calvinanglo/corpsec-ops-platform) | 59 | 7 | yes | no | `osquery`, `pack-corpsec-gws-intune`, `win-sysmon`; manager: integration custom-n8n-alert, integration custom-n8n-critical, localfile /var/ossec/logs/active-responses.log | 88% of 17 techniques | 2 ok (2 containment), 2 broken, 1 destructive without allowlist | NONE | 2026-05-02 | 1 |
| google-workspace | [wazuh/integrations](https://github.com/wazuh/integrations) | 22 | 0 | yes | yes | `pack-google-workspace`; to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| m365-aws-sap | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 157 | 0 | yes | yes | to be defined | 56% of 27 techniques | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| m365-inventory | [wazuh/integrations](https://github.com/wazuh/integrations) | 21 | 0 | yes | yes | `pack-m365-inventory`; manager: localfile /var/ossec/logs/m365_inventory.log | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| netsuite | [wazuh/integrations](https://github.com/wazuh/integrations) | 3 | 0 | yes | yes | `pack-netsuite` | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| office365 | [phastier/wazuh](https://github.com/phastier/wazuh) | 11 | 0 | yes | yes | manager: module office365 | 89% of 9 techniques | — | NONE | 2026-09-02 | — |
| oracle-cloud-infrastructure-streaming | [wazuh/integrations](https://github.com/wazuh/integrations) | 1 | 4 | yes | yes | `pack-oracle-cloud-infrastructure-streaming`; to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| salesforce | [wazuh/integrations](https://github.com/wazuh/integrations) | 1 | 6 | yes | yes | `pack-salesforce`; to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| stratus-red-team | [TheMuntu/Wazuh-Detection](https://github.com/TheMuntu/Wazuh-Detection) | 5 | 0 | yes | yes | manager: wodle aws-s3 | 67% of 6 techniques | — | NONE | 2024-11-01 | — |
| wazuh-blog-pack | [adampielak/wazuh-scripts-resource](https://github.com/adampielak/wazuh-scripts-resource) | 36 | 41 | no | yes (1 warning) | `pack-wazuh-blog-pack`; manager: integration custom-aws_block_host, wodle aws-s3, wodle gcp-pubsub | 80% of 10 techniques | 1 broken | NONE | 2026-06-27 | — |
| yandex-cloud | [opennix-solutions/wazuh-yandex-cloud-rules](https://github.com/opennix-solutions/wazuh-yandex-cloud-rules) | 274 | 0 | yes | yes | to be defined | 0% of 3 techniques | — | BSD | 2024-03-01 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
