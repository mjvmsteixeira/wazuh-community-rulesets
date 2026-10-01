# 15-infra-virt-storage-backup

Proxmox/PBS, VMware, Synology, QNAP, Veeam.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| esxi | [pfuz/wazuh-ruleset](https://github.com/pfuz/wazuh-ruleset) | 20 | 26 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2025-01-24 | — |
| monitoring-hyper-v-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 9 | 0 | yes | yes | `pack-monitoring-hyper-v-with-wazuh`; to be defined | no MITRE | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| monitoring-vmware-esxi-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 22 | 24 | no | no | `pack-monitoring-vmware-esxi-with-wazuh` | no MITRE | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| proxmox | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 4 | 0 | yes | yes | `pack-proxmox` | no MITRE | — | NONE | 2026-06-16 | — |
| proxmox | [captainobvious-sec/wazuh-field-notes](https://github.com/captainobvious-sec/wazuh-field-notes) | 32 | 6 | yes | yes | manager: remote syslog | 100% of 10 techniques | — | MIT | 2026-09-14 | — |
| proxmox | [phastier/wazuh](https://github.com/phastier/wazuh) | 18 | 16 | no | no | `linux-apache`; manager: remote syslog | 100% of 4 techniques | — | NONE | 2026-09-02 | — |
| qnap | [grandir66/wazuh-multivendor-installer](https://github.com/grandir66/wazuh-multivendor-installer) | 22 | 11 | yes | yes | manager: remote syslog | 60% of 5 techniques | — | NONE | 2026-09-06 | — |
| qnap | [wazuh/integrations](https://github.com/wazuh/integrations) | 8 | 7 | yes | yes | manager: remote syslog | no MITRE | 1 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| synology | [BeardedTinker/wazuh-homelab-security](https://github.com/BeardedTinker/wazuh-homelab-security) | 5 | 1 | yes | yes | `pack-synology` | no MITRE | — | NONE | 2026-09-28 | — |
| synology | [Tomo-9925/wazuh-synology-dsm-decoder-and-rules](https://github.com/Tomo-9925/wazuh-synology-dsm-decoder-and-rules) | 11 | 19 | yes | yes | manager: remote syslog | 80% of 5 techniques | — | NONE | 2025-07-29 | — |
| synology | [fredycibersec/wazuh-stuff](https://github.com/fredycibersec/wazuh-stuff) | 12 | 14 | yes | no | `pack-synology` | 60% of 5 techniques | — | MIT | 2025-06-09 | — |
| synology | [grandir66/wazuh-multivendor-installer](https://github.com/grandir66/wazuh-multivendor-installer) | 17 | 0 | yes | yes | to be defined | 50% of 4 techniques | — | NONE | 2026-09-06 | — |
| synology | [phastier/wazuh](https://github.com/phastier/wazuh) | 15 | 9 | yes | yes | manager: remote syslog | 100% of 4 techniques | — | NONE | 2026-09-02 | — |
| synology | [st0rm-cr0w/wazuh-synology-dsm-nas-decoder-and-rules](https://github.com/st0rm-cr0w/wazuh-synology-dsm-nas-decoder-and-rules) | 16 | 20 | yes | yes | manager: remote syslog | 80% of 10 techniques | — | NONE | 2024-05-10 | — |
| synology | [wazuh/integrations](https://github.com/wazuh/integrations) | 11 | 10 | yes | yes | manager: remote syslog | no MITRE | 1 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| veeam | [mritsurgeon/wazuh](https://github.com/mritsurgeon/wazuh) | 383 | 65 | yes | no | manager: remote syslog | 90% of 10 techniques | — | NONE | 2025-10-23 | — |
| veeam | [pfuz/wazuh-ruleset](https://github.com/pfuz/wazuh-ruleset) | 2 | 19 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2025-01-24 | — |
| vmware | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 4 | 0 | yes | yes | `pack-vmware` | no MITRE | — | NONE | 2026-06-16 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
