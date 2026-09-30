# 04-macos

macOS and Jamf.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| detection-engineering | [Jeremy-Burgos/wazuh-detection-engineering](https://github.com/Jeremy-Burgos/wazuh-detection-engineering) | 29 | 12 | no | yes (2 warnings) | to be defined | 100% of 12 techniques | — | MIT | 2026-04-10 | — |
| jamf | [phastier/wazuh](https://github.com/phastier/wazuh) | 26 | 7 | yes | yes | to be defined | 83% of 6 techniques | — | NONE | 2026-09-02 | — |
| macos | [phastier/wazuh](https://github.com/phastier/wazuh) | 21 | 18 | yes | yes | to be defined | 100% of 6 techniques | — | NONE | 2026-09-02 | — |
| monitoring-macos-resources | [wazuh.com/blog](https://wazuh.com/blog/) | 8 | 16 | yes | yes | `pack-monitoring-macos-resources` | no MITRE | 2 broken | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| monitoring-usb-drives-in-macos-using-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 6 | 0 | no | yes (4 warnings) | `pack-monitoring-usb-drives-in-macos-using-wazuh` | no MITRE | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
