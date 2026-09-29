# 04-macos

macOS and Jamf.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| detection-engineering | [Jeremy-Burgos/wazuh-detection-engineering](https://github.com/Jeremy-Burgos/wazuh-detection-engineering) | 29 | 12 | no | yes (2 warnings) | to be defined | 100% of 12 techniques | — | MIT | 2026-04-10 | — |
| jamf | [phastier/wazuh](https://github.com/phastier/wazuh) | 26 | 7 | yes | yes | to be defined | 83% of 6 techniques | — | NONE | 2026-09-02 | — |
| macos | [phastier/wazuh](https://github.com/phastier/wazuh) | 21 | 18 | yes | yes | to be defined | 100% of 6 techniques | — | NONE | 2026-09-02 | — |
| wazuh-blog-pack | [adampielak/wazuh-scripts-resource](https://github.com/adampielak/wazuh-scripts-resource) | 13 | 28 | yes | yes | `pack-wazuh-blog-pack` | 75% of 8 techniques | — | NONE | 2026-06-27 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
