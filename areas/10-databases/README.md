# 10-databases

MySQL, MSSQL, PostgreSQL, MongoDB (auditing/DAM).

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| dam-mysql-mssql-postgresql | [mjvmsteixeira/wazuh-database-compliance](https://github.com/mjvmsteixeira/wazuh-database-compliance) | 37 | 9 | yes | yes | `pack-dam-mysql-mssql-postgresql` | no MITRE | 2 ok (1 containment) | MIT | 2026-07-12 | 7 |
| mysql | [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) | 0 | 10 | yes | yes | to be defined | no MITRE | — | NONE | 2025-05-31 | — |
| postgres | [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) | 0 | 7 | yes | yes | to be defined | no MITRE | — | NONE | 2025-05-31 | — |
| wazuh-blog-pack | [adampielak/wazuh-scripts-resource](https://github.com/adampielak/wazuh-scripts-resource) | 20 | 0 | no | yes (3 warnings) | `pack-wazuh-blog-pack`; manager: wodle aws-s3 | 100% of 7 techniques | — | NONE | 2026-06-27 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
