# 10-databases

MySQL, MSSQL, PostgreSQL, MongoDB (auditing/DAM).

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| dam-mysql-mssql-postgresql | [mjvmsteixeira/wazuh-database-compliance](https://github.com/mjvmsteixeira/wazuh-database-compliance) | 37 | 9 | yes | yes | `pack-dam-mysql-mssql-postgresql` | no MITRE | 2 ok (1 containment) | MIT | 2026-07-12 | 7 |
| monitoring-mariadb-server-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 15 | 2 | yes | yes | to be defined | 71% of 7 techniques | 1 ok (0 containment), 1 broken | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| monitoring-mongodb-atlas-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 11 | 0 | yes | yes | `pack-monitoring-mongodb-atlas-with-wazuh`; manager: wodle aws-s3 | 100% of 4 techniques | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| monitoring-mongodb-database-using-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 12 | 0 | yes | yes | `pack-monitoring-mongodb-database-using-wazuh` | 100% of 5 techniques | 1 ok (1 containment), 1 broken | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| monitoring-postgresql-database-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 7 | 13 | yes | yes | `pack-monitoring-postgresql-database-with-wazuh` | 100% of 2 techniques | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| mysql | [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) | 0 | 10 | yes | yes | to be defined | no MITRE | — | NONE | 2025-05-31 | — |
| postgres | [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) | 0 | 7 | yes | yes | to be defined | no MITRE | — | NONE | 2025-05-31 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
