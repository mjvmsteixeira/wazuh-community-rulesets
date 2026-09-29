# 06-containers-k8s

Falco, Docker, Kubernetes, Tetragon.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| docker-journald | [mootzen/wazuhToolSet](https://github.com/mootzen/wazuhToolSet) | 3 | 2 | yes | yes | to be defined | no MITRE | — | NONE | 2026-02-16 | — |
| docker | [phastier/wazuh](https://github.com/phastier/wazuh) | 7 | 4 | yes | yes | `linux-docker`; to be defined | no MITRE | — | NONE | 2026-09-02 | — |
| falco | [Myth799/cyber-sec-k8s-security-deployment](https://github.com/Myth799/cyber-sec-k8s-security-deployment) | 7 | 1 | yes | yes | to be defined | 100% of 1 techniques | — | NONE | 2026-09-17 | — |
| falco | [michelep/wazuh-falco](https://github.com/michelep/wazuh-falco) | 5 | 7 | yes | yes | to be defined | no MITRE | — | GPL-2.0 | 2021-08-23 | — |
| falco | [paaszti/Wazuh-Falco-integration](https://github.com/paaszti/Wazuh-Falco-integration) | 8 | 1 | yes | yes | `pack-falco`; to be defined | no MITRE | — | NONE | 2025-11-27 | — |
| falco | [zeinoux/siem-falco-wazuh](https://github.com/zeinoux/siem-falco-wazuh) | 5 | 7 | yes | yes | `linux-docker`, `osquery`, `pack-falco`; manager: localfile /var/ossec/logs/active-responses.log, wodle cis-cat | no MITRE | — | NONE | 2022-06-16 | — |
| tetragon-falco | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 298 | 0 | yes | yes | to be defined | 49% of 98 techniques | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| wazuh-blog-pack | [adampielak/wazuh-scripts-resource](https://github.com/adampielak/wazuh-scripts-resource) | 51 | 11 | no | yes | `linux-docker`, `osquery`, `pack-wazuh-blog-pack`; manager: wodle cis-cat | 67% of 9 techniques | 1 broken | NONE | 2026-06-27 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
