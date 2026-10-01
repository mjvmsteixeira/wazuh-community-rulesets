# 06-containers-k8s

Falco, Docker, Kubernetes, Tetragon.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| auditing-kubernetes-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 5 | 0 | yes | yes | — | no MITRE | 1 ok (1 containment), 1 broken, 2 destructive without allowlist | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| cloud-native-security-with-wazuh-and-falco | [wazuh.com/blog](https://wazuh.com/blog/) | 8 | 0 | yes | yes | `pack-cloud-native-security-with-wazuh-and-falco` | no MITRE | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| container-image-security-with-wazuh-and-trivy | [wazuh.com/blog](https://wazuh.com/blog/) | 6 | 2 | yes | yes | `pack-container-image-security-with-wazuh-and-trivy` | no MITRE | 1 ok (1 containment) | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| container-vulnerability-scanning-with-wazuh-and-snyk | [wazuh.com/blog](https://wazuh.com/blog/) | 5 | 0 | yes | yes | `pack-container-vulnerability-scanning-with-wazuh-and-snyk`; manager: localfile /var/ossec/logs/container_vulnerability_scan.log; to be defined | no MITRE | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| detecting-kubernetes-attacks-with-wazuh-2 | [wazuh.com/blog](https://wazuh.com/blog/) | 16 | 0 | yes | yes | `pack-detecting-kubernetes-attacks-with-wazuh-2` | 60% of 5 techniques | 1 ok (1 containment), 2 broken, 2 destructive without allowlist | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| detecting-kubernetes-with-kubelinter-and-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 9 | 0 | yes | yes | `pack-detecting-kubernetes-with-kubelinter-and-wazuh` | 75% of 4 techniques | 3 broken, 1 destructive without allowlist | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| detecting-vulnerabilities-in-container-images-using-amazon-ecr | [wazuh.com/blog](https://wazuh.com/blog/) | 4 | 0 | yes | yes | manager: wodle aws-s3; to be defined | no MITRE | 1 broken | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| docker-container-security-monitoring-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 6 | 4 | yes | yes | `linux-docker`, `pack-docker-container-security-monitoring-with-wazuh` | no MITRE | 1 ok (1 containment), 1 broken | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| docker-journald | [mootzen/wazuhToolSet](https://github.com/mootzen/wazuhToolSet) | 3 | 2 | yes | yes | to be defined | no MITRE | — | NONE | 2026-02-16 | — |
| docker | [phastier/wazuh](https://github.com/phastier/wazuh) | 7 | 4 | yes | yes | `linux-docker`; to be defined | no MITRE | — | NONE | 2026-09-02 | — |
| falco | [Myth799/cyber-sec-k8s-security-deployment](https://github.com/Myth799/cyber-sec-k8s-security-deployment) | 7 | 1 | yes | yes | to be defined | 100% of 1 techniques | — | NONE | 2026-09-17 | — |
| falco | [michelep/wazuh-falco](https://github.com/michelep/wazuh-falco) | 5 | 7 | yes | yes | to be defined | no MITRE | — | GPL-2.0 | 2021-08-23 | — |
| falco | [paaszti/Wazuh-Falco-integration](https://github.com/paaszti/Wazuh-Falco-integration) | 8 | 1 | yes | yes | `pack-falco`; to be defined | no MITRE | — | NONE | 2025-11-27 | — |
| falco | [zeinoux/siem-falco-wazuh](https://github.com/zeinoux/siem-falco-wazuh) | 5 | 7 | yes | yes | `linux-docker`, `osquery`, `pack-falco`; manager: localfile /var/ossec/logs/active-responses.log, wodle cis-cat | no MITRE | — | NONE | 2022-06-16 | — |
| monitoring-docker-container-logs-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 1 | 5 | yes | yes | `pack-monitoring-docker-container-logs-with-wazuh` | 0% of 1 techniques | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| monitoring-gke-audit-logs | [wazuh.com/blog](https://wazuh.com/blog/) | 3 | 0 | no | yes (1 warning) | manager: wodle gcp-pubsub | no MITRE | — | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| security-observability-on-linux-with-wazuh-and-tetragon | [wazuh.com/blog](https://wazuh.com/blog/) | 5 | 7 | yes | yes | `pack-security-observability-on-linux-with-wazuh-and-tetragon` | 80% of 5 techniques | 1 ok (1 containment), 2 broken, 2 destructive without allowlist | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| streamlining-container-image-security-with-grype-and-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 7 | 2 | yes | yes | `pack-streamlining-container-image-security-with-grype-and-wazuh` | no MITRE | 2 broken | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| tetragon-falco | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 298 | 0 | yes | yes | to be defined | 49% of 98 techniques | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
