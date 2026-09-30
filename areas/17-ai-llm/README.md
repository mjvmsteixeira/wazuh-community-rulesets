# 17-ai-llm

AI services: Azure OpenAI/AI Foundry, AWS Bedrock, ChatGPT, Whisper.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| ai-exfil | [calvinanglo/corpsec-ops-platform](https://github.com/calvinanglo/corpsec-ops-platform) | 14 | 1 | yes | yes | to be defined | 100% of 1 techniques | 2 ok (2 containment), 1 destructive without allowlist | NONE | 2026-05-02 | 1 |
| azure-ai-foundry | [wazuh/integrations](https://github.com/wazuh/integrations) | 6 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| azure-openai | [wazuh/integrations](https://github.com/wazuh/integrations) | 4 | 0 | yes | yes | to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| chatgpt | [AnonymousWP/Wazuh-ChatGPT-integration](https://github.com/AnonymousWP/Wazuh-ChatGPT-integration) | 2 | 0 | yes | yes | manager: integration custom-chatgpt.py | no MITRE | 1 ok (0 containment) | GPL-3.0 | 2023-03-20 | — |
| chatgpt | [wazuh/integrations](https://github.com/wazuh/integrations) | 3 | 0 | yes | yes | manager: integration custom-chatgpt; to be defined | no MITRE | 1 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| whisper | [wazuh/integrations](https://github.com/wazuh/integrations) | 7 | 0 | yes | yes | manager: integration custom-whisper; to be defined | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
