# 14-ot-ics-iot

Modbus, DNP3, IEC-104, MQTT, OPC-UA, home automation.

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| home-assistant | [BeardedTinker/wazuh-homelab-security](https://github.com/BeardedTinker/wazuh-homelab-security) | 7 | 3 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-09-28 | — |
| monitoring-rapid-scada-with-wazuh | [wazuh.com/blog](https://wazuh.com/blog/) | 16 | 2 | yes | yes | `pack-monitoring-rapid-scada-with-wazuh` | 80% of 5 techniques | 1 ok (0 containment), 3 broken | © Wazuh, Inc. (blog; origem citada) | 2026-09-24 | — |
| ot-sentinel | [Sbharadwaj05/ot-sentinel-rules](https://github.com/Sbharadwaj05/ot-sentinel-rules) | 39 | 22 | yes | no | manager: localfile /var/ossec/logs/dnp3/dnp3_tap.log, localfile /var/ossec/logs/iec104/iec104_tap.log, localfile /var/ossec/logs/modbus/modbus_tap.log, localfile /var/ossec/logs/mqtt/mqtt_tap.log, localfile /var/ossec/logs/opcua/opcua_tap.log | no MITRE | — | Apache-2.0 | 2026-08-02 | 15 |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
