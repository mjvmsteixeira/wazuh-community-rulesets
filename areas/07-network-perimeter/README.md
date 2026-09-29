# 07-network-perimeter

Firewalls, routers, switches, VPN, NAC (FortiGate, Sophos, MikroTik, UniFi, Meraki, Cisco...).

| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |
|---|---|---:|---:|---|---|---|---|---|---|---|---:|
| arista-ngfw | [wazuh/integrations](https://github.com/wazuh/integrations) | 14 | 1 | yes | yes (4 warnings) | manager: remote syslog | no MITRE | 1 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| arista | [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) | 0 | 17 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2025-05-31 | — |
| aruba-clearpass | [baro77/CPPM2Wazuh](https://github.com/baro77/CPPM2Wazuh) | 0 | 44 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2021-10-12 | — |
| checkpoint | [holeunlee/alienvault-ossec-checkpoint](https://github.com/holeunlee/alienvault-ossec-checkpoint) | 36 | 16 | yes | no | manager: remote syslog | no MITRE | — | NONE | 2026-04-10 | — |
| cisco-catalyst-1200-switches | [dominiktr/wazuh-decoders-rules](https://github.com/dominiktr/wazuh-decoders-rules) | 56 | 44 | yes | yes | manager: remote syslog | no MITRE | — | MIT | 2026-02-27 | — |
| cisco-ftd | [wazuh/integrations](https://github.com/wazuh/integrations) | 0 | 84 | yes | yes | manager: remote syslog | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| cisco-ios | [wazuh/integrations](https://github.com/wazuh/integrations) | 12 | 26 | yes | yes | manager: remote syslog | no MITRE | 2 ok (0 containment) | AGPL-3.0 | 2026-09-11 | — |
| cisco-wireless-radius | [patt502090/CE-Group1-NetOps](https://github.com/patt502090/CE-Group1-NetOps) | 43 | 13 | yes | yes | `osquery`, `pack-cisco-wireless-radius`; manager: localfile /var/ossec/logs/active-responses.log, wodle cis-cat | 100% of 2 techniques | — | NONE | 2026-03-18 | — |
| cisco | [sujalthakur-03/Wazuh-Decoders-Rules](https://github.com/sujalthakur-03/Wazuh-Decoders-Rules) | 30 | 11 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2025-06-25 | — |
| endian-mercury-utm | [wazuh/integrations](https://github.com/wazuh/integrations) | 18 | 31 | yes | yes | manager: remote syslog | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| f5 | [ArabMohammed/SOC-Notes](https://github.com/ArabMohammed/SOC-Notes) | 5 | 46 | no | yes (5 warnings) | manager: remote syslog | no MITRE | — | NONE | 2026-08-11 | — |
| fortianalyzer | [ArabMohammed/SOC-Notes](https://github.com/ArabMohammed/SOC-Notes) | 9 | 47 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-08-11 | — |
| fortigate | [AzizKpln/Fortigate-Rules](https://github.com/AzizKpln/Fortigate-Rules) | 36 | 298 | no | yes (2 warnings) | manager: remote syslog | no MITRE | — | NONE | 2023-09-01 | — |
| fortigate | [LFBernardo/wazuh-fortios-5.6.X](https://github.com/LFBernardo/wazuh-fortios-5.6.X) | 29 | 13 | yes | yes (1 warning) | manager: remote syslog | no MITRE | — | GPL-3.0 | 2018-08-14 | — |
| fortigate | [alextibor/wazuh-fortigate-rules-decoders](https://github.com/alextibor/wazuh-fortigate-rules-decoders) | 1387 | 738 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2024-03-25 | — |
| fortigate | [kboykov/wazuh-fortigate-v7](https://github.com/kboykov/wazuh-fortigate-v7) | 1403 | 738 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-05-31 | — |
| fortigate | [kboykov/wazuh-infoblox-ruleset](https://github.com/kboykov/wazuh-infoblox-ruleset) | 23 | 14 | yes | yes | manager: remote syslog | 57% of 7 techniques | — | MIT | 2026-06-09 | — |
| fortigate | [phastier/wazuh](https://github.com/phastier/wazuh) | 18 | 0 | yes | yes | manager: remote syslog | 100% of 1 techniques | — | NONE | 2026-09-02 | — |
| fortigate | [wazuh/integrations](https://github.com/wazuh/integrations) | 14 | 28 | yes | yes | manager: remote syslog | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| hp-cisco-switches | [parlakbarann/wazuh-custom-network-decoders](https://github.com/parlakbarann/wazuh-custom-network-decoders) | 0 | 15 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2025-12-13 | — |
| hp-router | [sujalthakur-03/Wazuh-Decoders-Rules](https://github.com/sujalthakur-03/Wazuh-Decoders-Rules) | 24 | 12 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2025-06-25 | — |
| huawei1-decoder | [Maverick000011/wazuh-custom-decoders](https://github.com/Maverick000011/wazuh-custom-decoders) | 0 | 16 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-09-02 | — |
| huawei2-decoder | [Maverick000011/wazuh-custom-decoders](https://github.com/Maverick000011/wazuh-custom-decoders) | 0 | 16 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-09-02 | — |
| meraki | [cbrede/wazuh-meraki](https://github.com/cbrede/wazuh-meraki) | 0 | 28 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2024-11-13 | — |
| meraki | [leperchaun/wazuh-decoders-rules](https://github.com/leperchaun/wazuh-decoders-rules) | 10 | 36 | no | yes (1 warning) | manager: remote syslog | no MITRE | — | GPL-3.0 | 2024-06-16 | — |
| meraki | [wazuh/integrations](https://github.com/wazuh/integrations) | 34 | 93 | yes | yes | `pack-meraki` | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| mikrotik | [AdamKorp/Wazuh-Mikrotik-Integration](https://github.com/AdamKorp/Wazuh-Mikrotik-Integration) | 2 | 2 | yes | yes | manager: remote syslog | no MITRE | 1 ok (0 containment) | NONE | 2025-06-23 | — |
| mikrotik | [H2FSpawn/wazuh-mikrotik-decoder](https://github.com/H2FSpawn/wazuh-mikrotik-decoder) | 7 | 3 | yes | yes | manager: remote syslog | no MITRE | — | MIT | 2026-06-14 | — |
| mikrotik | [MedNamouchi/SIEM-MikroTik-Wazuh-Graylog](https://github.com/MedNamouchi/SIEM-MikroTik-Wazuh-Graylog) | 24 | 11 | no | no | `pack-mikrotik`; manager: integration virustotal, localfile /var/ossec/logs/active-responses.log | 75% of 8 techniques | 6 ok (1 containment), 2 broken, 1 destructive without allowlist | MIT | 2026-08-01 | — |
| mikrotik | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 5 | 7 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-06-16 | — |
| mikrotik | [angolo40/WazuhMikrotik](https://github.com/angolo40/WazuhMikrotik) | 8 | 8 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2024-06-19 | — |
| mikrotik | [grandir66/wazuh-multivendor-installer](https://github.com/grandir66/wazuh-multivendor-installer) | 35 | 30 | yes | yes | manager: remote syslog | 78% of 9 techniques | — | NONE | 2026-09-06 | — |
| mikrotik | [phastier/wazuh](https://github.com/phastier/wazuh) | 27 | 24 | yes | yes | manager: remote syslog | 100% of 4 techniques | — | NONE | 2026-09-02 | — |
| mikrotik | [sujalthakur-03/Wazuh-Decoders-Rules](https://github.com/sujalthakur-03/Wazuh-Decoders-Rules) | 49 | 34 | yes | yes (4 warnings) | manager: remote syslog | no MITRE | — | NONE | 2025-06-25 | — |
| mikrotik | [wheelert/wazuh-mikrotik](https://github.com/wheelert/wazuh-mikrotik) | 25 | 13 | yes | yes | manager: remote syslog | no MITRE | — | GPL-3.0 | 2026-04-10 | — |
| mikrotik | [xArshh/Wazuh-MikroTik-Integration](https://github.com/xArshh/Wazuh-MikroTik-Integration) | 24 | 23 | yes | yes (1 warning) | manager: remote syslog | no MITRE | 1 ok (1 containment) | NONE | 2026-01-01 | — |
| openvpn-geoip | [TheMuntu/Wazuh-Detection](https://github.com/TheMuntu/Wazuh-Detection) | 2 | 4 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2024-11-01 | — |
| openvpn | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 4 | 2 | no | no | `pack-openvpn` | 50% of 4 techniques | — | NONE | 2026-06-16 | — |
| openvpn | [bret99/wazuh_custom_rules](https://github.com/bret99/wazuh_custom_rules) | 6 | 2 | no | no | `pack-openvpn` | 50% of 4 techniques | — | MIT | 2026-08-05 | — |
| opnsense-naxsi | [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) | 3 | 8 | yes | yes | `pack-opnsense-naxsi` | 0% of 1 techniques | — | MIT? (README badge, no LICENSE file) | 2026-03-11 | — |
| opnsense | [hawkteam404/Wazuh](https://github.com/hawkteam404/Wazuh) | 0 | 5 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2025-09-30 | — |
| opnsense | [sanesecurityguy/opnsense-ruleset-for-wazuh](https://github.com/sanesecurityguy/opnsense-ruleset-for-wazuh) | 3 | 4 | yes | yes | manager: remote syslog | 100% of 1 techniques | — | GPL-2.0 | 2023-09-03 | — |
| orangebox | [OrangeBox-Labs/Wazuh](https://github.com/OrangeBox-Labs/Wazuh) | 7 | 0 | yes | yes | manager: remote syslog | 67% of 3 techniques | 2 ok (2 containment) | NONE | 2026-09-29 | — |
| palo-alto | [ArabMohammed/SOC-Notes](https://github.com/ArabMohammed/SOC-Notes) | 0 | 31 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-08-11 | — |
| paloalto | [ArabMohammed/SOC-Notes](https://github.com/ArabMohammed/SOC-Notes) | 10 | 0 | no | no | manager: remote syslog | no MITRE | — | NONE | 2026-08-11 | — |
| pf-pflog | [steffenfritz/wazuh-pflog](https://github.com/steffenfritz/wazuh-pflog) | 2 | 3 | yes | yes | manager: remote syslog | no MITRE | — | GPL-3.0 | 2023-05-09 | — |
| radware | [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) | 0 | 47 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2025-05-31 | — |
| sangfor-fw | [Maverick000011/wazuh-custom-decoders](https://github.com/Maverick000011/wazuh-custom-decoders) | 0 | 11 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-09-02 | — |
| sophos-firewall | [Halino/Wazuh-Sophos](https://github.com/Halino/Wazuh-Sophos) | 60 | 99 | yes | no | manager: remote syslog | 82% of 11 techniques | — | NONE | 2026-02-10 | — |
| sophos-firewall | [JoernSchoenyan/Sophos-Wazuh-SOC](https://github.com/JoernSchoenyan/Sophos-Wazuh-SOC) | 60 | 112 | yes | yes | manager: remote syslog | 100% of 4 techniques | — | GPL-2.0 | 2026-09-16 | — |
| sophos-firewall | [Sparxx95/Wazuh-Sophos-WAF-IDP](https://github.com/Sparxx95/Wazuh-Sophos-WAF-IDP) | 9 | 28 | yes | yes (15 warnings) | manager: remote syslog | no MITRE | — | NONE | 2025-08-07 | — |
| stormshield | [FryggFR/Wazuh-Stormshield](https://github.com/FryggFR/Wazuh-Stormshield) | 12 | 52 | yes | yes | manager: remote syslog | 100% of 2 techniques | — | NONE | 2024-03-12 | — |
| stormshield | [Kaitsejo/Decoder](https://github.com/Kaitsejo/Decoder) | 0 | 9 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2024-11-28 | — |
| stormshield | [grandir66/wazuh-multivendor-installer](https://github.com/grandir66/wazuh-multivendor-installer) | 42 | 1 | yes | yes | to be defined | 83% of 6 techniques | — | NONE | 2026-09-06 | — |
| stormshield | [phastier/wazuh](https://github.com/phastier/wazuh) | 21 | 15 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-09-02 | — |
| unifi | [BeardedTinker/wazuh-homelab-security](https://github.com/BeardedTinker/wazuh-homelab-security) | 16 | 4 | yes | yes | `pack-unifi` | no MITRE | — | NONE | 2026-09-28 | — |
| unifi | [EvilForge/wazuh-unifi-decoder](https://github.com/EvilForge/wazuh-unifi-decoder) | 5 | 5 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2024-05-07 | — |
| unifi | [Halino/Wazuh-Unifi](https://github.com/Halino/Wazuh-Unifi) | 40 | 11 | yes | no | `pack-unifi` | 78% of 9 techniques | — | MIT | 2026-09-12 | 1 |
| unifi | [MrRobInIT/Wazuh-Decoders-Rules](https://github.com/MrRobInIT/Wazuh-Decoders-Rules) | 53 | 26 | yes | no | manager: remote syslog | 40% of 5 techniques | — | NONE | 2026-04-12 | — |
| unifi | [captainobvious-sec/wazuh-field-notes](https://github.com/captainobvious-sec/wazuh-field-notes) | 23 | 41 | yes | yes | `pack-unifi` | 83% of 12 techniques | — | MIT | 2026-09-14 | — |
| unifi | [horrorshow21/Wazuh-Unifi-UDMPFWLogs](https://github.com/horrorshow21/Wazuh-Unifi-UDMPFWLogs) | 8 | 5 | yes | yes | manager: remote syslog | no MITRE | — | MIT | 2026-04-15 | — |
| unifi | [mattsimpson/unifi-wazuh](https://github.com/mattsimpson/unifi-wazuh) | 36 | 39 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-06-02 | — |
| unifi | [nextep/wazuh_decoders](https://github.com/nextep/wazuh_decoders) | 14 | 26 | yes | yes | manager: remote syslog | 60% of 5 techniques | — | NONE | 2025-06-25 | — |
| unifi | [ph0tacular/unifi-wazuh](https://github.com/ph0tacular/unifi-wazuh) | 40 | 53 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-09-23 | — |
| unifi | [phastier/wazuh](https://github.com/phastier/wazuh) | 93 | 199 | yes | yes | manager: remote syslog | 100% of 3 techniques | — | NONE | 2026-09-02 | — |
| unifi | [wazuh/integrations](https://github.com/wazuh/integrations) | 6 | 36 | yes | yes | manager: remote syslog | no MITRE | — | AGPL-3.0 | 2026-09-11 | — |
| usergate | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 4 | 4 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-06-16 | — |
| usergate | [bret99/wazuh_custom_rules](https://github.com/bret99/wazuh_custom_rules) | 8 | 8 | yes | no | manager: remote syslog | no MITRE | — | MIT | 2026-08-05 | — |
| vipnet | [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) | 14 | 28 | yes | no | manager: remote syslog | no MITRE | — | NONE | 2026-06-16 | — |
| vipnet | [bret99/wazuh_custom_rules](https://github.com/bret99/wazuh_custom_rules) | 3 | 6 | yes | yes | manager: remote syslog | no MITRE | — | MIT | 2026-08-05 | — |
| vmware-nsx | [rankthree/decoder](https://github.com/rankthree/decoder) | 0 | 38 | yes | yes | manager: remote syslog | no MITRE | — | NONE | 2026-02-26 | — |
| watchguard | [Rayanex7/wazuh-siem-implementation](https://github.com/Rayanex7/wazuh-siem-implementation) | 36 | 28 | yes | yes | `pack-watchguard` | no MITRE | — | NONE | 2025-07-04 | — |
| wireguard | [jzsecops/wazuh-wireguard-integration](https://github.com/jzsecops/wazuh-wireguard-integration) | 8 | 6 | yes | yes | — | 100% of 1 techniques | — | MIT | 2025-10-20 | — |
| zyxel-switch | [dominiktr/wazuh-decoders-rules](https://github.com/dominiktr/wazuh-decoders-rules) | 31 | 29 | yes | yes | manager: remote syslog | no MITRE | — | MIT | 2026-02-27 | — |

*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. *Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.
