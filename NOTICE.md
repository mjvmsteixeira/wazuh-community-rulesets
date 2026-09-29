# NOTICE — source licenses

**English** · [Português](NOTICE.pt.md)

This repository aggregates third-party files **without modifying them**. Each source folder has a `SOURCE.md` with the exact origin commit and, when there is one, `LICENSE.upstream` with the original license. Rights belong to their respective authors.

Most Wazuh rules derive from the OSSEC/Wazuh ecosystem (GPLv2). Several sources declare GPL-3.0 or AGPL-3.0, whose terms propagate to derived works. Before publishing a combined pack, the resulting license must be compatible with every source included.

## Removal requests

Author of a source and do not want your content here? [Open an issue](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues/new/choose) (*Removal request* template) and the source is removed from the registry and the page in the next release.

## Sources with an identified license

- **AGPL-3.0** (1): wazuh/integrations
- **Apache-2.0** (2): Sbharadwaj05/Wazuh-NIST-Rules-Set, Sbharadwaj05/ot-sentinel-rules
- **BSD** (2): alonsobsd/wazuh-freebsd-ruleset, opennix-solutions/wazuh-yandex-cloud-rules
- **GPL-2.0** (7): JoernSchoenyan/Sophos-Wazuh-SOC, MikhailKasimov/maltrail-wazuh-decoder-and-rules, bayusky/wazuh-custom-rules-and-decoders, dzoelfi/skudonet-wazuh-decoders, fredycibersec/ENS-Wazuh-integration, michelep/wazuh-falco, sanesecurityguy/opnsense-ruleset-for-wazuh
- **GPL-3.0** (12): 0xbad53c/ossec-sysmon-for-linux-decoder, BernaldoPenasAntelo/Linux-MITRE_ATT-CK-Wazuh-Rules, BernaldoPenasAntelo/Windows-MITRE_ATT-CK-Wazuh-Rules, LFBernardo/wazuh-fortios-5.6.X, Lordkaly/wazuh-collection, NucleiAv/caddy-detection-rules, SanWieb/sigWah, federicofantini/Wazuh-TI, leperchaun/wazuh-decoders-rules, sametsazak/sysmon, steffenfritz/wazuh-pflog, wheelert/wazuh-mikrotik
- **MIT** (20): Dinas-Kominfo-Kota-Tangerang/cl-sta-1087-malware-rules, H2FSpawn/wazuh-mikrotik-decoder, Halino/Wazuh-Unifi, JM2K69/WAZUH-Sentinel-AD, Jeremy-Burgos/wazuh-detection-engineering, MedNamouchi/SIEM-MikroTik-Wazuh-Graylog, TristanGNS/wazuh-cjis-rules, bret99/wazuh_custom_rules, captainobvious-sec/wazuh-field-notes, dominiktr/wazuh-decoders-rules, fredycibersec/wazuh-stuff, horrorshow21/Wazuh-Unifi-UDMPFWLogs, jzsecops/wazuh-wireguard-integration, kboykov/wazuh-infoblox-ruleset, mjvmsteixeira/wazuh-database-compliance, mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4, mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4, paolokappa/wazuh-siem-rules, timohissink/vault-event-monitor, zshguy/tyrian-detection-pack
- **MIT? (README badge, no LICENSE file)** (1): socfortress/Wazuh-Rules

## Sources without a license file (67)

The author keeps all rights; the files are published unchanged, with their origin. Internal use recommended until the origin repository includes a license:

- [0xbad53c/wazuh-detection-rules](https://github.com/0xbad53c/wazuh-detection-rules) — 190 rules, 0 decoders
- [AdamKorp/Wazuh-Mikrotik-Integration](https://github.com/AdamKorp/Wazuh-Mikrotik-Integration) — 2 rules, 2 decoders
- [ArabMohammed/SOC-Notes](https://github.com/ArabMohammed/SOC-Notes) — 24 rules, 124 decoders
- [AzizKpln/Fortigate-Rules](https://github.com/AzizKpln/Fortigate-Rules) — 36 rules, 298 decoders
- [BeardedTinker/wazuh-homelab-security](https://github.com/BeardedTinker/wazuh-homelab-security) — 28 rules, 8 decoders
- [EvilForge/wazuh-unifi-decoder](https://github.com/EvilForge/wazuh-unifi-decoder) — 5 rules, 5 decoders
- [FryggFR/Wazuh-Stormshield](https://github.com/FryggFR/Wazuh-Stormshield) — 12 rules, 52 decoders
- [Halino/Wazuh-Sophos](https://github.com/Halino/Wazuh-Sophos) — 60 rules, 99 decoders
- [Hasitha9796/wazuh-custom-decoders](https://github.com/Hasitha9796/wazuh-custom-decoders) — 0 rules, 114 decoders
- [Kaitsejo/Decoder](https://github.com/Kaitsejo/Decoder) — 0 rules, 9 decoders
- [LeeHoang26/ad-kerberos-attack-detection-soar](https://github.com/LeeHoang26/ad-kerberos-attack-detection-soar) — 3 rules, 0 decoders
- [MISP/wazuh-integration](https://github.com/MISP/wazuh-integration) — 6 rules, 0 decoders
- [MORGADO01/wazuh-detection-rules](https://github.com/MORGADO01/wazuh-detection-rules) — 87 rules, 3 decoders
- [Maverick000011/wazuh-custom-decoders](https://github.com/Maverick000011/wazuh-custom-decoders) — 0 rules, 54 decoders
- [MrRobInIT/Wazuh-Decoders-Rules](https://github.com/MrRobInIT/Wazuh-Decoders-Rules) — 53 rules, 26 decoders
- [Myth799/cyber-sec-k8s-security-deployment](https://github.com/Myth799/cyber-sec-k8s-security-deployment) — 7 rules, 1 decoders
- [OrangeBox-Labs/Wazuh](https://github.com/OrangeBox-Labs/Wazuh) — 90 rules, 2 decoders
- [Rayanex7/wazuh-siem-implementation](https://github.com/Rayanex7/wazuh-siem-implementation) — 36 rules, 28 decoders
- [Sparxx95/Wazuh-Sophos-WAF-IDP](https://github.com/Sparxx95/Wazuh-Sophos-WAF-IDP) — 9 rules, 28 decoders
- [TheMuntu/Wazuh-Detection](https://github.com/TheMuntu/Wazuh-Detection) — 31 rules, 5 decoders
- [Tomo-9925/wazuh-pi-hole-decoder-and-rules](https://github.com/Tomo-9925/wazuh-pi-hole-decoder-and-rules) — 3 rules, 6 decoders
- [Tomo-9925/wazuh-synology-dsm-decoder-and-rules](https://github.com/Tomo-9925/wazuh-synology-dsm-decoder-and-rules) — 11 rules, 19 decoders
- [adampielak/wazuh-lkrg](https://github.com/adampielak/wazuh-lkrg) — 10 rules, 0 decoders
- [adampielak/wazuh-scripts-resource](https://github.com/adampielak/wazuh-scripts-resource) — 1010 rules, 408 decoders
- [adampielak/wazuh_custom_rules](https://github.com/adampielak/wazuh_custom_rules) — 76 rules, 56 decoders
- [alextibor/wazuh-fortigate-rules-decoders](https://github.com/alextibor/wazuh-fortigate-rules-decoders) — 1387 rules, 738 decoders
- [angolo40/WazuhMikrotik](https://github.com/angolo40/WazuhMikrotik) — 8 rules, 8 decoders
- [baro77/CPPM2Wazuh](https://github.com/baro77/CPPM2Wazuh) — 0 rules, 44 decoders
- [calvinanglo/corpsec-ops-platform](https://github.com/calvinanglo/corpsec-ops-platform) — 137 rules, 8 decoders
- [cbrede/wazuh-meraki](https://github.com/cbrede/wazuh-meraki) — 0 rules, 28 decoders
- [chrisandoryan/Wazoy](https://github.com/chrisandoryan/Wazoy) — 2 rules, 4 decoders
- [femontanher/cortex-xdr-wazuh-api-integration](https://github.com/femontanher/cortex-xdr-wazuh-api-integration) — 4 rules, 6 decoders
- [fusuyfusuy/wazuh_local_rules](https://github.com/fusuyfusuy/wazuh_local_rules) — 235 rules, 0 decoders
- [grandir66/wazuh-multivendor-installer](https://github.com/grandir66/wazuh-multivendor-installer) — 116 rules, 42 decoders
- [hawkteam404/Wazuh](https://github.com/hawkteam404/Wazuh) — 12 rules, 5 decoders
- [holeunlee/alienvault-ossec-checkpoint](https://github.com/holeunlee/alienvault-ossec-checkpoint) — 36 rules, 16 decoders
- [hrHVN/Wazuh_games](https://github.com/hrHVN/Wazuh_games) — 1 rules, 4 decoders
- [kboykov/wazuh-fortigate-v7](https://github.com/kboykov/wazuh-fortigate-v7) — 1403 rules, 738 decoders
- [lulzkiller666/Custom-Wazuh-decoders-and-rules](https://github.com/lulzkiller666/Custom-Wazuh-decoders-and-rules) — 15 rules, 13 decoders
- [mattsimpson/unifi-wazuh](https://github.com/mattsimpson/unifi-wazuh) — 36 rules, 39 decoders
- [mdnahidmondol/wazuh-AuditD-Sysmon-rules](https://github.com/mdnahidmondol/wazuh-AuditD-Sysmon-rules) — 21 rules, 0 decoders
- [mellomatcha/wazuh](https://github.com/mellomatcha/wazuh) — 62 rules, 15 decoders
- [michelep/wazuh-rules-sophos-cloud](https://github.com/michelep/wazuh-rules-sophos-cloud) — 4 rules, 0 decoders
- [moizl599/wazuh_okta-integration](https://github.com/moizl599/wazuh_okta-integration) — 17 rules, 0 decoders
- [mootzen/wazuhToolSet](https://github.com/mootzen/wazuhToolSet) — 3 rules, 2 decoders
- [mritsurgeon/wazuh](https://github.com/mritsurgeon/wazuh) — 383 rules, 65 decoders
- [n00bsteam/Wazuh-Extended](https://github.com/n00bsteam/Wazuh-Extended) — 1361 rules, 58 decoders
- [n0rthl1ght/wazuh_info_collection](https://github.com/n0rthl1ght/wazuh_info_collection) — 322 rules, 0 decoders
- [navein-kumar/wazuh-filezilla-sftp-rules](https://github.com/navein-kumar/wazuh-filezilla-sftp-rules) — 7 rules, 1 decoders
- [nextep/wazuh_decoders](https://github.com/nextep/wazuh_decoders) — 14 rules, 26 decoders
- [od55/wazuh-local-ruleset](https://github.com/od55/wazuh-local-ruleset) — 0 rules, 38 decoders
- [paaszti/Wazuh-Falco-integration](https://github.com/paaszti/Wazuh-Falco-integration) — 8 rules, 1 decoders
- [parlakbarann/wazuh-custom-network-decoders](https://github.com/parlakbarann/wazuh-custom-network-decoders) — 0 rules, 60 decoders
- [patt502090/CE-Group1-NetOps](https://github.com/patt502090/CE-Group1-NetOps) — 43 rules, 13 decoders
- [pfuz/wazuh-ruleset](https://github.com/pfuz/wazuh-ruleset) — 37 rules, 83 decoders
- [ph0tacular/unifi-wazuh](https://github.com/ph0tacular/unifi-wazuh) — 40 rules, 53 decoders
- [phastier/wazuh](https://github.com/phastier/wazuh) — 331 rules, 329 decoders
- [rankthree/decoder](https://github.com/rankthree/decoder) — 0 rules, 38 decoders
- [st0rm-cr0w/wazuh-synology-dsm-nas-decoder-and-rules](https://github.com/st0rm-cr0w/wazuh-synology-dsm-nas-decoder-and-rules) — 16 rules, 20 decoders
- [stephane-segning/keycloak-wazuh-siem](https://github.com/stephane-segning/keycloak-wazuh-siem) — 18 rules, 1 decoders
- [sujalthakur-03/Wazuh-Decoders-Rules](https://github.com/sujalthakur-03/Wazuh-Decoders-Rules) — 103 rules, 57 decoders
- [tread-lightly/Caddy_decoders_for_Wazuh](https://github.com/tread-lightly/Caddy_decoders_for_Wazuh) — 0 rules, 5 decoders
- [tread-lightly/KSC_decoders_and_rules_for_Wazuh](https://github.com/tread-lightly/KSC_decoders_and_rules_for_Wazuh) — 60 rules, 19 decoders
- [wirekits/wazuh-rules](https://github.com/wirekits/wazuh-rules) — 317 rules, 0 decoders
- [xArshh/Wazuh-MikroTik-Integration](https://github.com/xArshh/Wazuh-MikroTik-Integration) — 24 rules, 23 decoders
- [yunusmrcoban/wazuh-custom](https://github.com/yunusmrcoban/wazuh-custom) — 21 rules, 13 decoders
- [zeinoux/siem-falco-wazuh](https://github.com/zeinoux/siem-falco-wazuh) — 5 rules, 7 decoders

## Sources that failed to clone

- CitraIT/wazuh_decoders_and_rules (repository removed or private at collection time).
- Ghost47-coder/Wazuh-Rules (repository removed or private at collection time).
