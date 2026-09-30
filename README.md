# wazuh-community-rulesets

**English** · [Português](README.pt.md) · [Search page](https://mjvmsteixeira.github.io/wazuh-community-rulesets/) · [Issues](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues)

A registry of the community Wazuh rule and decoder collections (4.x XML format) scattered across GitHub, organized by area, validated on a real `wazuh-manager`, and cross-referenced with log collection, response playbooks, MITRE ATT&CK and SigmaHQ coverage. Original files are kept **unchanged**, each with its origin, author and pinned commit.

**[Open the search page](https://mjvmsteixeira.github.io/wazuh-community-rulesets/)** to browse packs, rules, decoders, techniques and playbooks, copy files, and generate an install script for your manager.

> ⚠️ **Do not load everything at once on a manager.** 1867 rule IDs conflict between sources (see [`catalog/id_conflicts.csv`](catalog/id_conflicts.csv)); combining sources requires renumbering first. Not every folder works on its own: **255 of 299** are standalone by static analysis — see [`catalog/folders.csv`](catalog/folders.csv) and the real result in [`catalog/validation.csv`](catalog/validation.csv).

## Questions, errors, new sources

[Open an issue](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues/new/choose): report a pack that does not load or misbehaves, propose a new source, or ask for anything in this registry. **Author of a source and want it removed? Open an issue (*Removal request*) and it will be taken down.**

## Numbers (2026-09-29)

| | |
|---|---:|
| Sources listed / cloned | 126 / 124 |
| Sources included | 115 |
| XML files | 1343 |
| Rules (entries) | 16373 (716 repeat an ID already in the same folder) |
| Decoders | 5298 |
| Distinct rule IDs | 9114 |
| Conflicting IDs | 1867: 1854 between community sources, 10 collisions with official IDs without `overwrite`, 3 official IDs rewritten by several sources |
| Missing dependencies (`if_sid`, `decoded_as`, `parent`) | 23 |
| Dependencies in another folder of the same source / in another source | 74 / 57 |
| CDB lists referenced | 67: 31 copied from the source, 3 official, 33 missing |
| Standalone folders (static analysis) | 255 of 299 |
| Folders that load in `wazuh-analysisd -t` (v4.14.8) | 261 of 299 (228 without warnings) |
| Root / child decoders | 639 / 4659 (43 root names colliding between sources; 17 with an official name) |
| Fields produced by decoders | 2918 distinct names; 305 mapped to ECS (35% of uses) |
| Log samples in `wazuh-logtest` | 372 in 27 folders: 256 ok, 27 shadowed by another decoder, 18 not decoded, 7 expected rule did not fire, 2 false positives |
| Rules with a valid MITRE technique | 8079 (2842 only after normalizing Sigma tags/groups) |
| Source responses (active response + integrations) | 109: 83 ok, 24 broken, 2 ignored by Wazuh; 14 destructive (12 without allowlist) |
| Techniques with level ≥ 12 rules | 335: 151 without playbook, 324 without working automated containment |
| Model agent groups | 67 (67 valid in `verify-agent-conf`) |
| SigmaHQ reference | 3760 rules, 381 techniques (43 only in Sigma) |

Reference: **wazuh/wazuh v4.14.8 ruleset**.

## Areas

| Area | Scope | Rules | Decoders | Sources |
|---|---|---:|---:|---:|
| [`01-windows-endpoint`](areas/01-windows-endpoint/) | Windows: Sysmon, EventChannel, PowerShell, Sigma-generated rules | 5273 | 3 | 11 |
| [`02-identity-access`](areas/02-identity-access/) | Active Directory, Entra ID, Okta, Duo, Auth0, Authentik, password vaults | 267 | 183 | 16 |
| [`03-linux-unix`](areas/03-linux-unix/) | Linux/BSD: auditd, Sysmon for Linux, LKRG, journald, LPE, reverse shells | 477 | 328 | 13 |
| [`04-macos`](areas/04-macos/) | macOS and Jamf | 89 | 65 | 3 |
| [`05-cloud-saas`](areas/05-cloud-saas/) | AWS, Azure, Google Workspace, Microsoft 365, Yandex, OCI, enterprise SaaS | 757 | 60 | 8 |
| [`06-containers-k8s`](areas/06-containers-k8s/) | Falco, Docker, Kubernetes, Tetragon | 384 | 33 | 8 |
| [`07-network-perimeter`](areas/07-network-perimeter/) | Firewalls, routers, switches, VPN, NAC (FortiGate, Sophos, MikroTik, UniFi, Meraki, Cisco...) | 4086 | 3605 | 50 |
| [`08-ndr-ids`](areas/08-ndr-ids/) | Suricata, Zeek, Maltrail, Packetbeat, commercial NDR, honeypots, scans | 144 | 62 | 7 |
| [`09-web-apps-waf`](areas/09-web-apps-waf/) | Web attacks, WAF, proxies/LB, web and collaboration apps | 314 | 88 | 17 |
| [`10-databases`](areas/10-databases/) | MySQL, MSSQL, PostgreSQL, MongoDB (auditing/DAM) | 57 | 26 | 3 |
| [`11-endpoint-security-edr`](areas/11-endpoint-security-edr/) | Commercial EDR/AV/XDR, YARA, Osquery, EPM | 1536 | 165 | 12 |
| [`12-threat-intel`](areas/12-threat-intel/) | MISP, OpenCTI, AbuseIPDB, VirusTotal, OTX, SOCRadar, GTI, domain reputation | 189 | 5 | 10 |
| [`13-vulnerability-mgmt`](areas/13-vulnerability-mgmt/) | Nessus, OpenVAS/Greenbone, Snyk, Nuclei, Lynis, asset inventory | 52 | 9 | 4 |
| [`14-ot-ics-iot`](areas/14-ot-ics-iot/) | Modbus, DNP3, IEC-104, MQTT, OPC-UA, home automation | 46 | 25 | 2 |
| [`15-infra-virt-storage-backup`](areas/15-infra-virt-storage-backup/) | Proxmox/PBS, VMware, Synology, QNAP, Veeam | 580 | 223 | 11 |
| [`16-dns-email`](areas/16-dns-email/) | DNS (Pi-hole, Technitium), email and phishing (Mimecast, Zimbra, Abnormal, Sublime) | 70 | 112 | 9 |
| [`17-ai-llm`](areas/17-ai-llm/) | AI services: Azure OpenAI/AI Foundry, AWS Bedrock, ChatGPT, Whisper | 36 | 1 | 3 |
| [`18-compliance-frameworks`](areas/18-compliance-frameworks/) | Framework-mapped packs: NIST CSF 2.0, CJIS, ENS (RD 311/2022) | 212 | 6 | 3 |
| [`19-threats-campaigns-cves`](areas/19-threats-campaigns-cves/) | Specific malware, APTs and CVEs | 64 | 0 | 6 |
| [`20-attck-multiplatform`](areas/20-attck-multiplatform/) | Generic packs organized by ATT&CK tactics / multi-platform | 1423 | 285 | 8 |
| [`21-wazuh-platform-ops`](areas/21-wazuh-platform-ops/) | Manager health, exclusions/tuning, active response, inventory, agents | 287 | 10 | 5 |
| [`90-misc`](areas/90-misc/) | Very specific cases (games, local ERPs, internal policies) | 30 | 4 | 3 |

## Collisions with the official ruleset

- **10** rules reuse an official ID without `overwrite="yes"` (startup warning; only one definition stays active).
- **3** official IDs are overwritten by more than one source with different content: loading those sources together makes the last one win (`other_overwriters` column).
- **154** rules intentionally `overwrite` official rules (4 change the `if_sid`/`if_group`/`decoded_as` chain, 54 only the level).
- **13** decoder files are named like an official file or redefine official decoder names. Tested in `validation.csv` (`decoder_exclude` column): irrelevant (fails) in 2, required in 2, do not use in 6, optional in 3 folders — decoders named like an official one add to it, so excluding the official file can break loading.
- **6362** rules use IDs outside the recommended custom range (100000–120000).

Details in [`catalog/official_overlap.csv`](catalog/official_overlap.csv) and [`catalog/decoder_replacements.csv`](catalog/decoder_replacements.csv).

## Collection and agent groups

Rules run on the manager for every agent; agent groups do not filter rules. What a group decides is **which events arrive**. Each folder lists what it needs in [`catalog/collection.csv`](catalog/collection.csv): collected by default, extra agent collection in [`groups/`](groups/) (104 folders), manager requirements such as cloud wodles, modules, integrations and `<remote>` syslog (116 folders), or still to be defined (112 folders). Requirements are **inferred** (the folder chains into official rules of a family, e.g. `win-sysmon` → Sysmon channel) or **declared** by the source (`<localfile>`/`<wodle>`/`<agent_config>` blocks, copied or extracted to `collection/`). See [`groups/README.md`](groups/README.md).

## Response and playbooks

1. **Source automated responses** — [`catalog/responses.csv`](catalog/responses.csv): every `<active-response>` and `<integration>` the sources ship, with script, triggering rules, action, impact, safeguards and status (**broken** when the script is missing or misnamed, the rule does not exist or was renumbered by the author; **ignored** when defined in an `agent.conf`).
2. **Procedural playbooks** — [`catalog/playbooks.csv`](catalog/playbooks.csv), from licensed libraries pinned in `sources.lock` (only linked, never copied):
- ADORSYS-GIS/wazuh-playbook — procedural (by rule.id/technique): 3
- ADORSYS-GIS/wazuh-playbook — SCA remediation (by check): 71
- austinsonger/Incident-Playbook — procedural (by technique): 43
- cisagov/playbook-ng — countermeasure (CISA COUN7ER): 152
- guardsight/gsvsoc_cirt-playbook-battle-cards — procedural (PICERL battle card): 63
3. **Coverage** — [`catalog/technique_coverage.csv`](catalog/technique_coverage.csv) by technique and [`catalog/response_coverage.csv`](catalog/response_coverage.csv) by folder.

The correlation key is the technique, and Wazuh accepts any text in `<mitre><id>` without warning; many sources use Sigma tags (`attack.t1059.001`) or only put the technique in groups. The catalog normalizes to T-IDs in `rules.csv` (`mitre_norm`, `mitre_status`), resolving revoked techniques to their ATT&CK successor; the XML is not changed. None of the source responses is recommended as is: the destructive ones have no allowlist nor test mode.

### SigmaHQ as a coverage reference

[SigmaHQ](https://github.com/SigmaHQ/sigma) (pinned, commit `07ec293a5169`) is used as a reference only: 3760 rules, 381 techniques; no Sigma rule is copied or converted (DRL 1.1 license). Compared with the registry: 313 both, 25 registry without level ≥ 12 rules, 43 Sigma only, 80 registry only; 20 of the Sigma-only techniques have high or critical rules. See [`catalog/sigma_coverage.csv`](catalog/sigma_coverage.csv).

### Priority gaps: techniques with most level ≥ 12 rules and no playbook

| Technique | Name | Tactics | Level ≥ 12 rules | Folders | CISA countermeasures | Automated containment | Other automation |
|---|---|---|---:|---:|---:|---:|---:|
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | defense-evasion | 135 | 10 | 2 | 0 | 2 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | command-and-control | 106 | 24 | 3 | 1 | 4 |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | defense-evasion | 89 | 16 | 3 | 0 | 2 |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | execution | 77 | 12 | 5 | 0 | 2 |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | initial-access | 75 | 26 | 8 | 1 | 2 |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | lateral-movement | 64 | 12 | 7 | 0 | 0 |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | defense-evasion | 58 | 8 | 1 | 0 | 0 |
| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | execution | 57 | 8 | 5 | 0 | 0 |
| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | discovery | 46 | 15 | 0 | 0 | 2 |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | lateral-movement | 40 | 9 | 7 | 0 | 0 |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | defense-evasion | 38 | 13 | 1 | 0 | 2 |
| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | defense-evasion | 37 | 10 | 1 | 0 | 2 |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 | defense-evasion | 33 | 10 | 1 | 0 | 2 |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | discovery | 27 | 13 | 0 | 0 | 2 |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | defense-evasion | 27 | 12 | 2 | 0 | 2 |

## Layout

```
areas/<NN-area>/<topic>/<owner>__<repo>/
    rules/  decoders/  lists/     original files, unchanged (lists: CDB lists the rules reference)
    tests/                        the source's tests for this folder
    collection/  response/        collection config and response scripts/blocks from the source
    SOURCE.md                     origin, pinned commit, license, original path → path here
    LICENSE.upstream              copy of the source license (when there is one)
catalog/                          CSV/JSON catalog (sources, rules, decoders, conflicts, dependencies, validation, tests, coverage...)
groups/<group>/agent.conf         model agent groups
site/index.html  site/pt/         standalone search page (English and Portuguese)
tools/                            fetch.sh, build.py, validate.py, logtest.py, make_docs.py, make_site.py and modules
```

## Rebuild / update

```bash
pip install -r requirements.txt
./tools/fetch.sh                 # reproduces the sources.lock snapshot; UPDATE=1 ./tools/fetch.sh to update
python3 tools/build.py --src .cache/src --official .cache/official/ruleset --out .
python3 tools/validate.py        # requires Docker (wazuh-analysisd -t, verify-agent-conf)
python3 tools/logtest.py         # requires Docker (log samples in wazuh-logtest)
python3 tools/make_docs.py .
python3 tools/make_site.py .
```

Run on a case-sensitive filesystem (Linux, or a case-sensitive APFS volume on macOS). The `.github/workflows/registo.yml` workflow runs this whole pipeline on every push and pull request (and weekly) and publishes the page to GitHub Pages. To add a source: append it to `tools/sources.txt`, classify it in `tools/taxonomy.py` (`MAP`) and run the commands above — or [open an issue](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues/new/choose).

## Licenses

67 of the 115 included sources **have no license file**: without a license the author keeps all rights. Every file is published unchanged, with its origin, author and exact commit in the folder's `SOURCE.md`. **Author of a source and want it removed? [Open an issue](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues/new/choose) and it will be taken down.** See [`NOTICE.md`](NOTICE.md).

## Roadmap

1. **Registry** (done): inventory, areas, catalog, conflicts, dependencies, real validation, collection, response and coverage.
2. **Triage**: mark each source *adopt / review / archive*, based on the indicators, `validation.csv` and `decoder_tests.csv`.
3. **4.x normalization**: assign an ID range per area, renumber and rewrite `if_sid` accordingly, producing a pack that loads all at once.
4. **Wazuh 5.0**: convert XML decoders → YAML/ECS and rules to the new engine, starting with the adopted sources (see `catalog/decoder_fields.csv`).

---
Curated by [@mjvmst](https://github.com/mjvmsteixeira) · [Wazuh Ambassador](https://wazuh.com/ambassadors/marco-teixeira/) · Portugal. Independent community registry; not an official Wazuh, Inc. product.
