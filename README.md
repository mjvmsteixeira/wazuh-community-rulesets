# wazuh-community-rulesets

**English** · [Português](README.pt.md) · [Search page](https://mjvmsteixeira.github.io/wazuh-community-rulesets/) · [Issues](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues)

A registry of the community Wazuh rule and decoder collections (4.x XML format) scattered across GitHub, organized by area, validated on a real `wazuh-manager`, and cross-referenced with log collection, response playbooks, MITRE ATT&CK and SigmaHQ coverage. Original files are kept **unchanged**, each with its origin, author and pinned commit.

**[Open the search page](https://mjvmsteixeira.github.io/wazuh-community-rulesets/)** to browse packs, rules, decoders, techniques and playbooks, copy files, and generate an install script for your manager.

> ⚠️ **Do not load everything at once on a manager.** 1884 rule IDs conflict between sources (see [`catalog/id_conflicts.csv`](catalog/id_conflicts.csv)); combining sources requires renumbering first. Not every folder works on its own: **405 of 479** are standalone by static analysis — see [`catalog/folders.csv`](catalog/folders.csv) and the real result in [`catalog/validation.csv`](catalog/validation.csv).

## Questions, errors, new sources

[Open an issue](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues/new/choose): report a pack that does not load or misbehaves, propose a new source, or ask for anything in this registry. **Author of a source and want it removed? Open an issue (*Removal request*) and it will be taken down.**

## Numbers (2026-09-29)

| | |
|---|---:|
| Sources listed / cloned | 126 / 125 |
| Sources included | 115 |
| XML files | 1688 |
| Rules (entries) | 16586 (719 repeat an ID already in the same folder) |
| Decoders | 5344 |
| Distinct rule IDs | 8321 |
| Conflicting IDs | 1884: 1862 between community sources, 19 collisions with official IDs without `overwrite`, 3 official IDs rewritten by several sources |
| Missing dependencies (`if_sid`, `decoded_as`, `parent`) | 8 |
| Dependencies in another folder of the same source / in another source | 102 / 6 |
| CDB lists referenced | 82: 31 copied from the source, 4 official, 47 missing |
| Standalone folders (static analysis) | 405 of 479 |
| Folders that load in `wazuh-analysisd -t` (v4.14.8) | 410 of 479 (365 without warnings) |
| Root / child decoders | 660 / 4684 (42 root names colliding between sources; 17 with an official name) |
| Fields produced by decoders | 2932 distinct names; 305 mapped to ECS (35% of uses) |
| Log samples in `wazuh-logtest` | 372 in 27 folders: 254 ok, 29 shadowed by another decoder, 18 not decoded, 7 expected rule did not fire, 2 false positives |
| Rules with a valid MITRE technique | 8197 (2845 only after normalizing Sigma tags/groups) |
| Source responses (active response + integrations) | 149: 91 ok, 56 broken, 2 ignored by Wazuh; 19 destructive (17 without allowlist) |
| Techniques with level ≥ 12 rules | 336: 151 without playbook, 300 without working automated containment |
| Model agent groups | 129 (129 valid in `verify-agent-conf`) |
| SigmaHQ reference | 3760 rules, 381 techniques (39 only in Sigma) |

Reference: **wazuh/wazuh v4.14.8 ruleset**.

## Areas

| Area | Scope | Rules | Decoders | Sources |
|---|---|---:|---:|---:|
| [`01-windows-endpoint`](areas/01-windows-endpoint/) | Windows: Sysmon, EventChannel, PowerShell, Sigma-generated rules | 5264 | 3 | 11 |
| [`02-identity-access`](areas/02-identity-access/) | Active Directory, Entra ID, Okta, Duo, Auth0, Authentik, password vaults | 310 | 191 | 17 |
| [`03-linux-unix`](areas/03-linux-unix/) | Linux/BSD: auditd, Sysmon for Linux, LKRG, journald, LPE, reverse shells | 498 | 322 | 13 |
| [`04-macos`](areas/04-macos/) | macOS and Jamf | 90 | 53 | 3 |
| [`05-cloud-saas`](areas/05-cloud-saas/) | AWS, Azure, Google Workspace, Microsoft 365, Yandex, OCI, enterprise SaaS | 767 | 58 | 8 |
| [`06-containers-k8s`](areas/06-containers-k8s/) | Falco, Docker, Kubernetes, Tetragon | 408 | 42 | 8 |
| [`07-network-perimeter`](areas/07-network-perimeter/) | Firewalls, routers, switches, VPN, NAC (FortiGate, Sophos, MikroTik, UniFi, Meraki, Cisco...) | 4094 | 3605 | 50 |
| [`08-ndr-ids`](areas/08-ndr-ids/) | Suricata, Zeek, Maltrail, Packetbeat, commercial NDR, honeypots, scans | 155 | 112 | 8 |
| [`09-web-apps-waf`](areas/09-web-apps-waf/) | Web attacks, WAF, proxies/LB, web and collaboration apps | 334 | 88 | 18 |
| [`10-databases`](areas/10-databases/) | MySQL, MSSQL, PostgreSQL, MongoDB (auditing/DAM) | 82 | 41 | 3 |
| [`11-endpoint-security-edr`](areas/11-endpoint-security-edr/) | Commercial EDR/AV/XDR, YARA, Osquery, EPM | 1553 | 176 | 13 |
| [`12-threat-intel`](areas/12-threat-intel/) | MISP, OpenCTI, AbuseIPDB, VirusTotal, OTX, SOCRadar, GTI, domain reputation | 229 | 10 | 11 |
| [`13-vulnerability-mgmt`](areas/13-vulnerability-mgmt/) | Nessus, OpenVAS/Greenbone, Snyk, Nuclei, Lynis, asset inventory | 72 | 10 | 5 |
| [`14-ot-ics-iot`](areas/14-ot-ics-iot/) | Modbus, DNP3, IEC-104, MQTT, OPC-UA, home automation | 62 | 27 | 3 |
| [`15-infra-virt-storage-backup`](areas/15-infra-virt-storage-backup/) | Proxmox/PBS, VMware, Synology, QNAP, Veeam | 611 | 247 | 12 |
| [`16-dns-email`](areas/16-dns-email/) | DNS (Pi-hole, Technitium), email and phishing (Mimecast, Zimbra, Abnormal, Sublime) | 94 | 181 | 9 |
| [`17-ai-llm`](areas/17-ai-llm/) | AI services: Azure OpenAI/AI Foundry, AWS Bedrock, ChatGPT, Whisper | 44 | 1 | 4 |
| [`18-compliance-frameworks`](areas/18-compliance-frameworks/) | Framework-mapped packs: NIST CSF 2.0, CJIS, ENS (RD 311/2022) | 214 | 6 | 4 |
| [`19-threats-campaigns-cves`](areas/19-threats-campaigns-cves/) | Specific malware, APTs and CVEs | 654 | 107 | 7 |
| [`20-attck-multiplatform`](areas/20-attck-multiplatform/) | Generic packs organized by ATT&CK tactics / multi-platform | 690 | 28 | 8 |
| [`21-wazuh-platform-ops`](areas/21-wazuh-platform-ops/) | Manager health, exclusions/tuning, active response, inventory, agents | 331 | 32 | 6 |
| [`90-misc`](areas/90-misc/) | Very specific cases (games, local ERPs, internal policies) | 30 | 4 | 3 |

## Collisions with the official ruleset

- **19** rules reuse an official ID without `overwrite="yes"` (startup warning; only one definition stays active).
- **3** official IDs are overwritten by more than one source with different content: loading those sources together makes the last one win (`other_overwriters` column).
- **155** rules intentionally `overwrite` official rules (4 change the `if_sid`/`if_group`/`decoded_as` chain, 55 only the level).
- **14** decoder files are named like an official file or redefine official decoder names. Tested in `validation.csv` (`decoder_exclude` column): irrelevant (fails) in 2, required in 2, do not use in 7, optional in 3 folders — decoders named like an official one add to it, so excluding the official file can break loading.
- **5417** rules use IDs outside the recommended custom range (100000–120000).

Details in [`catalog/official_overlap.csv`](catalog/official_overlap.csv) and [`catalog/decoder_replacements.csv`](catalog/decoder_replacements.csv).

## Sibling rules (children of the same parent)

Measured on `wazuh-analysisd` v4.14.8: **level-0 children** of the same parent (`if_sid`/`if_group`) **are evaluated first**, then the rest by **level, highest first**; on equal level by **load order**, which is the file-name order across the whole set (official and `etc/rules` mixed; the ID does not matter). The first one that matches takes the event. A child **with no conditions of its own** (*catch-all*) always matches and silences every sibling evaluated after it — official rules included, with the folder installed alone — and `wazuh-analysisd -t` does not warn about it. An ID repeated in two files keeps only the definition loaded first; the other does not exist (not even under its parent). That is why the page's script and the tests install each file as `<pack-prefix>__<file>`: an original name such as `02-rules.xml` would load before the official files and the official `if_sid` would fail.

- **20** catch-all rules in 10 folders silence **37** official rules ([`catalog/catchall_silences_official.csv`](catalog/catchall_silences_official.csv)).
- **274** parents have children in different sources (10359 rules; 70 with a catch-all; 154 parents whose ID is defined differently in several sources); 141 folder pairs where one silences the other when installed together ([`catalog/sibling_parents.csv`](catalog/sibling_parents.csv)). The page's cart applies this model to the selection.
- Synthetic samples (`tools/synth.py`): one event per rule, generated from the conditions of the rule and its parent chain (JSON events in `wazuh-logtest`; Windows EventChannel events injected into the `wazuh-analysisd` queue, since logtest does not decode them). 3085 of 3552 confirmed by the engine in 172 folders (1470 of 1851 Windows); 11 ended on an official rule instead of the folder's rule; 142 Windows rules use a capitalized field (`win.eventdata.TargetFilename`) that the decoder never produces, so they never fire ([`catalog/synthetic_tests.csv`](catalog/synthetic_tests.csv)). Only confirmed ones are used in the pair test.
- Empirical proof (`tools/combo_test.py`): 150 folder pairs loaded together, 4425 samples replayed; 421 changed owner (6 by decoder, 72 by a sibling rule, 333 by an ID conflict: the same ID, or an ancestor in the `if_sid` chain, defined in both folders) in 62 pairs; 1 pairs do not load together ([`catalog/combo_summary.csv`](catalog/combo_summary.csv), [`catalog/combo_tests.csv`](catalog/combo_tests.csv)).

## Collection and agent groups

Rules run on the manager for every agent; agent groups do not filter rules. What a group decides is **which events arrive**. Each folder lists what it needs in [`catalog/collection.csv`](catalog/collection.csv): collected by default, extra agent collection in [`groups/`](groups/) (248 folders), manager requirements such as cloud wodles, modules, integrations and `<remote>` syslog (150 folders), or still to be defined (129 folders). Requirements are **inferred** (the folder chains into official rules of a family, e.g. `win-sysmon` → Sysmon channel) or **declared** by the source (`<localfile>`/`<wodle>`/`<agent_config>` blocks, copied or extracted to `collection/`). See [`groups/README.md`](groups/README.md).

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

[SigmaHQ](https://github.com/SigmaHQ/sigma) (pinned, commit `07ec293a5169`) is used as a reference only: 3760 rules, 381 techniques; no Sigma rule is copied or converted (DRL 1.1 license). Compared with the registry: 316 both, 26 registry without level ≥ 12 rules, 39 Sigma only, 84 registry only; 18 of the Sigma-only techniques have high or critical rules. See [`catalog/sigma_coverage.csv`](catalog/sigma_coverage.csv).

### Priority gaps: techniques with most level ≥ 12 rules and no playbook

| Technique | Name | Tactics | Level ≥ 12 rules | Folders | CISA countermeasures | Automated containment | Other automation |
|---|---|---|---:|---:|---:|---:|---:|
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | defense-evasion | 135 | 12 | 2 | 0 | 2 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | command-and-control | 108 | 33 | 3 | 2 | 6 |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | defense-evasion | 93 | 28 | 3 | 1 | 4 |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | execution | 78 | 16 | 5 | 1 | 3 |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | initial-access | 76 | 31 | 8 | 2 | 3 |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | lateral-movement | 65 | 13 | 7 | 0 | 0 |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | defense-evasion | 58 | 8 | 1 | 0 | 0 |
| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | execution | 58 | 9 | 5 | 0 | 0 |
| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | discovery | 46 | 19 | 0 | 0 | 3 |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | lateral-movement | 40 | 10 | 7 | 0 | 0 |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | defense-evasion | 38 | 13 | 1 | 0 | 2 |
| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | defense-evasion | 37 | 11 | 1 | 0 | 2 |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 | defense-evasion | 33 | 11 | 1 | 0 | 2 |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | discovery | 27 | 13 | 0 | 0 | 2 |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | defense-evasion | 27 | 16 | 2 | 0 | 2 |

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
tools/                            fetch.sh, build.py, validate.py, logtest.py, combo_test.py, make_docs.py, make_site.py and modules
```

## Rebuild / update

```bash
pip install -r requirements.txt
./tools/fetch.sh                 # reproduces the sources.lock snapshot; UPDATE=1 ./tools/fetch.sh to update
python3 tools/build.py --src .cache/src --official .cache/official/ruleset --out .
python3 tools/validate.py        # requires Docker (wazuh-analysisd -t, verify-agent-conf)
python3 tools/logtest.py         # requires Docker (log samples in wazuh-logtest)
python3 tools/combo_test.py --auto   # requires Docker (folder pairs loaded together; ~30 min; runs weekly in CI)
python3 tools/make_docs.py .
python3 tools/make_site.py .
```

Run on a case-sensitive filesystem (Linux, or a case-sensitive APFS volume on macOS). The `.github/workflows/registo.yml` workflow runs this whole pipeline on every push and pull request (and weekly) and publishes the page to GitHub Pages. To add a source: append it to `tools/sources.txt`, classify it in `tools/taxonomy.py` (`MAP`) and run the commands above — or [open an issue](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues/new/choose).

## Licenses

66 of the 115 included sources **have no license file**: without a license the author keeps all rights. Every file is published unchanged, with its origin, author and exact commit in the folder's `SOURCE.md`. **Author of a source and want it removed? [Open an issue](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues/new/choose) and it will be taken down.** See [`NOTICE.md`](NOTICE.md).

## Roadmap

1. **Registry** (done): inventory, areas, catalog, conflicts, dependencies, real validation, collection, response and coverage.
2. **Triage**: mark each source *adopt / review / archive*, based on the indicators, `validation.csv` and `decoder_tests.csv`.
3. **4.x normalization**: assign an ID range per area, renumber and rewrite `if_sid` accordingly, producing a pack that loads all at once.
4. **Wazuh 5.0**: convert XML decoders → YAML/ECS and rules to the new engine, starting with the adopted sources (see `catalog/decoder_fields.csv`).

---
Curated by [@mjvmst](https://github.com/mjvmsteixeira) · [Wazuh Ambassador](https://wazuh.com/ambassadors/marco-teixeira/) · Portugal. Independent community registry; not an official Wazuh, Inc. product.
