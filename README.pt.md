# wazuh-community-rulesets

[English](README.md) · **Português** · [Página de pesquisa](https://mjvmsteixeira.github.io/wazuh-community-rulesets/pt/) · [Issues](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues)

Registo organizado por áreas das coleções comunitárias de regras e decoders Wazuh (formato XML 4.x) espalhadas pelo GitHub. O objetivo desta fase é **inventariar e arrumar**, preservando os ficheiros originais sem alterações. A normalização de IDs e a conversão para o motor do Wazuh 5.0 (YAML/ECS) são fases seguintes.

> ⚠️ **Não carregar tudo de uma vez num manager.** Há 1884 IDs de regra em conflito entre fontes (ver [`catalog/id_conflicts.csv`](catalog/id_conflicts.csv)); combinar fontes exige renumeração prévia. Nem todas as pastas funcionam sozinhas: só **405 de 479** são autónomas por análise estática (sem IDs repetidos, dependências externas, listas CDB em falta nem colisões com IDs oficiais) — ver [`catalog/folders.csv`](catalog/folders.csv) e o resultado real em [`catalog/validation.csv`](catalog/validation.csv).

## Números (2026-09-29)

| | |
|---|---:|
| Fontes listadas / clonadas | 126 / 125 |
| Fontes incluídas | 115 |
| Ficheiros XML registados | 1688 |
| Regras (entradas) | 16586 (das quais 719 repetem um ID já presente na mesma pasta) |
| Decoders | 5344 |
| IDs de regra distintos | 8321 |
| IDs em conflito | 1884: 1862 entre fontes da comunidade, 19 colisões com IDs oficiais sem `overwrite`, 3 IDs oficiais reescritos por várias fontes |
| Dependências em falta (`if_sid`, `decoded_as`, `parent`) | 8 |
| Dependências noutra pasta da mesma fonte | 102 |
| Dependências noutra fonte do pack | 6 |
| Listas CDB referidas | 82: 31 copiadas da fonte, 4 oficiais, 47 em falta |
| Pastas autónomas (análise estática) | 405 de 479 |
| Pastas que carregam em `wazuh-analysisd -t` (v4.14.8) | 409 de 479 (291 sem avisos) |
| Ficheiros de teste copiados | 134 |
| Decoders raiz / filhos | 660 / 4684 (42 nomes de raiz em colisão entre fontes; 17 com nome oficial) |
| Campos produzidos pelos decoders | 2932 nomes distintos; 305 com correspondência ECS (35% dos usos) |
| Amostras de log no wazuh-logtest | 372 em 27 pastas: 256 ok, 27 sombreadas por outro decoder, 18 não descodificadas, 7 sem a regra esperada, 2 falsos positivos |
| Configuração de recolha das fontes | 364 ficheiros, 701 entradas (60 ficheiros sem pasta atribuída) |
| Regras com técnica MITRE válida | 8197 (2845 só depois de normalizar etiquetas Sigma/grupos; 122 com técnicas descontinuadas sem sucessor) |
| Respostas das fontes (active response + integrações) | 149: 91 ok, 56 partidas, 2 ignoradas pelo Wazuh; 19 destrutivas (17 sem allowlist) |
| Técnicas com regras de nível ≥ 12 | 336: 151 sem playbook, 78 sem contramedida CISA, 300 sem contenção automática a funcionar |
| Grupos de agentes-modelo | 129 (129 válidos em `verify-agent-conf`) |
| Ficheiros excluídos (cópias, temporários, duplicados) | 255 |

Referência para comparação: **wazuh/wazuh v4.14.8 ruleset**.

## Áreas

| Área | Âmbito | Regras | Decoders | Fontes |
|---|---|---:|---:|---:|
| [`01-windows-endpoint`](areas/01-windows-endpoint/) | Windows: Sysmon, EventChannel, PowerShell, regras geradas a partir de Sigma | 5264 | 3 | 11 |
| [`02-identity-access`](areas/02-identity-access/) | Active Directory, Entra ID, Okta, Duo, Auth0, Authentik, cofres de passwords | 310 | 191 | 17 |
| [`03-linux-unix`](areas/03-linux-unix/) | Linux/BSD: auditd, Sysmon for Linux, LKRG, journald, LPE, reverse shells | 498 | 322 | 13 |
| [`04-macos`](areas/04-macos/) | macOS e Jamf | 90 | 53 | 3 |
| [`05-cloud-saas`](areas/05-cloud-saas/) | AWS, Azure, Google Workspace, Microsoft 365, Yandex, OCI, SaaS empresariais | 767 | 58 | 8 |
| [`06-containers-k8s`](areas/06-containers-k8s/) | Falco, Docker, Kubernetes, Tetragon | 408 | 42 | 8 |
| [`07-network-perimeter`](areas/07-network-perimeter/) | Firewalls, routers, switches, VPN, NAC (FortiGate, Sophos, MikroTik, UniFi, Meraki, Cisco...) | 4094 | 3605 | 50 |
| [`08-ndr-ids`](areas/08-ndr-ids/) | Suricata, Zeek, Maltrail, Packetbeat, NDR comerciais, honeypots, scans | 155 | 112 | 8 |
| [`09-web-apps-waf`](areas/09-web-apps-waf/) | Ataques web, WAF, proxies/LB, aplicações web e de colaboração | 334 | 88 | 18 |
| [`10-databases`](areas/10-databases/) | MySQL, MSSQL, PostgreSQL, MongoDB (auditoria/DAM) | 82 | 41 | 3 |
| [`11-endpoint-security-edr`](areas/11-endpoint-security-edr/) | EDR/AV/XDR comerciais, YARA, Osquery, EPM | 1553 | 176 | 13 |
| [`12-threat-intel`](areas/12-threat-intel/) | MISP, OpenCTI, AbuseIPDB, VirusTotal, OTX, SOCRadar, GTI, reputação de domínios | 229 | 10 | 11 |
| [`13-vulnerability-mgmt`](areas/13-vulnerability-mgmt/) | Nessus, OpenVAS/Greenbone, Snyk, Nuclei, Lynis, inventário de ativos | 72 | 10 | 5 |
| [`14-ot-ics-iot`](areas/14-ot-ics-iot/) | Modbus, DNP3, IEC-104, MQTT, OPC-UA, domótica | 62 | 27 | 3 |
| [`15-infra-virt-storage-backup`](areas/15-infra-virt-storage-backup/) | Proxmox/PBS, VMware, Synology, QNAP, Veeam | 611 | 247 | 12 |
| [`16-dns-email`](areas/16-dns-email/) | DNS (Pi-hole, Technitium), email e phishing (Mimecast, Zimbra, Abnormal, Sublime) | 94 | 181 | 9 |
| [`17-ai-llm`](areas/17-ai-llm/) | Serviços de IA: Azure OpenAI/AI Foundry, AWS Bedrock, ChatGPT, Whisper | 44 | 1 | 4 |
| [`18-compliance-frameworks`](areas/18-compliance-frameworks/) | Packs mapeados a frameworks: NIST CSF 2.0, CJIS, ENS (RD 311/2022) | 214 | 6 | 4 |
| [`19-threats-campaigns-cves`](areas/19-threats-campaigns-cves/) | Malware, APTs e CVEs específicos | 654 | 107 | 7 |
| [`20-attck-multiplatform`](areas/20-attck-multiplatform/) | Packs genéricos organizados por táticas ATT&CK / multi-plataforma | 690 | 28 | 8 |
| [`21-wazuh-platform-ops`](areas/21-wazuh-platform-ops/) | Saúde do manager, exclusões/afinação, active response, inventário, agentes | 331 | 32 | 6 |
| [`90-misc`](areas/90-misc/) | Casos muito específicos (jogos, ERPs locais, políticas internas) | 30 | 4 | 3 |

## Colisões com o ruleset oficial (v4.14.8)

- **19** regras reutilizam um ID oficial sem `overwrite="yes"` (gera aviso no arranque e só uma das definições fica ativa).
- **3** IDs oficiais são reescritos com `overwrite` por mais do que uma fonte, com conteúdo diferente: carregar essas fontes em conjunto faz valer a última carregada (coluna `other_overwriters`).
- **155** regras fazem `overwrite` intencional de regras oficiais (4 alteram a cadeia `if_sid`/`if_group`/`decoded_as`, 55 só o nível).
- **4** regras declaram `overwrite` sobre IDs que não existem no oficial.
- **14** ficheiros de decoders têm o nome de um ficheiro oficial ou redefinem nomes de decoders oficiais. Testado em `validation.csv` (coluna `decoder_exclude`): indiferente (falha) em 3, necessário em 2, não usar em 6, opcional em 3 pastas — decoders com o nome de um oficial somam-se ao oficial, pelo que excluir o ficheiro oficial pode partir o carregamento.
- **5417** regras usam IDs fora do intervalo recomendado para regras custom (100000–120000); o oficial já ocupa blocos em 150xxx, 184xxx–185xxx e 500xxx.

Detalhe em [`catalog/official_overlap.csv`](catalog/official_overlap.csv) e [`catalog/decoder_replacements.csv`](catalog/decoder_replacements.csv); este último traz as linhas `<decoder_exclude>` candidatas para `ossec.conf` — usar só onde `validation.csv` indica *necessário* ou *opcional*.

## Recolha e grupos de agentes

As regras correm no manager e aplicam-se a todos os agentes; os grupos de agentes não filtram regras. O que um grupo decide é **que eventos chegam** (`<localfile>`, wodles), e uma pasta só dispara se os eventos de que depende forem recolhidos. Por isso cada pasta tem em [`catalog/collection.csv`](catalog/collection.csv) o que exige:

- **por omissão**: já recolhido pelo `ossec.conf` de um agente (canais Security/System/Application, syslog/journald do sistema);
- **grupos de agente**: recolha extra no agente, em [`groups/`](groups/) — 248 pastas;
- **manager**: wodles de cloud (`aws-s3`, `azure-logs`, `gcp-pubsub`), módulos (`office365`, `github`, `ms-graph`), integrações e `<remote>` syslog para equipamentos de rede — 150 pastas;
- **por definir**: eventos JSON ou de texto cuja origem a fonte não documenta — 129 pastas.

Os requisitos vêm de duas origens: **inferidos** (a pasta encadeia em regras oficiais de uma família, p.ex. `win-sysmon` → canal Sysmon, ou filtra `win.system.channel`) e **declarados** (blocos `<localfile>`/`<wodle>`/`<agent_config>` que a fonte traz em `agent.conf`, `ossec.conf` ou nos READMEs; copiados ou extraídos para `collection/` na pasta). Detalhe por entrada em [`catalog/collection_entries.csv`](catalog/collection_entries.csv).

Os grupos são componíveis — um agente pode estar em vários: os partilhados (`win-sysmon`, `win-powershell`, `linux-auditd`, `linux-apache`, `linux-docker`, `osquery`, ...) servem muitas pastas; os `pack-<tópico>` trazem a recolha específica de um produto, com blocos `<agent_config os=...>` por sistema operativo. Cada fonte de eventos aparece uma só vez por grupo (queries diferentes para o mesmo canal passam a recolha completa). Entradas com marcadores por preencher, incompletas ou malformadas na origem ficam no catálogo mas fora dos grupos. Ver [`groups/README.md`](groups/README.md).

## Resposta e playbooks

As regras detetam; o que fazer a seguir vem de três camadas, todas cruzadas por **técnica ATT&CK** (`rule.mitre.id`) e, quando existe, por `rule.id`:

1. **Resposta automática das fontes** — [`catalog/responses.csv`](catalog/responses.csv): cada `<active-response>` e `<integration>` que as fontes trazem, com o script, as regras que o disparam, a ação (bloquear IP, apagar ficheiro, desativar conta, enriquecimento, caso/SOAR...), o impacto e as salvaguardas. Fica **partida** quando o script não existe ou tem outro nome, quando a regra não existe ou foi renumerada pelo autor, e **ignorada** quando está num `agent.conf` (o Wazuh só lê `<active-response>` no `ossec.conf` do manager). Das fontes com licença, scripts e blocos são copiados para `response/` na pasta.
2. **Playbooks procedimentais** — [`catalog/playbooks.csv`](catalog/playbooks.csv), de bibliotecas licenciadas fixadas no `sources.lock` (só se aponta para o documento no commit fixado; nada é copiado):
- ADORSYS-GIS/wazuh-playbook — procedimental (por rule.id/técnica): 3
- ADORSYS-GIS/wazuh-playbook — remediação SCA (por check): 71
- austinsonger/Incident-Playbook — procedimental (por técnica): 43
- cisagov/playbook-ng — contramedida (CISA COUN7ER): 152
- guardsight/gsvsoc_cirt-playbook-battle-cards — procedimental (battle card PICERL): 63
3. **Cobertura** — [`catalog/technique_coverage.csv`](catalog/technique_coverage.csv) por técnica (regras, regras de nível ≥ 12, playbooks, contramedidas, respostas a funcionar, lacunas) e [`catalog/response_coverage.csv`](catalog/response_coverage.csv) por pasta.

A chave de correlação é a técnica, e o Wazuh aceita qualquer texto em `<mitre><id>` sem aviso: muitas fontes usam etiquetas Sigma (`attack.t1059.001`, `attack.defense_evasion`) ou só põem a técnica nos grupos. O catálogo normaliza para T-ID em `rules.csv` (`mitre_norm`, `mitre_status`), resolvendo técnicas revogadas pelo sucessor do ATT&CK (p.ex. T1086 → T1059.001); os XML não são alterados.

Um playbook de uma técnica-mãe cobre as sub-técnicas (T1059 cobre T1059.001). Nenhuma resposta das fontes é recomendada tal como está: as destrutivas não têm allowlist nem modo de teste, e o modelo de active response muda no Wazuh 5.0.

### Sigma como referência de cobertura

A [SigmaHQ](https://github.com/SigmaHQ/sigma) (fixada no `sources.lock`, commit `07ec293a5169`) é usada só como referência: 3760 regras, 381 técnicas. Nenhuma regra Sigma é copiada ou convertida (licença DRL 1.1). Face ao registo: 316 técnicas ambos, 26 técnicas registo sem regras de nível ≥ 12, 39 técnicas só Sigma, 84 técnicas só registo; 18 das que só a Sigma cobre têm regras de nível alto ou crítico. Detalhe em [`catalog/sigma_coverage.csv`](catalog/sigma_coverage.csv), com exemplos e links para cada regra Sigma.

### Lacunas prioritárias: técnicas com mais regras de nível ≥ 12 e sem playbook

| Técnica | Nome | Táticas | Regras nível ≥ 12 | Pastas | Contramedidas CISA | Contenção automática | Outras automações (enriquecimento, notificação, caso) |
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

## Estrutura

```
areas/<NN-área>/<tópico>/<dono>__<repo>/
    rules/*.xml          ficheiros originais, sem alterações
    decoders/*.xml
    lists/               listas CDB referidas pelas regras e encontradas na fonte (quando existem)
    tests/               testes da fonte que dizem respeito a esta pasta (caminhos originais preservados)
    response/            scripts e blocos de resposta da fonte (só fontes com licença)
    collection/          configuração de recolha da fonte: agent.conf/ossec.conf copiados, ou *.extracted.xml com os blocos dos READMEs
    SOURCE.md            origem, commit fixado, licença, mapa caminho-original → caminho-aqui, outras partes da fonte
    LICENSE.upstream     cópia da licença da fonte (quando existe)
catalog/
    sources.csv          uma linha por fonte: commit, licença, testes, % MITRE, % XML estrito, conflitos, intervalo de IDs
    rules.csv            uma linha por regra: id, nível, descrição, MITRE, grupos, if_sid/if_group/decoded_as, área, ficheiro
    decoders.csv         uma linha por decoder: nome, parent, colisão com nome oficial
    id_conflicts.csv     IDs usados por mais do que uma fonte com conteúdo diferente, ou que colidem com o oficial
    dependencies.csv     referências (if_sid, decoded_as, parent, listas CDB) que não existem na pasta nem no oficial, e onde estão
    lists.csv            listas CDB referidas por pasta: copiada da fonte / oficial / em falta
    folders.csv          uma linha por pasta: IDs repetidos, dependências externas, listas em falta, testes, autónoma
    validation.csv       resultado de wazuh-analysisd -t por pasta (gerado por tools/validate.py)
    collection.csv       requisitos de recolha por pasta: por omissão, grupos de agente, manager, por definir
    collection_entries.csv  cada entrada de recolha (inferida ou declarada) e o grupo onde ficou
    groups.csv           grupos-modelo: SO, entradas, pastas que servem
    responses.csv        active responses e integrações das fontes: ação, impacto, gatilho resolvido, salvaguardas, estado
    playbooks.csv        documentos das bibliotecas de playbooks, com técnicas e rule.id
    technique_coverage.csv  por técnica: regras, playbooks, contramedidas, respostas, regras Sigma, lacunas
    sigma_coverage.csv   por técnica: regras Sigma (e de nível alto), fontes de log, regras do registo, estado, exemplos
    response_coverage.csv   por pasta: técnicas com playbook, respostas ok/partidas, destrutivas sem allowlist
    validation_agent_conf.csv  verify-agent-conf dos grupos e dos agent.conf das fontes
    decoder_collisions.csv  nomes de decoder raiz definidos em mais de uma fonte ou também no oficial (sombreiam-se)
    decoder_fields.csv   nomes de campo produzidos pelos decoders, usos, e campo ECS sugerido
    decoder_tests.csv    cada amostra de log (testes da fonte e exemplos nos comentários) no wazuh-logtest: decoder, campos, regra, veredito
    decoder_test_summary.csv  por pasta: ok, sombreado, não descodificado, regra não disparou, falso positivo
site/index.html      página autónoma de pesquisa (abrir no browser, sem servidor): packs, regras, técnicas e playbooks,
                     respostas, grupos, lacunas; cesto de instalação que gera um script com verificação wazuh-analysisd -t
groups/<grupo>/agent.conf  grupos de agentes-modelo, prontos a copiar para etc/shared/<grupo>/ no manager
    excluded.csv         o que ficou de fora e porquê
    stats.json           números agregados
tools/
    sources.txt          lista de repositórios
    playbooks.txt        bibliotecas de playbooks de resposta
    references.txt       referências de cobertura (SigmaHQ)
    sigma.py             leitura das regras SigmaHQ (técnicas, nível, fonte de log)
    sources.lock         commit fixado de cada fonte e biblioteca + data de referência (as-of)
    fetch.sh             clona as fontes no commit do lock (UPDATE=1 avança para o HEAD) e o ruleset oficial para .cache/
    build.py             regenera areas/ e catalog/ (determinístico para o mesmo lock)
    logtest.py           corre as amostras de log de cada pasta no wazuh-logtest (Docker) e verifica decoder, campos e regra
    fields.py            mapa de nomes de campo para ECS
    validate.py          carrega cada pasta num wazuh-manager em Docker (wazuh-analysisd -t) e valida os agent.conf (verify-agent-conf)
    responses.py         extração e classificação de active responses e integrações das fontes
    playbooks.py         leitura das bibliotecas de playbooks (Markdown e dataset COUN7ER)
    mitre.py             normalização MITRE ATT&CK para T-ID
    collection.py        requisitos de recolha: famílias oficiais → entradas, extração de blocos das fontes, grupos
    make_site.py + site_template.html  gera site/index.html a partir do catálogo
    make_docs.py         regenera este README e o NOTICE a partir do catálogo
    taxonomy.py          áreas + regras de classificação e exclusão
    parse_ruleset.py     parser tolerante para o XML sem raiz única do Wazuh
```

Uma fonte que cobre várias áreas (p.ex. SOCFortress, wazuh/integrations, phastier) aparece dividida pelas áreas respetivas, com um `SOURCE.md` em cada parte.

## Reconstruir / atualizar

```bash
pip install -r requirements.txt
./tools/fetch.sh                 # reproduz o snapshot do sources.lock; UPDATE=1 ./tools/fetch.sh para atualizar
python3 tools/build.py --src .cache/src --official .cache/official/ruleset --out .
python3 tools/validate.py        # opcional: requer Docker
python3 tools/logtest.py         # opcional: requer Docker (amostras de log no wazuh-logtest)
python3 tools/make_docs.py .
python3 tools/make_site.py .     # site/index.html: pesquisa de packs, regras, playbooks e script de instalação
```

Correr num sistema de ficheiros sensível a maiúsculas (Linux, ou um volume APFS *case-sensitive* no macOS): o `wazuh/integrations` tem caminhos que só diferem nas maiúsculas (`technitium_dns` / `Technitium_DNS`). Noutro sistema de ficheiros o resultado final é o mesmo, porque o segundo caminho é um duplicado excluído, mas o `excluded.csv` perde essa linha.

O workflow `.github/workflows/registo.yml` corre este pipeline completo em cada push e pull request (e todas as semanas), falha se alguma ferramenta falhar e publica a página e o catálogo como artefacto.

Para acrescentar uma fonte: adicionar a `tools/sources.txt`, classificá-la em `tools/taxonomy.py` (`MAP`) e correr os comandos acima (o `fetch.sh` fixa o commit no lock). O que não tiver regra de classificação cai em `areas/99-unclassified/`.

## Critérios

**Incluído:** qualquer ficheiro com pelo menos uma `<rule id=…>` ou `<decoder name=…>` num repositório público.

**Excluído** (ver `catalog/excluded.csv`): cópias integrais do ruleset oficial, ficheiros `.xml.tmp`, exemplos gerados por ferramentas, versões anteriores do mesmo autor, derivados idênticos de outra fonte e duplicados byte-a-byte (fica a cópia introduzida primeiro, pela data do commit que adicionou o ficheiro; algumas fontes originais conhecidas têm prioridade).

**Conflito de ID:** o mesmo `id` aparece em fontes diferentes com conteúdo diferente, ou reutiliza um ID oficial sem `overwrite="yes"`.

**Dependência:** `if_sid`, `decoded_as`, `<parent>` ou lista CDB que não existe na própria pasta nem no ruleset oficial. "Noutra pasta da mesma fonte" acontece quando uma fonte foi dividida por áreas; "noutra fonte do pack" significa que a peça vive noutro repositório; "em falta" significa que não existe em lado nenhum.

**Pasta autónoma:** sem IDs repetidos dentro da pasta, sem dependências fora dela, sem listas CDB em falta e sem colisões com IDs oficiais. É uma verificação estática: não apanha regex inválidas, opções inexistentes nem a ordem de definição das regras.

**Testes de decoders** (`tools/logtest.py`): cada amostra de log é corrida no `wazuh-logtest` com a pasta carregada sozinha. *Sombreado* quer dizer que o log foi apanhado por um decoder oficial ou de outra origem e os da pasta nunca chegam a correr; *não descodificado*, que nenhum decoder o reconhece. Amostras com `trigger`/`benign` no nome têm de disparar/não disparar uma regra da pasta; ficheiros `.ini` seguem o formato oficial da Wazuh (regra, nível e decoder esperados).

**Validação real** (`tools/validate.py`): cada pasta é carregada sozinha, sobre o ruleset oficial, num `wazuh-manager` em Docker, e corre-se `wazuh-analysisd -t`. *Carrega* significa código de saída 0 e nenhum `ERROR`/`CRITICAL`. Atenção aos avisos: um `if_sid` cujo pai não existe gera só um aviso (7617) e a regra fica ativa **sem essa condição**.

**XML estrito:** o Wazuh aceita XML que um parser rigoroso rejeita (p.ex. `&` ou `<` não escapados em regex). A coluna `wellformed_pct` mede isso; é relevante para a conversão futura, não para o funcionamento em 4.x.

## Licenças

66 das 115 fontes incluídas **não têm ficheiro de licença**: sem licença, o autor mantém todos os direitos. Cada ficheiro é publicado sem alterações, com a origem, o autor e o commit exato no `SOURCE.md` da pasta. **É autor de uma fonte e quer que seja retirada? [Abra uma issue](https://github.com/mjvmsteixeira/wazuh-community-rulesets/issues/new/choose) e é removida.** Ver [`NOTICE.pt.md`](NOTICE.pt.md).

## Indicadores de qualidade

Só 9 fontes trazem testes (`ArabMohammed/SOC-Notes`, `Halino/Wazuh-Unifi`, `NucleiAv/caddy-detection-rules`, `Sbharadwaj05/Wazuh-NIST-Rules-Set`, `Sbharadwaj05/ot-sentinel-rules`, `calvinanglo/corpsec-ops-platform`, `fredycibersec/ENS-Wazuh-integration`, `mjvmsteixeira/wazuh-database-compliance`, `wazuh/integrations`). As colunas de `catalog/sources.csv` permitem priorizar: `has_tests`, `mitre_pct`, `age_days`, `missing_deps`, `deps_other_folder`, `lists_missing`, `internal_dup_ids`, `folders_standalone`; `catalog/validation.csv` diz se cada pasta carrega de facto e qual o primeiro erro.

## Roadmap

1. **Registo** (esta fase): inventário, arrumação por áreas, catálogo, conflitos e dependências.
2. **Triagem**: marcar por fonte *adotar / rever / arquivar*, com base nos indicadores, em `validation.csv` e nos testes copiados para `tests/` (logtest / detlab).
3. **Normalização 4.x**: atribuir um intervalo de IDs por área, renumerar e reescrever `if_sid` em conformidade, gerando um pack carregável de uma só vez.
4. **Wazuh 5.0**: converter decoders XML → YAML/ECS e regras para o novo motor, começando pelas fontes adotadas.
