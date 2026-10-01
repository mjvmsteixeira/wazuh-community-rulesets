#!/usr/bin/env python3
"""Gera README.md/NOTICE.md (inglês, por omissão), README.pt.md/NOTICE.pt.md, os README das áreas e groups/README.md a partir de catalog/."""
import json, csv, os, sys
ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'
sys.path.insert(0, os.path.join(ROOT, 'tools'))
from taxonomy import AREAS, AREAS_EN
s = json.load(open(os.path.join(ROOT, 'catalog/stats.json')))
src = list(csv.DictReader(open(os.path.join(ROOT, 'catalog/sources.csv'))))
inc = [x for x in src if x['status'] == 'incluída']
nolic = [x for x in inc if x['license'] == 'NONE']
tested = [x for x in inc if x['has_tests'] == 'True']
val_path = os.path.join(ROOT, 'catalog/validation.csv')
val = list(csv.DictReader(open(val_path))) if os.path.exists(val_path) else []
val_ok = sum(1 for v in val if v['loads_ok'] == 'True')
val_txt = (f"| Pastas que carregam em `wazuh-analysisd -t` ({s['official_reference'].split()[1]}) | {val_ok} de {len(val)} "
           f"({sum(1 for v in val if v['loads_ok'] == 'True' and v['warnings'] == '0')} sem avisos) |\n") if val else ''
lists = s.get('cdb_lists', {})
cs = s.get('collection', {})
gv_path = os.path.join(ROOT, 'catalog/validation_agent_conf.csv')
gval = list(csv.DictReader(open(gv_path))) if os.path.exists(gv_path) else []
gok = {r['file'].split('/')[1]: r['ok'] == 'True' for r in gval if r['kind'] == 'grupo'}
fval = [r for r in gval if r['kind'] == 'fonte']
dd = s.get('decoders_detail', {})
dt_path = os.path.join(ROOT, 'catalog/decoder_test_summary.csv')
dts = list(csv.DictReader(open(dt_path))) if os.path.exists(dt_path) else []
dt_tot = {k: sum(int(r[k]) for r in dts) for k in ('samples', 'ok', 'not_tested', 'sombreado', 'não descodificado', 'regra não disparou', 'falso positivo')} if dts else {}
sb = s.get('siblings', {})
sy_path = os.path.join(ROOT, 'catalog/synthetic_tests.csv')
sys_ = list(csv.DictReader(open(sy_path))) if os.path.exists(sy_path) else []
sy = {'n': len(sys_), 'ok': sum(1 for r in sys_ if r['verdict'] == 'ok'), 'folders': len({r['folder'] for r in sys_}),
      'ec': sum(1 for r in sys_ if r['format'] == 'eventchannel'), 'ec_ok': sum(1 for r in sys_ if r['format'] == 'eventchannel' and r['verdict'] == 'ok'),
      'off': sum(1 for r in sys_ if r['verdict'] == 'regra oficial'), 'bad': sum(1 for r in sys_ if r['verdict'] == 'campo inexistente')}
cb_path = os.path.join(ROOT, 'catalog/combo_summary.csv')
cbs = list(csv.DictReader(open(cb_path))) if os.path.exists(cb_path) else []
cb = {'combos': len(cbs), 'samples': sum(int(r['samples']) for r in cbs), 'shadowed': sum(int(r['shadowed']) for r in cbs),
      'with_shadow': sum(1 for r in cbs if int(r['shadowed'])), 'not_together': sum(1 for r in cbs if r['loaded_together'] != 'True'),
      'dec': sum(int(r['sombreado (decoder)']) for r in cbs), 'sib': sum(int(r['sombreado (regra irmã)']) for r in cbs), 'conf': sum(int(r['conflito de ID']) for r in cbs)}
rs = s.get('response', {}); ms = s.get('mitre', {})
techs = list(csv.DictReader(open(os.path.join(ROOT, 'catalog/technique_coverage.csv'))))
gap_rows = sorted([x for x in techs if int(x['rules_level12']) and not int(x['playbooks'])], key=lambda x: (-int(x['rules_level12']), x['technique']))[:15]
gap_tab = '\n'.join(f"| [{x['technique']}](https://attack.mitre.org/techniques/{x['technique'].replace('.', '/')}/) | {x['name']} "
                    f"| {x['tactics'].replace(';', ', ')} | {x['rules_level12']} | {x['folders']} | {x['countermeasures'] or '—'} "
                    f"| {x['containment_ok'] or '—'} | {x['automations_ok'] or '—'} |" for x in gap_rows)
pbd = rs.get('playbook_docs', {})
pb_lines = '\n'.join(f"- {k.split(' — ')[0]} — {k.split(' — ')[1]}: {v}" for k, v in pbd.items())
dex = {}
for v in val:
    if v.get('decoder_exclude'): dex[v['decoder_exclude']] = dex.get(v['decoder_exclude'], 0) + 1
dex_txt = (' Testado em `validation.csv` (coluna `decoder_exclude`): ' + ', '.join(f'{k} em {n}' for k, n in sorted(dex.items()))
           + ' pastas — decoders com o nome de um oficial somam-se ao oficial, pelo que excluir o ficheiro oficial pode partir o carregamento.') if dex else ''
rows = '\n'.join(f"| [`{a}`](areas/{a}/) | {AREAS[a]} | {v['rules']} | {v['decoders']} | {v['sources']} |"
                 for a, v in s['per_area'].items() if v['rules'] or v['decoders'])
ov = s.get('official_overlap', {})
ov_txt = (f"- **{ov.get('colisão', 0)}** regras reutilizam um ID oficial sem `overwrite=\"yes\"` (gera aviso no arranque e só uma das definições fica ativa).\n"
          f"- **{s['id_conflicts_official_multi_overwrite']}** IDs oficiais são reescritos com `overwrite` por mais do que uma fonte, com conteúdo diferente: carregar essas fontes em conjunto faz valer a última carregada (coluna `other_overwriters`).\n"
          f"- **{sum(v for k, v in ov.items() if k.startswith('overwrite') and 'inexistente' not in k)}** regras fazem `overwrite` intencional de regras oficiais "
          f"({ov.get('overwrite estrutural', 0)} alteram a cadeia `if_sid`/`if_group`/`decoded_as`, {ov.get('overwrite de nível', 0)} só o nível).\n"
          f"- **{ov.get('overwrite de ID inexistente no oficial', 0)}** regras declaram `overwrite` sobre IDs que não existem no oficial.\n"
          f"- **{s.get('decoder_replacement_files', 0)}** ficheiros de decoders têm o nome de um ficheiro oficial ou redefinem nomes de decoders oficiais.{dex_txt}\n"
          f"- **{s.get('rules_outside_custom_range', 0)}** regras usam IDs fora do intervalo recomendado para regras custom (100000–120000); o oficial já ocupa blocos em 150xxx, 184xxx–185xxx e 500xxx.")
REPO = 'https://github.com/mjvmsteixeira/wazuh-community-rulesets'
SITE = 'https://mjvmsteixeira.github.io/wazuh-community-rulesets/'
readme = f"""# wazuh-community-rulesets

[English](README.md) · **Português** · [Página de pesquisa]({SITE}pt/) · [Issues]({REPO}/issues)

Registo organizado por áreas das coleções comunitárias de regras e decoders Wazuh (formato XML 4.x) espalhadas pelo GitHub. O objetivo desta fase é **inventariar e arrumar**, preservando os ficheiros originais sem alterações. A normalização de IDs e a conversão para o motor do Wazuh 5.0 (YAML/ECS) são fases seguintes.

> ⚠️ **Não carregar tudo de uma vez num manager.** Há {s['id_conflicts']} IDs de regra em conflito entre fontes (ver [`catalog/id_conflicts.csv`](catalog/id_conflicts.csv)); combinar fontes exige renumeração prévia. Nem todas as pastas funcionam sozinhas: só **{s['folders_standalone']} de {s['folders']}** são autónomas por análise estática (sem IDs repetidos, dependências externas, listas CDB em falta nem colisões com IDs oficiais) — ver [`catalog/folders.csv`](catalog/folders.csv){' e o resultado real em [`catalog/validation.csv`](catalog/validation.csv)' if val else ''}.

## Números ({s['generated']})

| | |
|---|---:|
| Fontes listadas / clonadas | {s['sources_listed']} / {s['sources_cloned']} |
| Fontes incluídas | {s['sources_included']} |
| Ficheiros XML registados | {s['files']} |
| Regras (entradas) | {s['rules']} (das quais {s['rule_entries_dup_in_folder']} repetem um ID já presente na mesma pasta) |
| Decoders | {s['decoders']} |
| IDs de regra distintos | {s['unique_rule_ids']} |
| IDs em conflito | {s['id_conflicts']}: {s['id_conflicts_community']} entre fontes da comunidade, {s['id_conflicts_official_collision']} colisões com IDs oficiais sem `overwrite`, {s['id_conflicts_official_multi_overwrite']} IDs oficiais reescritos por várias fontes |
| Dependências em falta (`if_sid`, `decoded_as`, `parent`) | {s['deps_missing']} |
| Dependências noutra pasta da mesma fonte | {s['deps_same_source_other_folder']} |
| Dependências noutra fonte do pack | {s['deps_cross_source']} |
| Listas CDB referidas | {sum(lists.values())}: {lists.get('copiada da fonte', 0)} copiadas da fonte, {lists.get('oficial', 0)} oficiais, {lists.get('em falta', 0)} em falta |
| Pastas autónomas (análise estática) | {s['folders_standalone']} de {s['folders']} |
{val_txt}| Ficheiros de teste copiados | {s['test_files_copied']} |
| Decoders raiz / filhos | {dd.get('roots', 0)} / {dd.get('children', 0)} ({dd.get('root_collisions_between_sources', 0)} nomes de raiz em colisão entre fontes; {dd.get('root_names_also_official', 0)} com nome oficial) |
| Campos produzidos pelos decoders | {dd.get('distinct_fields', 0)} nomes distintos; {dd.get('fields_with_ecs', 0)} com correspondência ECS ({dd.get('field_uses_with_ecs_pct', 0)}% dos usos) |
{f"| Amostras de log no wazuh-logtest | {dt_tot['samples']} em {len(dts)} pastas: {dt_tot['ok']} ok, {dt_tot['sombreado']} sombreadas por outro decoder, {dt_tot['não descodificado']} não descodificadas, {dt_tot['regra não disparou']} sem a regra esperada, {dt_tot['falso positivo']} falsos positivos |" if dts else ''}
| Configuração de recolha das fontes | {cs.get('declared_files', 0)} ficheiros, {cs.get('declared_entries', 0)} entradas ({cs.get('unassigned_files', 0)} ficheiros sem pasta atribuída) |
| Regras com técnica MITRE válida | {ms.get('válido', 0) + ms.get('normalizado', 0)} ({ms.get('normalizado', 0)} só depois de normalizar etiquetas Sigma/grupos; {ms.get('inválido', 0)} com técnicas descontinuadas sem sucessor) |
| Respostas das fontes (active response + integrações) | {rs.get('definitions', 0)}: {rs.get('by_status', {}).get('ok', 0)} ok, {rs.get('by_status', {}).get('partido', 0)} partidas, {rs.get('by_status', {}).get('ignorado', 0)} ignoradas pelo Wazuh; {rs.get('destructive', 0)} destrutivas ({rs.get('destructive_without_allowlist', 0)} sem allowlist) |
| Técnicas com regras de nível ≥ 12 | {rs.get('techniques_level12', 0)}: {rs.get('techniques_level12_without_playbook', 0)} sem playbook, {rs.get('techniques_level12_without_countermeasure', 0)} sem contramedida CISA, {rs.get('techniques_level12_without_containment', 0)} sem contenção automática a funcionar |
| Grupos de agentes-modelo | {cs.get('groups', 0)}{f" ({sum(gok.values())} válidos em `verify-agent-conf`)" if gok else ''} |
| Ficheiros excluídos (cópias, temporários, duplicados) | {s['excluded_files']} |

Referência para comparação: **{s['official_reference']}**.

## Áreas

| Área | Âmbito | Regras | Decoders | Fontes |
|---|---|---:|---:|---:|
{rows}

## Colisões com o ruleset oficial ({s["official_reference"].split()[1]})

{ov_txt}

Detalhe em [`catalog/official_overlap.csv`](catalog/official_overlap.csv) e [`catalog/decoder_replacements.csv`](catalog/decoder_replacements.csv); este último traz as linhas `<decoder_exclude>` candidatas para `ossec.conf` — usar só onde `validation.csv` indica *necessário* ou *opcional*.

## Regras irmãs (filhas do mesmo pai)

Comportamento medido no `wazuh-analysisd` {s["official_reference"].split()[1]}: os filhos de um mesmo pai (`if_sid`/`if_group`) de **nível 0 são avaliados primeiro**, depois os restantes por **nível decrescente**; em empate, pela **ordem de carregamento**, que é a ordem do nome do ficheiro em todo o conjunto (oficiais e `etc/rules` misturados; o ID não conta). O primeiro que corresponder fica com o evento. Uma filha **sem condições próprias** (*apanha-tudo*) corresponde sempre e silencia todas as irmãs avaliadas depois dela — incluindo regras oficiais, com a pasta instalada sozinha — e o `wazuh-analysisd -t` não avisa. Um ID repetido em dois ficheiros fica só com a definição carregada primeiro; a outra não existe (nem pendurada no pai). Por isso o script da página e os testes instalam cada ficheiro como `<prefixo-do-pack>__<ficheiro>`: um nome original como `02-rules.xml` carregaria antes dos oficiais e os `if_sid` oficiais falhariam.

- **{sb.get('catchalls_silencing_official', 0)}** regras apanha-tudo em {sb.get('folders_silencing_official', 0)} pastas silenciam **{sb.get('official_rules_silenced', 0)}** regras oficiais ([`catalog/catchall_silences_official.csv`](catalog/catchall_silences_official.csv)).
- **{sb.get('shared_parents', 0)}** pais têm filhos em fontes diferentes ({sb.get('rules_involved', 0)} regras; {sb.get('parents_with_catchall', 0)} com apanha-tudo; {sb.get('ambiguous_parents', 0)} pais com o mesmo ID definido de forma diferente em várias fontes); {sb.get('folder_pairs', 0)} pares de pastas em que uma silencia a outra se forem instaladas juntas ([`catalog/sibling_parents.csv`](catalog/sibling_parents.csv)). O cesto da página aplica este modelo à seleção.
{f'''- Amostras sintéticas (`tools/synth.py`): um evento por regra, gerado a partir das condições da regra e da cadeia de pais (eventos JSON no `wazuh-logtest`; eventos Windows EventChannel injetados na fila do `wazuh-analysisd`, que o logtest não descodifica). {sy["ok"]} de {sy["n"]} confirmadas pelo motor em {sy["folders"]} pastas ({sy["ec_ok"]} de {sy["ec"]} Windows); {sy["off"]} acabaram numa regra oficial em vez da regra da pasta; {sy["bad"]} regras Windows usam um campo com maiúscula (`win.eventdata.TargetFilename`) que o decoder nunca produz e por isso nunca disparam ([`catalog/synthetic_tests.csv`](catalog/synthetic_tests.csv)). Só as confirmadas entram no teste de pares.''' if sys_ else ''}
{f'''- Prova empírica (`tools/combo_test.py`): {cb["combos"]} pares de pastas carregados juntos, {cb["samples"]} amostras repetidas; {cb["shadowed"]} mudaram de dono ({cb["dec"]} por decoder, {cb["sib"]} por regra irmã, {cb["conf"]} por conflito de ID: o mesmo ID, ou um antepassado na cadeia `if_sid`, definido nas duas pastas) em {cb["with_shadow"]} pares; {cb["not_together"]} pares não carregam juntos ([`catalog/combo_summary.csv`](catalog/combo_summary.csv), [`catalog/combo_tests.csv`](catalog/combo_tests.csv)).''' if cbs else ''}

## Recolha e grupos de agentes

As regras correm no manager e aplicam-se a todos os agentes; os grupos de agentes não filtram regras. O que um grupo decide é **que eventos chegam** (`<localfile>`, wodles), e uma pasta só dispara se os eventos de que depende forem recolhidos. Por isso cada pasta tem em [`catalog/collection.csv`](catalog/collection.csv) o que exige:

- **por omissão**: já recolhido pelo `ossec.conf` de um agente (canais Security/System/Application, syslog/journald do sistema);
- **grupos de agente**: recolha extra no agente, em [`groups/`](groups/) — {cs.get('folders_with_agent_groups', 0)} pastas;
- **manager**: wodles de cloud (`aws-s3`, `azure-logs`, `gcp-pubsub`), módulos (`office365`, `github`, `ms-graph`), integrações e `<remote>` syslog para equipamentos de rede — {cs.get('folders_with_manager_requirements', 0)} pastas;
- **por definir**: eventos JSON ou de texto cuja origem a fonte não documenta — {cs.get('folders_with_undefined', 0)} pastas.

Os requisitos vêm de duas origens: **inferidos** (a pasta encadeia em regras oficiais de uma família, p.ex. `win-sysmon` → canal Sysmon, ou filtra `win.system.channel`) e **declarados** (blocos `<localfile>`/`<wodle>`/`<agent_config>` que a fonte traz em `agent.conf`, `ossec.conf` ou nos READMEs; copiados ou extraídos para `collection/` na pasta). Detalhe por entrada em [`catalog/collection_entries.csv`](catalog/collection_entries.csv).

Os grupos são componíveis — um agente pode estar em vários: os partilhados (`win-sysmon`, `win-powershell`, `linux-auditd`, `linux-apache`, `linux-docker`, `osquery`, ...) servem muitas pastas; os `pack-<tópico>` trazem a recolha específica de um produto, com blocos `<agent_config os=...>` por sistema operativo. Cada fonte de eventos aparece uma só vez por grupo (queries diferentes para o mesmo canal passam a recolha completa). Entradas com marcadores por preencher, incompletas ou malformadas na origem ficam no catálogo mas fora dos grupos. Ver [`groups/README.md`](groups/README.md).

## Resposta e playbooks

As regras detetam; o que fazer a seguir vem de três camadas, todas cruzadas por **técnica ATT&CK** (`rule.mitre.id`) e, quando existe, por `rule.id`:

1. **Resposta automática das fontes** — [`catalog/responses.csv`](catalog/responses.csv): cada `<active-response>` e `<integration>` que as fontes trazem, com o script, as regras que o disparam, a ação (bloquear IP, apagar ficheiro, desativar conta, enriquecimento, caso/SOAR...), o impacto e as salvaguardas. Fica **partida** quando o script não existe ou tem outro nome, quando a regra não existe ou foi renumerada pelo autor, e **ignorada** quando está num `agent.conf` (o Wazuh só lê `<active-response>` no `ossec.conf` do manager). Das fontes com licença, scripts e blocos são copiados para `response/` na pasta.
2. **Playbooks procedimentais** — [`catalog/playbooks.csv`](catalog/playbooks.csv), de bibliotecas licenciadas fixadas no `sources.lock` (só se aponta para o documento no commit fixado; nada é copiado):
{pb_lines}
3. **Cobertura** — [`catalog/technique_coverage.csv`](catalog/technique_coverage.csv) por técnica (regras, regras de nível ≥ 12, playbooks, contramedidas, respostas a funcionar, lacunas) e [`catalog/response_coverage.csv`](catalog/response_coverage.csv) por pasta.

A chave de correlação é a técnica, e o Wazuh aceita qualquer texto em `<mitre><id>` sem aviso: muitas fontes usam etiquetas Sigma (`attack.t1059.001`, `attack.defense_evasion`) ou só põem a técnica nos grupos. O catálogo normaliza para T-ID em `rules.csv` (`mitre_norm`, `mitre_status`), resolvendo técnicas revogadas pelo sucessor do ATT&CK (p.ex. T1086 → T1059.001); os XML não são alterados.

Um playbook de uma técnica-mãe cobre as sub-técnicas (T1059 cobre T1059.001). Nenhuma resposta das fontes é recomendada tal como está: as destrutivas não têm allowlist nem modo de teste, e o modelo de active response muda no Wazuh 5.0.

### Sigma como referência de cobertura

A [SigmaHQ](https://github.com/SigmaHQ/sigma) (fixada no `sources.lock`, commit `{s.get('sigma', {}).get('commit', '')}`) é usada só como referência: {s.get('sigma', {}).get('rules', 0)} regras, {s.get('sigma', {}).get('techniques_sigma', 0)} técnicas. Nenhuma regra Sigma é copiada ou convertida (licença DRL 1.1). Face ao registo: {', '.join(f'{v} técnicas {k}' for k, v in s.get('sigma', {}).get('by_status', {}).items())}; {s.get('sigma', {}).get('sigma_only_with_high', 0)} das que só a Sigma cobre têm regras de nível alto ou crítico. Detalhe em [`catalog/sigma_coverage.csv`](catalog/sigma_coverage.csv), com exemplos e links para cada regra Sigma.

### Lacunas prioritárias: técnicas com mais regras de nível ≥ 12 e sem playbook

| Técnica | Nome | Táticas | Regras nível ≥ 12 | Pastas | Contramedidas CISA | Contenção automática | Outras automações (enriquecimento, notificação, caso) |
|---|---|---|---:|---:|---:|---:|---:|
{gap_tab}

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
    sibling_parents.csv  pais com filhos em fontes diferentes: filhos por pasta (id@nível, * = apanha-tudo), filhos oficiais
    catchall_silences_official.csv  regras apanha-tudo que silenciam regras oficiais irmãs
    synthetic_tests.csv  amostras sintéticas (uma por regra) e a regra que o motor disparou com a pasta sozinha
    combo_tests.csv / combo_summary.csv  pares de pastas carregados juntos: cada amostra de log e o que mudou face à pasta sozinha
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
    combo_test.py        carrega pastas juntas no wazuh-logtest e repete as amostras (sombreamento entre packs)
    samples.py           extração das amostras de log e script que corre dentro do contentor
    synth.py             amostras sintéticas a partir das condições das regras (JSON e Windows EventChannel)
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
python3 tools/combo_test.py --auto   # opcional: requer Docker (pares de pastas carregados juntos; ~30 min; corre todas as semanas no CI)
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

{len(nolic)} das {len(inc)} fontes incluídas **não têm ficheiro de licença**: sem licença, o autor mantém todos os direitos. Cada ficheiro é publicado sem alterações, com a origem, o autor e o commit exato no `SOURCE.md` da pasta. **É autor de uma fonte e quer que seja retirada? [Abra uma issue]({REPO}/issues/new/choose) e é removida.** Ver [`NOTICE.pt.md`](NOTICE.pt.md).

## Indicadores de qualidade

Só {len(tested)} fontes trazem testes ({', '.join('`'+x['repo']+'`' for x in tested)}). As colunas de `catalog/sources.csv` permitem priorizar: `has_tests`, `mitre_pct`, `age_days`, `missing_deps`, `deps_other_folder`, `lists_missing`, `internal_dup_ids`, `folders_standalone`; `catalog/validation.csv` diz se cada pasta carrega de facto e qual o primeiro erro.

## Roadmap

1. **Registo** (esta fase): inventário, arrumação por áreas, catálogo, conflitos e dependências.
2. **Triagem**: marcar por fonte *adotar / rever / arquivar*, com base nos indicadores, em `validation.csv` e nos testes copiados para `tests/` (logtest / detlab).
3. **Normalização 4.x**: atribuir um intervalo de IDs por área, renumerar e reescrever `if_sid` em conformidade, gerando um pack carregável de uma só vez.
4. **Wazuh 5.0**: converter decoders XML → YAML/ECS e regras para o novo motor, começando pelas fontes adotadas.
"""
open(os.path.join(ROOT, 'README.pt.md'), 'w').write(readme)

lic = {}
for x in inc: lic.setdefault(x['license'], []).append(x['repo'])
ll = '\n'.join(f"- **{k}** ({len(v)}): {', '.join(v)}" for k, v in sorted(lic.items()) if k != 'NONE')
nl = '\n'.join(f"- [{x['repo']}]({x['url']}) — {x['rules']} regras, {x['decoders']} decoders" for x in nolic)
open(os.path.join(ROOT, 'NOTICE.pt.md'), 'w').write(f"""# NOTICE — licenças das fontes

[English](NOTICE.md) · **Português**

Este repositório agrega ficheiros de terceiros **sem os modificar**. Cada pasta de fonte tem `SOURCE.md` com o commit exato de origem e, quando existe, `LICENSE.upstream` com a licença original. Os direitos pertencem aos respetivos autores.

A maior parte das regras Wazuh derivam do ecossistema OSSEC/Wazuh (GPLv2). Várias fontes declaram GPL-3.0 ou AGPL-3.0, cujos termos se propagam a trabalhos derivados. Antes de publicar um pack combinado, a licença resultante tem de ser compatível com todas as fontes incluídas.

## Fontes com licença identificada

{ll}

## Blog da Wazuh

Os exemplos de regras, decoders e configuração dos artigos do [blog da Wazuh](https://wazuh.com/blog/) são capturados por `tools/fetch_blog.py` para `snapshots/wazuh-blog/` e reproduzidos sem alterações, um artigo por pasta. O conteúdo é © Wazuh, Inc.; cada pasta indica no `SOURCE.md` o artigo de origem, com o link, o título e as datas de publicação e de captura.

## Pedidos de remoção

É autor de uma fonte e não quer o seu conteúdo aqui? [Abra uma issue]({REPO}/issues/new/choose) (modelo *Pedido de remoção*) e a fonte é retirada do registo e da página na versão seguinte.

## Fontes sem ficheiro de licença ({len(nolic)})

O autor mantém todos os direitos; os ficheiros são publicados sem alterações e com a origem indicada. Uso interno recomendado até o repositório de origem incluir licença:

{nl}

## Fontes que falharam o clone

{chr(10).join(f'- {r} (repositório removido ou privado à data da recolha).' for r in s['sources_failed']) or '- nenhuma'}
""")
# README por área (depois do build e, se existir, da validação)
folders = list(csv.DictReader(open(os.path.join(ROOT, 'catalog/folders.csv'))))
collection = {r['folder']: r for r in csv.DictReader(open(os.path.join(ROOT, 'catalog/collection.csv')))}
rcov = {r['folder']: r for r in csv.DictReader(open(os.path.join(ROOT, 'catalog/response_coverage.csv')))}
srcinfo = {x['repo']: x for x in src}
vinfo = {v['folder']: v for v in val}
for ar in AREAS:
    d = os.path.join(ROOT, 'areas', ar)
    if not os.path.isdir(d): continue
    with open(os.path.join(d, 'README.md'), 'w') as fh:
        fh.write(f"# {ar}\n\n{AREAS_EN[ar]}.\n\n| Topic | Source | Rules | Decoders | Standalone | Loads | Collection | Playbooks | Responses | License | Last commit | Tests |\n"
                 f"|---|---|---:|---:|---|---|---|---|---|---|---|---:|\n")
        for x in [x for x in folders if x['area'] == ar]:
            si, v = srcinfo[x['source']], vinfo.get(x['folder'])
            loads = '—' if v is None else ('no' if v['loads_ok'] != 'True' else ('yes' if v['warnings'] == '0' else f"yes ({v['warnings']} warning{'' if v['warnings'] == '1' else 's'})"))
            c, q = collection[x['folder']], rcov[x['folder']]
            pbc = f"{round(100 * int(q['techniques_with_playbook']) / int(q['techniques']))}% of {q['techniques']} techniques" if int(q['techniques']) else 'no MITRE'
            rsp = ', '.join(filter(None, [f"{q['responses_ok']} ok ({q['containment_ok']} containment)" if q['responses_ok'] != '0' else '',
                                           f"{q['responses_broken']} broken" if q['responses_broken'] != '0' else '',
                                           f"{q['responses_destructive_unsafe']} destructive without allowlist" if q['responses_destructive_unsafe'] != '0' else ''])) or '—'
            rec = '; '.join(filter(None, [', '.join(f'`{g}`' for g in c['agent_groups'].split(';') if g),
                                          'manager: ' + c['manager_requirements'].replace(';', ', ') if c['manager_requirements'] else '',
                                          'to be defined' if c['undefined'] else ''])) or ('default' if c['default_inputs'] else '—')
            lic_s = 'MIT? (README badge, no LICENSE file)' if si['license'].startswith('MIT?') else si['license']
            fh.write(f"| {x['topic']} | [{x['source']}]({si['url']}) | {x['rules']} | {x['decoders']} | {'yes' if x['standalone'] == 'True' else 'no'} "
                     f"| {loads} | {rec} | {pbc} | {rsp} | {lic_s} | {si['last_commit']} | {x['tests'] if x['tests'] != '0' else '—'} |\n")
        fh.write("\n*Standalone*: static analysis (no repeated IDs, external dependencies, missing CDB lists or collisions with official IDs), "
                 "see `catalog/folders.csv`. *Loads*: `wazuh-analysisd -t` with the folder alone on top of the official ruleset, "
                 "see `catalog/validation.csv`. *Collection*: agent groups (`groups/`) and manager requirements, see `catalog/collection.csv`. "
                 "*Playbooks*: the folder's techniques with a procedural playbook; *Responses*: the source's active responses and integrations "
                 "linked to the folder, see `catalog/response_coverage.csv` and `catalog/responses.csv`.\n")
groups_rows = list(csv.DictReader(open(os.path.join(ROOT, 'catalog/groups.csv'))))
ORIGIN_EN = {'inferido': 'inferred', 'declarado pela fonte': 'declared by the source'}
gtab = '\n'.join(f"| [`{g['group']}`]({g['group']}/agent.conf) | {g['os'].replace(';', ', ').replace('qualquer', 'any')} | {g['entries']} | {g['folders']} "
                 f"| {', '.join(ORIGIN_EN.get(o, o) for o in g['origin'].split(';'))} | {'—' if g['group'] not in gok else ('yes' if gok[g['group']] else '**no**')} |" for g in groups_rows)
open(os.path.join(ROOT, 'groups', 'README.md'), 'w').write(f"""# Model agent groups

Generated by `tools/build.py` from [`../catalog/collection_entries.csv`](../catalog/collection_entries.csv). Each group only carries the **extra** agent-side collection; what the default `ossec.conf` already collects and what runs on the manager (cloud wodles, modules, integrations, `<remote>` syslog) is in [`../catalog/collection.csv`](../catalog/collection.csv).

Groups **do not filter rules**: a folder's rules run on the manager for every agent. A group makes sure the events the folder depends on arrive. To use a pack: load the folder on the manager (`rules/`, `decoders/`, `lists/`) and put the agents in the groups listed in the *Collection* column of the area README.

## How to apply

```bash
# on the manager
mkdir -p /var/ossec/etc/shared/win-sysmon
cp groups/win-sysmon/agent.conf /var/ossec/etc/shared/win-sysmon/agent.conf
chown -R wazuh:wazuh /var/ossec/etc/shared/win-sysmon
/var/ossec/bin/verify-agent-conf -f /var/ossec/etc/shared/win-sysmon/agent.conf
/var/ossec/bin/agent_groups -a -g win-sysmon -q            # create the group
/var/ossec/bin/agent_groups -a -i <agent ID> -g win-sysmon -q
```

An agent can be in several groups (`win-sysmon` + `win-powershell` + `pack-...`). The `pack-*` paths come from the sources: review before use.

## Groups ({len(groups_rows)})

| Group | OS | Entries | Folders served | Origin | `verify-agent-conf` |
|---|---|---:|---:|---|---|
{gtab}
""")

# ---------- inglês (por omissão)
OV_EN = {'colisão': 'collision', 'overwrite de nível': 'level overwrite', 'overwrite estrutural': 'structural overwrite'}
dex_en = (' Tested in `validation.csv` (`decoder_exclude` column): ' + ', '.join(f"{ {'necessário': 'required', 'opcional': 'optional', 'não usar': 'do not use', 'indiferente (falha)': 'irrelevant (fails)'}.get(k, k)} in {n}" for k, n in sorted(dex.items()))
          + ' folders — decoders named like an official one add to it, so excluding the official file can break loading.') if dex else ''
rows_en = '\n'.join(f"| [`{a}`](areas/{a}/) | {AREAS_EN[a]} | {v['rules']} | {v['decoders']} | {v['sources']} |"
                    for a, v in s['per_area'].items() if v['rules'] or v['decoders'])
sg = s.get('sigma', {})
SG_EN = {'ambos': 'both', 'só registo': 'registry only', 'só Sigma': 'Sigma only', 'registo sem regras de nível ≥ 12': 'registry without level ≥ 12 rules'}
PB_EN = {'procedimental (por rule.id/técnica)': 'procedural (by rule.id/technique)', 'remediação SCA (por check)': 'SCA remediation (by check)',
         'procedimental (por técnica)': 'procedural (by technique)', 'contramedida (CISA COUN7ER)': 'countermeasure (CISA COUN7ER)',
         'procedimental (battle card PICERL)': 'procedural (PICERL battle card)'}
pb_en = '\n'.join(f"- {k.split(' — ')[0]} — {PB_EN.get(k.split(' — ')[1], k.split(' — ')[1])}: {v}" for k, v in pbd.items())
readme_en = f"""# wazuh-community-rulesets

**English** · [Português](README.pt.md) · [Search page]({SITE}) · [Issues]({REPO}/issues)

A registry of the community Wazuh rule and decoder collections (4.x XML format) scattered across GitHub, organized by area, validated on a real `wazuh-manager`, and cross-referenced with log collection, response playbooks, MITRE ATT&CK and SigmaHQ coverage. Original files are kept **unchanged**, each with its origin, author and pinned commit.

**[Open the search page]({SITE})** to browse packs, rules, decoders, techniques and playbooks, copy files, and generate an install script for your manager.

> ⚠️ **Do not load everything at once on a manager.** {s['id_conflicts']} rule IDs conflict between sources (see [`catalog/id_conflicts.csv`](catalog/id_conflicts.csv)); combining sources requires renumbering first. Not every folder works on its own: **{s['folders_standalone']} of {s['folders']}** are standalone by static analysis — see [`catalog/folders.csv`](catalog/folders.csv){' and the real result in [`catalog/validation.csv`](catalog/validation.csv)' if val else ''}.

## Questions, errors, new sources

[Open an issue]({REPO}/issues/new/choose): report a pack that does not load or misbehaves, propose a new source, or ask for anything in this registry. **Author of a source and want it removed? Open an issue (*Removal request*) and it will be taken down.**

## Numbers ({s['generated']})

| | |
|---|---:|
| Sources listed / cloned | {s['sources_listed']} / {s['sources_cloned']} |
| Sources included | {s['sources_included']} |
| XML files | {s['files']} |
| Rules (entries) | {s['rules']} ({s['rule_entries_dup_in_folder']} repeat an ID already in the same folder) |
| Decoders | {s['decoders']} |
| Distinct rule IDs | {s['unique_rule_ids']} |
| Conflicting IDs | {s['id_conflicts']}: {s['id_conflicts_community']} between community sources, {s['id_conflicts_official_collision']} collisions with official IDs without `overwrite`, {s['id_conflicts_official_multi_overwrite']} official IDs rewritten by several sources |
| Missing dependencies (`if_sid`, `decoded_as`, `parent`) | {s['deps_missing']} |
| Dependencies in another folder of the same source / in another source | {s['deps_same_source_other_folder']} / {s['deps_cross_source']} |
| CDB lists referenced | {sum(lists.values())}: {lists.get('copiada da fonte', 0)} copied from the source, {lists.get('oficial', 0)} official, {lists.get('em falta', 0)} missing |
| Standalone folders (static analysis) | {s['folders_standalone']} of {s['folders']} |
{f"| Folders that load in `wazuh-analysisd -t` ({s['official_reference'].split()[1]}) | {val_ok} of {len(val)} ({sum(1 for v in val if v['loads_ok'] == 'True' and v['warnings'] == '0')} without warnings) |" if val else ''}
| Root / child decoders | {dd.get('roots', 0)} / {dd.get('children', 0)} ({dd.get('root_collisions_between_sources', 0)} root names colliding between sources; {dd.get('root_names_also_official', 0)} with an official name) |
| Fields produced by decoders | {dd.get('distinct_fields', 0)} distinct names; {dd.get('fields_with_ecs', 0)} mapped to ECS ({dd.get('field_uses_with_ecs_pct', 0)}% of uses) |
{f"| Log samples in `wazuh-logtest` | {dt_tot['samples']} in {len(dts)} folders: {dt_tot['ok']} ok, {dt_tot['sombreado']} shadowed by another decoder, {dt_tot['não descodificado']} not decoded, {dt_tot['regra não disparou']} expected rule did not fire, {dt_tot['falso positivo']} false positives |" if dts else ''}
| Rules with a valid MITRE technique | {ms.get('válido', 0) + ms.get('normalizado', 0)} ({ms.get('normalizado', 0)} only after normalizing Sigma tags/groups) |
| Source responses (active response + integrations) | {rs.get('definitions', 0)}: {rs.get('by_status', {}).get('ok', 0)} ok, {rs.get('by_status', {}).get('partido', 0)} broken, {rs.get('by_status', {}).get('ignorado', 0)} ignored by Wazuh; {rs.get('destructive', 0)} destructive ({rs.get('destructive_without_allowlist', 0)} without allowlist) |
| Techniques with level ≥ 12 rules | {rs.get('techniques_level12', 0)}: {rs.get('techniques_level12_without_playbook', 0)} without playbook, {rs.get('techniques_level12_without_containment', 0)} without working automated containment |
| Model agent groups | {cs.get('groups', 0)}{f" ({sum(gok.values())} valid in `verify-agent-conf`)" if gok else ''} |
| SigmaHQ reference | {sg.get('rules', 0)} rules, {sg.get('techniques_sigma', 0)} techniques ({sg.get('by_status', {}).get('só Sigma', 0)} only in Sigma) |

Reference: **{s['official_reference']}**.

## Areas

| Area | Scope | Rules | Decoders | Sources |
|---|---|---:|---:|---:|
{rows_en}

## Collisions with the official ruleset

- **{ov.get('colisão', 0)}** rules reuse an official ID without `overwrite="yes"` (startup warning; only one definition stays active).
- **{s['id_conflicts_official_multi_overwrite']}** official IDs are overwritten by more than one source with different content: loading those sources together makes the last one win (`other_overwriters` column).
- **{sum(v for k, v in ov.items() if k.startswith('overwrite') and 'inexistente' not in k)}** rules intentionally `overwrite` official rules ({ov.get('overwrite estrutural', 0)} change the `if_sid`/`if_group`/`decoded_as` chain, {ov.get('overwrite de nível', 0)} only the level).
- **{s.get('decoder_replacement_files', 0)}** decoder files are named like an official file or redefine official decoder names.{dex_en}
- **{s.get('rules_outside_custom_range', 0)}** rules use IDs outside the recommended custom range (100000–120000).

Details in [`catalog/official_overlap.csv`](catalog/official_overlap.csv) and [`catalog/decoder_replacements.csv`](catalog/decoder_replacements.csv).

## Sibling rules (children of the same parent)

Measured on `wazuh-analysisd` {s["official_reference"].split()[1]}: **level-0 children** of the same parent (`if_sid`/`if_group`) **are evaluated first**, then the rest by **level, highest first**; on equal level by **load order**, which is the file-name order across the whole set (official and `etc/rules` mixed; the ID does not matter). The first one that matches takes the event. A child **with no conditions of its own** (*catch-all*) always matches and silences every sibling evaluated after it — official rules included, with the folder installed alone — and `wazuh-analysisd -t` does not warn about it. An ID repeated in two files keeps only the definition loaded first; the other does not exist (not even under its parent). That is why the page's script and the tests install each file as `<pack-prefix>__<file>`: an original name such as `02-rules.xml` would load before the official files and the official `if_sid` would fail.

- **{sb.get('catchalls_silencing_official', 0)}** catch-all rules in {sb.get('folders_silencing_official', 0)} folders silence **{sb.get('official_rules_silenced', 0)}** official rules ([`catalog/catchall_silences_official.csv`](catalog/catchall_silences_official.csv)).
- **{sb.get('shared_parents', 0)}** parents have children in different sources ({sb.get('rules_involved', 0)} rules; {sb.get('parents_with_catchall', 0)} with a catch-all; {sb.get('ambiguous_parents', 0)} parents whose ID is defined differently in several sources); {sb.get('folder_pairs', 0)} folder pairs where one silences the other when installed together ([`catalog/sibling_parents.csv`](catalog/sibling_parents.csv)). The page's cart applies this model to the selection.
{f'''- Synthetic samples (`tools/synth.py`): one event per rule, generated from the conditions of the rule and its parent chain (JSON events in `wazuh-logtest`; Windows EventChannel events injected into the `wazuh-analysisd` queue, since logtest does not decode them). {sy["ok"]} of {sy["n"]} confirmed by the engine in {sy["folders"]} folders ({sy["ec_ok"]} of {sy["ec"]} Windows); {sy["off"]} ended on an official rule instead of the folder's rule; {sy["bad"]} Windows rules use a capitalized field (`win.eventdata.TargetFilename`) that the decoder never produces, so they never fire ([`catalog/synthetic_tests.csv`](catalog/synthetic_tests.csv)). Only confirmed ones are used in the pair test.''' if sys_ else ''}
{f'''- Empirical proof (`tools/combo_test.py`): {cb["combos"]} folder pairs loaded together, {cb["samples"]} samples replayed; {cb["shadowed"]} changed owner ({cb["dec"]} by decoder, {cb["sib"]} by a sibling rule, {cb["conf"]} by an ID conflict: the same ID, or an ancestor in the `if_sid` chain, defined in both folders) in {cb["with_shadow"]} pairs; {cb["not_together"]} pairs do not load together ([`catalog/combo_summary.csv`](catalog/combo_summary.csv), [`catalog/combo_tests.csv`](catalog/combo_tests.csv)).''' if cbs else ''}

## Collection and agent groups

Rules run on the manager for every agent; agent groups do not filter rules. What a group decides is **which events arrive**. Each folder lists what it needs in [`catalog/collection.csv`](catalog/collection.csv): collected by default, extra agent collection in [`groups/`](groups/) ({cs.get('folders_with_agent_groups', 0)} folders), manager requirements such as cloud wodles, modules, integrations and `<remote>` syslog ({cs.get('folders_with_manager_requirements', 0)} folders), or still to be defined ({cs.get('folders_with_undefined', 0)} folders). Requirements are **inferred** (the folder chains into official rules of a family, e.g. `win-sysmon` → Sysmon channel) or **declared** by the source (`<localfile>`/`<wodle>`/`<agent_config>` blocks, copied or extracted to `collection/`). See [`groups/README.md`](groups/README.md).

## Response and playbooks

1. **Source automated responses** — [`catalog/responses.csv`](catalog/responses.csv): every `<active-response>` and `<integration>` the sources ship, with script, triggering rules, action, impact, safeguards and status (**broken** when the script is missing or misnamed, the rule does not exist or was renumbered by the author; **ignored** when defined in an `agent.conf`).
2. **Procedural playbooks** — [`catalog/playbooks.csv`](catalog/playbooks.csv), from licensed libraries pinned in `sources.lock` (only linked, never copied):
{pb_en}
3. **Coverage** — [`catalog/technique_coverage.csv`](catalog/technique_coverage.csv) by technique and [`catalog/response_coverage.csv`](catalog/response_coverage.csv) by folder.

The correlation key is the technique, and Wazuh accepts any text in `<mitre><id>` without warning; many sources use Sigma tags (`attack.t1059.001`) or only put the technique in groups. The catalog normalizes to T-IDs in `rules.csv` (`mitre_norm`, `mitre_status`), resolving revoked techniques to their ATT&CK successor; the XML is not changed. None of the source responses is recommended as is: the destructive ones have no allowlist nor test mode.

### SigmaHQ as a coverage reference

[SigmaHQ](https://github.com/SigmaHQ/sigma) (pinned, commit `{sg.get('commit', '')}`) is used as a reference only: {sg.get('rules', 0)} rules, {sg.get('techniques_sigma', 0)} techniques; no Sigma rule is copied or converted (DRL 1.1 license). Compared with the registry: {', '.join(f"{v} {SG_EN.get(k, k)}" for k, v in sg.get('by_status', {}).items())}; {sg.get('sigma_only_with_high', 0)} of the Sigma-only techniques have high or critical rules. See [`catalog/sigma_coverage.csv`](catalog/sigma_coverage.csv).

### Priority gaps: techniques with most level ≥ 12 rules and no playbook

| Technique | Name | Tactics | Level ≥ 12 rules | Folders | CISA countermeasures | Automated containment | Other automation |
|---|---|---|---:|---:|---:|---:|---:|
{gap_tab}

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

Run on a case-sensitive filesystem (Linux, or a case-sensitive APFS volume on macOS). The `.github/workflows/registo.yml` workflow runs this whole pipeline on every push and pull request (and weekly) and publishes the page to GitHub Pages. To add a source: append it to `tools/sources.txt`, classify it in `tools/taxonomy.py` (`MAP`) and run the commands above — or [open an issue]({REPO}/issues/new/choose).

## Licenses

{len(nolic)} of the {len(inc)} included sources **have no license file**: without a license the author keeps all rights. Every file is published unchanged, with its origin, author and exact commit in the folder's `SOURCE.md`. **Author of a source and want it removed? [Open an issue]({REPO}/issues/new/choose) and it will be taken down.** See [`NOTICE.md`](NOTICE.md).

## Roadmap

1. **Registry** (done): inventory, areas, catalog, conflicts, dependencies, real validation, collection, response and coverage.
2. **Triage**: mark each source *adopt / review / archive*, based on the indicators, `validation.csv` and `decoder_tests.csv`.
3. **4.x normalization**: assign an ID range per area, renumber and rewrite `if_sid` accordingly, producing a pack that loads all at once.
4. **Wazuh 5.0**: convert XML decoders → YAML/ECS and rules to the new engine, starting with the adopted sources (see `catalog/decoder_fields.csv`).

---
Curated by [@mjvmst](https://github.com/mjvmsteixeira) · [Wazuh Ambassador](https://wazuh.com/ambassadors/marco-teixeira/) · Portugal. Independent community registry; not an official Wazuh, Inc. product.
"""
open(os.path.join(ROOT, 'README.md'), 'w').write(readme_en)
ll_en = '\n'.join(f"- **{k}** ({len(v)}): {', '.join(v)}" for k, v in sorted(lic.items()) if k != 'NONE').replace('MIT? (badge no README, sem ficheiro LICENSE)', 'MIT? (README badge, no LICENSE file)')
nl_en = '\n'.join(f"- [{x['repo']}]({x['url']}) — {x['rules']} rules, {x['decoders']} decoders" for x in nolic)
open(os.path.join(ROOT, 'NOTICE.md'), 'w').write(f"""# NOTICE — source licenses

**English** · [Português](NOTICE.pt.md)

This repository aggregates third-party files **without modifying them**. Each source folder has a `SOURCE.md` with the exact origin commit and, when there is one, `LICENSE.upstream` with the original license. Rights belong to their respective authors.

Most Wazuh rules derive from the OSSEC/Wazuh ecosystem (GPLv2). Several sources declare GPL-3.0 or AGPL-3.0, whose terms propagate to derived works. Before publishing a combined pack, the resulting license must be compatible with every source included.

## Wazuh blog

The rule, decoder and configuration examples from the [Wazuh blog](https://wazuh.com/blog/) articles are captured by `tools/fetch_blog.py` into `snapshots/wazuh-blog/` and reproduced unchanged, one article per folder. The content is © Wazuh, Inc.; each folder's `SOURCE.md` names the source article, with its link, title, and publication and capture dates.

## Removal requests

Author of a source and do not want your content here? [Open an issue]({REPO}/issues/new/choose) (*Removal request* template) and the source is removed from the registry and the page in the next release.

## Sources with an identified license

{ll_en}

## Sources without a license file ({len(nolic)})

The author keeps all rights; the files are published unchanged, with their origin. Internal use recommended until the origin repository includes a license:

{nl_en}

## Sources that failed to clone

{chr(10).join(f'- {r} (repository removed or private at collection time).' for r in s['sources_failed']) or '- none'}
""")
print('README.md, NOTICE.md (inglês), README.pt.md, NOTICE.pt.md, README das áreas e groups/README.md regenerados')
