# Backlog

Trabalho decidido mas ainda não feito, por ordem de prioridade. O que já está feito vive no README (gerado) e no histórico do git.

## 1. Triagem automática (adotar / rever / arquivar) — próxima

Proposta calculada a partir dos sinais já medidos, que o mantenedor confirma ou corrige. Não altera os ficheiros originais.

- **Funciona:** carrega no `wazuh-analysisd -t` (`validation.csv`), avisos, % de amostras sintéticas confirmadas (`synthetic_tests.csv`), regras que nunca disparam (campo `win.eventdata.X` com maiúscula, IDs descartados por repetição).
- **Não prejudica:** apanha-tudo que silenciam regras oficiais (`catchall_silences_official.csv`), conflitos de ID (`id_conflicts.csv`), sombras em pares (`combo_tests.csv`), dependência da ordem dos ficheiros (p.ex. `0454-*.xml`).
- **Usável:** licença, último commit, pasta autónoma ou com dependências noutras fontes.
- Saída: `catalog/triage.csv` (veredito + motivos por pasta), `catalog/triage_overrides.csv` (decisões manuais, que prevalecem), filtro e selo na página.

## 2. Pack derivado 4.x (renumeração) — depois da triagem

Só sobre as fontes **adotadas**, como artefacto à parte (os originais continuam publicados sem alterações): um intervalo de IDs por área, reescrita de `if_sid`/`if_matched_sid`, listas e decoders com prefixo, um pack que carrega de uma vez sem conflitos. Resolve na origem os conflitos de ID medidos no teste de pares.

## 3. Wazuh 5.0

Converter os decoders XML para YAML/ECS e as regras para o novo motor, a partir do pack derivado (ver `catalog/decoder_fields.csv` para o mapa ECS).

## Lacunas conhecidas

- **Amostras sintéticas para cadeias syslog** (decoders com `prematch`/`regex`): hoje só JSON e Windows EventChannel. Exige inverter a cadeia de decoders; cobriria fortigate, cisco, etc.
- **Amostras sintéticas para regras de correlação** (`frequency`, `if_matched_*`, `same_*`): gerar a sequência de eventos da regra referida e repeti-la na mesma sessão do logtest (o `tools/model_checks.py` já usa sessões; falta o gerador).
- **`<UserData>`** dos eventos Windows (vai para `win.eventXML`, não para `eventdata`): não coberto pelo gerador.
- **hawkteam404/opnsense:** depende de `0454-opnsense_decoders.xml` carregar antes do decoder oficial do filterlog; com o script da página (prefixo) o oficial ganha. Avaliar `decoder_exclude` ou aviso específico na página.
- **MORGADO01 100305** (sob 60103): sintética sem disparar e sem causa apurada.
- Chaves PT antigas sem uso em `site_template.html` (inofensivas; limpar).
