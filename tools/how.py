"""Gera site/how.html (inglês) e site/pt/how.html (português): como o registo avalia os packs e como ler os avisos.

Chamado por make_site.py. Todos os números vêm do catálogo, para a página não ficar desatualizada.
"""
import os, csv, json, html

REPO = 'https://github.com/mjvmsteixeira/wazuh-community-rulesets'

def _csv(root, name):
    p = os.path.join(root, 'catalog', name)
    return list(csv.DictReader(open(p))) if os.path.exists(p) else []

def numbers(root):
    s = json.load(open(os.path.join(root, 'catalog/stats.json')))
    sb = s.get('siblings', {})
    val = _csv(root, 'validation.csv'); syn = _csv(root, 'synthetic_tests.csv'); cb = _csv(root, 'combo_summary.csv')
    em = _csv(root, 'engine_model.csv'); cso = _csv(root, 'catchall_silences_official.csv')
    sil = lambda rule, folder_part: sum(int(r['official_silenced']) for r in cso if r['rule'] == rule and folder_part in r['folder'])
    return {
        'packs': s['folders'], 'sources': s['sources_included'], 'rules': s['rules'], 'ref': s['official_reference'].split()[1],
        'load': sum(r['loads_ok'] == 'True' for r in val), 'clean': sum(r['loads_ok'] == 'True' and r['warnings'] == '0' for r in val),
        'em_ok': sum(r['verdict'] == 'ok' for r in em), 'em_obs': sum(r['verdict'] == 'observação' for r in em), 'em_n': len(em),
        'shared': sb.get('shared_parents', 0), 'ca': sb.get('catchall_rules', 0), 'dom': sb.get('dominated_catchalls', 0),
        'sil': sb.get('catchalls_silencing_official', 0), 'sil_off': sb.get('official_rules_silenced', 0), 'sil_fo': sb.get('folders_silencing_official', 0),
        'cond': sb.get('conditional_shadow_rules', 0), 'cond_fo': sb.get('conditional_shadow_folders', 0), 'amb': sb.get('ambiguous_parents', 0),
        'nonascii': sb.get('non_ascii_condition_rules', 0), 'idc': s.get('id_conflicts', 0),
        'syn_ok': sum(r['verdict'] == 'ok' for r in syn), 'syn_n': len(syn), 'syn_fo': len({r['folder'] for r in syn}),
        'win_ok': sum(r['verdict'] == 'ok' and r['format'] == 'eventchannel' for r in syn), 'win_n': sum(r['format'] == 'eventchannel' for r in syn),
        'pairs': len(cb), 'pair_samples': sum(int(r['samples']) for r in cb), 'pair_sib': sum(int(r['sombreado (regra irmã)']) for r in cb),
        'pair_dec': sum(int(r['sombreado (decoder)']) for r in cb), 'pair_id': sum(int(r['conflito de ID']) for r in cb),
        'pair_bad': sum(1 for r in cb if int(r['shadowed'])),
        'sysmon_sil': sil('101101', 'mdnahidmondol'), 'morgado_sil': sil('100513', 'MORGADO01'),
    }

def fmt(n, lang):
    s = f'{n:,}'
    return s.replace(',', ' ') if lang == 'pt' else s

def texts(n, lang):
    N = {k: (fmt(v, lang) if isinstance(v, int) else v) for k, v in n.items()}
    L = lambda en, pt: (pt if lang == 'pt' else en).format(**N)
    dl = lambda rows: ''.join(f'<dt>{a}</dt><dd>{b}</dd>' for a, b in rows)
    csvl = lambda f: f'<a href="{REPO}/blob/main/catalog/{f}">catalog/{f}</a>'
    t = {
        'lang': lang, 'title': L('How it works', 'Como funciona'), 'title_up': L('HOW IT WORKS', 'COMO FUNCIONA'),
        'back': L('← Search', '← Pesquisa'), 'theme': L('Theme', 'Tema'), 'toc': L('Contents', 'Índice'),
        'lang_href': 'pt/how.html' if lang == 'en' else '../how.html', 'lang_other': 'pt' if lang == 'en' else 'en', 'lang_label': 'PT' if lang == 'en' else 'EN',
        'lead': L('The registry collects {rules} Wazuh rules from {sources} community sources, in {packs} packs, and measures each one on a real wazuh-manager {ref}. '
                  'The search page warns when a pack can silence other rules. This page explains how those warnings are worked out, and how far each one is proven.',
                  'O registo junta {rules} regras Wazuh de {sources} fontes da comunidade, em {packs} packs, e mede cada um num wazuh-manager {ref} real. '
                  'A página de pesquisa avisa quando um pack pode silenciar outras regras. Esta página explica como esses avisos são calculados e até onde cada um está provado.'),
        'h_siblings': L('Sibling rules', 'Regras irmãs'), 'h_load': L('Load order', 'Ordem de carregamento'), 'h_proof': L('How much is proven', 'Quanto está provado'),
        'h_warnings': L('Reading the warnings', 'Como ler os avisos'), 'h_findings': L('What the tests found', 'O que os testes encontraram'),
        'sib_p1': L('Rules that hang off the same parent (<code>if_sid</code>, or <code>if_group</code> on any rule that has the group) compete for each event, and only one wins. '
                    'Measured on the engine: <b>level-0</b> siblings are evaluated first, then the others by <b>level, highest first</b>, and on a tie by <b>the file loaded first</b>. '
                    'A rule with no conditions of its own (a <i>catch-all</i>) always matches, so it takes every event that reaches it, and the siblings after it never alert. <code>wazuh-analysisd -t</code> does not warn.',
                    'Regras penduradas no mesmo pai (<code>if_sid</code>, ou <code>if_group</code> em qualquer regra que tenha o grupo) disputam cada evento, e só uma ganha. '
                    'Medido no motor: as irmãs de <b>nível 0</b> são avaliadas primeiro, depois as outras por <b>nível, o mais alto primeiro</b>, e em empate ganha <b>o ficheiro carregado primeiro</b>. '
                    'Uma regra sem condições próprias (um <i>apanha-tudo</i>) corresponde sempre, por isso fica com todos os eventos que lhe chegam, e as irmãs depois dela não alertam. O <code>wazuh-analysisd -t</code> não avisa.'),
        'sib_p2': L('Try it with a real Sysmon event and two real packs. Tick and untick the packs to see the evaluation order change.',
                    'Experimenta com um evento Sysmon real e dois packs reais. Marca e desmarca os packs para ver a ordem de avaliação mudar.'),
        'sim_event': L('Event', 'Evento'), 'sim_event_sub': L('Sysmon event 1 (process creation), parent rule <code>61603</code>', 'Sysmon evento 1 (criação de processo), regra pai <code>61603</code>'),
        'sim_packs': L('Installed packs', 'Packs instalados'), 'sim_official': L('Official ruleset', 'Ruleset oficial'),
        'sim_official_sub': L('always installed; loads first', 'sempre instalado; carrega primeiro'),
        'sim_mdn_sub': L('ships a level-5 catch-all', 'traz um apanha-tudo de nível 5'), 'sim_order': L('Evaluation order', 'Ordem de avaliação'),
        'load_p1': L('The engine sorts <b>all</b> rule files by name, official and custom mixed. A pack installed with its original file name, such as the <code>02-rules.xml</code> of a Wazuh blog post, loads before the official files: '
                     'the official parents of its <code>if_sid</code> do not exist yet, the engine warns (7617) and the rule loses that condition.',
                     'O motor ordena <b>todos</b> os ficheiros de regras pelo nome, oficiais e locais misturados. Um pack instalado com o nome original, como o <code>02-rules.xml</code> de um artigo do blog da Wazuh, carrega antes dos ficheiros oficiais: '
                     'os pais oficiais dos seus <code>if_sid</code> ainda não existem, o motor avisa (7617) e a regra perde essa condição.'),
        'load_p2': L('The install script on the search page, and every test in the registry, name each file <code>&lt;pack-prefix&gt;__&lt;file&gt;</code>. That also stops two packs from overwriting each other\'s files, '
                     'and each pack\'s CDB lists go to <code>etc/lists/&lt;pack-prefix&gt;/</code>, so a pack\'s <code>audit-keys</code> no longer replaces the official one.',
                     'O script de instalação da página de pesquisa, e todos os testes do registo, dão a cada ficheiro o nome <code>&lt;prefixo-do-pack&gt;__&lt;ficheiro&gt;</code>. Isso também impede dois packs de se sobrescreverem, '
                     'e as listas CDB de cada pack vão para <code>etc/lists/&lt;prefixo-do-pack&gt;/</code>, por isso a <code>audit-keys</code> de um pack deixa de substituir a oficial.'),
        'load_orig': L('Original name', 'Nome original'), 'load_pref': L('With pack prefix', 'Com prefixo do pack'),
        'load_read': L('Order the engine reads them', 'Ordem em que o motor os lê'), 'load_result': L('Result', 'Resultado'),
        'proof_p': L('Each warning on the search page rests on one of these layers. The model of the engine is checked first, so the other three do not draw conclusions from a wrong model.',
                     'Cada aviso da página de pesquisa assenta numa destas camadas. O modelo do motor é verificado primeiro, para as outras três não tirarem conclusões de um modelo errado.'),
        'l0_t': L('0 · The engine itself', '0 · O próprio motor'), 'l0_q': L('“Is the model still right in this Wazuh version?”', '“O modelo continua certo nesta versão da Wazuh?”'),
        'l0_p': L('Controlled scenarios with minimal rules, run on every push (<code>tools/model_checks.py</code>).', 'Cenários controlados com regras mínimas, corridos em cada push (<code>tools/model_checks.py</code>).'),
        'l0_dl': dl([(f"{N['em_ok']} / {fmt(n['em_n'] - n['em_obs'], lang)}", L('scenarios with an expected result pass', 'cenários com resultado esperado passam')),
                     (N['em_obs'], L('observation: a regex with a non-ASCII character behaves differently on arm64 and amd64', 'observação: uma regex com um carácter não-ASCII comporta-se de forma diferente em arm64 e amd64'))]),
        'l1_t': L('1 · Static analysis', '1 · Análise estática'), 'l1_q': L('“By the model, who silences whom?”', '“Pelo modelo, quem silencia quem?”'),
        'l1_p': L('Reads the XML and applies the model to every shared parent. Complete and fast, but a prediction.', 'Lê o XML e aplica o modelo a cada pai partilhado. Completa e rápida, mas é uma previsão.'),
        'l1_dl': dl([(N['shared'], L('parents with children in different sources', 'pais com filhos em fontes diferentes')),
                     (N['sil'], L('catch-alls that silence {sil_off} official rules, in {sil_fo} packs', 'apanha-tudo que silenciam {sil_off} regras oficiais, em {sil_fo} packs')),
                     (N['cond'], L('rules that lose events to official siblings only in some situations', 'regras que perdem eventos para irmãs oficiais só em certas situações'))]),
        'l2_t': L('2 · Synthetic samples', '2 · Amostras sintéticas'), 'l2_q': L('“Can this rule fire at all?”', '“Esta regra consegue disparar?”'),
        'l2_p': L('One event per rule, built from the conditions of the rule and its whole parent chain. Windows events are injected straight into the analysis engine, because wazuh-logtest does not decode them.',
                  'Um evento por regra, construído a partir das condições da regra e de toda a cadeia de pais. Os eventos Windows são injetados diretamente no motor de análise, porque o wazuh-logtest não os descodifica.'),
        'l2_dl': dl([(N['syn_ok'], L('of {syn_n} confirmed by the engine, in {syn_fo} packs', 'de {syn_n} confirmadas pelo motor, em {syn_fo} packs')),
                     (N['win_ok'], L('of {win_n} Windows events confirmed', 'de {win_n} eventos Windows confirmados'))]),
        'l3_t': L('3 · Packs loaded together', '3 · Packs carregados juntos'), 'l3_q': L('“Installed together, what changes?”', '“Instalados juntos, o que muda?”'),
        'l3_p': L('Loads two packs at once and replays each one\'s samples. The empirical proof, but it only sees what has a sample.', 'Carrega dois packs ao mesmo tempo e repete as amostras de cada um. É a prova empírica, mas só vê o que tem amostra.'),
        'l3_dl': dl([(N['pair_samples'], L('samples in {pairs} pairs', 'amostras em {pairs} pares')),
                     (N['pair_sib'], L('lost to a sibling rule, {pair_dec} to a decoder', 'perdidas para uma regra irmã, {pair_dec} para um decoder')),
                     (N['pair_id'], L('lost to a repeated rule ID', 'perdidas por um ID de regra repetido'))]),
        'warn_p': L('Each warning box on a pack page and in the install cart, what it means and which layer backs it.', 'Cada caixa de aviso na ficha de um pack e no cesto de instalação, o que quer dizer e em que camada assenta.'),
        'w_box': L('Warning', 'Aviso'), 'w_means': L('What it means', 'O que quer dizer'), 'w_basis': L('Backed by', 'Assenta em'), 'w_do': L('What to do', 'O que fazer'),
        'find_p': L('Results with proof, from the current run. The files behind them are on GitHub, where they open as searchable tables.',
                    'Resultados com prova, da corrida atual. Os ficheiros por trás estão no GitHub, onde abrem como tabelas pesquisáveis.'),
        'foot': L(f'Generated from the catalog of <a href="{REPO}">wazuh-community-rulesets</a> · reference: official ruleset {n["ref"]} · questions and corrections: <a href="{REPO}/issues/new/choose">open an issue</a>',
                  f'Gerado a partir do catálogo de <a href="{REPO}">wazuh-community-rulesets</a> · referência: ruleset oficial {n["ref"]} · dúvidas e correções: <a href="{REPO}/issues/new/choose">abre uma issue</a>'),
    }
    W = [
        (L('Packs that silence official Wazuh rules, even installed alone', 'Packs que silenciam regras oficiais da Wazuh, mesmo instalados sozinhos'),
         L('A catch-all rule of the pack is evaluated before official siblings. Those official detections stop alerting.', 'Uma regra apanha-tudo do pack é avaliada antes de irmãs oficiais. Essas deteções oficiais deixam de alertar.'),
         L('Static analysis (1) on the measured model (0); the Sysmon case was proven with an injected event.', 'Análise estática (1) sobre o modelo medido (0); o caso Sysmon foi provado com um evento injetado.'),
         L('Give the rule a condition, or a level below the official siblings, before installing.', 'Dar uma condição à regra, ou um nível abaixo das irmãs oficiais, antes de instalar.')),
        (L('Rules that lose events to official siblings in some situations', 'Regras que perdem eventos para irmãs oficiais em certas situações'),
         L('An official sibling evaluated first fires on context: repeated events, time of day or first occurrence. In those moments the pack rule does not alert.', 'Uma irmã oficial avaliada primeiro dispara por contexto: eventos repetidos, hora do dia ou primeira ocorrência. Nesses momentos a regra do pack não alerta.'),
         L('Static analysis (1); the case from issue #1 (rule 40112) is a check in layer 0.', 'Análise estática (1); o caso da issue #1 (regra 40112) é um cenário da camada 0.'),
         L('If the rule must always alert, raise its level above the sibling or hang it off a different parent.', 'Se a regra tem de alertar sempre, subir o nível acima da irmã ou pendurá-la noutro pai.')),
        (L('Parent rules where a pack will silence another', 'Pais em que um pack vai silenciar outro'),
         L('In the cart, a catch-all of one pack is evaluated before the rules of another pack under the same parent.', 'No cesto, um apanha-tudo de um pack é avaliado antes das regras de outro pack sob o mesmo pai.'),
         L('Static analysis (1) applied to the packs in the cart, with their real load order.', 'Análise estática (1) aplicada aos packs do cesto, com a ordem de carregamento real.'),
         L('Keep only one of the packs, or adjust the catch-all.', 'Ficar só com um dos packs, ou ajustar o apanha-tudo.')),
        (L('Parent rules shared between the chosen packs', 'Pais partilhados entre os packs escolhidos'),
         L('Both packs have rules under the same parent. If both match an event, the one evaluated first takes it.', 'Os dois packs têm regras sob o mesmo pai. Se ambas corresponderem a um evento, fica com ele a avaliada primeiro.'),
         L('Static analysis (1). Overlap is possible, not certain.', 'Análise estática (1). A sobreposição é possível, não certa.'),
         L('Check the “Tested together” box, or test the pair with tools/combo_test.py.', 'Ver a caixa “Testados juntos”, ou testar o par com tools/combo_test.py.')),
        (L('Rule IDs repeated between the chosen packs', 'IDs de regra repetidos entre os packs escolhidos'),
         L('Only the definition loaded first exists. The other one is gone, not even attached to its parent.', 'Só existe a definição carregada primeiro. A outra desaparece, nem fica pendurada no pai.'),
         L('Measured in layer 0; replayed in layer 3.', 'Medido na camada 0; repetido na camada 3.'),
         L('Remove one of the packs or renumber before installing.', 'Retirar um dos packs ou renumerar antes de instalar.')),
        (L('Root decoders with the same name', 'Decoders raiz com o mesmo nome'),
         L('Both stay active, but their children share the name: a log can be parsed by the other pack\'s children, with different fields.', 'Ficam ambos ativos, mas os filhos partilham o nome: um log pode ser extraído pelos filhos do outro pack, com campos diferentes.'),
         L('Static analysis; replayed in layer 3 by comparing the fields.', 'Análise estática; repetido na camada 3, comparando os campos.'),
         L('Install only one of the packs for that log source.', 'Instalar só um dos packs para essa fonte de logs.')),
        (L('Tested together', 'Testados juntos'),
         L('This pair was loaded together and its samples were replayed: how many changed owner, and why.', 'Este par foi carregado junto e as amostras repetidas: quantas mudaram de dono, e porquê.'),
         L('Empirical (3).', 'Empírico (3).'),
         L('A pair with changed samples should not be installed as is.', 'Um par com amostras que mudaram não deve ser instalado assim.')),
    ]
    t['warn_rows'] = ''.join(f'<tr><td class="box">{a}</td><td>{b}</td><td>{c}</td><td>{d}</td></tr>' for a, b, c, d in W)
    F = [
        ('', L('A Sysmon pack installed alone removes the official T1059.003 detection (92032).', 'Um pack Sysmon instalado sozinho faz desaparecer a deteção oficial de T1059.003 (92032).'),
         L('Its rule 101101 “Process creation” has level 5 and no conditions, so it takes every Sysmon event 1 before 92032 and {sysmon_sil} official rules in total. Proven with an injected event. ',
           'A regra 101101 “Process creation” tem nível 5 e nenhuma condição, por isso fica com todos os eventos Sysmon 1 antes da 92032 e de {sysmon_sil} regras oficiais no total. Provado com um evento injetado. ') + csvl('catchall_silences_official.csv')),
        ('', L('A level-0 grouping rule sits in front of {morgado_sil} official web detections.', 'Uma regra de agrupamento de nível 0 fica à frente de {morgado_sil} deteções web oficiais.'),
         L('MORGADO01 rule 100513 was written to feed a correlation, but level-0 siblings are evaluated first, so it takes the events of 31101 and 30101.',
           'A regra 100513 do MORGADO01 foi escrita para alimentar uma correlação, mas as irmãs de nível 0 são avaliadas primeiro, por isso fica com os eventos de 31101 e 30101.')),
        ('w', L('{cond} rules in {cond_fo} packs lose events to official siblings in some situations.', '{cond} regras em {cond_fo} packs perdem eventos para irmãs oficiais em certas situações.'),
         L('Reported in issue #1: a child of 5715 (SSH login accepted) below level 12 loses the login to 40112 after several failures from the same IP. 40112 has no if_sid; it is a sibling through if_group. ',
           'Reportado na issue #1: uma filha da 5715 (login SSH aceite) abaixo do nível 12 perde o login para a 40112 depois de várias falhas do mesmo IP. A 40112 não tem if_sid; é irmã por if_group. ') + csvl('conditional_shadows.csv')),
        ('w', L('{idc} rule IDs are defined differently by several sources.', '{idc} IDs de regra estão definidos de forma diferente por várias fontes.'),
         L('Installed together, only the definition loaded first exists. In the pair test this cost {pair_id} samples. ', 'Instalados juntos, só existe a definição carregada primeiro. No teste de pares isto custou {pair_id} amostras. ') + csvl('id_conflicts.csv')),
        ('w', L('The same pack can behave differently depending on the manager\'s CPU.', 'O mesmo pack pode comportar-se de forma diferente conforme o processador do manager.'),
         L('A regex with a non-ASCII dash matched on arm64 and not on amd64. {nonascii} rules have conditions like that; the CI runs on amd64, like most managers.',
           'Uma regex com um traço não-ASCII correspondeu em arm64 e não em amd64. Há {nonascii} regras com condições assim; o CI corre em amd64, como a maioria dos managers.')),
        ('w', L('A pack can depend on loading before the official files.', 'Um pack pode depender de carregar antes dos ficheiros oficiais.'),
         L('hawkteam404/opnsense names its file 0454-opnsense_decoders.xml to load before the official filterlog decoder. Installed with the pack prefix, the official decoder takes the logs; the pack needs decoder_exclude.',
           'O hawkteam404/opnsense chama ao ficheiro 0454-opnsense_decoders.xml para carregar antes do decoder oficial do filterlog. Instalado com o prefixo do pack, o decoder oficial fica com os logs; o pack precisa de decoder_exclude.')),
    ]
    t['finds'] = ''.join(f'<div class="panel find{" w" if k else ""}"><span></span><div><p>{a}</p><p>{b}</p></div></div>' for k, a, b in F)
    J = lambda en, pt: pt if lang == 'pt' else en   # textos do script: os {r}/{who} são preenchidos no browser
    t['js_text'] = json.dumps({
        'lvl': J('lvl', 'nív'), 'catchall': J('CATCH-ALL', 'APANHA-TUDO'), 'officialTag': J('OFFICIAL', 'OFICIAL'), 'official': J('official', 'oficial'),
        'caWins': J('Rule {r} has no conditions and is evaluated first, so it takes the event. {lost} stop alerting, and wazuh-analysisd -t does not warn.',
                    'A regra {r} não tem condições e é avaliada primeiro, por isso fica com o evento. {lost} deixam de alertar, e o wazuh-analysisd -t não avisa.'),
        'wins': J('{r} ({who}) wins: it is the first rule, in evaluation order, whose conditions match the event.',
                  'Ganha {r} ({who}): é a primeira regra, na ordem de avaliação, cujas condições correspondem ao evento.'),
        'dropped': J('The mdnahidmondol catch-all is missing because socfortress also defines ID 101101 and loads first: the second definition is discarded. The pair test measured exactly this.',
                     'O apanha-tudo do mdnahidmondol não aparece porque o socfortress também define o ID 101101 e carrega primeiro: a segunda definição é descartada. Foi isto que o teste de pares mediu.'),
        'loadOrig': J('The pack loads before <code>0580-win-security_rules.xml</code>: rule <code>100111</code>, with <code>if_sid 60103</code>, looks for a parent that does not exist yet. The engine warns (7617) and the rule loses that condition.',
                      'O pack carrega antes de <code>0580-win-security_rules.xml</code>: a regra <code>100111</code>, com <code>if_sid 60103</code>, procura um pai que ainda não existe. O motor avisa (7617) e a regra perde essa condição.'),
        'loadPref': J('The pack loads after every official file: when rule <code>100111</code> refers to <code>if_sid 60103</code>, the parent already exists and the rule works. Measured: the pack now loads with no warnings.',
                      'O pack carrega depois de todos os ficheiros oficiais: quando a regra <code>100111</code> refere <code>if_sid 60103</code>, o pai já existe e a regra funciona. Medido: o pack passou a carregar sem avisos.'),
    }, ensure_ascii=False)
    return t

def build(root):
    n = numbers(root)
    tpl = open(os.path.join(root, 'tools', 'how_template.html')).read()
    for lang, path in (('en', 'site/how.html'), ('pt', 'site/pt/how.html')):
        out = tpl
        for k, v in texts(n, lang).items(): out = out.replace('{{' + k + '}}', str(v))
        if '{{' in out: raise SystemExit(f'how.html: marcadores por preencher: {out[out.index("{{"):out.index("{{") + 40]}')
        os.makedirs(os.path.dirname(os.path.join(root, path)), exist_ok=True)
        open(os.path.join(root, path), 'w').write(out)
        print(f'{path}: {len(out) / 1e3:.0f} kB')
