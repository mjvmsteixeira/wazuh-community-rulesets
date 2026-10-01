#!/usr/bin/env python3
"""Camada 2 das regras irmãs: carrega várias pastas JUNTAS no wazuh-logtest e repete as amostras de log de cada uma.

Cada pasta valida sozinha, mas instaladas juntas o primeiro filho que corresponder fica com o evento (regras irmãs) e o
primeiro decoder carregado apanha o log (decoders homónimos). Uma amostra que, com a pasta sozinha, acabava numa regra
ou decoder dessa pasta e, com as pastas juntas, passa a acabar numa regra ou decoder de OUTRA pasta foi sombreada.

Uso:
  python3 tools/combo_test.py --folders areas/.../A areas/.../B [...]   # uma combinação (p.ex. o cesto da página)
  python3 tools/combo_test.py --auto [--max-pairs 150]                  # pares com pais/decoders em comum e amostras
Os ficheiros têm o nome que o script de instalação da página lhes dá (prefixo do pack), logo a ordem de carregamento é a real.
O modo --auto escreve catalog/combo_tests.csv e catalog/combo_summary.csv.
"""
import os, re, csv, json, argparse, subprocess, tempfile, collections
from samples import samples, RUNNER

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C = lambda n: list(csv.DictReader(open(os.path.join(ROOT, 'catalog', n))))
stats = json.load(open(os.path.join(ROOT, 'catalog/stats.json')))
ap = argparse.ArgumentParser()
ap.add_argument('--folders', nargs='+')
ap.add_argument('--auto', action='store_true')
ap.add_argument('--max-pairs', type=int, default=150)
ap.add_argument('--per-folder', type=int, default=40, help='amostras de cada pasta por combinação no modo --auto')
ap.add_argument('--reclassify', action='store_true', help='reaproveita os resultados brutos da última corrida --auto (.cache/combo_raw.jsonl)')
ap.add_argument('--image', default='wazuh/wazuh-manager:' + stats['official_reference'].split()[1].lstrip('v'))
a = ap.parse_args()
if not a.folders and not a.auto: ap.error('indicar --folders ou --auto')
NAME = 'wcr-combo'

folders = {r['folder']: r for r in C('folders.csv')}
val = {r['folder']: r for r in C('validation.csv')}
alone = {(r['folder'], r['log']): r for r in C('decoder_tests.csv')}
ids, decs = collections.defaultdict(set), collections.defaultdict(set)
first_parent = {}   # (pasta, id) -> pais if_sid, para seguir a cadeia de antepassados
rparents = collections.defaultdict(set)   # (pasta, id) -> pais diretos ('if_sid 5715', 'if_group x')
for r in C('rules.csv'):
    fo = '/'.join(r['file'].split('/')[:4]); ids[fo].add(r['id'])
    first_parent[(fo, r['id'])] = [x.strip() for x in r['if_sid'].replace(' ', ',').split(',') if x.strip()]
    rparents[(fo, r['id'])] |= {'if_sid ' + x.strip() for x in r['if_sid'].replace(' ', ',').split(',') if x.strip()} | \
                               {'if_group ' + x.strip() for x in r['if_group'].split(',') if x.strip()}
fparents = collections.defaultdict(set)   # pasta -> pais partilhados com outras fontes
for r in C('sibling_parents.csv'):
    for x in r['children'].split(' | '): fparents[x.split(': ')[0]].add(f"{r['kind']} {r['parent']}")
for r in C('decoders.csv'): decs['/'.join(r['file'].split('/')[:4])].add(r['name'])
excl = collections.defaultdict(set)
for r in C('decoder_replacements.csv'):
    fo = '/'.join(r['file'].split('/')[:4])
    if val.get(fo, {}).get('decoder_exclude') == 'necessário': excl[fo].update(x for x in r['official_files'].split(';') if x)

def slug(s): return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')
def base_prefix(f): return slug(f['topic'] + '-' + f['source'].split('/')[1])[:60]
def fnv(s):
    h = 0x811c9dc5
    for c in s.encode(): h = ((h ^ c) * 0x01000193) & 0xffffffff
    return f'{h:08x}'
prefix_count = collections.Counter(base_prefix(f) for f in folders.values())
def prefix(fo):   # igual a packPrefix() da página: slug(tópico + '-' + repositório), com hash da pasta se colidir
    b = base_prefix(folders[fo]); return b[:51] + '-' + fnv(fo) if prefix_count[b] > 1 else b
_ok = {}
def ok_samples(fo):
    """Amostras que, com a pasta sozinha, terminaram numa regra ou decoder da própria pasta (as que podem ser roubadas)."""
    if fo not in _ok: _ok[fo] = [s for s in samples(fo) if (fo, s[0][:500]) in alone and alone[(fo, s[0][:500])]['verdict'] == 'ok']
    return _ok[fo]
def pick(fo, other):
    """Amostras de fo a repetir com other: primeiro as que acabam numa regra filha de um pai partilhado com other ou num decoder
    raiz que other também define (só essas podem ser sombreadas), depois as restantes; no máximo --per-folder."""
    shared = fparents[fo] & set().union(*(fparents[x] for x in other))
    od = set().union(*(decs[x] for x in other))
    def hot(s):
        b = alone[(fo, s[0][:500])]
        return not (rparents[(fo, b['rule'])] & shared or b['decoder'] in od)
    return sorted(ok_samples(fo), key=hot)[:a.per_folder]

def combos():
    if a.folders:
        missing = [f for f in a.folders if f not in folders]
        if missing: raise SystemExit(f'pastas desconhecidas: {missing}')
        return [tuple(a.folders)]
    with_samples = {fo for fo in folders if ok_samples(fo)}
    score = collections.Counter()
    for r in C('sibling_parents.csv'):
        fs = [x.split(': ')[0] for x in r['children'].split(' | ')]
        ca = set(filter(None, r['catchall_folders'].split(';')))
        for i, x in enumerate(fs):
            for y in fs[i + 1:]:
                if folders[x]['source'] == folders[y]['source'] or not ({x, y} & with_samples): continue
                if val[x]['loads_ok'] != 'True' or val[y]['loads_ok'] != 'True': continue
                # com um apanha-tudo, só se vê o sombreamento se a vítima (o outro lado) tiver amostras
                victims = ({x, y} - ca) or {x, y}
                if ca & {x, y}:
                    if victims & with_samples: score[tuple(sorted((x, y)))] += 10
                else: score[tuple(sorted((x, y)))] += 1
    for r in C('decoder_collisions.csv'):
        fs = r['in'].split(';')
        for i, x in enumerate(fs):
            for y in fs[i + 1:]:
                if folders[x]['source'] == folders[y]['source']: continue
                if {x, y} & with_samples and val.get(x, {}).get('loads_ok') == 'True' and val.get(y, {}).get('loads_ok') == 'True':
                    score[tuple(sorted((x, y)))] += 5
    return [p for p, _ in score.most_common(a.max_pairs)]

plan = []
for combo in combos():
    meta, ss = [], []
    for fo in combo:
        for s in (pick(fo, [x for x in combo if x != fo]) if a.auto else samples(fo)):
            meta.append((fo, s)); ss.append({'log': s[0], 'fmt': 'json' if s[0].lstrip().startswith('{') else 'syslog'})
    if not ss: continue
    plan.append({'combo': combo, 'meta': meta,
                 'job': {'folder': ' + '.join(combo), 'parts': [{'path': fo, 'prefix': prefix(fo)} for fo in combo],
                         'excludes': sorted(set().union(*(excl[fo] for fo in combo))), 'samples': ss}})
if not plan: raise SystemExit('nenhuma combinação com amostras de log')
print(f'{len(plan)} combinações, {sum(len(p["meta"]) for p in plan)} amostras', flush=True)

def ancestors(fo, rid):
    seen, todo = set(), list(first_parent.get((fo, rid), []))
    while todo and len(seen) < 50:
        x = todo.pop()
        if x in seen: continue
        seen.add(x); todo += first_parent.get((fo, x), [])
    return seen

RAW = os.path.join(ROOT, '.cache', 'combo_raw.jsonl')
if a.reclassify:
    out = open(RAW).read()
else:
  with tempfile.TemporaryDirectory() as tmp:
      with open(os.path.join(tmp, 'plan.jsonl'), 'w') as fh:
          for p in plan: fh.write(json.dumps(p['job']) + '\n')
      open(os.path.join(tmp, 'runner.py'), 'w').write(RUNNER)
      subprocess.run(['docker', 'rm', '-f', NAME], capture_output=True)
      subprocess.run(['docker', 'run', '-d', '--init', '--name', NAME, '--ulimit', 'nofile=458752:458752', '--entrypoint', 'sleep', a.image, 'infinity'],
                     check=True, capture_output=True)
      try:
          for src, dst in ((os.path.join(ROOT, 'areas'), '/tmp/areas'), (os.path.join(tmp, 'plan.jsonl'), '/tmp/plan.jsonl'),
                           (os.path.join(tmp, 'runner.py'), '/tmp/runner.py')):
              subprocess.run(['docker', 'cp', src, f'{NAME}:{dst}'], check=True, capture_output=True)
          subprocess.run(['docker', 'exec', NAME, 'bash', '-c', 'cd /var/ossec && cp -a data_tmp/exclusion/var/ossec/etc/. etc/ && '
                          'rm -f etc/rules/local_rules.xml etc/decoders/local_decoder.xml && chown -R wazuh:wazuh etc && cp -a etc /tmp/etc.orig'],
                         check=True, capture_output=True)
          out = subprocess.run(['docker', 'exec', NAME, '/var/ossec/framework/python/bin/python3', '/tmp/runner.py'],
                               check=True, capture_output=True, text=True).stdout
      finally:
          subprocess.run(['docker', 'rm', '-f', NAME], capture_output=True)
  if a.auto:
    os.makedirs(os.path.dirname(RAW), exist_ok=True); open(RAW, 'w').write(out)
got = {j['folder']: j for j in map(json.loads, out.splitlines())}
if a.reclassify and any(len(got.get(p['job']['folder'], {}).get('results') or p['meta']) != len(p['meta']) for p in plan):
    raise SystemExit('os resultados guardados não correspondem ao plano atual: correr de novo sem --reclassify')

def owner_of(rule, decoder, parent, combo):
    """Pasta(s) do conjunto a que pertence a regra/decoder final."""
    r = [fo for fo in combo if rule and rule in ids[fo]]
    d = [fo for fo in combo if decoder in decs[fo] or parent in decs[fo]]
    return r, d

rows, summary = [], []
for p in plan:
    combo, res = p['combo'], got.get(p['job']['folder'], {})
    cnt = collections.Counter()
    for i, (fo, s) in enumerate(p['meta']):
        base = alone.get((fo, s[0][:500]), {})
        b_rule, b_dec = base.get('rule', ''), base.get('decoder', '')
        b_fields = set(filter(None, base.get('fields', '').split(','))) if base else None
        others = [x for x in combo if x != fo]
        dup = ids[fo] & set().union(*(ids[x] for x in others))   # IDs definidos nas duas pastas: só vale a 1.ª definição carregada
        if not res.get('loaded'):
            v, why, r = 'não carrega junto', '; '.join(res.get('errors', []))[:200], {}
        else:
            r = res['results'][i]
            if 'error' in r: v, why = 'erro', r['error']
            else:
                rown, down = owner_of(r['rule'], r['decoder'], r['parent'], combo)
                others_r, others_d = [x for x in rown if x != fo], [x for x in down if x != fo]
                fields_changed = b_fields is not None and set(r['fields']) != b_fields
                shared_root = [x for x in others if r['decoder'] in decs[fo] and r['decoder'] in decs[x]]
                anc_dup = sorted(ancestors(fo, b_rule) & dup) if b_rule in ids[fo] else []
                if r['rule'] and r['rule'] in dup or (b_rule in dup and r['rule'] != b_rule):
                    x = r['rule'] if r['rule'] in dup else b_rule
                    v, why = 'conflito de ID', f"regra {x} definida também em {[o for o in others if x in ids[o]][0]}"
                elif anc_dup and r['rule'] != b_rule:
                    v, why = 'conflito de ID', f"antepassado {anc_dup[0]} de {b_rule} definido também em {[o for o in others if anc_dup[0] in ids[o]][0]}"
                elif r['rule'] == b_rule and r['decoder'] == b_dec and not fields_changed: v, why = 'igual', ''
                elif r['decoder'] != b_dec and others_d and fo not in down:
                    v, why = 'sombreado (decoder)', f"decoder {b_dec} → {r['decoder']} de {others_d[0]}"
                elif shared_root and fields_changed:
                    # o logtest só devolve o nome da raiz: com a raiz partilhada, o sombreamento vê-se nos campos extraídos
                    v, why = 'sombreado (decoder)', (f"raiz {r['decoder']} partilhada com {shared_root[0]}; campos "
                                                    f"{','.join(sorted(b_fields - set(r['fields'])))[:80] or '-'} → {','.join(sorted(set(r['fields']) - b_fields))[:80] or '-'}")
                elif b_rule in ids[fo] and r['rule'] != b_rule and others_r and fo not in rown:
                    v, why = 'sombreado (regra irmã)', f"regra {b_rule} → {r['rule']} de {others_r[0]}"
                elif b_rule in ids[fo] and not r['rule']:
                    v, why = 'perdeu o alerta', f"regra {b_rule} → nenhuma"
                elif b_rule not in ids[fo] and others_r and r['rule'] != b_rule:
                    v, why = 'outra pasta alerta', f"regra {b_rule or '-'} → {r['rule']} de {others_r[0]}"
                else:
                    v, why = 'mudou', f"{b_dec}/{b_rule} → {r['decoder']}/{r['rule']}" + (' (campos)' if fields_changed else '')
        cnt[v] += 1
        rows.append({'combo': ' + '.join(combo), 'folder': fo, 'verdict': v, 'why': why, 'log': s[0][:300],
                     'alone_decoder': b_dec, 'alone_rule': b_rule,
                     'combined_decoder': r.get('decoder', ''), 'combined_rule': r.get('rule', '')})
    shadowed = cnt['sombreado (decoder)'] + cnt['sombreado (regra irmã)'] + cnt['perdeu o alerta'] + cnt['conflito de ID']
    dup_warn = sum(1 for w in res.get('warnings', []) if '7612' in w)
    summary.append({'combo': ' + '.join(combo), 'loaded_together': bool(res.get('loaded')), 'samples': len(p['meta']),
                    'unchanged': cnt['igual'], 'shadowed': shadowed, **{k: cnt[k] for k in ('sombreado (decoder)', 'sombreado (regra irmã)',
                    'perdeu o alerta', 'conflito de ID', 'outra pasta alerta', 'mudou', 'não carrega junto', 'erro')},
                    'duplicate_id_warnings': dup_warn, 'load_errors': '; '.join(res.get('errors', []))[:300]})

if a.auto:
    for name, data in (('combo_tests.csv', rows), ('combo_summary.csv', summary)):
        with open(os.path.join(ROOT, 'catalog', name), 'w', newline='') as fh:
            w = csv.DictWriter(fh, fieldnames=list(data[0].keys())); w.writeheader(); w.writerows(data)
tot = collections.Counter(r['verdict'] for r in rows)
print(f"{len(summary)} combinações; amostras: {dict(tot)}; {sum(1 for s in summary if s['shadowed'])} combinações com sombra; "
      f"{sum(1 for s in summary if not s['loaded_together'])} não carregam juntas")
if not a.auto:
    for r in rows:
        if r['verdict'] != 'igual': print(f"  {r['verdict']:24} {r['folder'].split('/')[3][:28]:28} {r['why'][:90]}")
