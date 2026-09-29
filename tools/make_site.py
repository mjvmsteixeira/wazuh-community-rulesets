#!/usr/bin/env python3
"""Gera site/index.html: página autónoma de pesquisa de packs, regras, playbooks, respostas e grupos (correr depois de make_docs.py).

Os dados vão embutidos e comprimidos (gzip + base64) e são descomprimidos no browser; os ficheiros XML/listas/agent.conf
vão num segundo bloco, lido só quando se abre um pack ou se gera um script de instalação.
"""
import os, sys, csv, json, gzip, base64, re
ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'
C = lambda n: list(csv.DictReader(open(os.path.join(ROOT, 'catalog', n)))) if os.path.exists(os.path.join(ROOT, 'catalog', n)) else []
stats = json.load(open(os.path.join(ROOT, 'catalog/stats.json')))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
from taxonomy import AREAS, AREAS_EN
folders = C('folders.csv'); val = {r['folder']: r for r in C('validation.csv')}
coll = {r['folder']: r for r in C('collection.csv')}; rcov = {r['folder']: r for r in C('response_coverage.csv')}
src = {r['repo']: r for r in C('sources.csv')}
dex = {r['folder']: r.get('decoder_exclude', '') for r in C('validation.csv')}
repl = {}
for r in C('decoder_replacements.csv'):
    fo = '/'.join(r['file'].split('/')[:4]); repl.setdefault(fo, set()).update(x for x in r['official_files'].split(';') if x)
deps, needs = {}, {}
for r in C('dependencies.csv'):
    deps.setdefault(r['folder'], []).append(f"{r['kind']} {r['missing']}: {r['status']}" + (f" ({r['found_in']})" if r['found_in'] else ''))
    for x in r['found_in'].split(';'):
        if x: needs.setdefault(r['folder'], set()).add(x)
tsum = {r['folder']: r for r in C('decoder_test_summary.csv')}

contents, content_idx = [], {}
def content(path):
    if path not in content_idx:
        content_idx[path] = len(contents)
        contents.append(open(os.path.join(ROOT, path), errors='replace').read())
    return content_idx[path]

pack_idx = {}
packs = []
for i, f in enumerate(folders):
    fo = f['folder']; pack_idx[fo] = i
    files = []
    for kind in ('rules', 'decoders', 'lists', 'collection', 'response', 'tests'):
        d = os.path.join(ROOT, fo, kind)
        if not os.path.isdir(d): continue
        for dp, dn, fn in os.walk(d):
            dn.sort()
            for n in sorted(fn):
                p = os.path.relpath(os.path.join(dp, n), ROOT)
                if os.path.getsize(os.path.join(ROOT, p)) > 1_500_000: continue
                files.append([kind, os.path.relpath(p, fo), content(p)])
    s = src.get(f['source'], {}); v = val.get(fo, {}); c = coll.get(fo, {}); q = rcov.get(fo, {})
    packs.append({
        'f': fo, 'a': f['area'], 't': f['topic'], 's': f['source'], 'url': s.get('url', ''), 'commit': s.get('commit', ''),
        'lic': s.get('license', ''), 'last': s.get('last_commit', ''), 'r': int(f['rules']), 'd': int(f['decoders']),
        'sa': f['standalone'] == 'True', 'ok': v.get('loads_ok') == 'True', 'w': int(v.get('warnings') or 0),
        'err': v.get('first_error', ''), 'warn': v.get('first_warning', ''), 'dex': dex.get(fo, ''), 'repl': sorted(repl.get(fo, ())),
        'grp': [g for g in c.get('agent_groups', '').split(';') if g], 'mgr': [g for g in c.get('manager_requirements', '').split(';') if g],
        'undef': [g for g in c.get('undefined', '').split(';') if g], 'def': [g for g in c.get('default_inputs', '').split(';') if g],
        'tech': int(q.get('techniques') or 0), 'tpb': int(q.get('techniques_with_playbook') or 0),
        'rok': int(q.get('responses_ok') or 0), 'rbad': int(q.get('responses_broken') or 0), 'deps': deps.get(fo, [])[:40],
        'tests': {k: int(tsum[fo][k]) for k in ('samples', 'ok', 'failed', 'not_tested', 'sombreado', 'não descodificado', 'regra não disparou',
                                                 'falso positivo', 'diferente do esperado')} if fo in tsum else None,
        'files': files})

for p in packs: p['needs'] = sorted(pack_idx[x] for x in needs.get(p['f'], ()) if x in pack_idx and x != p['f'])
rules = [[r['id'], int(r['level'] or 0), r['description'], r['mitre_norm'], pack_idx['/'.join(r['file'].split('/')[:4])], r['conflict'],
          r['groups'][:160], r['mitre_status']] for r in C('rules.csv')]
decs = [[r['name'], r['parent'], pack_idx['/'.join(r['file'].split('/')[:4])], r['root'] == 'True', r['ident'], r['regex_types'], r['fields']]
        for r in C('decoders.csv')]
dcoll = {r['name']: {'off': r['official'] == 'True', 'p': [pack_idx[x] for x in r['in'].split(';') if x in pack_idx]} for r in C('decoder_collisions.csv')}
dfields = [[r['field'], int(r['uses']), int(r['folders']), r['ecs']] for r in C('decoder_fields.csv')]
dtests = [[pack_idx[r['folder']], r['kind'], r['verdict'], r['why'], r['log'][:300], r['decoder'], r['rule'], r['level'], r['fields'][:300]]
          for r in C('decoder_tests.csv') if r['folder'] in pack_idx]
techs = [[r['technique'], r['name'], r['tactics'], int(r['rules']), int(r['rules_level12']), int(r['folders']), r['areas'],
          int(r['playbooks']), int(r['countermeasures']), int(r['containment_ok']), int(r['automations_ok']),
          int(r.get('sigma_rules') or 0), int(r.get('sigma_high') or 0)] for r in C('technique_coverage.csv')]
sigma_only = [[r['technique'], r['name'], r['tactics'], int(r['sigma_rules']), int(r['sigma_high']), r['sigma_logsources'], r['sigma_examples'], r['status'],
               int(r['registry_rules'])] for r in C('sigma_coverage.csv') if r['status'] in ('só Sigma', 'registo sem regras de nível ≥ 12')]
pbs = [[r['library'], r['kind'], r['doc_id'], r['title'], r['techniques'], r['rule_ids'], r['url']] for r in C('playbooks.csv')
       if not r['kind'].startswith('remediação SCA')]
resps = [[r['source'], r['kind'], r['name'], r['action'], r['impact'], r['trigger'], r['status'], r['problems'], r['warnings'],
          [pack_idx[x] for x in r['folders'].split(';') if x in pack_idx], r['license']] for r in C('responses.csv')]
gval = {r['file'].split('/')[1]: r['ok'] == 'True' for r in C('validation_agent_conf.csv') if r['kind'] == 'grupo'}
groups = [[g['group'], g['os'], int(g['entries']), g['origin'], [pack_idx[x] for x in g['serves'].split(';') if x in pack_idx],
           content(f"groups/{g['group']}/agent.conf"), gval.get(g['group'])] for g in C('groups.csv')]
conflicts = {r['id']: r['type'] for r in C('id_conflicts.csv')}

meta = {'stats': stats, 'areas': AREAS, 'areas_en': AREAS_EN, 'packs': packs, 'rules': rules, 'decs': decs, 'dcoll': dcoll, 'dfields': dfields, 'dtests': dtests, 'techs': techs, 'pbs': pbs,
        'resps': resps, 'groups': groups, 'sigma': sigma_only, 'conflicts': conflicts,
        'sources': [[r['repo'], r['license'], r['status'], r['last_commit'], int(r['rules'] or 0)] for r in C('sources.csv')]}
enc = lambda o: base64.b64encode(gzip.compress(json.dumps(o, ensure_ascii=False, separators=(',', ':')).encode(), 9, mtime=0)).decode()
tpl = open(os.path.join(ROOT, 'tools', 'site_template.html')).read()
# todas as strings passadas a _() têm de ter tradução portuguesa
ptblock = tpl[tpl.index('const PT = {'):tpl.index('const _ = ')]
pt_keys = set(re.findall(r"'((?:[^'\\]|\\.)*)'\s*:", ptblock))
used = set(re.findall(r"_\('((?:[^'\\]|\\.)*)'", tpl)) | {l for _, l in re.findall(r"\['(\w+)', '([^']+)'\]", tpl[tpl.index('const TABS'):tpl.index('function nav')])}
used |= {l for _, l in re.findall(r"\['([\w.]+)', '([^']+)'\]", tpl[tpl.index('const CONCEPTS'):tpl.index('let ECSMAP')])}
missing = sorted(used - pt_keys)
if missing: print('AVISO: sem tradução portuguesa:', missing)
meta_b, files_b = enc(meta), enc(contents)
for lang, path, href, other, label in (('en', 'site/index.html', 'pt/', 'pt', 'PT'), ('pt', 'site/pt/index.html', '../', 'en', 'EN')):
    html = (tpl.replace('__META__', meta_b).replace('__FILES__', files_b).replace('__LANG_HREF__', href)
               .replace('__LANG_OTHER__', other).replace('__LANG_LABEL__', label).replace('__LANG__', lang))
    os.makedirs(os.path.dirname(os.path.join(ROOT, path)), exist_ok=True)
    open(os.path.join(ROOT, path), 'w').write(html)
    print(f"{path}: {len(html) / 1e6:.1f} MB ({len(packs)} packs, {len(rules)} regras, {len(contents)} ficheiros)")
