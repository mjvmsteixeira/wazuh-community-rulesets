#!/usr/bin/env python3
"""Constrói o mega-repositório a partir dos clones em SRC e do ruleset oficial 4.x em OFFICIAL.

Uso: python3 tools/build.py --src <dir clones> --official <wazuh/ruleset> --out <repo> [--as-of AAAA-MM-DD]

Determinístico: para os mesmos commits (tools/sources.lock) e a mesma data as-of, gera os mesmos ficheiros.
"""
import os, sys, json, csv, shutil, re, argparse, hashlib, subprocess, datetime
from collections import defaultdict, Counter
sys.path.insert(0, os.path.dirname(__file__))
from parse_ruleset import parse_file
from taxonomy import AREAS, classify, slug
import collection as col
import responses as resp
import playbooks as pb
import mitre
import fields as fld
import sigma as sg

TOOLS = os.path.dirname(os.path.abspath(__file__))
LOCK = os.path.join(TOOLS, 'sources.lock')

def lock_as_of():
    if os.path.exists(LOCK):
        for line in open(LOCK):
            m = re.match(r'#\s*as-of:\s*(\d{4}-\d{2}-\d{2})', line)
            if m: return m.group(1)
    return datetime.date.today().isoformat()

ap = argparse.ArgumentParser()
ap.add_argument('--src', required=True); ap.add_argument('--official', required=True); ap.add_argument('--out', required=True)
ap.add_argument('--playbooks', default=None, help='clones das bibliotecas de playbooks (por omissão: <src>/../playbooks)')
ap.add_argument('--as-of', default=None, help='data de referência para age_days e stats (por omissão: a do sources.lock)')
a = ap.parse_args()
SRC, OFF, OUT = a.src, a.official, a.out
REFS = os.path.join(os.path.dirname(os.path.abspath(SRC).rstrip('/')), 'refs')
PBK = a.playbooks or os.path.join(os.path.dirname(os.path.abspath(SRC).rstrip('/')), 'playbooks')
AS_OF = datetime.date.fromisoformat(a.as_of or lock_as_of())

def git(d, *args):
    return subprocess.run(['git', '-C', d, *args], capture_output=True, text=True).stdout.strip()

def repo_of(d):
    url = git(d, 'remote', 'get-url', 'origin')
    return url.removeprefix('https://github.com/').removesuffix('/').removesuffix('.git')

def walk(d):
    """os.walk ordenado e sem .git, para a saída não depender da ordem do sistema de ficheiros."""
    for dp, dn, fn in os.walk(d):
        dn[:] = sorted(x for x in dn if x != '.git')
        yield dp, sorted(fn)

def detect_license(d):
    for f in sorted(os.listdir(d)):
        if re.match(r'(LICEN[CS]E|COPYING)', f, re.I):
            t = open(os.path.join(d, f), errors='ignore').read(4000)
            for pat, name in [(r'GNU AFFERO', 'AGPL-3.0'), (r'GNU GENERAL PUBLIC LICENSE\s+Version 3', 'GPL-3.0'),
                              (r'GNU GENERAL PUBLIC LICENSE\s+Version 2', 'GPL-2.0'), (r'Apache License', 'Apache-2.0'),
                              (r'MIT License|Permission is hereby granted, free of charge', 'MIT'), (r'BSD', 'BSD'),
                              (r'CC0|Creative Commons Zero', 'CC0-1.0')]:
                if re.search(pat, t, re.I):
                    return name, f
            return 'OTHER', f
    return 'NONE', None

TEST_MAX_BYTES = 2_000_000

def test_files(d):
    """Ficheiros de teste da fonte (caminhos relativos): pastas tests/testing/logtest e .ini no formato do wazuh-logtest."""
    out = []
    for dp, fn in walk(d):
        in_tests = re.search(r'(^|/)(tests?|testing|logtest)(/|$)', os.path.relpath(dp, d).lower())
        for f in fn:
            fp = os.path.join(dp, f)
            if os.path.getsize(fp) > TEST_MAX_BYTES: continue
            if in_tests:
                out.append(os.path.relpath(fp, d))
            elif f.endswith('.ini'):
                try:
                    if re.search(r'^\s*rule\s*=', open(fp, errors='ignore').read(), re.M):
                        out.append(os.path.relpath(fp, d))
                except OSError: pass
    return out

# fontes originais conhecidas: ganham aos seus copiadores nos duplicados
PREFERRED = {'socfortress/Wazuh-Rules', 'sanesecurityguy/opnsense-ruleset-for-wazuh', 'MikhailKasimov/maltrail-wazuh-decoder-and-rules',
             'NucleiAv/caddy-detection-rules', 'sametsazak/sysmon', 'SanWieb/sigWah'}
# licenças declaradas fora de um ficheiro LICENSE
LICENSE_OVERRIDE = {'socfortress/Wazuh-Rules': 'MIT? (badge no README, sem ficheiro LICENSE)'}
LIST_SKIP_EXT = ('.xml', '.md', '.py', '.sh', '.ps1', '.json', '.yml', '.yaml', '.cdb', '.ini', '.conf', '.png', '.jpg', '.gif')

def list_rel(ref):
    """'etc/lists/malicious-ioc/malicious-ip' -> 'malicious-ioc/malicious-ip'"""
    ref = ref.strip().lstrip('/')
    return ref.split('lists/', 1)[1] if 'lists/' in ref else os.path.basename(ref)

# ---------- oficial
off_rule_ids, off_dec_names = set(), set()
off_rule = {}                      # id -> regra oficial + ficheiro
off_dec_file = defaultdict(set)    # nome de decoder -> ficheiros oficiais
for sub in ('rules', 'decoders'):
    for f in sorted(os.listdir(os.path.join(OFF, sub))):
        r = parse_file(os.path.join(OFF, sub, f))
        off_rule_ids |= {x['id'] for x in r['rules']}
        off_dec_names |= {x['name'] for x in r['decoders']}
        for x in r['rules']: off_rule[x['id']] = {**x, 'file': f}
        for x in r['decoders']: off_dec_file[x['name']].add(f)
# decoders embutidos no analysisd: válidos em <decoded_as>, mas não como <parent> (confirmado com wazuh-analysisd -t)
BUILTIN_DECODED_AS = {'windows_eventchannel'}
off_lists = set()
if os.path.isdir(os.path.join(OFF, 'lists')):
    for dp, fn in walk(os.path.join(OFF, 'lists')):
        off_lists |= {os.path.relpath(os.path.join(dp, f), os.path.join(OFF, 'lists')) for f in fn if not f.endswith('.cdb')}

# ---------- recolha
listed = [l.strip() for l in open(os.path.join(TOOLS, 'sources.txt')) if l.strip() and not l.startswith('#')]
sources, files, excluded = {}, [], []

def collect(repo, p):
    for dp, fn in walk(p):
        for f in fn:
            fp = os.path.join(dp, f); low = f.lower()
            if not (low.endswith('.xml') or low.endswith('.xml.tmp') or low in ('rules', 'decoders')): continue
            txt = open(fp, errors='ignore').read()
            if not re.search(r'<rule\s[^>]*id=|<decoder\s[^>]*name=', txt): continue
            res = parse_file(fp)
            if not res['rules'] and not res['decoders']: continue
            rel = os.path.relpath(fp, p)
            area, topic, why = classify(repo, rel)
            rec = {'repo': repo, 'path': rel, 'abs': fp, 'sha256': hashlib.sha256(open(fp, 'rb').read()).hexdigest(),
                   'rules': res['rules'], 'decoders': res['decoders'], 'wellformed': res['wellformed'],
                   'area': area, 'topic': topic}
            if why:
                rec['why'] = why; excluded.append(rec)
            else:
                files.append(rec)

for d in sorted(os.listdir(SRC)):
    p = os.path.join(SRC, d)
    if not os.path.isdir(os.path.join(p, '.git')): continue
    repo = repo_of(p)
    lic, licfile = detect_license(p)
    tests = test_files(p)
    sources[repo] = {'repo': repo, 'url': f'https://github.com/{repo}', 'commit': git(p, 'rev-parse', 'HEAD'),
                     'last_commit': git(p, 'log', '-1', '--format=%cs'), 'license': LICENSE_OVERRIDE.get(repo, lic),
                     'license_file': licfile, 'has_tests': bool(tests), 'tests': tests, 'dir': p}
    collect(repo, p)

# capturas guardadas no repositório (p.ex. o blog da Wazuh, que não é um repositório git): snapshots/<nome>/SNAPSHOT.json
SNAPS = os.path.join(os.path.dirname(TOOLS), 'snapshots')
for d in sorted(os.listdir(SNAPS)) if os.path.isdir(SNAPS) else []:
    p = os.path.join(SNAPS, d)
    if not os.path.exists(os.path.join(p, 'SNAPSHOT.json')): continue
    meta = json.load(open(os.path.join(p, 'SNAPSHOT.json')))
    posts = {x: json.load(open(os.path.join(p, x, 'post.json'))) for x in sorted(os.listdir(p)) if os.path.exists(os.path.join(p, x, 'post.json'))}
    digest = hashlib.sha256(json.dumps({k: v['files'] for k, v in posts.items()}, sort_keys=True).encode()).hexdigest()
    sources[meta['repo']] = {'repo': meta['repo'], 'url': meta['url'], 'commit': digest[:40], 'retrieved': meta['retrieved'],
                             'last_commit': max((v['published'] for v in posts.values() if v['published']), default=''),
                             'license': meta['license'], 'license_file': None, 'has_tests': False, 'tests': [], 'dir': p,
                             'snapshot': True, 'posts': posts}
    collect(meta['repo'], p)
failed = [r for r in listed if r not in sources]

# duplicados exatos de ficheiro entre repos: fica a cópia introduzida primeiro (data do commit que adicionou o ficheiro)
def introduced(f):
    s = sources[f['repo']]
    if s.get('snapshot'): return s['posts'][f['path'].split('/')[0]]['published'] or s['last_commit']
    out = git(sources[f['repo']]['dir'], 'log', '--diff-filter=A', '--format=%cs', '--', f['path'])
    return out.splitlines()[-1] if out else (sources[f['repo']]['last_commit'] or '9999')

by_sha = defaultdict(list)
for f in files: by_sha[f['sha256']].append(f)
dups, kept = [], []
for group in by_sha.values():
    if len(group) > 1:
        for f in group: f['introduced'] = introduced(f)
        group.sort(key=lambda x: (x['repo'] not in PREFERRED, x['introduced'], x['repo'], x['path']))
    kept.append(group[0])
    dups += [(f, group[0]) for f in group[1:]]
files = sorted(kept, key=lambda x: (x['repo'], x['path']))

# ---------- pastas de destino
def folder_of(area, topic, repo):
    return os.path.join('areas', area, topic, repo.replace('/', '__'))

placed = defaultdict(list)   # pasta -> ficheiros
for f in files:
    f['folder'] = folder_of(f['area'], f['topic'], f['repo'])
    placed[f['folder']].append(f)

# ---------- análise regras
by_id = defaultdict(list)
fold_ids = defaultdict(set); fold_decs = defaultdict(set)
id_folders = defaultdict(set); dec_folders = defaultdict(set)
for f in files:
    for r in f['rules']:
        by_id[r['id']].append((f, r)); fold_ids[f['folder']].add(r['id']); id_folders[r['id']].add(f['folder'])
    for dd in f['decoders']:
        fold_decs[f['folder']].add(dd['name']); dec_folders[dd['name']].add(f['folder'])
repo_of_folder = {fo: fl[0]['repo'] for fo, fl in placed.items()}

conflicts = []
for rid, lst in by_id.items():
    repos = {f['repo'] for f, r in lst}
    hashes = {r['hash'] for f, r in lst}
    official = rid in off_rule_ids
    if official and not all(r['overwrite'] for f, r in lst):
        kind = 'oficial: colisão sem overwrite'
    elif official and len(repos) > 1 and len(hashes) > 1:
        kind = 'oficial: overwrite por várias fontes'
    elif len(repos) > 1 and len(hashes) > 1:
        kind = 'comunidade'
    else:
        continue
    conflicts.append({'id': rid, 'type': kind, 'official_id': official, 'n_sources': len(repos),
                      'sources': ';'.join(sorted(repos)), 'n_variants': len(hashes)})
conflict_type = {c['id']: c['type'] for c in conflicts}

def split_ids(s):
    return [x for x in re.split(r'[,\s]+', s) if x]

def dep_status(folder, where):
    """Onde vive a peça que falta na pasta: noutra pasta da mesma fonte, noutra fonte ou em lado nenhum."""
    if not where: return 'em falta', ''
    same = sorted(w for w in where if repo_of_folder[w] == repo_of_folder[folder])
    return ('noutra pasta da mesma fonte', ';'.join(same)) if same else ('noutra fonte do pack', ';'.join(sorted(where)))

deps = []
def add_dep(kind, missing, ref, f, where):
    status, found = dep_status(f['folder'], where)
    deps.append({'kind': kind, 'missing': missing, 'status': status, 'found_in': found, 'rule_id': ref,
                 'repo': f['repo'], 'folder': f['folder'], 'file': f['path']})

for f in files:
    fo = f['folder']
    for r in f['rules']:
        for sid in split_ids(r['if_sid']):
            if sid in off_rule_ids or sid in fold_ids[fo]: continue
            add_dep('if_sid', sid, r['id'], f, id_folders.get(sid))
        for dn in [x.strip() for x in r['decoded_as'].split(',') if x.strip()]:
            if dn in off_dec_names or dn in BUILTIN_DECODED_AS or dn in fold_decs[fo]: continue
            add_dep('decoded_as', dn, r['id'], f, dec_folders.get(dn))
    for dd in f['decoders']:
        for par in [x.strip() for x in dd['parent'].split(',') if x.strip()]:
            if par in off_dec_names or par in fold_decs[fo]: continue
            add_dep('decoder_parent', par, dd['name'], f, dec_folders.get(par))

# ---------- listas CDB referidas pelas regras: procurar o ficheiro-fonte da lista no repositório de origem
repo_file_index = {}
def repo_files(repo):
    if repo not in repo_file_index:
        idx = defaultdict(list)
        for dp, fn in walk(sources[repo]['dir']):
            for f in fn:
                if f.lower().endswith(LIST_SKIP_EXT): continue
                rel = os.path.relpath(os.path.join(dp, f), sources[repo]['dir'])
                idx[f].append(rel); idx[os.path.splitext(f)[0]].append(rel)
        repo_file_index[repo] = idx
    return repo_file_index[repo]

list_rows, list_copies = [], defaultdict(dict)   # pasta -> {rel destino: caminho na fonte}
for fo, fl in sorted(placed.items()):
    refs = Counter(l for f in fl for r in f['rules'] for l in r['lists'])
    for ref, n in sorted(refs.items()):
        rel = list_rel(ref)
        cands = sorted(set(repo_files(fl[0]['repo']).get(os.path.basename(rel), [])),
                       key=lambda c: ('list' not in c.lower(), len(c), c))
        if cands:
            status, origin = 'copiada da fonte', cands[0]; list_copies[fo][rel] = cands[0]
        elif rel in off_lists:
            status, origin = 'oficial', ''
        else:
            status, origin = 'em falta', ''
            deps.append({'kind': 'cdb_list', 'missing': ref, 'status': 'em falta', 'found_in': '', 'rule_id': '',
                         'repo': fl[0]['repo'], 'folder': fo, 'file': ''})
        list_rows.append({'list': ref, 'status': status, 'origin_path': origin, 'rules': n, 'source': fl[0]['repo'], 'folder': fo})

# ---------- escrever repositório
# só regenera areas/, catalog/ e groups/ — nunca apaga tools/, README, etc.
# exceto os resultados do combo_test (demora ~1 h, não corre no CI): mantêm-se até à próxima corrida manual
KEEP = ('combo_tests.csv', 'combo_summary.csv')
kept = {n: open(os.path.join(OUT, 'catalog', n), 'rb').read() for n in KEEP if os.path.exists(os.path.join(OUT, 'catalog', n))}
for sub in ('areas', 'catalog', 'groups'):
    if os.path.exists(os.path.join(OUT, sub)): shutil.rmtree(os.path.join(OUT, sub))
os.makedirs(OUT, exist_ok=True)

src_folders = defaultdict(list)
for fo in sorted(placed): src_folders[repo_of_folder[fo]].append(fo)

def tests_for(fo):
    """Testes da fonte que dizem respeito a esta pasta: todos se a fonte só tem uma pasta, senão os que citam IDs da pasta."""
    s = sources[repo_of_folder[fo]]
    if len(src_folders[s['repo']]) == 1: return s['tests']
    ids = sorted(fold_ids[fo], key=len, reverse=True)
    if not ids: return []
    pat = re.compile(r'(?<!\d)(' + '|'.join(map(re.escape, ids)) + r')(?!\d)')
    return [t for t in s['tests'] if pat.search(open(os.path.join(s['dir'], t), errors='ignore').read())]

# ---------- recolha: configuração de agente/manager que as fontes trazem, atribuída à pasta a que diz respeito
registered = defaultdict(set)
for f in files + excluded + [d for d, _ in dups]: registered[f['repo']].add(f['path'])

def assign(repo, rel):
    """Pasta de destino de um ficheiro de configuração: a única da fonte, a que a taxonomia dá ao caminho, ou a de prefixo comum mais longo."""
    fos = src_folders[repo]
    if len(fos) == 1: return fos[0]
    area, topic, why = classify(repo, rel)
    if not why and folder_of(area, topic, repo) in placed: return folder_of(area, topic, repo)
    parts = os.path.dirname(rel).split('/')
    def score(fo):
        return max(len(os.path.commonprefix([parts, os.path.dirname(f['path']).split('/')])) for f in placed[fo])
    best = sorted(((score(fo), fo) for fo in fos), reverse=True)
    return best[0][1] if best[0][0] > 0 and best[0][0] > best[1][0] else None

coll_files = defaultdict(list)     # pasta -> [(caminho na fonte, modo, entradas)]
unassigned = []
for repo in sorted(src_folders):
    for rel, txt in col.candidate_files(sources[repo]['dir'], registered[repo]):
        bl = col.blocks(txt)
        ents = [e for b in bl for e in col.entries_of(b)]
        if not ents: continue
        whole = os.path.splitext(rel)[1].lower() in ('.conf', '.xml', '.cfg') or txt.lstrip().startswith('<')
        fo = assign(repo, rel)
        if fo is None:
            unassigned.append((repo, rel, ents)); continue
        coll_files[fo].append((rel, 'cópia' if whole else 'extraído', ents, bl))

# ---------- resposta: <active-response>/<command>/<integration> das fontes, ligados a script e regras
LICENSED = lambda lic: lic not in ('NONE', 'OTHER') and not lic.startswith('MIT?')
repo_rule_ids = defaultdict(set); repo_group_folders = defaultdict(lambda: defaultdict(set))
for fo, fl in placed.items():
    for f in fl:
        for r in f['rules']:
            repo_rule_ids[f['repo']].add(r['id'])
            for g in r['groups']: repo_group_folders[f['repo']][g].add(fo)
off_groups = {g for r in off_rule.values() for g in r['groups']}
resp_rows, resp_copies = [], defaultdict(dict)   # pasta -> {destino relativo: origem absoluta}
for repo in sorted(src_folders):
    s = sources[repo]; d = s['dir']
    by_base = defaultdict(list)
    for dp, dn, fn in os.walk(d):
        dn[:] = sorted(x for x in dn if x != '.git')
        for f in sorted(fn): by_base[f].append(os.path.relpath(os.path.join(dp, f), d))
    remap = resp.load_remap(d)
    defs, cmds, texts = [], {}, {}
    for rel, txt in resp.scan(d):
        texts[rel] = txt
        in_agent_conf = bool(re.match(r'\s*(<!--.*?-->\s*)*<agent_config\b', txt, re.S))
        for b in resp.blocks(txt):
            b['file'], b['agent_conf'] = rel, in_agent_conf
            if b['kind'] == 'command': cmds.setdefault(b['name'], b)
            else: defs.append(b)
    seen = set()
    for b in defs:
        ar = b['kind'] == 'active-response'
        if ar:
            name = b['command']; cmd = cmds.get(name); exe = cmd['executable'] if cmd else ''
            ids, grps = resp.split_ids(b['rules_id']), resp.split_ids(b['rules_group'].replace('|', ','))
        else:
            name = b['name']; cmd = None; exe = name
            ids, grps = resp.split_ids(b['rule_id']), resp.split_ids(b['group'])
        key = (b['kind'], name, exe, tuple(ids), tuple(grps), b['level'])
        if key in seen: continue
        seen.add(key)
        problems, warnings, folders = [], [], set()
        builtin = (name in resp.BUILTIN_AR or exe in resp.BUILTIN_AR) if ar else name in resp.BUILTIN_INTEGRATIONS
        script, note = ('', '') if builtin else resp.find_script(by_base, exe or name, b['file'])
        if note: problems.append(note)
        elif not builtin and not script: problems.append(f'script em falta ({exe or name})' if (exe or name) else 'sem nome de comando/integração')
        for i in ids:
            others = {fo for fo in id_folders.get(i, ()) if repo_of_folder[fo] != repo}
            if i in repo_rule_ids[repo]:
                folders |= {fo for fo in id_folders[i] if repo_of_folder[fo] == repo}
                if others: warnings.append(f'ID {i} também existe noutras fontes')
            elif i in off_rule_ids:
                if others: warnings.append(f'ID oficial {i} reescrito por outras fontes')
            elif i in remap:
                new = sorted(remap[i]); problems.append(f"ID {i} renumerado pelo autor ({','.join(new)})")
                folders |= {fo for n in new for fo in id_folders.get(n, ()) if repo_of_folder[fo] == repo}
            elif others:
                problems.append(f'ID {i} só existe noutras fontes')
            else:
                problems.append(f'regra {i} inexistente')
        for g in grps:
            if g in repo_group_folders[repo]: folders |= repo_group_folders[repo][g]
            elif g not in off_groups: problems.append(f'grupo {g} inexistente')
        if not ids and not grps and not b['level']:
            if ar: problems.append('sem gatilho')
            else: warnings.append('sem filtro: recebe todos os alertas')
        if ar and b['agent_conf']: problems.append('ignorado: definido num agent.conf (o Wazuh só lê <active-response> no ossec.conf do manager)')
        stext = open(os.path.join(d, script), errors='ignore').read(20000) if script and os.path.getsize(os.path.join(d, script)) < 2_000_000 else ''
        action, impact = resp.classify_response(b['kind'], ' '.join([name, exe]), stext)
        allow = '<white_list>' in texts[b['file']] or bool(re.search(r'allow.?list|white.?list|exclu', stext, re.I))
        if impact == 'destrutivo' and not allow: warnings.append('destrutivo sem allowlist')
        if ar and action == 'bloquear IP' and not b['timeout']: warnings.append('bloqueio sem timeout')
        if b['location'] == 'all': warnings.append('location=all')
        if not folders:
            fo = assign(repo, b['file'])
            if fo: folders.add(fo)
        folders = sorted(folders)
        trig = '; '.join(filter(None, [f"rules_id {','.join(ids)}" if ids else '', f"grupo {','.join(grps)}" if grps else '',
                                        f"nível ≥{b['level']}" if b['level'] else '']))
        row = {'source': repo, 'license': s['license'], 'kind': b['kind'], 'name': name, 'script': script or ('nativo' if builtin else ''),
               'action': action, 'impact': impact, 'trigger': trig, 'location': b['location'], 'timeout': b['timeout'],
               'allowlist': allow, 'status': 'ignorado' if ar and b['agent_conf'] else ('partido' if problems else 'ok'),
               'problems': '; '.join(problems), 'warnings': '; '.join(sorted(set(warnings))), 'folders': ';'.join(folders),
               'file': b['file'], 'copied': False, 'rules': sorted(set(ids)), 'groups_': grps}
        if folders and LICENSED(s['license']):
            fo = folders[0]; row['copied'] = True
            if script: resp_copies[fo][script] = os.path.join(d, script)
            resp_copies[fo][b['file'] + '.extracted.xml'] = ('blocks', b['file'], repo)
        resp_rows.append(row)
resp_blocks = defaultdict(list)   # (fonte, ficheiro) -> blocos, para os .extracted.xml
for repo in sorted(src_folders):
    for rel, txt in resp.scan(sources[repo]['dir']):
        resp_blocks[(repo, rel)] = [b['raw'] for b in resp.blocks(txt)]

folder_tests = {}
for fo, fl in sorted(placed.items()):
    base = os.path.join(OUT, fo)
    used = set()
    for f in fl:
        kind = 'rules' if f['rules'] else 'decoders'
        name = os.path.basename(f['path'])
        if name.lower() in ('rules', 'decoders'): name += '.xml'
        if (kind, name) in used:
            name = slug(os.path.dirname(f['path'])) + '__' + name
        used.add((kind, name))
        dst = os.path.join(base, kind, name)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(f['abs'], dst)
        f['dest'] = os.path.relpath(dst, OUT)
    s = sources[fl[0]['repo']]
    for rel, origin in sorted(list_copies[fo].items()):
        dst = os.path.join(base, 'lists', rel); os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(s['dir'], origin), dst)
    folder_tests[fo] = tests_for(fo)
    for t in folder_tests[fo]:
        dst = os.path.join(base, 'tests', t); os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(s['dir'], t), dst)
    for rel, mode, ents, bl in coll_files[fo]:
        if mode == 'cópia':
            dst = os.path.join(base, 'collection', rel); os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(os.path.join(s['dir'], rel), dst)
        else:
            dst = os.path.join(base, 'collection', rel + '.extracted.xml'); os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, 'w') as fh:
                fh.write(f"<!-- Blocos de configuração extraídos, sem alterações, de {s['repo']}:{rel} @ {s['commit'][:12]} -->\n"
                         + '\n\n'.join(bl) + '\n')
    for rel, src in sorted(resp_copies[fo].items()):
        dst = os.path.join(base, 'response', rel); os.makedirs(os.path.dirname(dst), exist_ok=True)
        if isinstance(src, tuple):
            with open(dst, 'w') as fh:
                fh.write(f"<!-- Blocos de resposta extraídos, sem alterações, de {src[2]}:{src[1]} @ {s['commit'][:12]} -->\n"
                         + '\n\n'.join(resp_blocks[(src[2], src[1])]) + '\n')
        else:
            shutil.copy2(src, dst)
    if s['license_file']:
        shutil.copy2(os.path.join(s['dir'], s['license_file']), os.path.join(base, 'LICENSE.upstream'))
    area, topic = fl[0]['area'], fl[0]['topic']
    with open(os.path.join(base, 'SOURCE.md'), 'w') as fh:
        if s.get('snapshot'):
            post = s['posts'][fl[0]['path'].split('/')[0]]
            fh.write(f"# {post['title']}\n\n- Fonte: blog da Wazuh — [{post['title']}]({post['url']})\n- Publicado: {post['published']}"
                     f"{' (atualizado ' + post['modified'] + ')' if post['modified'] and post['modified'] != post['published'] else ''}\n"
                     f"- Captura: {s['retrieved']} (`snapshots/wazuh-blog/{fl[0]['path'].split('/')[0]}/`)\n"
                     f"- Direitos: conteúdo © Wazuh, Inc., reproduzido sem alterações a partir do artigo citado\n- Área: {area} / {topic}\n\n"
                     f"## Blocos de código do artigo (ficheiro capturado → caminho aqui)\n\n")
        else:
            fh.write(f"# {s['repo']}\n\n- Origem: {s['url']}\n- Commit: `{s['commit']}` ({s['last_commit']})\n"
                     f"- Licença: {s['license']}\n- Área: {area} / {topic}\n\n## Ficheiros (caminho original → caminho aqui)\n\n")
        for f in fl:
            fh.write(f"- `{f['path']}` → `{os.path.relpath(f['dest'], fo)}` "
                     f"({len(f['rules'])} regras, {len(f['decoders'])} decoders{'' if f['wellformed'] else ', XML tolerado pelo Wazuh mas não estrito'})\n")
        for rel, origin in sorted(list_copies[fo].items()):
            fh.write(f"- `{origin}` → `lists/{rel}` (lista CDB)\n")
        for rel, mode, ents, bl in coll_files[fo]:
            fh.write(f"- `{rel}` → `collection/{rel}{'' if mode == 'cópia' else '.extracted.xml'}` "
                     f"({'cópia' if mode == 'cópia' else 'blocos extraídos'}: {len(ents)} entradas de recolha)\n")
        for rel in sorted(resp_copies[fo]):
            fh.write(f"- `{rel.removesuffix('.extracted.xml')}` → `response/{rel}` "
                     f"({'blocos de resposta extraídos' if rel.endswith('.extracted.xml') else 'script de resposta'})\n")
        if folder_tests[fo]:
            fh.write(f"\n## Testes da fonte ({len(folder_tests[fo])} ficheiros em `tests/`, caminhos originais preservados)\n")
        others = [x for x in src_folders[s['repo']] if x != fo]
        if others:
            fh.write("\n## Outras partes desta fonte\n\n" + ''.join(f"- `{x}`\n" for x in others))

# ---------- catálogo
cat = os.path.join(OUT, 'catalog'); os.makedirs(cat)
for n, b in kept.items(): open(os.path.join(cat, n), 'wb').write(b)
def wcsv(name, rows, cols):
    with open(os.path.join(cat, name), 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction='ignore'); w.writeheader(); w.writerows(rows)

fold_id_count = {fo: Counter(r['id'] for f in fl for r in f['rules']) for fo, fl in placed.items()}
def is_catchall(r):
    """Filho sem nenhuma condição própria (nem correlação): apanha todos os eventos do pai e silencia os irmãos seguintes."""
    return bool(r['if_sid'] or r['if_group']) and not r['n_conds'] and not r['correlation']
att_active, att_replaced = mitre.load(os.path.join(OFF, 'mitre', 'enterprise-attack.json'))
for f in files:
    for r in f['rules']:
        r['mitre_norm'], r['mitre_status'] = mitre.normalize(r['mitre'], r['groups'], att_active, att_replaced)
rule_rows, dec_rows = [], []
for f in files:
    for r in f['rules']:
        rule_rows.append({**r, 'groups': ','.join(r['groups']), 'mitre': ','.join(r['mitre']), 'lists': ','.join(r['lists']),
                          'channels': ';'.join(r['channels']), 'mitre_norm': ','.join(r['mitre_norm']),
                          'area': f['area'], 'topic': f['topic'], 'source': f['repo'], 'file': f['dest'],
                          'conflict': conflict_type.get(r['id'], ''), 'dup_in_folder': fold_id_count[f['folder']][r['id']] > 1,
                          'catchall': is_catchall(r)})
    for d in f['decoders']:
        dec_rows.append({**d, 'fields': ','.join(d['fields']), 'regex_types': ','.join(d['regex_types']), 'root': not d['parent'],
                         'folder': f['folder'], 'area': f['area'], 'topic': f['topic'], 'source': f['repo'], 'file': f['dest'],
                         'official_name_clash': d['name'] in off_dec_names})
h2src = defaultdict(set)
for r in rule_rows: h2src[r['hash']].add(r['source'])
for r in rule_rows: r['same_rule_in'] = ';'.join(sorted(h2src[r['hash']] - {r['source']}))
wcsv('rules.csv', rule_rows, ['id', 'level', 'description', 'mitre', 'mitre_norm', 'mitre_status', 'groups', 'if_sid', 'if_group', 'decoded_as', 'lists', 'channels',
                              'frequency', 'overwrite', 'n_conds', 'catchall', 'area', 'topic', 'source', 'file', 'conflict', 'dup_in_folder', 'same_rule_in', 'hash'])
wcsv('decoders.csv', dec_rows, ['name', 'parent', 'root', 'ident', 'plugin', 'regex_types', 'fields', 'official_name_clash', 'area', 'topic',
                                'source', 'file', 'hash'])

# ---------- decoders: colisões de nomes de raiz entre fontes e mapa de campos para ECS
root_folders = defaultdict(set)
for d in dec_rows:
    if d['root']: root_folders[d['name']].add(d['folder'])
dcol_rows = [{'name': n, 'official': n in off_dec_names, 'folders': len(fs), 'sources': ';'.join(sorted({repo_of_folder[x] for x in fs})),
              'in': ';'.join(sorted(fs)),
              'effect': 'também existe no oficial: o oficial é carregado primeiro e apanha os logs que ambos reconhecem' if n in off_dec_names
                        else 'carregadas juntas, as raízes ficam ambas ativas mas os filhos dos dois ligam-se ao mesmo nome: o primeiro carregado que corresponder extrai os campos e o outro pack perde os seus'}
             for n, fs in sorted(root_folders.items()) if len({repo_of_folder[x] for x in fs}) > 1 or n in off_dec_names]
wcsv('decoder_collisions.csv', dcol_rows, ['name', 'official', 'folders', 'sources', 'effect', 'in'])
fcount, ffold = Counter(), defaultdict(set)
for d in dec_rows:
    for x in d['fields'].split(','):
        if x: fcount[x] += 1; ffold[x].add(d['folder'])
field_rows = [{'field': k, 'uses': n, 'folders': len(ffold[k]), 'static': k in fld.STATIC, 'normalized_key': fld.key(k), 'ecs': fld.ecs(k)}
              for k, n in sorted(fcount.items(), key=lambda x: (-x[1], x[0]))]
wcsv('decoder_fields.csv', field_rows, ['field', 'uses', 'folders', 'static', 'normalized_key', 'ecs'])

# ---------- regras irmãs: filhos do mesmo pai. Comportamento medido no wazuh-analysisd 4.14.8: os irmãos de NÍVEL 0 são
# avaliados primeiro, depois os outros por nível decrescente; em empate, pela ordem de carregamento, que é a ordem do NOME DO
# FICHEIRO em todo o conjunto (oficiais e etc/rules misturados; os packs instalados pela página têm prefixo alfabético e
# carregam depois dos oficiais). O primeiro que corresponder fica com o evento. Um irmão sem condições próprias ("apanha-tudo")
# corresponde sempre e silencia todos os que vêm depois dele nessa ordem — incluindo regras OFICIAIS, com a pasta sozinha.
# Um apanha-tudo de nível 0 é avaliado antes de todas as irmãs com alerta.
def lvl(r): return int(r['level']) if (r['level'] or '').isdigit() else 0
def ek(r): return (0 if lvl(r) == 0 else 1, -lvl(r))   # ordem de avaliação, sem a ordem de carregamento
# if_group: o motor pendura a regra como filha de TODAS as regras cujos grupos correspondem (OS_Match, sem distinguir
# maiúsculas; os grupos incluem os <group name> envolventes). Verificado em tools/model_checks.py (issue #1: a 40112,
# if_group authentication_success, é irmã de qualquer filha da 5715). Um padrão 'a,b' exige os dois grupos; '|' alterna.
def group_match(pat, groups):
    gs = ','.join(groups).lower()
    return any(all(tok in gs for tok in alt.strip('^$').lower().split(',') if tok) for alt in pat.split('|') if alt.strip())
_gp = {}
def group_parents(pat):   # regras oficiais com grupos correspondentes
    if pat not in _gp: _gp[pat] = [rid for rid, o in off_rule.items() if group_match(pat, o['groups'])]
    return _gp[pat]
off_children = defaultdict(list)   # pai -> regras oficiais filhas
for rid, r in off_rule.items():
    for p_ in split_ids(r['if_sid']): off_children[('if_sid', p_)].append(r)
    for g in [x.strip() for x in r['if_group'].split(',') if x.strip()]: off_children[('if_group', g)].append(r)
    if r['parent_group'] and not r['parent_sid']:
        for p_ in group_parents(r['parent_group']):
            if p_ != rid: off_children[('if_sid', p_)].append(r)
sib = defaultdict(lambda: defaultdict(list))   # pai -> pasta -> regras filhas
for f in files:
    for r in f['rules']:
        for p_ in split_ids(r['if_sid']): sib[('if_sid', p_)][f['folder']].append(r)
        for g in [x.strip() for x in r['if_group'].split(',') if x.strip()]: sib[('if_group', g)][f['folder']].append(r)
sib_rows, silences_official = [], []
sib_keys, ca_keys, sil_pairs = set(), set(), set()
for (kind, parent), by_fo in sorted(sib.items()):
    srcs = {repo_of_folder[fo] for fo in by_fo}
    offk = off_children.get((kind, parent), [])
    # o oficial carrega antes do pack: em empate é avaliado primeiro
    def off_dominates(r): return any(is_catchall(o) and ek(o) <= ek(r) for o in offk if o['id'] != r['id'])
    for fo, rs in by_fo.items() if kind == 'if_sid' else ():   # if_group: resolvido abaixo, pai a pai
        for r in rs:
            if not is_catchall(r) or off_dominates(r): continue
            lost = [o for o in offk if o['id'] != r['id'] and ek(o) > ek(r)]
            if r['overwrite'] and r['id'] in off_rule and is_catchall(off_rule[r['id']]):   # já silenciava: só conta o que é novo
                lost = [o for o in lost if not ek(o) > ek(off_rule[r['id']])]
            if lost: silences_official.append({'rule': r['id'], 'level': lvl(r), 'parent': f'{kind} {parent}', 'folder': fo,
                                               'official_silenced': len(lost), 'silenced_ids': ';'.join(sorted(o['id'] for o in lost)),
                                               'silenced_alerting': sum(1 for o in lost if lvl(o) > 0),
                                               'examples': '; '.join(f"{o['id']} (nível {o['level']}): {o['description'][:60]}" for o in sorted(lost, key=lvl, reverse=True)[:5])})
    if kind == 'if_group':
        for fo, rs in by_fo.items():
            for r in rs:
                if not is_catchall(r) or not r['parent_group'] or r['parent_sid']: continue
                lost = {}
                for p_ in group_parents(r['parent_group']):
                    sib_off = off_children.get(('if_sid', p_), [])
                    if any(is_catchall(o) and ek(o) <= ek(r) for o in sib_off if o['id'] != r['id']): continue
                    for o in sib_off:
                        if o['id'] != r['id'] and ek(o) > ek(r): lost[o['id']] = o
                if lost: silences_official.append({'rule': r['id'], 'level': lvl(r), 'parent': f'if_group {parent} ({len(group_parents(r["parent_group"]))} pais)', 'folder': fo,
                                                   'official_silenced': len(lost), 'silenced_ids': ';'.join(sorted(lost)),
                                                   'silenced_alerting': sum(1 for o in lost.values() if lvl(o) > 0),
                                                   'examples': '; '.join(f"{o['id']} (nível {o['level']}): {o['description'][:60]}" for o in sorted(lost.values(), key=lvl, reverse=True)[:5])})
    if len(srcs) < 2: continue
    if kind == 'if_sid':
        owners = {repo_of_folder[fo] for fo in id_folders.get(parent, ())}
        owner = 'oficial' if parent in off_rule_ids else ('comunidade' if owners else 'inexistente')
        # o mesmo ID de pai definido com conteúdo diferente em várias fontes: ao juntar pastas, o filho pode ficar pendurado no pai errado
        ambiguous = parent not in off_rule_ids and conflict_type.get(parent) == 'comunidade'
    else:
        owner, ambiguous = ('oficial' if parent in {g for r in off_rule.values() for g in r['groups']} else 'comunidade'), False
    rules_ = [r for rs in by_fo.values() for r in rs]
    cas = {fo: [r for r in rs if is_catchall(r)] for fo, rs in by_fo.items()}
    # apanha-tudo que nunca chega a ser avaliado: um apanha-tudo oficial antes dele, ou de outra pasta estritamente antes
    dominated = [f"{fo}: {r['id']}@{lvl(r)}" for fo, rs in sorted(cas.items()) for r in rs
                 if off_dominates(r) or any(ek(c) < ek(r) for o, cs in cas.items() if o != fo for c in cs)]
    sib_keys.update((fo, r['id']) for fo, rs in by_fo.items() for r in rs)
    ca_keys.update((fo, r['id']) for fo, rs in cas.items() for r in rs)
    for fo, cs in cas.items():   # pares de pastas de fontes diferentes em que um apanha-tudo de uma silencia filhos da outra
        for c in cs:
            for fo2, rs2 in by_fo.items():
                if repo_of_folder[fo2] != repo_of_folder[fo] and any(ek(x) >= ek(c) for x in rs2): sil_pairs.add(tuple(sorted((fo, fo2))))
    sib_rows.append({'parent': parent, 'kind': kind, 'owner': owner, 'ambiguous_parent': ambiguous,
                     'folders': len(by_fo), 'sources': len(srcs), 'rules': len(rules_),
                     'catchall_rules': sum(len(cs) for cs in cas.values()),
                     'catchall_folders': ';'.join(sorted(fo for fo, cs in cas.items() if cs)),
                     'children': ' | '.join(f"{fo}: {','.join(sorted({r['id'] + '@' + str(lvl(r)) + ('*' if is_catchall(r) else '') for r in rs}))}"
                                            for fo, rs in sorted(by_fo.items())),
                     'official_children': ','.join(sorted({o['id'] + '@' + str(lvl(o)) + ('*' if is_catchall(o) else '') for o in offk})),
                     'dominated_catchalls': ' | '.join(dominated)})
# sombra condicional: uma irmã oficial avaliada antes (nível 0, nível superior, ou igual — o oficial carrega primeiro) cujas
# condições dependem do contexto (correlação, horário, primeira vez) e não do conteúdo: nessas situações fica com o evento
# e a regra do pack não alerta; o wazuh-analysisd -t não avisa (issue #1: 40112 face a uma filha de 5715)
cond_rows = []
for f in files:
    for r in f['rules']:
        if lvl(r) == 0: continue
        seen = set()
        for p_ in split_ids(r['parent_sid']) or [x for x in group_parents(r['parent_group']) if r['parent_group']][:50]:
            for o in off_children.get(('if_sid', p_), []):
                if o['id'] in seen or o['id'] == r['id'] or not o['context'] or ek(o) > ek(r): continue
                seen.add(o['id'])
                cond_rows.append({'rule': r['id'], 'level': lvl(r), 'folder': f['folder'], 'parent': p_, 'official_rule': o['id'],
                                  'official_level': lvl(o), 'condition': o['context'], 'official_description': o['description'][:100]})
cond_rows.sort(key=lambda x: (x['folder'], int(x['rule']) if x['rule'].isdigit() else 0, x['official_rule']))
wcsv('conditional_shadows.csv', cond_rows, ['rule', 'level', 'folder', 'parent', 'official_rule', 'official_level', 'condition', 'official_description'])
sib_rows.sort(key=lambda r: (-r['folders'], r['kind'], r['parent']))
wcsv('catchall_silences_official.csv', sorted(silences_official, key=lambda r: (-r['official_silenced'], r['folder'], r['rule'])),
     ['rule', 'level', 'parent', 'folder', 'official_silenced', 'silenced_alerting', 'silenced_ids', 'examples'])
wcsv('sibling_parents.csv', sib_rows, ['parent', 'kind', 'owner', 'ambiguous_parent', 'folders', 'sources', 'rules', 'catchall_rules',
                                       'catchall_folders', 'children', 'official_children', 'dominated_catchalls'])
wcsv('id_conflicts.csv', sorted(conflicts, key=lambda c: int(c['id']) if c['id'].isdigit() else 0),
     ['id', 'type', 'official_id', 'n_sources', 'n_variants', 'sources'])
wcsv('dependencies.csv', deps, ['kind', 'missing', 'status', 'found_in', 'rule_id', 'repo', 'folder', 'file'])
wcsv('lists.csv', list_rows, ['list', 'status', 'origin_path', 'rules', 'source', 'folder'])
wcsv('excluded.csv', [{'repo': e['repo'], 'path': e['path'], 'reason': e['why'], 'rules': len(e['rules']),
                       'decoders': len(e['decoders'])} for e in excluded] +
     [{'repo': d['repo'], 'path': d['path'], 'reason': f"duplicado byte-a-byte de {o['repo']}:{o['path']} (introduzido {o['introduced']}; este {d['introduced']})",
       'rules': len(d['rules']), 'decoders': len(d['decoders'])} for d, o in sorted(dups, key=lambda x: (x[0]['repo'], x[0]['path']))],
     ['repo', 'path', 'reason', 'rules', 'decoders'])

# ---------- sobreposição com o ruleset oficial
overwriters = defaultdict(set)   # id oficial -> fontes que o reescrevem
for f in files:
    for r in f['rules']:
        if r['overwrite'] and r['id'] in off_rule: overwriters[r['id']].add(f['repo'])
ov_rows = []
for f in files:
    for r in f['rules']:
        o = off_rule.get(r['id'])
        if o:
            ch = [k for k in ('if_sid', 'if_group', 'decoded_as') if r[k] != o[k]]
            if not r['overwrite']:
                kind, action = 'colisão (sem overwrite)', 'remover ou renumerar: só uma definição do mesmo ID fica ativa'
            elif ch:
                kind, action = 'overwrite estrutural (' + ','.join(ch) + ')', 'rever: altera a cadeia da regra oficial'
            elif r['level'] != o['level']:
                kind, action = f"overwrite de nível ({o['level']}→{r['level']})", 'aceitável; decidir se é para manter'
            else:
                kind, action = 'overwrite com mesma cadeia e nível', 'rever diferenças em match/field/descrição/MITRE'
            others = overwriters[r['id']] - {f['repo']}
            if r['overwrite'] and others and conflict_type.get(r['id']) == 'oficial: overwrite por várias fontes':
                action += '; outra fonte também reescreve este ID de forma diferente: carregar as duas faz valer a última'
            ov_rows.append({'id': r['id'], 'type': kind, 'action': action, 'official_file': o['file'],
                            'official_description': o['description'], 'description': r['description'],
                            'other_overwriters': ';'.join(sorted(others)), 'source': f['repo'], 'file': f['dest']})
        elif r['overwrite']:
            ov_rows.append({'id': r['id'], 'type': 'overwrite de ID inexistente no oficial', 'action': 'retirar overwrite="yes"',
                            'official_file': '', 'official_description': '', 'description': r['description'],
                            'other_overwriters': '', 'source': f['repo'], 'file': f['dest']})
wcsv('official_overlap.csv', sorted(ov_rows, key=lambda x: (x['source'], int(x['id']) if x['id'].isdigit() else 0, x['file'])),
     ['id', 'type', 'action', 'official_file', 'official_description', 'description', 'other_overwriters', 'source', 'file'])

# Decoders com o nome de um oficial somam-se aos oficiais (irmãos); só um ficheiro com o mesmo nome de um oficial é, por
# convenção, uma cópia modificada que exige <decoder_exclude>. A necessidade real é medida por tools/validate.py.
rep = defaultdict(lambda: {'names': set(), 'official': set(), 'same_file': False})
off_dec_files = set(os.listdir(os.path.join(OFF, 'decoders')))
for f in files:
    if f['decoders'] and os.path.basename(f['path']) in off_dec_files:
        k = (f['repo'], f['dest']); rep[k]['official'].add(os.path.basename(f['path'])); rep[k]['same_file'] = True
    for d in f['decoders']:
        if d['name'] in off_dec_file:
            k = (f['repo'], f['dest']); rep[k]['names'].add(d['name']); rep[k]['official'] |= off_dec_file[d['name']]
wcsv('decoder_replacements.csv', [{'source': k[0], 'file': k[1], 'kind': 'mesmo nome de ficheiro' if v['same_file'] else 'redefine nomes oficiais',
                                   'official_files': ';'.join(sorted(v['official'])), 'decoder_names': ';'.join(sorted(v['names'])),
                                   'ossec_conf': ' '.join(f'<decoder_exclude>ruleset/decoders/{o}</decoder_exclude>' for o in sorted(v['official']))}
                                  for k, v in sorted(rep.items())],
     ['source', 'file', 'kind', 'official_files', 'decoder_names', 'ossec_conf'])

# ---------- pastas: cada pasta de fonte carrega sozinha?
fold_rows = []
for fo, fl in sorted(placed.items()):
    fd = [d for d in deps if d['folder'] == fo]
    cnt = fold_id_count[fo]
    s_ = sources[fl[0]['repo']]
    origin_url = s_['posts'][fl[0]['path'].split('/')[0]]['url'] if s_.get('snapshot') else s_['url']
    row = {'folder': fo, 'source': fl[0]['repo'], 'origin_url': origin_url, 'area': fl[0]['area'], 'topic': fl[0]['topic'], 'files': len(fl),
           'rules': sum(cnt.values()), 'decoders': sum(len(f['decoders']) for f in fl),
           'dup_ids': sum(1 for c in cnt.values() if c > 1), 'dup_entries': sum(c - 1 for c in cnt.values() if c > 1),
           'official_clashes': sum(1 for i in cnt if conflict_type.get(i) == 'oficial: colisão sem overwrite'),
           'deps_same_source': sum(1 for d in fd if d['status'] == 'noutra pasta da mesma fonte'),
           'deps_other_source': sum(1 for d in fd if d['status'] == 'noutra fonte do pack'),
           'deps_missing': sum(1 for d in fd if d['status'] == 'em falta' and d['kind'] != 'cdb_list'),
           'lists_copied': len(list_copies[fo]), 'lists_missing': sum(1 for d in fd if d['kind'] == 'cdb_list'),
           'tests': len(folder_tests[fo])}
    row['standalone'] = not any(row[k] for k in ('dup_ids', 'official_clashes', 'deps_same_source', 'deps_other_source', 'deps_missing', 'lists_missing'))
    fold_rows.append(row)
wcsv('folders.csv', fold_rows, list(fold_rows[0].keys()))

# ---------- requisitos de recolha por pasta e grupos de agentes-modelo
id_fam, grp_fam, dec_fam = col.official_index(OFF, parse_file)
coll_rows, entry_rows = [], []
groups = defaultdict(dict)          # grupo -> {chave: entrada}
group_folders = defaultdict(set); group_origin = defaultdict(set)
ENTRY_COLS = ['folder', 'source', 'origin', 'side', 'kind', 'os', 'log_format', 'location', 'name', 'command', 'query', 'placeholder',
              'incomplete', 'malformed', 'group']

def mgr_label(e):
    return f"{e['kind']} {e.get('name') or e.get('location')}"

folder_inputs = {}
for fo, fl in sorted(placed.items()):
    fams = col.folder_families(fl, id_fam, grp_fam, dec_fam)
    inferred, default, undefined, needs_json = [], set(), [], False
    for fam, n in sorted(fams.items()):
        req = col.requirement(fam)
        if req is None: undefined.append(f'família oficial {fam} ({n} regras)')
        elif req['side'] == 'default': default.add(fam)
        elif req['side'] == 'json': needs_json = True
        elif req['side'] != 'internal': inferred.append(({**req}, f'inferido: família {fam}'))
    for ch in sorted({c for f in fl for r in f['rules'] for c in r['channels']}):
        if ch in col.DEFAULT_CHANNELS: default.add(f'canal {ch}')
        else: inferred.append((col.EC(ch), 'inferido: win.system.channel'))
    roots = col.own_roots(fl, off_dec_names)
    declared = [(e, rel) for rel, mode, ents, bl in coll_files[fo] for e in ents]
    if (needs_json or 'json' in roots) and not any(e['kind'] == 'localfile' and e.get('log_format') == 'json' for e, _ in declared):
        undefined.append('eventos JSON: definir o <localfile> json com a localização do ficheiro')
    if 'texto' in roots and not declared and not any(e['side'] == 'manager' for e, _ in inferred):
        if fl[0]['area'] in col.SYSLOG_AREAS: inferred.append((col.REMOTE_SYSLOG, 'inferido: decoders próprios de um equipamento de rede/infra'))
        else: undefined.append('decoders próprios de texto: definir <localfile> ou <remote> syslog')
    folder_inputs[fo] = (fams, inferred, declared, default, undefined)

def groupable(e):
    return (e['side'] == 'agent' and not e.get('placeholder') and not e.get('incomplete') and not e.get('malformed')
            and e.get('name') not in col.DEFAULT_WODLES
            and not (e.get('log_format') == 'eventchannel' and e.get('location') in col.DEFAULT_CHANNELS))
# canais usados por duas ou mais pastas têm grupo próprio; os de um só pack ficam no pack-<tópico>
chan_folders = defaultdict(set)
for fo, (fams, inferred, declared, default, undefined) in folder_inputs.items():
    for e, _ in inferred + declared:
        if groupable(e) and e.get('log_format') == 'eventchannel': chan_folders[e['location']].add(fo)
shared_channels = {ch for ch, fs in chan_folders.items() if len(fs) > 1}

for fo, (fams, inferred, declared, default, undefined) in sorted(folder_inputs.items()):
    topic, repo = placed[fo][0]['topic'], placed[fo][0]['repo']
    agent_groups, manager, seen = set(), set(), set()
    for e, origin in inferred + declared:
        k = col.entry_key(e)
        if (k, origin) in seen: continue
        seen.add((k, origin))
        g = ''
        if e['side'] == 'manager':
            manager.add(mgr_label(e))
        elif groupable(e):
            g = col.group_name(e, topic, shared_channels)
            groups[g].setdefault(k, e); group_folders[g].add(fo)
            group_origin[g].add('inferido' if origin.startswith('inferido') else 'declarado pela fonte')
            agent_groups.add(g)
        entry_rows.append({**e, 'folder': fo, 'source': repo, 'origin': origin, 'group': g})
    coll_rows.append({'folder': fo, 'source': repo,
                      'families': ';'.join(f'{k}:{v}' for k, v in sorted(fams.items(), key=lambda x: (-x[1], x[0]))),
                      'default_inputs': ';'.join(sorted(default)), 'agent_groups': ';'.join(sorted(agent_groups)),
                      'manager_requirements': ';'.join(sorted(manager)), 'undefined': ';'.join(undefined),
                      'declared_files': len(coll_files[fo]), 'declared_entries': len(declared),
                      'declared_placeholders': sum(1 for e, _ in declared if e.get('placeholder')),
                      'declared_incomplete': sum(1 for e, _ in declared if e.get('incomplete') or e.get('malformed'))})
for repo, rel, ents in unassigned:
    for e in ents: entry_rows.append({**e, 'folder': '', 'source': repo, 'origin': rel, 'group': ''})
wcsv('collection.csv', coll_rows, list(coll_rows[0].keys()))
wcsv('collection_entries.csv', entry_rows, ENTRY_COLS)

group_rows = []
for g in sorted(groups):
    ents = col.merge(groups[g].values())
    d = os.path.join(OUT, 'groups', g); os.makedirs(d)
    open(os.path.join(d, 'agent.conf'), 'w').write(col.render_group(g, ents))
    group_rows.append({'group': g, 'os': ';'.join(sorted({e.get('os') or 'qualquer' for e in ents})), 'entries': len(ents),
                       'origin': ';'.join(sorted(group_origin[g])), 'folders': len(group_folders[g]),
                       'sources': ';'.join(sorted({repo_of_folder[x] for x in group_folders[g]})),
                       'serves': ';'.join(sorted(group_folders[g]))})
wcsv('groups.csv', group_rows, ['group', 'os', 'entries', 'origin', 'folders', 'sources', 'serves'])

# ---------- resposta e playbooks: cobertura por técnica e por pasta
wcsv('responses.csv', resp_rows, ['source', 'license', 'kind', 'name', 'script', 'action', 'impact', 'trigger', 'location', 'timeout',
                                  'allowlist', 'status', 'problems', 'warnings', 'folders', 'file', 'copied'])
pb_rows = []
for lib in sorted(pb.LIBS):
    ldir = os.path.join(PBK, lib.replace('/', '_'))
    if not os.path.isdir(ldir): continue
    for doc in pb.docs(ldir, lib, git(ldir, 'rev-parse', 'HEAD')):
        techs = sorted({x for x in (tt if tt in att_active else att_replaced.get(tt) for tt in doc['techniques']) if x})
        pb_rows.append({**doc, 'techniques': techs})
wcsv('playbooks.csv', [{**r, 'techniques': ','.join(r['techniques']), 'rule_ids': ','.join(r['rule_ids']),
                        'sca_checks': ','.join(r['sca_checks'])} for r in pb_rows],
     ['library', 'kind', 'doc_id', 'title', 'techniques', 'rule_ids', 'sca_checks', 'automatable', 'url'])
PROC = lambda r: r['kind'].startswith('procedimental')
CONTAINMENT = ('destrutivo', 'contenção reversível')
def docs_for(tech):
    """Documentos que cobrem a técnica: os da própria técnica e os da técnica-mãe (T1059 cobre T1059.001)."""
    return [r for r in pb_rows if tech in r['techniques'] or tech.split('.')[0] in r['techniques']]
rule_doc = defaultdict(list)
for r in pb_rows:
    for i in r['rule_ids']: rule_doc[i].append(r)

resp_techs = []
for row in resp_rows:
    ts = set()
    for fo in [x for x in row['folders'].split(';') if x]:
        for f in placed[fo]:
            for r in f['rules']:
                if r['id'] in row['rules'] or set(row['groups_']) & set(r['groups']): ts |= set(r['mitre_norm'])
    resp_techs.append(ts)
tech_rows, tech_idx = [], defaultdict(list)
for f in files:
    for r in f['rules']:
        for tt in r['mitre_norm']: tech_idx[tt].append((f, r))
for tt in sorted(tech_idx):
    lst = tech_idx[tt]; d = docs_for(tt)
    ok = sum(1 for row, ts in zip(resp_rows, resp_techs) if tt in ts and row['status'] == 'ok')
    contain = sum(1 for row, ts in zip(resp_rows, resp_techs) if tt in ts and row['status'] == 'ok' and row['impact'] in CONTAINMENT)
    hi = sum(1 for f, r in lst if (r['level'] or '0').isdigit() and int(r['level']) >= 12)
    procs, cms = [x for x in d if PROC(x)], [x for x in d if x['kind'].startswith('contramedida')]
    gaps = [g for g, cond in (('sem playbook', not procs), ('sem contramedida', not cms), ('sem contenção automática', not contain)) if cond]
    tech_rows.append({'technique': tt, 'name': att_active[tt][0], 'tactics': ';'.join(att_active[tt][1]), 'rules': len(lst), 'rules_level12': hi,
                      'folders': len({f['folder'] for f, r in lst}), 'areas': ';'.join(sorted({f['area'] for f, r in lst})),
                      'playbooks': len(procs), 'countermeasures': len(cms), 'automations_ok': ok, 'containment_ok': contain, 'gaps': ';'.join(gaps),
                      'playbook_refs': ';'.join(sorted({f"{x['library'].split('/')[0]}:{x['doc_id']}" for x in procs}))})
# SigmaHQ: o que a comunidade Sigma deteta, por técnica, face ao registo
sig_dir = os.path.join(REFS, 'SigmaHQ_sigma')
sig_rows = sg.load(sig_dir, git(sig_dir, 'rev-parse', 'HEAD')) if os.path.isdir(sig_dir) else []
sig_by_tech = defaultdict(list)
for r in sig_rows:
    r['techniques'], _ = mitre.normalize([], r['tags'], att_active, att_replaced)
    for tt in r['techniques']: sig_by_tech[tt].append(r)
HIGH = ('high', 'critical')
for row in tech_rows:
    sr = sig_by_tech.get(row['technique'], [])
    row['sigma_rules'] = len(sr); row['sigma_high'] = sum(1 for r in sr if r['level'] in HIGH)
wcsv('technique_coverage.csv', tech_rows, list(tech_rows[0].keys()))
sc_rows = []
for tt in sorted(set(sig_by_tech) | set(tech_idx)):
    sr, reg = sig_by_tech.get(tt, []), tech_idx.get(tt, [])
    reg_hi = sum(1 for f, r in reg if (r['level'] or '0').isdigit() and int(r['level']) >= 12)
    hi = [r for r in sr if r['level'] in HIGH]
    status = ('só Sigma' if sr and not reg else 'só registo' if reg and not sr else
              'registo sem regras de nível ≥ 12' if hi and not reg_hi else 'ambos')
    top = sorted(sr, key=lambda r: (r['level'] not in HIGH, r['status'] != 'stable', r['title']))[:3]
    sc_rows.append({'technique': tt, 'name': att_active[tt][0], 'tactics': ';'.join(att_active[tt][1]), 'status': status,
                    'sigma_rules': len(sr), 'sigma_high': len(hi), 'sigma_stable': sum(1 for r in sr if r['status'] == 'stable'),
                    'sigma_logsources': ';'.join(f'{k}:{v}' for k, v in Counter(sg.logsource(r) for r in sr).most_common(3)),
                    'registry_rules': len(reg), 'registry_level12': reg_hi, 'registry_folders': len({f['folder'] for f, r in reg}),
                    'sigma_examples': ' | '.join(f"{r['level']}: {r['title']} <{r['url']}>" for r in top)})
wcsv('sigma_coverage.csv', sc_rows, list(sc_rows[0].keys()) if sc_rows else ['technique'])
tech_info = {r['technique']: r for r in tech_rows}
rc_rows = []
for fo, fl in sorted(placed.items()):
    ts = {tt for f in fl for r in f['rules'] for tt in r['mitre_norm']}
    rr = [row for row in resp_rows if fo in row['folders'].split(';')]
    rc_rows.append({'folder': fo, 'source': fl[0]['repo'], 'area': fl[0]['area'],
                    'rules': sum(len(f['rules']) for f in fl), 'rules_with_mitre': sum(1 for f in fl for r in f['rules'] if r['mitre_norm']),
                    'techniques': len(ts), 'techniques_with_playbook': sum(1 for x in ts if tech_info[x]['playbooks']),
                    'techniques_with_countermeasure': sum(1 for x in ts if tech_info[x]['countermeasures']),
                    'playbooks_by_rule_id': sum(1 for f in fl for r in f['rules'] if r['id'] in rule_doc),
                    'responses_ok': sum(1 for x in rr if x['status'] == 'ok'),
                    'containment_ok': sum(1 for x in rr if x['status'] == 'ok' and x['impact'] in CONTAINMENT), 'responses_broken': sum(1 for x in rr if x['status'] != 'ok'),
                    'responses_destructive_unsafe': sum(1 for x in rr if 'destrutivo sem allowlist' in x['warnings'])})
wcsv('response_coverage.csv', rc_rows, list(rc_rows[0].keys()))

# fontes + indicadores de qualidade
src_rows = []
for repo in sorted(set(sources) | set(failed)):
    s = sources.get(repo)
    if s is None:
        src_rows.append({'repo': repo, 'url': f'https://github.com/{repo}', 'status': 'clone falhou'}); continue
    fl = [f for f in files if f['repo'] == repo]
    rules = [r for f in fl for r in f['rules']]
    nd = sum(len(f['decoders']) for f in fl)
    if not rules and not nd:
        status = 'excluída' if any(e['repo'] == repo for e in excluded) else 'sem XML Wazuh'
    else:
        status = 'incluída'
    fr = [x for x in fold_rows if x['source'] == repo]
    mitre = sum(1 for r in rules if r['mitre'])
    age = (AS_OF - datetime.date.fromisoformat(s['last_commit'])).days if s['last_commit'] else None
    variants = defaultdict(set)
    for f in fl:
        for r in f['rules']: variants[(f['folder'], r['id'])].add(r['hash'])
    src_rows.append({'repo': repo, 'url': s['url'], 'commit': s['commit'][:12], 'last_commit': s['last_commit'],
                     'age_days': age, 'license': s['license'], 'has_tests': s['has_tests'], 'tests': len(s['tests']), 'status': status,
                     'files': len(fl), 'rules': len(rules), 'decoders': nd,
                     'mitre_pct': round(100 * mitre / len(rules)) if rules else '',
                     'wellformed_pct': round(100 * sum(f['wellformed'] for f in fl) / len(fl)) if fl else '',
                     'official_id_clashes': sum(1 for r in rules if conflict_type.get(r['id']) == 'oficial: colisão sem overwrite'),
                     'missing_deps': sum(x['deps_missing'] for x in fr),
                     'deps_other_folder': sum(x['deps_same_source'] + x['deps_other_source'] for x in fr),
                     'lists_missing': sum(x['lists_missing'] for x in fr),
                     'internal_dup_ids': sum(x['dup_ids'] for x in fr),
                     'internal_dup_variants': sum(1 for v in variants.values() if len(v) > 1),
                     'folders': len(fr), 'folders_standalone': sum(1 for x in fr if x['standalone']),
                     'id_range': (lambda ids: f"{min(ids)}-{max(ids)}" if ids else '')(sorted(int(r['id']) for r in rules if r['id'].isdigit())),
                     'areas': ';'.join(sorted({f['area'] for f in fl}))})
wcsv('sources.csv', src_rows, ['repo', 'url', 'commit', 'last_commit', 'age_days', 'license', 'has_tests', 'tests', 'status', 'files',
                               'rules', 'decoders', 'mitre_pct', 'wellformed_pct', 'official_id_clashes', 'missing_deps',
                               'deps_other_folder', 'lists_missing', 'internal_dup_ids', 'internal_dup_variants', 'folders',
                               'folders_standalone', 'id_range', 'areas'])

ctype = Counter(c['type'] for c in conflicts)
stats = {
    'generated': AS_OF.isoformat(), 'official_reference': 'wazuh/wazuh ' + (git(os.path.dirname(OFF.rstrip('/')), 'describe', '--tags') or '?') + ' ruleset',
    'sources_listed': len(listed), 'sources_cloned': len(sources), 'sources_failed': failed,
    'sources_included': sum(1 for s in src_rows if s['status'] == 'incluída'),
    'files': len(files), 'rules': len(rule_rows), 'decoders': len(dec_rows),
    'rule_entries_dup_in_folder': sum(x['dup_entries'] for x in fold_rows),
    'unique_rule_ids': len(by_id), 'id_conflicts': len(conflicts),
    'id_conflicts_community': ctype['comunidade'],
    'id_conflicts_official_collision': ctype['oficial: colisão sem overwrite'],
    'id_conflicts_official_multi_overwrite': ctype['oficial: overwrite por várias fontes'],
    'deps_missing': sum(1 for d in deps if d['status'] == 'em falta' and d['kind'] != 'cdb_list'),
    'deps_same_source_other_folder': sum(1 for d in deps if d['status'] == 'noutra pasta da mesma fonte'),
    'deps_cross_source': sum(1 for d in deps if d['status'] == 'noutra fonte do pack'),
    'cdb_lists': dict(Counter(r['status'] for r in list_rows)),
    'folders': len(fold_rows), 'folders_standalone': sum(1 for x in fold_rows if x['standalone']),
    'test_files_copied': sum(len(v) for v in folder_tests.values()),
    'excluded_files': len(excluded) + len(dups),
    'siblings': {'shared_parents': len(sib_rows), 'rules_involved': len(sib_keys),
                 'parents_with_catchall': sum(1 for r in sib_rows if r['catchall_rules']),
                 'non_ascii_condition_rules': sum(1 for f in files for r in f['rules'] if r.get('non_ascii')),
                 'conditional_shadows': len(cond_rows), 'conditional_shadow_rules': len({(x['folder'], x['rule']) for x in cond_rows}),
                 'conditional_shadow_folders': len({x['folder'] for x in cond_rows}),
                 'dominated_catchalls': sum(len(r['dominated_catchalls'].split(' | ')) for r in sib_rows if r['dominated_catchalls']),
                 'catchall_rules': len(ca_keys),
                 'ambiguous_parents': sum(1 for r in sib_rows if r['ambiguous_parent']),
                 'catchalls_silencing_official': len(silences_official),
                 'official_rules_silenced': len({x for r in silences_official for x in r['silenced_ids'].split(';')}),
                 'folders_silencing_official': len({r['folder'] for r in silences_official}),
                 'folder_pairs': len(sil_pairs)},
    'decoders_detail': {'roots': sum(1 for d in dec_rows if d['root']), 'children': sum(1 for d in dec_rows if not d['root']),
                        'root_collisions_between_sources': sum(1 for r in dcol_rows if int(r['folders']) > 1 and len(r['sources'].split(';')) > 1),
                        'root_names_also_official': sum(1 for r in dcol_rows if r['official'] == True),
                        'distinct_fields': len(field_rows), 'fields_with_ecs': sum(1 for r in field_rows if r['ecs']),
                        'field_uses_with_ecs_pct': round(100 * sum(r['uses'] for r in field_rows if r['ecs']) / max(1, sum(r['uses'] for r in field_rows))),
                        'regex_engines': dict(sorted(Counter(x for d in dec_rows for x in d['regex_types'].split(',') if x).items()))},
    'mitre': dict(sorted(Counter(r['mitre_status'] for f in files for r in f['rules']).items())),
    'response': {'definitions': len(resp_rows), 'by_status': dict(sorted(Counter(r['status'] for r in resp_rows).items())),
                 'by_kind': dict(sorted(Counter(r['kind'] for r in resp_rows).items())),
                 'destructive': sum(1 for r in resp_rows if r['impact'] == 'destrutivo'),
                 'destructive_without_allowlist': sum(1 for r in resp_rows if 'destrutivo sem allowlist' in r['warnings']),
                 'copied': sum(1 for r in resp_rows if r['copied']),
                 'playbook_docs': dict(sorted(Counter(f"{r['library']} — {r['kind']}" for r in pb_rows).items())),
                 'techniques': len(tech_rows), 'techniques_level12': sum(1 for r in tech_rows if r['rules_level12']),
                 'techniques_level12_without_playbook': sum(1 for r in tech_rows if r['rules_level12'] and not r['playbooks']),
                 'techniques_level12_without_countermeasure': sum(1 for r in tech_rows if r['rules_level12'] and not r['countermeasures']),
                 'techniques_level12_without_containment': sum(1 for r in tech_rows if r['rules_level12'] and not r['containment_ok'])},
    'sigma': {'rules': len(sig_rows), 'with_technique': sum(1 for r in sig_rows if r['techniques']),
              'commit': git(sig_dir, 'rev-parse', 'HEAD')[:12] if sig_rows else '',
              'techniques_sigma': len(sig_by_tech), 'techniques_registry': len(tech_idx),
              'by_status': dict(sorted(Counter(r['status'] for r in sc_rows).items())),
              'sigma_only_with_high': sum(1 for r in sc_rows if r['status'] == 'só Sigma' and r['sigma_high'])},
    'collection': {'folders_with_agent_groups': sum(1 for r in coll_rows if r['agent_groups']),
                   'folders_default_only': sum(1 for r in coll_rows if r['default_inputs'] and not r['agent_groups'] and not r['manager_requirements'] and not r['undefined']),
                   'folders_with_manager_requirements': sum(1 for r in coll_rows if r['manager_requirements']),
                   'folders_with_undefined': sum(1 for r in coll_rows if r['undefined']),
                   'declared_files': sum(r['declared_files'] for r in coll_rows), 'declared_entries': sum(r['declared_entries'] for r in coll_rows),
                   'unassigned_files': len(unassigned), 'groups': len(group_rows)},
    'official_overlap': dict(sorted(Counter(r['type'].split(' (')[0] for r in ov_rows).items())),
    'decoder_replacement_files': len(rep),
    'rules_outside_custom_range': sum(1 for r in rule_rows if r['id'].isdigit() and r['id'] not in off_rule_ids and not 100000 <= int(r['id']) <= 120000),
    'per_area': {ar: {'rules': sum(1 for r in rule_rows if r['area'] == ar), 'decoders': sum(1 for r in dec_rows if r['area'] == ar),
                      'sources': len({r['source'] for r in rule_rows + dec_rows if r['area'] == ar})} for ar in AREAS},
}
json.dump(stats, open(os.path.join(cat, 'stats.json'), 'w'), indent=1, ensure_ascii=False)

print(json.dumps({k: v for k, v in stats.items() if k != 'per_area'}, indent=1, ensure_ascii=False))
