#!/usr/bin/env python3
"""Testa decoders e regras de cada pasta com amostras de log reais, no wazuh-logtest de um wazuh-manager em Docker.

Uso: python3 tools/logtest.py [--image wazuh/wazuh-manager:4.14.8] [--only <regex de pasta>]

Amostras (por pasta):
  - tests/**/*.ini no formato oficial da Wazuh (log N pass/fail, rule, alert, decoder): verifica regra, nível e decoder;
  - tests/**/*.log|*.txt: cada linha; 'trigger' no nome = tem de disparar uma regra da pasta, 'benign' = não pode;
  - exemplos de log nos comentários dos decoders: têm de ser descodificados por um decoder da pasta.
Só se testam pastas que carregam (catalog/validation.csv). Escreve catalog/decoder_tests.csv e catalog/decoder_test_summary.csv.
"""
import os, re, csv, json, glob, argparse, subprocess, tempfile, configparser, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
stats = json.load(open(os.path.join(ROOT, 'catalog/stats.json')))
ap = argparse.ArgumentParser()
ap.add_argument('--image', default='wazuh/wazuh-manager:' + stats['official_reference'].split()[1].lstrip('v'))
ap.add_argument('--only', default='')
a = ap.parse_args()
NAME = 'wcr-logtest'
MAX_SAMPLES = 400   # por pasta

LOG_RE = re.compile(r'^\s*(<\d{1,3}>)?\s*((\w{3}\s+\d{1,2}\s\d\d:\d\d:\d\d)|(\d{4}-\d\d-\d\d[T ]\d\d:\d\d)|(\{".{20,})|(.*CEF:\d\|)|'
                    r'(.*\bdate=\d{4}-\d\d-\d\d.*\btime=)|(.*\blogver=)|(type=\w+ msg=audit\())')
PLACEHOLDER = re.compile(r'<[a-z_]{1,12}>|X{2}:X{2}|\.\.\.$')

def comment_samples(path):
    raw = open(path, errors='ignore').read()
    for c in re.findall(r'<!--(.*?)-->', raw, re.S):
        for line in c.splitlines():
            line = re.sub(r'^\s*(?:(?:log|sample|example|exemplo|ejemplo)s?\s*\d*\s*:)\s*', '', line.strip(), flags=re.I)
            if len(line) > 25 and LOG_RE.match(line) and not PLACEHOLDER.search(line):
                yield line

def ini_samples(path):
    cp = configparser.RawConfigParser(strict=False, delimiters=('=',), comment_prefixes=(';', '#'), inline_comment_prefixes=None)
    cp.optionxform = str
    try: cp.read_string(open(path, errors='ignore').read())
    except configparser.Error: return
    for sec in cp.sections():
        o = dict(cp.items(sec))
        for k, v in o.items():
            m = re.match(r'log \d+ (pass|fail)$', k)
            if m: yield v, {'kind': 'ini-' + m.group(1), 'rule': o.get('rule', ''), 'alert': o.get('alert', ''), 'decoder': o.get('decoder', ''), 'case': sec}

def samples(folder):
    out = []
    for p in sorted(glob.glob(os.path.join(ROOT, folder, 'tests', '**', '*.ini'), recursive=True)):
        out += [(log, exp, os.path.relpath(p, os.path.join(ROOT, folder))) for log, exp in ini_samples(p)]
    for p in sorted(glob.glob(os.path.join(ROOT, folder, 'tests', '**', '*'), recursive=True)):
        if not p.endswith(('.log', '.txt')) or not os.path.isfile(p): continue
        kind = 'trigger' if 'trigger' in os.path.basename(p) else 'benign' if 'benign' in os.path.basename(p) else 'descodifica'
        for line in open(p, errors='ignore'):
            if line.strip() and not line.startswith('#'):
                out.append((line.rstrip('\n'), {'kind': kind}, os.path.relpath(p, os.path.join(ROOT, folder))))
    for p in sorted(glob.glob(os.path.join(ROOT, folder, 'decoders', '*.xml'))):
        out += [(s, {'kind': 'comentário'}, os.path.relpath(p, os.path.join(ROOT, folder))) for s in comment_samples(p)]
    seen, uniq = set(), []
    for s in out:
        if s[0] not in seen: seen.add(s[0]); uniq.append(s)
    return uniq[:MAX_SAMPLES]

val = {r['folder']: r for r in csv.DictReader(open(os.path.join(ROOT, 'catalog/validation.csv')))}
excl = {}
for r in csv.DictReader(open(os.path.join(ROOT, 'catalog/decoder_replacements.csv'))):
    excl.setdefault(os.path.join(*r['file'].split('/')[:4]), set()).update(r['official_files'].split(';'))
rules_by_folder, decs_by_folder = collections.defaultdict(set), collections.defaultdict(set)
for r in csv.DictReader(open(os.path.join(ROOT, 'catalog/rules.csv'))): rules_by_folder[os.path.join(*r['file'].split('/')[:4])].add(r['id'])
for r in csv.DictReader(open(os.path.join(ROOT, 'catalog/decoders.csv'))): decs_by_folder[os.path.join(*r['file'].split('/')[:4])].add(r['name'])

plan = []
for fo, v in sorted(val.items()):
    if a.only and not re.search(a.only, fo): continue
    ss = samples(fo)
    if not ss: continue
    plan.append({'folder': fo, 'ok': v['loads_ok'] == 'True',
                 'excludes': sorted(excl.get(fo, ())) if v.get('decoder_exclude') in ('necessário',) else [],
                 'samples': [{'log': s[0], 'fmt': 'json' if s[0].lstrip().startswith('{') else 'syslog'} for s in ss], 'meta': ss})

RUNNER = r'''
import os, sys, json, socket, struct, shutil, subprocess, time, glob
O = '/var/ossec'
def q(ev, fmt):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(20); s.connect(O + '/queue/sockets/logtest')
    m = json.dumps({"version": 1, "command": "log_processing", "parameters": {"event": ev, "log_format": fmt, "location": "wcr"}}).encode()
    s.sendall(struct.pack('<I', len(m)) + m); n = struct.unpack('<I', s.recv(4))[0]; b = b''
    while len(b) < n: b += s.recv(n - len(b))
    s.close(); return json.loads(b)
def flat(d, p=''):
    for k, v in (d or {}).items():
        if isinstance(v, dict): yield from flat(v, p + k + '.')
        else: yield p + k
def stop():
    # esperar que o analysisd anterior saia de facto: ao sair apaga o socket de logtest, que já podia ser o do seguinte
    subprocess.run(['pkill', '-x', 'wazuh-analysisd'])
    for _ in range(100):
        if subprocess.run(['pgrep', '-x', 'wazuh-analysisd'], capture_output=True).returncode: break
        time.sleep(0.1)
    else:
        subprocess.run(['pkill', '-9', '-x', 'wazuh-analysisd']); time.sleep(0.5)
subprocess.run([O + '/bin/wazuh-db']); time.sleep(1)
for line in open('/tmp/plan.jsonl'):
    job = json.loads(line); fo = job['folder']
    stop(); shutil.rmtree(O + '/etc'); shutil.copytree('/tmp/etc.orig', O + '/etc', symlinks=True)
    src = '/tmp/areas/' + fo.split('/', 1)[1]; extra = ''
    for kind in ('rules', 'decoders'):
        for f in glob.glob(f'{src}/{kind}/*.xml'): shutil.copy(f, f'{O}/etc/{kind}/')
    for f in sorted(glob.glob(f'{src}/lists/**', recursive=True)):
        if os.path.isfile(f):
            rel = os.path.relpath(f, src + '/lists'); os.makedirs(os.path.dirname(f'{O}/etc/lists/{rel}'), exist_ok=True)
            shutil.copy(f, f'{O}/etc/lists/{rel}'); extra += f'<list>etc/lists/{rel}</list>'
    extra += ''.join(f'<decoder_exclude>ruleset/decoders/{x}</decoder_exclude>' for x in job['excludes'])
    if extra:
        c = open(O + '/etc/ossec.conf').read().replace('<decoder_dir>etc/decoders</decoder_dir>', '<decoder_dir>etc/decoders</decoder_dir>' + extra, 1)
        open(O + '/etc/ossec.conf', 'w').write(c)
    subprocess.run(['chown', '-R', 'wazuh:wazuh', O + '/etc'])
    try: os.remove(O + '/queue/sockets/logtest')
    except FileNotFoundError: pass
    open(O + '/logs/ossec.log', 'w').close()
    subprocess.run([O + '/bin/wazuh-analysisd'])
    t0 = time.time()
    while time.time() - t0 < 60 and not (os.path.exists(O + '/queue/sockets/logtest') and 'Logtest started' in open(O + '/logs/ossec.log').read()): time.sleep(0.2)
    res = []
    for s in job['samples']:
        try:
            o = q(s['log'], s['fmt'])['data']['output']
            res.append({'decoder': (o.get('decoder') or {}).get('name', ''), 'parent': (o.get('decoder') or {}).get('parent', ''),
                        'fields': sorted(flat(o.get('data'))), 'rule': (o.get('rule') or {}).get('id', ''), 'level': (o.get('rule') or {}).get('level', ''),
                        'alert': bool(o.get('rule')) and (o.get('rule') or {}).get('level', 0) > 0})
        except Exception as e:
            res.append({'error': str(e)[:200]})
    print(json.dumps({'folder': fo, 'results': res}), flush=True)
stop()
'''

rows, summary = [], []
with tempfile.TemporaryDirectory() as tmp:
    with open(os.path.join(tmp, 'plan.jsonl'), 'w') as fh:
        for p in plan:
            if p['ok']: fh.write(json.dumps({k: p[k] for k in ('folder', 'excludes', 'samples')}) + '\n')
    open(os.path.join(tmp, 'runner.py'), 'w').write(RUNNER)
    subprocess.run(['docker', 'rm', '-f', NAME], capture_output=True)
    subprocess.run(['docker', 'run', '-d', '--name', NAME, '--entrypoint', 'sleep', a.image, 'infinity'], check=True, capture_output=True)
    try:
        for src, dst in ((os.path.join(ROOT, 'areas'), '/tmp/areas'), (os.path.join(tmp, 'plan.jsonl'), '/tmp/plan.jsonl'),
                         (os.path.join(tmp, 'runner.py'), '/tmp/runner.py')):
            subprocess.run(['docker', 'cp', src, f'{NAME}:{dst}'], check=True, capture_output=True)
        subprocess.run(['docker', 'exec', NAME, 'bash', '-c', 'cd /var/ossec && cp -a data_tmp/exclusion/var/ossec/etc/. etc/ && '
                        'rm -f etc/rules/local_rules.xml etc/decoders/local_decoder.xml && chown -R wazuh:wazuh etc && cp -a etc /tmp/etc.orig'],
                       check=True, capture_output=True)
        out = subprocess.run(['docker', 'exec', NAME, '/var/ossec/framework/python/bin/python3', '/tmp/runner.py'],
                             check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        print('runner falhou:', e.returncode, (e.stderr or '')[-2000:], (e.stdout or '')[-500:]); raise
    finally:
        if not os.environ.get('WCR_KEEP'): subprocess.run(['docker', 'rm', '-f', NAME], capture_output=True)

got = {j['folder']: j['results'] for j in map(json.loads, out.splitlines())}

OFF_DECS = set(re.findall(r'<decoder\s+name="([^"]+)"', ' '.join(
    open(f, errors='ignore').read() for f in glob.glob(os.path.join(ROOT, '.cache/official/ruleset/decoders/*.xml')))))

def verdict(exp, r, fo):
    """ok | sombreado (o log é apanhado por um decoder oficial ou de outra origem, e os da pasta nunca correm) | não descodificado |
    regra não disparou | falso positivo | diferente do esperado (.ini) | erro"""
    if 'error' in r: return 'erro', r['error']
    pack_rule = r['rule'] in rules_by_folder[fo]
    dec_ok = r['decoder'] in decs_by_folder[fo] or r['parent'] in decs_by_folder[fo]
    k = exp['kind']
    if k.startswith('ini-'):
        probs = []
        if k == 'ini-pass':
            if exp['rule'] and r['rule'] != exp['rule']: probs.append(f"regra {r['rule'] or '—'} ≠ {exp['rule']}")
            if exp['alert'] and str(r['level']) != exp['alert']: probs.append(f"nível {r['level']} ≠ {exp['alert']}")
            if exp['decoder'] and exp['decoder'] not in (r['decoder'], r['parent']): probs.append(f"decoder {r['decoder'] or '—'} ≠ {exp['decoder']}")
        elif exp['rule'] and r['rule'] == exp['rule']:
            probs.append(f"a regra {exp['rule']} não devia disparar")
        return ('ok' if not probs else 'diferente do esperado'), '; '.join(probs)
    if k == 'trigger':
        return ('ok', '') if pack_rule and r['alert'] else ('regra não disparou', f"decoder {r['decoder'] or 'nenhum'}, regra {r['rule'] or 'nenhuma'}")
    if k == 'benign':
        return ('ok', '') if not (pack_rule and r['alert']) else ('falso positivo', f"regra {r['rule']} (nível {r['level']}) disparou num log benigno")
    if dec_ok or (r['decoder'] == 'json' and pack_rule): return 'ok', ''
    if not r['decoder']: return 'não descodificado', 'nenhum decoder apanhou o log'
    if not decs_by_folder[fo]: return ('ok', '') if pack_rule else ('regra não disparou', f"decoder {r['decoder']}, nenhuma regra da pasta")
    origin = 'oficial' if r['decoder'] in OFF_DECS else 'outra origem'
    return 'sombreado', f"apanhado pelo decoder {origin} {r['decoder']}; os decoders da pasta nunca correm para este log"

for p in plan:
    fo, res = p['folder'], got.get(p['folder'])
    cnt = collections.Counter()
    for i, (log, exp, origin) in enumerate(p['meta']):
        if res is None:
            v, why, r = 'não testado', 'a pasta não carrega no wazuh-analysisd', {}
        else:
            r = res[i]; v, why = verdict(exp, r, fo)
        cnt[v] += 1
        rows.append({'folder': fo, 'origin': origin, 'kind': exp['kind'], 'case': exp.get('case', ''), 'log': log[:500], 'verdict': v, 'why': why,
                     'decoder': r.get('decoder', ''), 'parent': r.get('parent', ''), 'fields': ','.join(r.get('fields', [])),
                     'rule': r.get('rule', ''), 'level': r.get('level', '')})
    summary.append({'folder': fo, 'samples': len(p['meta']), 'ok': cnt['ok'],
                    'failed': sum(n for k, n in cnt.items() if k not in ('ok', 'não testado')), 'not_tested': cnt['não testado'],
                    **{k: cnt[k] for k in ('sombreado', 'não descodificado', 'regra não disparou', 'falso positivo', 'diferente do esperado', 'erro')},
                    'sources': ';'.join(sorted({m[1]['kind'] for m in p['meta']}))})

for name, data in (('decoder_tests.csv', rows), ('decoder_test_summary.csv', summary)):
    with open(os.path.join(ROOT, 'catalog', name), 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(data[0].keys())); w.writeheader(); w.writerows(data)
tot = collections.Counter(r['verdict'] for r in rows)
print(f"{len(summary)} pastas com amostras, {len(rows)} amostras: {dict(tot)}; imagem {a.image}")
