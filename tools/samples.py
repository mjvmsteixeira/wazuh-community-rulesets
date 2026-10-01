"""Amostras de log de uma pasta do registo e o runner que as corre no wazuh-logtest dentro de um wazuh-manager (Docker).

Usado por tools/logtest.py (cada pasta sozinha) e tools/combo_test.py (várias pastas carregadas juntas).
"""
import os, re, glob, configparser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
    extra = ''
    # uma ou várias pastas; com prefixo, os ficheiros têm o nome que o script de instalação lhes dá (e a mesma ordem de carregamento)
    for part in job.get('parts') or [{'path': fo, 'prefix': ''}]:
        src = '/tmp/areas/' + part['path'].split('/', 1)[1]
        for kind in ('rules', 'decoders'):
            for f in sorted(glob.glob(f'{src}/{kind}/*.xml')):
                name = (part['prefix'] + '__' if part['prefix'] else '') + os.path.basename(f)
                shutil.copy(f, f'{O}/etc/{kind}/{name}')
        for f in sorted(glob.glob(f'{src}/lists/**', recursive=True)):
            if os.path.isfile(f):
                rel = os.path.relpath(f, src + '/lists'); os.makedirs(os.path.dirname(f'{O}/etc/lists/{rel}'), exist_ok=True)
                shutil.copy(f, f'{O}/etc/lists/{rel}')
                if f'<list>etc/lists/{rel}</list>' not in extra: extra += f'<list>etc/lists/{rel}</list>'
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
    # esperar enquanto o analysisd estiver vivo (um conjunto grande de pastas pode demorar mais de um minuto a carregar)
    while time.time() - t0 < 600 and not (os.path.exists(O + '/queue/sockets/logtest') and 'Logtest started' in open(O + '/logs/ossec.log').read()):
        if time.time() - t0 > 5 and subprocess.run(['pgrep', '-x', 'wazuh-analysisd'], capture_output=True).returncode: break
        time.sleep(0.2)
    loaded = os.path.exists(O + '/queue/sockets/logtest')
    log = open(O + '/logs/ossec.log').read()
    errs = [l.split('wazuh-analysisd: ', 1)[-1] for l in log.splitlines() if ('ERROR' in l or 'CRITICAL' in l)
            and 'resource limit' not in l and 'wdb' not in l and 'Wazuh-DB' not in l and 'Mitre' not in l]
    res = []
    if not loaded:
        print(json.dumps({'folder': fo, 'loaded': False, 'errors': errs[:5], 'results': []}), flush=True); continue
    fails = 0
    for s in job['samples']:
        if fails >= 3:   # o analysisd caiu: não esperar o timeout em cada amostra que falta
            res.append({'error': 'analysisd deixou de responder'}); continue
        try:
            o = q(s['log'], s['fmt'])['data']['output']
            res.append({'decoder': (o.get('decoder') or {}).get('name', ''), 'parent': (o.get('decoder') or {}).get('parent', ''),
                        'fields': sorted(flat(o.get('data'))), 'rule': (o.get('rule') or {}).get('id', ''), 'level': (o.get('rule') or {}).get('level', ''),
                        'alert': bool(o.get('rule')) and (o.get('rule') or {}).get('level', 0) > 0})
            fails = 0
        except Exception as e:
            fails += 1
            res.append({'error': str(e)[:200]})
    warns = [l.split('wazuh-analysisd: ', 1)[-1] for l in log.splitlines() if 'WARNING' in l]
    print(json.dumps({'folder': fo, 'loaded': True, 'errors': errs[:5], 'warnings': warns[:200], 'results': res}), flush=True)
stop()
'''
