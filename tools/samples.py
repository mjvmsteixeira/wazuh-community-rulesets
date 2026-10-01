"""Amostras de log de uma pasta do registo e o runner que as corre no wazuh-logtest dentro de um wazuh-manager (Docker).

Usado por tools/logtest.py (cada pasta sozinha) e tools/combo_test.py (várias pastas carregadas juntas).
"""
import os, re, glob, configparser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_SAMPLES = 400   # por pasta
# arquitetura da imagem do wazuh-manager: a nativa (emular amd64 num Mac arm64 é ~50x mais lento). O motor só divergiu
# entre arm64 e amd64 em regex com caracteres não-ASCII (tools/model_checks.py, regex-nao-ascii); o gerador sintético
# não gera amostras para essas regras, para os resultados locais e do CI (amd64) coincidirem
import platform as _pf
PLATFORM = os.environ.get('WCR_PLATFORM') or ('linux/arm64' if _pf.machine().lower() in ('arm64', 'aarch64') else 'linux/amd64')

# prefixo que o script de instalação da página dá aos ficheiros de cada pack (packPrefix() em site_template.html):
# slug(tópico + '-' + repositório), com um hash FNV-1a da pasta quando dois packs dariam o mesmo prefixo. O wazuh-analysisd
# ordena TODOS os ficheiros de regras/decoders (oficiais e de etc/) pelo nome: instalar com o nome original (p.ex. 02-rules.xml)
# carrega-os antes dos oficiais e os if_sid oficiais falham (7617). Os testes instalam como o script, com o prefixo.
def _slug(s): return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')
def _fnv(s):
    h = 0x811c9dc5
    for c in s.encode(): h = ((h ^ c) * 0x01000193) & 0xffffffff
    return f'{h:08x}'
_prefixes = None
def pack_prefix(folder):
    global _prefixes
    if _prefixes is None:
        import csv, collections
        fs = list(csv.DictReader(open(os.path.join(ROOT, 'catalog', 'folders.csv'))))
        base = {f['folder']: _slug(f['topic'] + '-' + f['source'].split('/')[1])[:60] for f in fs}
        n = collections.Counter(base.values())
        _prefixes = {fo: b[:51] + '-' + _fnv(fo) if n[b] > 1 else b for fo, b in base.items()}
    return _prefixes[folder]

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
import os, re, sys, json, socket, struct, shutil, subprocess, time, glob
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
# amostras eventchannel: injetadas na fila do analysisd (como o agente faz) e lidas do alerts.json; alertar a partir do nível 1
_c = open('/tmp/etc.orig/ossec.conf').read()
_c = re.sub(r'<log_alert_level>\d+</log_alert_level>', '<log_alert_level>1</log_alert_level>', _c).replace('<jsonout_output>no</jsonout_output>', '<jsonout_output>yes</jsonout_output>')
open('/tmp/etc.orig/ossec.conf', 'w').write(_c)
ALERTS = O + '/logs/alerts/alerts.json'
def inject(evs):
    """evs: [(tag, payload)] -> {tag: alerta}. Espera pelo menos 10 s e depois até 3 s sem alertas novos (máximo 120 s).
    Duas passagens: com muitos eventos seguidos a fila do analysisd pode descartar algum, por isso os que não deram
    alerta são reenviados uma vez (uma regra que de facto não dispara continua sem alerta)."""
    got = {}
    for attempt in range(2):
        todo = [(tag, ev) for tag, ev in evs if tag not in got]
        if not todo: break
        open(ALERTS, 'a').close(); start = os.path.getsize(ALERTS)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.connect(O + '/queue/sockets/queue')
        for tag, ev in todo: s.send(('f:EventChannel:' + ev).encode()); time.sleep(0.005)
        s.close()
        last, t0, size = time.time(), time.time(), start
        while (time.time() - t0 < 10 or time.time() - last < 3) and time.time() - t0 < 120:
            time.sleep(0.3)
            if os.path.getsize(ALERTS) != size: size = os.path.getsize(ALERTS); last = time.time()
        with open(ALERTS, errors='replace') as fh:
            fh.seek(start)
            for line in fh:
                try: a = json.loads(line)
                except ValueError: continue
                tag = (((a.get('data') or {}).get('win') or {}).get('eventdata') or {}).get('wcrId')
                if tag: got[tag] = a
    return got
for line in open('/tmp/plan.jsonl'):
    job = json.loads(line); fo = job['folder']
    stop(); shutil.rmtree(O + '/etc'); shutil.copytree('/tmp/etc.orig', O + '/etc', symlinks=True)
    extra = ''
    # uma ou várias pastas; com prefixo, os ficheiros têm o nome que o script de instalação lhes dá (e a mesma ordem de carregamento)
    for part in job.get('parts') or [{'path': fo, 'prefix': job.get('prefix', '')}]:
        src = '/tmp/areas/' + part['path'].split('/', 1)[1]
        # com prefixo, como o script de instalação: listas em etc/lists/<prefixo>/ e referências das regras reescritas
        lp = part['prefix'] + '/' if part['prefix'] else ''
        own = [os.path.relpath(f, src + '/lists') for f in sorted(glob.glob(f'{src}/lists/**', recursive=True)) if os.path.isfile(f)]
        for kind in ('rules', 'decoders'):
            for f in sorted(glob.glob(f'{src}/{kind}/*.xml')):
                name = (part['prefix'] + '__' if part['prefix'] else '') + os.path.basename(f)
                if not (kind == 'rules' and lp and own):
                    shutil.copy(f, f'{O}/etc/{kind}/{name}'); continue
                body = open(f, encoding='utf-8', errors='surrogateescape').read()
                for l in own: body = re.sub(r'(<list\b[^>]*>\s*)etc/lists/' + re.escape(l) + r'(\s*</list>)', r'\g<1>etc/lists/' + lp + l + r'\g<2>', body)
                open(f'{O}/etc/{kind}/{name}', 'w', encoding='utf-8', errors='surrogateescape').write(body)
        for rel in own:
            d = f'{O}/etc/lists/{lp}{rel}'; os.makedirs(os.path.dirname(d), exist_ok=True)
            shutil.copy(f'{src}/lists/{rel}', d)
            if f'<list>etc/lists/{lp}{rel}</list>' not in extra: extra += f'<list>etc/lists/{lp}{rel}</list>'
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
    ec = [(s['tag'], s['log']) for s in job['samples'] if s['fmt'] == 'eventchannel']
    ec_got = inject(ec) if ec else {}
    for s in job['samples']:
        if s['fmt'] == 'eventchannel':
            a = ec_got.get(s['tag']) or {}
            rule = a.get('rule') or {}
            res.append({'decoder': (a.get('decoder') or {}).get('name', ''), 'parent': (a.get('decoder') or {}).get('parent', ''),
                        'fields': sorted(flat(a.get('data'))), 'rule': rule.get('id', ''), 'level': rule.get('level', ''), 'alert': bool(rule)})
            continue
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
