#!/usr/bin/env python3
"""Verifica no wazuh-manager o modelo de avaliação de regras irmãs em que o registo se baseia.

Cada cenário instala regras próprias em etc/rules e corre eventos no wazuh-logtest (as sequências partilham a sessão,
para que as regras de correlação se possam cumprir). Se a imagem da Wazuh mudar de comportamento, falha e a análise
estática (build.py) e o cesto da página deixam de estar certos.

Uso: python3 tools/model_checks.py [--image wazuh/wazuh-manager:4.14.8]
Escreve catalog/engine_model.csv. Sai com 1 se algum cenário com resultado esperado não o der.
"""
import os, csv, json, argparse, subprocess, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
stats = json.load(open(os.path.join(ROOT, 'catalog/stats.json')))
ap = argparse.ArgumentParser()
ap.add_argument('--image', default='wazuh/wazuh-manager:' + stats['official_reference'].split()[1].lstrip('v'))
a = ap.parse_args()
NAME = 'wcr-model'

OK = 'Oct  1 10:00:00 host sshd[100]: Accepted password for admin from 10.0.0.5 port 22 ssh2'
FAIL = 'Oct  1 10:00:0{} host sshd[100]: Failed password for admin from 10.0.0.9 port 22 ssh2'
OK9 = 'Oct  1 10:00:09 host sshd[100]: Accepted password for admin from 10.0.0.9 port 22 ssh2'
def R(rid, lvl, body, extra=''): return f'<rule id="{rid}" level="{lvl}"{extra}>{body}<description>wcr {rid}</description></rule>'
def G(*rules): return '<group name="wcr,">' + ''.join(rules) + '</group>'

# (nome, o que prova, {ficheiro: xml}, [eventos], regra esperada no último evento ou None = só observar)
CASES = [
    ('nivel-maior-primeiro', 'entre irmãs, o nível mais alto é avaliado primeiro',
     {'a.xml': G(R(100010, 5, '<if_sid>5715</if_sid><user>admin</user>'), R(100011, 10, '<if_sid>5715</if_sid><user>admin</user>'))}, [OK], '100011'),
    ('empate-nome-ficheiro', 'em empate de nível, ganha o ficheiro carregado primeiro (nome), não o ID',
     {'a.xml': G(R(100021, 5, '<if_sid>5715</if_sid><user>admin</user>')), 'b.xml': G(R(100020, 5, '<if_sid>5715</if_sid><user>admin</user>'))}, [OK], '100021'),
    ('nivel-0-primeiro', 'uma irmã de nível 0 é avaliada antes das irmãs com alerta, mesmo de nível 12',
     {'a.xml': G(R(100031, 12, '<if_sid>5715</if_sid><user>admin</user>')), 'b.xml': G(R(100030, 0, '<if_sid>5715</if_sid>'))}, [OK], '100030'),
    ('apanha-tudo-silencia', 'uma irmã sem condições corresponde sempre e fica com o evento',
     {'a.xml': G(R(100040, 7, '<if_sid>5715</if_sid>'), R(100041, 6, '<if_sid>5715</if_sid><user>admin</user>'))}, [OK], '100040'),
    ('id-repetido', 'um ID repetido fica com a definição do ficheiro carregado primeiro; a outra não existe',
     {'a.xml': G(R(100050, 4, '<if_sid>5715</if_sid><user>admin</user>')), 'b.xml': G(R(100050, 12, '<if_sid>5715</if_sid><user>admin</user>'))}, [OK], '100050:4'),
    ('if_group-e-irma', 'issue #1: a 40112 (if_group authentication_success) é irmã de uma filha de 5715 e ganha-lhe com nível 12',
     {'a.xml': G(R(100080, 9, '<if_sid>5715</if_sid><match>Accepted password</match>'))}, [FAIL.format(i) for i in range(1, 9)] + [OK9], '40112'),
    ('if_group-sem-correlacao', 'issue #1: sem as falhas antes, a filha de 5715 dispara',
     {'a.xml': G(R(100080, 9, '<if_sid>5715</if_sid><match>Accepted password</match>'))}, [OK], '100080'),
    ('if_group-nivel-13', 'issue #1: a nível 13 a filha de 5715 passa à frente da 40112',
     {'a.xml': G(R(100080, 13, '<if_sid>5715</if_sid><match>Accepted password</match>'))}, [FAIL.format(i) for i in range(1, 9)] + [OK9], '100080'),
    ('if_matched_sid-controlo', 'uma regra só com if_matched_sid (sem if_sid) é filha da regra referida: ao N-ésimo evento em que esta é a regra final, substitui-a',
     {'b.xml': G(R(100061, 10, '<if_matched_sid>5760</if_matched_sid><same_source_ip />', ' frequency="3" timeframe="120"'))},
     [FAIL.format(i) for i in range(1, 7)], '100061'),
    ('if_matched_sid-irma', 'um apanha-tudo filho da regra referida silencia a de correlação: fica com o evento e a referida deixa de ser a final (não conta)',
     {'a.xml': G(R(100060, 0, "<if_sid>5760</if_sid>")),
      'b.xml': G(R(100061, 10, '<if_matched_sid>5760</if_matched_sid><same_source_ip />', ' frequency="3" timeframe="120"'))},
     [FAIL.format(i) for i in range(1, 7)], '100060'),
]

RUNNER = r'''
import os, sys, json, socket, struct, shutil, subprocess, time
O = '/var/ossec'
def q(ev, token=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(20); s.connect(O + '/queue/sockets/logtest')
    p = {"event": ev, "log_format": "syslog", "location": "wcr"}
    if token: p["token"] = token
    m = json.dumps({"version": 1, "command": "log_processing", "parameters": p}).encode()
    s.sendall(struct.pack('<I', len(m)) + m); n = struct.unpack('<I', s.recv(4))[0]; b = b''
    while len(b) < n: b += s.recv(n - len(b))
    s.close(); return json.loads(b)['data']
def stop():
    subprocess.run(['pkill', '-x', 'wazuh-analysisd'])
    for _ in range(100):
        if subprocess.run(['pgrep', '-x', 'wazuh-analysisd'], capture_output=True).returncode: break
        time.sleep(0.1)
subprocess.run([O + '/bin/wazuh-db']); time.sleep(1)
for line in open('/tmp/cases.jsonl'):
    c = json.loads(line)
    stop(); shutil.rmtree(O + '/etc'); shutil.copytree('/tmp/etc.orig', O + '/etc', symlinks=True)
    for name, xml in c['files'].items(): open(f'{O}/etc/rules/{name}', 'w').write(xml)
    subprocess.run(['chown', '-R', 'wazuh:wazuh', O + '/etc'])
    try: os.remove(O + '/queue/sockets/logtest')
    except FileNotFoundError: pass
    open(O + '/logs/ossec.log', 'w').close()
    subprocess.run([O + '/bin/wazuh-analysisd']); t0 = time.time()
    while time.time() - t0 < 120 and not (os.path.exists(O + '/queue/sockets/logtest') and 'Logtest started' in open(O + '/logs/ossec.log').read()): time.sleep(0.2)
    token, fired = None, []
    for ev in c['events']:
        d = q(ev, token); token = d.get('token') or token
        r = (d.get('output') or {}).get('rule') or {}
        fired.append(f"{r.get('id', '')}:{r.get('level', '')}" if r else '')
    warns = [l.split('wazuh-analysisd: ', 1)[-1][:160] for l in open(O + '/logs/ossec.log').read().splitlines() if 'WARNING' in l and 'wcr' not in l][:3]
    print(json.dumps({'name': c['name'], 'fired': fired, 'warnings': warns}), flush=True)
stop()
'''

with tempfile.TemporaryDirectory() as tmp:
    with open(os.path.join(tmp, 'cases.jsonl'), 'w') as fh:
        for name, why, files, events, want in CASES: fh.write(json.dumps({'name': name, 'files': files, 'events': events}) + '\n')
    open(os.path.join(tmp, 'runner.py'), 'w').write(RUNNER)
    subprocess.run(['docker', 'rm', '-f', NAME], capture_output=True)
    subprocess.run(['docker', 'run', '-d', '--init', '--name', NAME, '--ulimit', 'nofile=458752:458752', '--entrypoint', 'sleep', a.image, 'infinity'],
                   check=True, capture_output=True)
    try:
        for f in ('cases.jsonl', 'runner.py'): subprocess.run(['docker', 'cp', os.path.join(tmp, f), f'{NAME}:/tmp/{f}'], check=True, capture_output=True)
        subprocess.run(['docker', 'exec', NAME, 'bash', '-c', 'cd /var/ossec && cp -a data_tmp/exclusion/var/ossec/etc/. etc/ && '
                        'rm -f etc/rules/local_rules.xml etc/decoders/local_decoder.xml && chown -R wazuh:wazuh etc && cp -a etc /tmp/etc.orig'],
                       check=True, capture_output=True)
        out = subprocess.run(['docker', 'exec', NAME, '/var/ossec/framework/python/bin/python3', '/tmp/runner.py'],
                             check=True, capture_output=True, text=True).stdout
    finally:
        subprocess.run(['docker', 'rm', '-f', NAME], capture_output=True)

got = {j['name']: j for j in map(json.loads, out.splitlines())}
rows, bad = [], 0
for name, why, files, events, want in CASES:
    g = got.get(name, {}); last = (g.get('fired') or [''])[-1]
    rid, lvl = (last.split(':') + [''])[:2]
    if want == 'observar': v = 'observação'
    else:
        wid, _, wlvl = want.partition(':')
        v = 'ok' if rid == wid and (not wlvl or lvl == wlvl) else 'FALHOU'
    bad += v == 'FALHOU'
    rows.append({'case': name, 'proves': why, 'expected': '' if want == 'observar' else want, 'got': last, 'verdict': v,
                 'sequence': ' '.join(x or '-' for x in g.get('fired', [])), 'warnings': '; '.join(g.get('warnings', []))})
    print(f"{v:10} {name:26} esperado {want or '-':10} obtido {last or '-':10}  {why}")
with open(os.path.join(ROOT, 'catalog', 'engine_model.csv'), 'w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
raise SystemExit(1 if bad else 0)
