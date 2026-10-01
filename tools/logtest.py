#!/usr/bin/env python3
"""Testa decoders e regras de cada pasta com amostras de log reais, no wazuh-logtest de um wazuh-manager em Docker.

Uso: python3 tools/logtest.py [--image wazuh/wazuh-manager:4.14.8] [--only <regex de pasta>]

Amostras (por pasta):
  - tests/**/*.ini no formato oficial da Wazuh (log N pass/fail, rule, alert, decoder): verifica regra, nível e decoder;
  - tests/**/*.log|*.txt: cada linha; 'trigger' no nome = tem de disparar uma regra da pasta, 'benign' = não pode;
  - exemplos de log nos comentários dos decoders: têm de ser descodificados por um decoder da pasta.
Só se testam pastas que carregam (catalog/validation.csv). Escreve catalog/decoder_tests.csv e catalog/decoder_test_summary.csv.
"""
import os, re, csv, json, glob, argparse, subprocess, tempfile, collections
from samples import samples, RUNNER, pack_prefix, PLATFORM
from synth import synthetic

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
stats = json.load(open(os.path.join(ROOT, 'catalog/stats.json')))
ap = argparse.ArgumentParser()
ap.add_argument('--image', default='wazuh/wazuh-manager:' + stats['official_reference'].split()[1].lstrip('v'))
ap.add_argument('--only', default='')
a = ap.parse_args()
NAME = 'wcr-logtest'


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
    sy = synthetic(fo) if v['loads_ok'] == 'True' else []
    if not ss and not sy: continue
    plan.append({'folder': fo, 'ok': v['loads_ok'] == 'True', 'n_real': len(ss), 'prefix': pack_prefix(fo),
                 'excludes': sorted(excl.get(fo, ())) if v.get('decoder_exclude') in ('necessário',) else [],
                 'samples': [{'log': s[0], 'fmt': 'json' if s[0].lstrip().startswith('{') else 'syslog'} for s in ss] +
                            [{'log': s[0], 'fmt': s[1]['fmt'], 'tag': s[1]['tag']} for s in sy], 'meta': ss + sy})



rows, summary, synth_rows = [], [], []
with tempfile.TemporaryDirectory() as tmp:
    with open(os.path.join(tmp, 'plan.jsonl'), 'w') as fh:
        for p in plan:
            if p['ok']: fh.write(json.dumps({k: p[k] for k in ('folder', 'prefix', 'excludes', 'samples')}) + '\n')
    open(os.path.join(tmp, 'runner.py'), 'w').write(RUNNER)
    subprocess.run(['docker', 'rm', '-f', NAME], capture_output=True)
    subprocess.run(['docker', 'run', '-d', '--init', '--platform', PLATFORM, '--name', NAME, '--ulimit', 'nofile=458752:458752', '--entrypoint', 'sleep', a.image, 'infinity'], check=True, capture_output=True)
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

got = {j['folder']: (j['results'] if j.get('loaded', True) else None) for j in map(json.loads, out.splitlines())}

OFF_RULES = set(re.findall(r'<rule\s+id="(\d+)"', ' '.join(
    open(f, errors='ignore').read() for f in glob.glob(os.path.join(ROOT, '.cache/official/ruleset/rules/*.xml')))))
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
        if exp['kind'] == 'sintética':
            r = res[i] if res else {}
            if 'error' in r or not res: continue
            v = ('ok' if r['rule'] == exp['rule'] else 'outra regra da pasta' if r['rule'] in rules_by_folder[fo]
                 else 'regra oficial' if r['rule'] and r['rule'] in OFF_RULES else 'outra regra' if r['rule'] else 'nenhuma regra')
            synth_rows.append({'folder': fo, 'rule': exp['rule'], 'format': exp['fmt'], 'verdict': v, 'fired_rule': r['rule'],
                               'fired_level': r.get('level', ''), 'decoder': r['decoder'],
                               'fields': ','.join(r.get('fields', [])), 'log': log})
            continue
        if res is None:
            v, why, r = 'não testado', 'a pasta não carrega no wazuh-analysisd', {}
        else:
            r = res[i]; v, why = verdict(exp, r, fo)
        cnt[v] += 1
        rows.append({'folder': fo, 'origin': origin, 'kind': exp['kind'], 'case': exp.get('case', ''), 'log': log[:500], 'verdict': v, 'why': why,
                     'decoder': r.get('decoder', ''), 'parent': r.get('parent', ''), 'fields': ','.join(r.get('fields', [])),
                     'rule': r.get('rule', ''), 'level': r.get('level', '')})
    if not p['n_real']: continue
    summary.append({'folder': fo, 'samples': p['n_real'], 'ok': cnt['ok'],
                    'failed': sum(n for k, n in cnt.items() if k not in ('ok', 'não testado')), 'not_tested': cnt['não testado'],
                    **{k: cnt[k] for k in ('sombreado', 'não descodificado', 'regra não disparou', 'falso positivo', 'diferente do esperado', 'erro')},
                    'sources': ';'.join(sorted({m[1]['kind'] for m in p['meta']}))})

for name, data in (('decoder_tests.csv', rows), ('decoder_test_summary.csv', summary), ('synthetic_tests.csv', synth_rows)):
    if not data: continue
    with open(os.path.join(ROOT, 'catalog', name), 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(data[0].keys())); w.writeheader(); w.writerows(data)
tot = collections.Counter(r['verdict'] for r in rows)
print(f"{len(summary)} pastas com amostras, {len(rows)} amostras: {dict(tot)}; imagem {a.image}")
st = collections.Counter((r['format'], r['verdict']) for r in synth_rows)
print(f"sintéticas: {len(synth_rows)} em {len({r['folder'] for r in synth_rows})} pastas: {dict(st)}")
