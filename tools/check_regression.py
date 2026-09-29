#!/usr/bin/env python3
"""Falha (código 1) se a validação ou os testes regrediram face ao catálogo do commit de referência (por omissão HEAD).

Uso: python3 tools/check_regression.py [--ref HEAD]
Compara: pastas que carregam em wazuh-analysisd -t, agent.conf válidos e amostras de log ok no wazuh-logtest.
Um ambiente partido (p.ex. zero pastas a carregar) também falha, mesmo sem referência.
"""
import os, csv, io, argparse, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ap = argparse.ArgumentParser()
ap.add_argument('--ref', default='HEAD')
a = ap.parse_args()

def rows(name, ref=None):
    if ref is None:
        p = os.path.join(ROOT, 'catalog', name)
        return list(csv.DictReader(open(p))) if os.path.exists(p) else None
    r = subprocess.run(['git', '-C', ROOT, 'show', f'{ref}:catalog/{name}'], capture_output=True, text=True)
    return list(csv.DictReader(io.StringIO(r.stdout))) if r.returncode == 0 else None

METRICS = {
    'pastas que carregam': ('validation.csv', lambda rs: sum(1 for r in rs if r['loads_ok'] == 'True')),
    'agent.conf válidos': ('validation_agent_conf.csv', lambda rs: sum(1 for r in rs if r['ok'] == 'True')),
    'amostras de log ok': ('decoder_tests.csv', lambda rs: sum(1 for r in rs if r['verdict'] == 'ok')),
}
fail = False
for label, (name, f) in METRICS.items():
    cur, ref = rows(name), rows(name, a.ref)
    if cur is None:
        print(f'FALHA {label}: catalog/{name} não foi gerado'); fail = True; continue
    now = f(cur)
    if ref is None:
        print(f'{label}: {now} (sem referência em {a.ref})')
        if not now: print(f'FALHA {label}: zero'); fail = True
        continue
    before = f(ref)
    ok = now >= before and (now or not before)
    print(f"{'ok' if ok else 'FALHA'} {label}: {now} (referência {a.ref}: {before})")
    fail |= not ok
raise SystemExit(1 if fail else 0)
