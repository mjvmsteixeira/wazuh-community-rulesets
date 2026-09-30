#!/usr/bin/env python3
"""Falha (código 1) se a validação ou os testes regrediram face ao catálogo do commit de referência (por omissão HEAD).

Uso: python3 tools/check_regression.py [--ref HEAD]
Compara item a item o que existe nos dois catálogos: uma pasta que carregava e deixou de carregar, um agent.conf que era
válido e deixou de ser, uma amostra de log que passava e deixou de passar. Itens novos ou retirados (fontes acrescentadas
ou excluídas) não contam como regressão. Um ambiente partido (zero pastas a carregar) falha sempre.
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

# (ficheiro, chave do item, está bom?)
CHECKS = {
    'pastas que carregam': ('validation.csv', lambda r: r['folder'], lambda r: r['loads_ok'] == 'True'),
    'agent.conf válidos': ('validation_agent_conf.csv', lambda r: r['file'], lambda r: r['ok'] == 'True'),
    'amostras de log ok': ('decoder_tests.csv', lambda r: (r['folder'], r['origin'], r['log']), lambda r: r['verdict'] == 'ok'),
}
fail = False
for label, (name, key, good) in CHECKS.items():
    cur, ref = rows(name), rows(name, a.ref)
    if cur is None:
        print(f'FALHA {label}: catalog/{name} não foi gerado'); fail = True; continue
    now = {key(r): good(r) for r in cur}
    total = sum(now.values())
    if label == 'pastas que carregam' and not total:
        print(f'FALHA {label}: nenhuma (ambiente partido?)'); fail = True; continue
    if ref is None:
        print(f'{label}: {total} (sem referência em {a.ref})'); continue
    before = {key(r): good(r) for r in ref}
    lost = sorted(str(k) for k in now.keys() & before.keys() if before[k] and not now[k])
    new = len(now.keys() - before.keys()); gone = len(before.keys() - now.keys())
    print(f"{'FALHA' if lost else 'ok'} {label}: {total} agora, {sum(before.values())} em {a.ref}; "
          f"{len(lost)} regrediram, {new} novos, {gone} retirados")
    for k in lost[:15]: print('   regrediu:', k[:160])
    fail |= bool(lost)
raise SystemExit(1 if fail else 0)
