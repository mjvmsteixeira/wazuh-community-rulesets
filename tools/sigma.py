"""SigmaHQ como referência de cobertura: técnicas ATT&CK que a comunidade Sigma deteta e o registo não.

Não se converte nem copia nenhuma regra Sigma (licença DRL 1.1); o catálogo aponta para a regra no commit fixado.
"""
import os, re, glob
from urllib.parse import quote
import yaml

DIRS = ('rules', 'rules-emerging-threats', 'rules-threat-hunting', 'rules-dfir', 'rules-compliance')

def load(sigma_dir, commit):
    out = []
    for d in DIRS:
        for p in sorted(glob.glob(os.path.join(sigma_dir, d, '**', '*.yml'), recursive=True)):
            try:
                docs = list(yaml.safe_load_all(open(p, errors='ignore')))
            except yaml.YAMLError:
                continue
            doc = next((x for x in docs if isinstance(x, dict) and 'title' in x), None)
            if not doc: continue
            ls = doc.get('logsource') or {}
            rel = os.path.relpath(p, sigma_dir)
            out.append({'id': doc.get('id', ''), 'title': str(doc.get('title', ''))[:160], 'status': doc.get('status', ''),
                        'level': doc.get('level', ''), 'tags': [str(t) for t in doc.get('tags') or []],
                        'product': ls.get('product', ''), 'category': ls.get('category', ''), 'service': ls.get('service', ''),
                        'path': rel, 'url': f'https://github.com/SigmaHQ/sigma/blob/{commit}/{quote(rel)}', 'set': d})
    return out

def logsource(r):
    return '/'.join(x for x in (r['product'], r['category'] or r['service']) if x) or '—'
