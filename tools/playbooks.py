"""Bibliotecas de playbooks de resposta (clonadas em .cache/playbooks, fixadas no sources.lock) -> documentos com técnicas ATT&CK e rule.id.

Não se copia conteúdo para o registo: o catálogo aponta para o documento no commit fixado.
"""
import os, re, json
from urllib.parse import quote

TECH_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
LIBS = {
    'ADORSYS-GIS/wazuh-playbook': {'kind': 'procedimental (por rule.id/técnica)'},
    'guardsight/gsvsoc_cirt-playbook-battle-cards': {'kind': 'procedimental (battle card PICERL)', 'subdir': 'Markdown'},
    'austinsonger/Incident-Playbook': {'kind': 'procedimental (por técnica)', 'subdir': 'Playbooks'},
    'cisagov/playbook-ng': {'kind': 'contramedida (CISA COUN7ER)', 'dataset': 'shared/data/datasets/coun7er/latest.json'},
}
SKIP_NAMES = re.compile(r'(?i)^(readme|license|template|playbook-template|action-template|changelog|contributing)')

def _title(txt, fname):
    m = re.search(r'^#+\s*(.+)$', txt, re.M)
    t = re.sub(r'[*_`]', '', m.group(1)).strip() if m else os.path.splitext(fname)[0]
    return t[:160]

def docs(lib_dir, repo, commit):
    cfg = LIBS[repo]
    url = lambda p: f'https://github.com/{repo}/blob/{commit}/{quote(p)}'
    if 'dataset' in cfg:
        d = json.load(open(os.path.join(lib_dir, cfg['dataset'])))
        for it in d['items']:
            if it.get('revoked') or it.get('deprecated'): continue
            yield {'library': repo, 'kind': cfg['kind'], 'doc_id': it['id'], 'title': it['name'], 'path': cfg['dataset'],
                   'url': f'https://github.com/{repo}', 'techniques': sorted({t['tech_id'] for t in it.get('techniques', [])}),
                   'rule_ids': [], 'sca_checks': [], 'automatable': it.get('automatable') or ''}
        return
    base = os.path.join(lib_dir, cfg.get('subdir', ''))
    for dp, dn, fn in os.walk(base):
        dn[:] = sorted(x for x in dn if x != '.git')
        for f in sorted(fn):
            if not f.lower().endswith('.md') or SKIP_NAMES.match(f): continue
            p = os.path.join(dp, f); rel = os.path.relpath(p, lib_dir)
            txt = open(p, errors='ignore').read()
            title = _title(txt, f)
            head = TECH_RE.findall(f + ' ' + title)
            techs = sorted(set(head or TECH_RE.findall(txt)))
            stem = os.path.splitext(f)[0]
            sca = 'Configuration Assesment' in rel.split(os.sep)[0]   # ADORSYS: o número é o ID do check SCA, não um rule.id
            rule_ids = [stem] if stem.isdigit() and not sca else []
            sca_checks = [stem] if stem.isdigit() and sca else []
            if not techs and not rule_ids and not sca_checks: continue
            yield {'library': repo, 'kind': 'remediação SCA (por check)' if sca else cfg['kind'], 'doc_id': stem, 'title': title,
                   'path': rel, 'url': url(rel), 'techniques': techs, 'rule_ids': rule_ids, 'sca_checks': sca_checks, 'automatable': ''}
