"""Normalização MITRE ATT&CK: etiquetas Sigma/grupos -> T-ID válido, com o bundle enterprise-attack.json do ruleset oficial.

O Wazuh aceita qualquer texto em <mitre><id> sem aviso; um ID inválido não se liga a nenhuma técnica e não serve de chave
de correlação com playbooks. A normalização é só do catálogo: os XML ficam como estão.
"""
import json, re

TOKEN_RE = re.compile(r'(?i)^(?:attack\.)?(t\d{4}(?:\.\d{3})?)$')

def load(bundle_path):
    """-> (ativas {T-ID: (nome, [táticas])}, substituição {T-ID revogado: T-ID novo ou None})"""
    b = json.load(open(bundle_path))
    ext, active, dead = {}, {}, set()
    for o in b['objects']:
        if o.get('type') != 'attack-pattern': continue
        tid = next((r['external_id'] for r in o.get('external_references', []) if r.get('source_name') == 'mitre-attack'), None)
        if not tid: continue
        ext[o['id']] = tid
        if o.get('revoked') or o.get('x_mitre_deprecated'):
            dead.add(tid)
        else:
            active[tid] = (o['name'], [p['phase_name'] for p in o.get('kill_chain_phases', [])])
    replaced = {t: None for t in dead}
    for o in b['objects']:
        if o.get('type') == 'relationship' and o.get('relationship_type') == 'revoked-by':
            s, t = ext.get(o['source_ref']), ext.get(o['target_ref'])
            if s in replaced and t in active: replaced[s] = t
    return active, replaced

def normalize(mitre_ids, groups, active, replaced):
    """-> (T-IDs válidos, estado). Estado: válido | normalizado | inválido | sem mitre."""
    raw = [m for m in mitre_ids if m]
    tokens = raw + [g for g in groups if re.match(r'(?i)^attack\.t\d{4}', g)]
    out, bad = [], False
    for tok in tokens:
        m = TOKEN_RE.match(tok.strip())
        if not m:
            if tok in raw and not re.match(r'(?i)^attack\.[a-z_]+$', tok): bad = True   # tática Sigma (attack.execution) não é técnica
            continue
        t = m.group(1).upper()
        if t not in active: t = replaced.get(t)
        if t: out.append(t)
        else: bad = True
    out = sorted(set(out))
    if not tokens: return out, 'sem mitre'
    if not out: return out, 'inválido'
    if sorted(set(raw)) == out and not bad: return out, 'válido'
    return out, 'normalizado'
