"""Parser tolerante para ficheiros de regras/decoders Wazuh 4.x (XML sem raiz única)."""
import re, hashlib
from lxml import etree

COMMENT_RE = re.compile(r'<!--.*?-->', re.S)

def load_xml(text):
    text = re.sub(r'<\?xml[^>]*\?>', '', text)
    parser = etree.XMLParser(recover=True, huge_tree=True, remove_comments=True)
    try:
        root = etree.fromstring(('<__root__>' + text + '</__root__>').encode('utf-8', 'ignore'), parser)
    except Exception:
        return None, False
    # heurística de validade: re-parse estrito
    strict_ok = True
    try:
        etree.fromstring(('<__root__>' + text + '</__root__>').encode('utf-8', 'ignore'))
    except Exception:
        strict_ok = False
    return root, strict_ok

def txt(el, tag):
    return [ (c.text or '').strip() for c in el.findall(tag) ]

def norm(el):
    s = etree.tostring(el, encoding='unicode')
    return re.sub(r'\s+', ' ', s).strip()

def channels(expr):
    """Canais EventChannel concretos numa expressão de <field name="win.system.channel"> ('^Security$|^System$' -> Security, System)."""
    out = []
    for alt in (expr or '').split('|'):
        alt = alt.strip().strip('^$()').replace('\\/', '/').replace('\\-', '-')
        if alt and not re.search(r'[\\*+?\[\]{}]', alt):
            out.append(alt)
    return out

def parse_file(path):
    raw = open(path, encoding='utf-8', errors='ignore').read()
    root, strict_ok = load_xml(raw)
    out = {'rules': [], 'decoders': [], 'wellformed': strict_ok, 'parse_ok': root is not None}
    if root is None:
        return out
    for r in root.iter('rule'):
        rid = (r.get('id') or '').strip()
        if not rid:
            continue
        groups = []
        p = r.getparent()
        while p is not None:
            if p.tag == 'group' and p.get('name'):
                groups += [g for g in p.get('name').split(',') if g.strip()]
            p = p.getparent()
        for g in txt(r, 'group'):
            groups += [x for x in g.split(',') if x.strip()]
        mitre = [(i.text or '').strip() for i in r.iter('id') if i.getparent() is not None and i.getparent().tag == 'mitre']
        out['rules'].append({
            'id': rid,
            'level': r.get('level'),
            'frequency': r.get('frequency'),
            'description': ' '.join(' '.join(txt(r, 'description')).split())[:300],
            'groups': sorted(set(g.strip() for g in groups)),
            'if_sid': ','.join(txt(r, 'if_sid') + txt(r, 'if_matched_sid')),
            'if_group': ','.join(txt(r, 'if_group') + txt(r, 'if_matched_group')),
            'decoded_as': ','.join(txt(r, 'decoded_as')),
            'mitre': sorted(set(m for m in mitre if m)),
            'overwrite': r.get('overwrite') == 'yes',
            'lists': sorted({(l.text or '').strip() for l in r.iter('list') if (l.text or '').strip()}),
            'channels': sorted({c for f in r.iter('field') if f.get('name') == 'win.system.channel' for c in channels(f.text)}),
            'hash': hashlib.sha1(norm(r).encode()).hexdigest()[:12],
        })
    for d in root.iter('decoder'):
        name = d.get('name')
        if not name:
            continue
        out['decoders'].append({
            'name': name,
            'parent': ','.join(txt(d, 'parent')),
            'plugin': ','.join(txt(d, 'plugin_decoder')),
            'fields': [x.strip() for o in txt(d, 'order') for x in o.split(',') if x.strip()],
            'ident': 'plugin' if d.find('plugin_decoder') is not None else 'program_name' if d.find('program_name') is not None
                     else 'prematch' if d.find('prematch') is not None else '',
            'regex_types': sorted({(c.get('type') or 'osregex').lower() for c in d.findall('regex') + d.findall('prematch')}),
            'hash': hashlib.sha1(norm(d).encode()).hexdigest()[:12],
        })
    return out
