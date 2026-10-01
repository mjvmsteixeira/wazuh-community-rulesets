"""Amostras sintéticas: um evento por regra, construído a partir das condições da regra e de toda a cadeia de pais.

Só para cadeias que se conseguem satisfazer só com campos: eventos Windows EventChannel (cadeia até à 60000,
decoded_as windows_eventchannel; injetados no analysisd, porque o wazuh-logtest não os descodifica) e eventos JSON
(decoded_as json; corridos no wazuh-logtest). O valor de cada campo é a menor cadeia que satisfaz a regex
(re._parser); regras com condições que não se geram (listas, horas, correlação, regex sobre o log inteiro em
Windows, campos estáticos...) ficam de fora. Uma amostra só conta depois de o motor confirmar que a pasta sozinha
dispara a regra (tools/logtest.py); as outras são falhas do gerador, não da regra.
"""
import os, re, glob, json, html, hashlib, collections
import re._parser as sre
from parse_ruleset import load_xml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_PER_FOLDER = 300
SKIP = {'list', 'time', 'weekday', 'frequency', 'timeframe', 'if_matched_sid', 'if_matched_group', 'same_source_ip', 'srcip', 'dstip',
        'srcport', 'dstport', 'user', 'program_name', 'hostname', 'url', 'id', 'action', 'status', 'extra_data', 'location', 'protocol',
        'system_name', 'data', 'srcgeoip', 'dstgeoip', 'if_fts', 'compiled_rule', 'check_diff', 'if_matched_regex', 'if_level'}

def rules_in(paths):
    """{id: (elemento, grupos)}; os grupos juntam o <group> da regra e os <group name="..."> que a envolvem."""
    out = {}
    for p in paths:
        root, _ = load_xml(open(p, errors='ignore').read())
        if root is None: continue
        for r in root.iter('rule'):
            if not r.get('id') or r.get('id') in out: continue
            gs = [g.get('name') or '' for g in r.iterancestors('group')] + [r.findtext('group') or '']
            out[r.get('id')] = (r, ','.join(x.strip(',') for x in gs if x.strip(',')))
    return out

_official = None
_group_off = {}   # if_group -> regras oficiais com grupos correspondentes
def official():
    global _official
    if _official is None: _official = rules_in(sorted(glob.glob(os.path.join(ROOT, '.cache/official/ruleset/rules/*.xml'))))
    return _official

# ---------- regex -> menor cadeia que corresponde
def os_regex_to_py(s):
    """OS_Regex (sintaxe por omissão do Wazuh 4.x) para regex Python, com a semântica medida no 4.14.8: '.' é literal e
    '\\.' qualquer carácter; '+'/'*' só quantificam depois de uma classe (\\w \\d \\s \\. ...), depois de um literal são
    literais; '?' é literal; '^'/'$' só ancoram no início/fim (de cada alternativa); \\s é só o espaço."""
    out, i, prev_class = [], 0, False
    m = {'w': r'[A-Za-z0-9@_\-]', 'd': r'\d', 's': ' ', 't': r'\t', 'p': r'[()*+,\-.:;<=>?\[\]!"\'#$%&|{}]', 'W': r'[^A-Za-z0-9@_\-]',
         'D': r'\D', 'S': r'[^ ]', '.': '.'}
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            n = s[i + 1]
            if n == '-': raise Unsat('\\- é erro de sintaxe no OS_Regex')
            out.append(m.get(n, re.escape(n))); prev_class = n in m; i += 2; continue
        if c in '*+' and prev_class: out.append(c); prev_class = False
        elif c == '^' and (i == 0 or s[i - 1] in '|('): out.append(c)
        elif c == '$' and (i == len(s) - 1 or s[i + 1] in '|)'): out.append(c)
        elif c in '()|': out.append(c)
        else: out.append(re.escape(c))
        if not (c in '*+' and out[-1] == c): prev_class = False
        i += 1
    return ''.join(out)

def os_match_to_py(s):
    """OS_Match: só literais, '^'/'$' por alternativa; '!' no início nega (tratado em conditions)."""
    alts = []
    for a in s.split('|'):
        b, e = a.startswith('^'), a.endswith('$')
        core = a[1 if b else 0:len(a) - (1 if e else 0)]
        alts.append(('^' if b else '') + re.escape(core) + ('$' if e else ''))
    return '|'.join(alts)

def to_py(el, s=None):
    """-> (regex Python, flags). <match> sem type é OS_Match; os outros, OS_Regex. Só o pcre2 distingue maiúsculas."""
    t = (el.get('type') or ('osmatch' if el.tag == 'match' else 'osregex')).lower()
    s = (el.text or '') if s is None else s
    if t == 'pcre2': return flags_of(s)
    return (os_match_to_py(s) if t == 'osmatch' else os_regex_to_py(s)), re.I

class Unsat(Exception): pass

def minimal(pattern, flags=0):
    def gen(items):
        out = ''
        for op, av in items:
            n = str(op)
            if n == 'LITERAL': out += chr(av)
            elif n == 'NOT_LITERAL': out += 'x' if chr(av) != 'x' else 'y'
            elif n == 'ANY': out += 'x'
            elif n == 'IN': out += pick_in(av)
            elif n in ('MAX_REPEAT', 'MIN_REPEAT', 'POSSESSIVE_REPEAT'):
                lo, hi, sub = av; out += gen(sub) * lo
            elif n == 'SUBPATTERN': out += gen(av[-1])
            elif n == 'ATOMIC_GROUP': out += gen(av)
            elif n == 'BRANCH': out += gen(av[1][0])
            elif n == 'AT': pass
            elif n == 'CATEGORY': out += cat(av)
            elif n == 'ASSERT_NOT': pass
            else: raise Unsat(n)
        return out
    def cat(c):
        return {'CATEGORY_DIGIT': '1', 'CATEGORY_NOT_DIGIT': 'a', 'CATEGORY_SPACE': ' ', 'CATEGORY_NOT_SPACE': 'x',
                'CATEGORY_WORD': 'a', 'CATEGORY_NOT_WORD': '-'}.get(str(c), 'x')
    def pick_in(items):
        neg = any(str(op) == 'NEGATE' for op, _ in items)
        if neg:
            for ch in 'xqz1-_ ':
                if not re.fullmatch(sre_rebuild(items), ch, flags): return ch
            raise Unsat('class')
        op, av = items[0]
        if str(op) == 'LITERAL': return chr(av)
        if str(op) == 'RANGE': return chr(av[0])
        if str(op) == 'CATEGORY': return cat(av)
        raise Unsat('class')
    def sre_rebuild(items):
        return '[' + ''.join('^' if str(op) == 'NEGATE' else re.escape(chr(av)) if str(op) == 'LITERAL' else
                             f'{re.escape(chr(av[0]))}-{re.escape(chr(av[1]))}' if str(op) == 'RANGE' else
                             {'CATEGORY_DIGIT': r'\d', 'CATEGORY_SPACE': r'\s', 'CATEGORY_WORD': r'\w', 'CATEGORY_NOT_DIGIT': r'\D',
                              'CATEGORY_NOT_SPACE': r'\S', 'CATEGORY_NOT_WORD': r'\W'}.get(str(av), '') for op, av in items) + ']'
    return gen(sre.parse(pattern, flags))

def value_for(conds):
    """conds: [(regex_py, negate, flags)] do mesmo campo -> valor que satisfaz todas, ou Unsat."""
    pos = [c for c in conds if not c[1]]
    mins = [minimal(p, f) for p, _, f in pos]
    cands = mins[:] if pos else ['wcr']
    if len(mins) > 1:   # várias condições positivas: juntar os mínimos (as ancoradas no início à frente, no fim atrás)
        order = sorted(range(len(pos)), key=lambda k: (0 if pos[k][0].startswith('^') else 2 if pos[k][0].endswith('$') else 1))
        cands.append(''.join(mins[k] for k in order))
    for v in cands:
        if all(bool(re.search(p, v, f)) != neg for p, neg, f in conds): return v
    raise Unsat('conflito entre condições')

def flags_of(p):
    f = 0
    m = re.match(r'^\(\?([a-z]+)\)', p)
    if m:
        p = p[m.end():]
        if 'i' in m.group(1): f |= re.I
    return p, f

# ---------- cadeia de pais
def chains(rid, local, limit=8):
    """Cadeias possíveis da regra até à raiz (cada uma é uma lista de elementos), seguindo todos os if_sid e, para if_group,
    todas as regras cujos grupos correspondem (OS_Match, sem distinguir maiúsculas). No máximo `limit` cadeias."""
    off = official()
    def get(x): return local.get(x) or off.get(x)
    def parents(r, cur):
        sid = [x.strip() for x in (r.findtext('if_sid') or '').replace(' ', ',').split(',') if x.strip()]
        if sid: return sid
        g = (r.findtext('if_group') or '').strip()
        if not g: return None
        if g not in _group_off:
            rx = re.compile(os_match_to_py(g), re.I)
            _group_off[g] = [x for x, (_, gs) in off.items() if rx.search(gs)][:limit]
        rx = re.compile(os_match_to_py(g), re.I)
        return ([x for x, (_, gs) in local.items() if x != cur and rx.search(gs)] + _group_off[g])[:limit]
    out, budget = [], [300]   # nós visitados no máximo: as cadeias por if_group ramificam muito
    def walk(cur, acc, seen):
        if len(out) >= limit or budget[0] <= 0 or len(acc) > 20: return
        budget[0] -= 1
        e = get(cur)
        if e is None or cur in seen: return
        r = e[0]; ps = parents(r, cur)
        if ps is None: out.append(acc + [r]); return
        for x in ps: walk(x, acc + [r], seen | {cur})
    walk(rid, [], set())
    if not out: raise Unsat('sem cadeia até à raiz')
    return out

def conditions(rs):
    fields, matches, kind = collections.defaultdict(list), [], None
    for r in rs:
        for c in r:
            if not isinstance(c.tag, str): continue
            tag = c.tag
            if tag in SKIP: raise Unsat(tag)
            if tag == 'decoded_as':
                d = (c.text or '').strip()
                kind = kind or {'windows_eventchannel': 'eventchannel', 'json': 'json'}.get(d)
                if d not in ('windows_eventchannel', 'json'): raise Unsat('decoder ' + d)
            elif tag in ('field', 'match', 'regex'):
                neg, txt = c.get('negate') == 'yes', c.text or ''
                if (c.get('type') or ('osmatch' if tag == 'match' else '')).lower() == 'osmatch' and txt.startswith('!'):
                    neg, txt = not neg, txt[1:]   # OS_Match: '!' no início nega
                p, f = to_py(c, txt)
                if tag == 'field': fields[c.get('name')].append((p, neg, f))
                elif not neg: matches.append((p, f))
        if r.get('frequency') or r.find('same_source_ip') is not None: raise Unsat('correlação')
        if r.get('noalert') == '1': raise Unsat('noalert')
    return kind, fields, matches

# ---------- construção dos eventos
SYS = {'eventID': 'EventID', 'version': 'Version', 'level': 'Level', 'task': 'Task', 'opcode': 'Opcode', 'keywords': 'Keywords',
       'eventRecordID': 'EventRecordID', 'channel': 'Channel', 'computer': 'Computer'}

def eventchannel(fields, tag):
    # canal e fornecedor neutros quando a cadeia não os fixa: o canal Security mandaria o evento para os classificadores
    # oficiais de nível 0 (60001...), avaliados antes das regras penduradas diretamente na 60000
    sysv = {'providerName': 'WcrSynthetic', 'eventID': '1', 'version': '0', 'level': '4', 'task': '0',
            'opcode': '0', 'keywords': '0x0', 'eventRecordID': '1', 'channel': 'WcrSynthetic', 'computer': 'wcr-host'}
    data, message = {'WcrId': tag}, 'wcr synthetic event'
    def raw(v, conds):
        # o decoder eventchannel duplica cada barra invertida: a regex vê a forma duplicada, o evento leva a simples.
        # Uma sequência ímpar arredonda para cima; no fim confirma-se que a forma duplicada satisfaz todas as condições
        r = re.sub(r'\\+', lambda m: '\\' * ((len(m.group()) + 1) // 2), v)
        d = r.replace('\\', '\\\\')
        if not all(bool(re.search(p, d, f)) != neg for p, neg, f in conds): raise Unsat('barras invertidas')
        return r
    for name, conds in fields.items():
        if name == 'win.system.message':
            # o valor que as regras veem vem entre aspas (string JSON): ancorar em ^ ou $ nunca corresponde
            v = value_for([(p, n, f) for p, n, f in conds])
            if not all(bool(re.search(p, '"' + v + '"', f)) != n for p, n, f in conds): raise Unsat('message')
            message = v; continue
        v = raw(value_for(conds), conds)
        if name.startswith('win.eventdata.'):
            k = name.split('.', 2)[2]; data[k[:1].upper() + k[1:]] = v
        elif name == 'win.system.severityValue':
            m = {'AUDIT_SUCCESS': ('0', '0x8020000000000000'), 'AUDIT_FAILURE': ('0', '0x8010000000000000'), 'INFORMATION': ('4', '0x0'),
                 'WARNING': ('3', '0x0'), 'ERROR': ('2', '0x0'), 'CRITICAL': ('1', '0x0'), 'VERBOSE': ('5', '0x0')}
            hit = [k for k in m if all(bool(re.search(p, k, f)) != n for p, n, f in conds)]
            if not hit: raise Unsat('severityValue')
            sysv['level'], sysv['keywords'] = m[hit[0]]
        elif name.startswith('win.system.') and name.split('.')[2] in SYS or name == 'win.system.providerName':
            sysv[name.split('.')[2]] = v
        else: raise Unsat('campo ' + name)
    # o motor não descodifica &#x27;: só escapar &, <, > e aspas duplas (os atributos usam plicas, que não aparecem nos valores)
    def e(s):
        if "'" in s: raise Unsat('plica num atributo')
        return html.escape(s, quote=False).replace('"', '&quot;')
    def ev(s): return html.escape(s, quote=False).replace('"', '&quot;')
    xml = (f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{e(sysv['providerName'])}'/>"
           + ''.join(f"<{SYS[k]}>{ev(sysv[k])}</{SYS[k]}>" for k in ('eventID', 'version', 'level', 'task', 'opcode', 'keywords'))
           + "<TimeCreated SystemTime='2026-01-01T10:00:00.000000000Z'/>"
           + f"<EventRecordID>{ev(sysv['eventRecordID'])}</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/>"
           + f"<Channel>{ev(sysv['channel'])}</Channel><Computer>{ev(sysv['computer'])}</Computer><Security UserID='S-1-5-18'/></System>"
           + '<EventData>' + ''.join(f"<Data Name='{e(k)}'>{ev(v)}</Data>" for k, v in data.items()) + '</EventData></Event>')
    return json.dumps({'wcr': tag, 'Message': message, 'Event': xml}, ensure_ascii=False)

def json_event(fields, matches, tag):
    ev = {'wcr': tag}
    for name, conds in fields.items():
        v = value_for(conds); cur = ev; parts = name.split('.')
        for p_ in parts[:-1]:
            cur = cur.setdefault(p_, {})
            if not isinstance(cur, dict): raise Unsat('campo ' + name)
        cur[parts[-1]] = v
    for i, (p, f) in enumerate(matches):   # <match>/<regex> sobre o log inteiro: o texto vai num campo à parte
        ev[f'wcr_match{i}'] = minimal(p, f)
    s = json.dumps(ev, ensure_ascii=False)
    if not all(re.search(p, s, f) for p, f in matches): raise Unsat('match')
    return s

def synthetic(folder):
    """[(evento, {'kind': 'sintética', 'rule': id, 'fmt': 'eventchannel'|'json'}, 'sintética')] para as regras da pasta."""
    local = rules_in(sorted(glob.glob(os.path.join(ROOT, folder, 'rules', '*.xml'))))
    out = []
    for rid, (r, _) in local.items():
        if not (r.get('level') or '0').isdigit(): continue
        tag = hashlib.sha1(f'{folder}:{rid}'.encode()).hexdigest()[:10] + '-' + rid
        try: alts = chains(rid, local)
        except (Unsat, RecursionError): continue
        for ch in alts:
            try:
                kind, fields, matches = conditions(ch)
                if kind == 'eventchannel':
                    # sem alerta (nível 0) a injeção não se confirma pelo alerts.json
                    if matches or int(r.get('level')) < 1: raise Unsat('match em Windows / nível 0')
                    out.append((eventchannel(fields, tag), {'kind': 'sintética', 'rule': rid, 'fmt': 'eventchannel', 'tag': tag}, 'sintética'))
                elif kind == 'json':
                    out.append((json_event(fields, matches, tag), {'kind': 'sintética', 'rule': rid, 'fmt': 'json', 'tag': tag}, 'sintética'))
                else: continue
                break
            except (Unsat, re.error, RecursionError, OverflowError, ValueError, TypeError):
                continue
    return out[:MAX_PER_FOLDER]

if __name__ == '__main__':
    import csv, sys
    folders = sorted({'/'.join(r['file'].split('/')[:4]) for r in csv.DictReader(open(os.path.join(ROOT, 'catalog/rules.csv')))})
    tot = collections.Counter()
    for fo in folders:
        for s in synthetic(fo): tot[s[1]['fmt']] += 1
    print(dict(tot), 'em', len(folders), 'pastas')
    if len(sys.argv) > 1:
        for s in synthetic(sys.argv[1])[:3]: print(s[1], s[0][:600])
