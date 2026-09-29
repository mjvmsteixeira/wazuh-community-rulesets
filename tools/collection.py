"""Camada de recolha: o que cada pasta precisa que o agente (ou o manager) recolha, e grupos de agentes-modelo.

Duas origens para cada requisito:
  - inferido: a pasta encadeia em regras/decoders oficiais de uma família (win-sysmon, auditd...) ou filtra win.system.channel;
  - declarado: a fonte traz blocos <localfile>/<wodle>/<agent_config>/... (agent.conf, ossec.conf, READMEs).
Os requisitos do lado do agente com localização concreta dão grupos componíveis em groups/<grupo>/agent.conf.
"""
import os, re
from collections import defaultdict
from lxml import etree
from taxonomy import slug

# blocos de configuração procurados nos ficheiros das fontes
BLOCK_TAGS = ('agent_config', 'localfile', 'wodle', 'integration', 'office365', 'github', 'ms-graph')
BLOCK_RE = re.compile(r'<(' + '|'.join(re.escape(t) for t in BLOCK_TAGS) + r')\b[^>]*>.*?</\1\s*>', re.S)
TEXT_EXT = ('.md', '.markdown', '.txt', '.rst', '.conf', '.xml', '.cfg', '.ini', '.sh', '.ps1', '.yml', '.yaml', '')
MAX_BYTES = 1_000_000
PLACEHOLDER_RE = re.compile(r'%%|<[A-Z_]{3,}>|\bYOUR[_ -]|CHANGE[_ ]?ME|example\.(com|org)|x\.x\.x\.x|\$\{|\bpath/to\b', re.I)
MANAGER_WODLES = {'aws-s3', 'azure-logs', 'gcp-pubsub', 'gcp-bucket', 'vulnerability-detector', 'cis-cat'}
DEFAULT_CHANNELS = {'Security', 'System', 'Application'}   # já recolhidos pelo ossec.conf por omissão num agente Windows

def EC(ch):
    return {'side': 'agent', 'kind': 'localfile', 'os': 'windows', 'log_format': 'eventchannel', 'location': ch}
def LF(os_, fmt, loc):
    return {'side': 'agent', 'kind': 'localfile', 'os': os_, 'log_format': fmt, 'location': loc}
def WODLE(name, side='agent', os_='linux'):
    return {'side': side, 'kind': 'wodle', 'os': os_ if side == 'agent' else '', 'name': name}
def MGR(kind, name):
    return {'side': 'manager', 'kind': kind, 'os': '', 'name': name}
DEFAULT = {'side': 'default'}
INTERNAL = {'side': 'internal'}
REMOTE_SYSLOG = MGR('remote', 'syslog')

# família oficial (nome do ficheiro sem número) -> requisito de recolha
FAMILY_INPUT = {
    'win-sysmon': EC('Microsoft-Windows-Sysmon/Operational'), 'sysmon': EC('Microsoft-Windows-Sysmon/Operational'),
    'win-powershell': EC('Microsoft-Windows-PowerShell/Operational'),
    'win-wdefender': EC('Microsoft-Windows-Windows Defender/Operational'), 'ms_wdefender': EC('Microsoft-Windows-Windows Defender/Operational'),
    'win-wfirewall': EC('Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'),
    'auditd': LF('linux', 'audit', '/var/log/audit/audit.log'), 'audit': LF('linux', 'audit', '/var/log/audit/audit.log'),
    'dec:auditd': LF('linux', 'audit', '/var/log/audit/audit.log'),
    'suricata': LF('linux', 'json', '/var/log/suricata/eve.json'),
    'apache': LF('linux', 'apache', '/var/log/apache2/access.log'), 'web': LF('linux', 'apache', '/var/log/apache2/access.log'),
    'nginx': LF('linux', 'syslog', '/var/log/nginx/access.log'),
    'docker': WODLE('docker-listener'), 'docker_integration': WODLE('docker-listener'),
    'osquery': WODLE('osquery'),
    'office365': MGR('module', 'office365'), 'github': MGR('module', 'github'), 'microsoft-graph': MGR('module', 'ms-graph'),
    'amazon': MGR('wodle', 'aws-s3'), 'aws-security-hub-rules': MGR('wodle', 'aws-s3'), 'amazon-security-lake': MGR('wodle', 'aws-s3'),
    'azure': MGR('wodle', 'azure-logs'), 'gcp': MGR('wodle', 'gcp-pubsub'), 'virustotal': MGR('integration', 'virustotal'),
}
for f in ('win-security', 'msauth', 'win-base', 'win-system', 'win-application', 'win_event_channel', 'win-generic', 'win-ms_logs',
          'dec:windows', 'syslog', 'sshd', 'pam', 'systemd', 'dec:unix', 'dec:kernel', 'firewalld', 'dropbear', 'apparmor', 'usb'):
    FAMILY_INPUT[f] = DEFAULT
for f in ('ossec', 'wazuh', 'wazuh-api', 'sca', 'rootcheck', 'vulnerability-detector', 'ciscat', 'oscap', 'rules_config', 'policy',
          'malicious-ioc-rules', 'attack', 'dec:ossec'):
    FAMILY_INPUT[f] = INTERNAL
for f in ('fortigate', 'fortiddos', 'fortimail', 'fortiauth', 'cisco-ftd', 'cisco-asa', 'cisco-ios', 'cisco-estreamer', 'paloalto',
          'sophos_fw', 'sophos', 'pfsense', 'firewall', 'junos', 'checkpoint-smart1', 'f5_bigip', 'huawei-usg', 'sonicwall', 'netscreenfw',
          'pix', 'proxmox-ve', 'vmware', 'netscaler', 'imperva', 'arbor', 'fireeye', 'panda-paps', 'vpn_concentrator', 'openvpn'):
    FAMILY_INPUT[f] = REMOTE_SYSLOG
NEEDS_JSON = {'side': 'json'}   # decoder json oficial ou decoder raiz JSON próprio: a localização do ficheiro vem das fontes
FAMILY_INPUT['dec:json'] = NEEDS_JSON

def family(fname):
    return re.sub(r'^\d+-', '', fname).replace('_rules.xml', '').replace('_decoders.xml', '').replace('.xml', '')


# ---------- índice oficial: id/grupo/decoder -> família
def official_index(off, parse_file):
    id_fam, grp_fam, dec_fam = {}, defaultdict(set), {}
    for f in sorted(os.listdir(os.path.join(off, 'rules'))):
        for r in parse_file(os.path.join(off, 'rules', f))['rules']:
            id_fam[r['id']] = family(f)
            for g in r['groups']: grp_fam[g].add(family(f))
    for f in sorted(os.listdir(os.path.join(off, 'decoders'))):
        for d in parse_file(os.path.join(off, 'decoders', f))['decoders']:
            dec_fam.setdefault(d['name'], 'dec:' + family(f))
    return id_fam, grp_fam, dec_fam

def requirement(fam):
    return FAMILY_INPUT.get(fam) or (FAMILY_INPUT['win-sysmon'] if fam.startswith('sysmon_id') else None)

def unambiguous(fams):
    """Um grupo oficial definido em várias famílias só conta se todas pedirem a mesma recolha (sysmon_event1: win-sysmon e sysmon_id_1)."""
    reqs = [requirement(f) for f in fams]
    return bool(fams) and all(r is not None and r == reqs[0] for r in reqs)

def folder_families(files, id_fam, grp_fam, dec_fam):
    """Famílias oficiais em que as regras da pasta encadeiam (if_sid/if_group/decoded_as)."""
    fams = defaultdict(int)
    for f in files:
        for r in f['rules']:
            fs = {id_fam[s] for s in re.split(r'[,\s]+', r['if_sid']) if s in id_fam}
            fs |= {x for g in r['if_group'].split(',') if unambiguous(grp_fam.get(g, ())) for x in grp_fam[g]}
            fs |= {dec_fam[d] for d in r['decoded_as'].split(',') if d in dec_fam}
            for x in fs: fams[x] += 1
    return dict(fams)

def own_roots(files, off_dec_names):
    """Tipo dos decoders raiz próprios da pasta (sem parent ou com parent inexistente no oficial): json ou texto/syslog."""
    kinds = set()
    for f in files:
        for d in f['decoders']:
            if d['parent'] and any(p in off_dec_names for p in d['parent'].split(',')): continue
            if d['parent']: continue
            kinds.add('json' if 'JSON' in d['plugin'].upper() else 'texto')
    return kinds

# ---------- extração dos blocos de configuração das fontes
def candidate_files(src_dir, registered):
    for dp, dn, fn in os.walk(src_dir):
        dn[:] = sorted(x for x in dn if x != '.git')
        for f in sorted(fn):
            rel = os.path.relpath(os.path.join(dp, f), src_dir)
            ext = os.path.splitext(f)[1].lower()
            if rel in registered or ext not in TEXT_EXT or os.path.getsize(os.path.join(dp, f)) > MAX_BYTES: continue
            txt = open(os.path.join(dp, f), errors='ignore').read()
            if BLOCK_RE.search(txt):
                yield rel, txt

def blocks(txt):
    """Blocos de topo (um <localfile> dentro de um <agent_config> conta como parte do agent_config)."""
    out, end = [], -1
    for m in BLOCK_RE.finditer(re.sub(r'<!--.*?-->', lambda c: ' ' * len(c.group(0)), txt, flags=re.S)):
        if m.start() < end: continue
        out.append(txt[m.start():m.end()]); end = m.end()
    return out

def _t(el, tag):
    c = el.find(tag)
    return ' '.join((c.text or '').split()) if c is not None and c.text else ''

def infer_os(e, hint=''):
    h = (hint or '').lower()
    if 'windows' in h: return 'windows'
    if 'darwin' in h or 'macos' in h: return 'darwin'
    if 'linux' in h: return 'linux'
    loc, cmd = e.get('location', ''), e.get('command', '')
    if e.get('log_format') in ('eventchannel', 'eventlog') or re.match(r'^[A-Za-z]:\\', loc) or '.exe' in (loc + cmd).lower() \
            or re.search(r'\b(findstr|schtasks|powershell|wmic|netstat -ano)\b', cmd, re.I): return 'windows'
    if e.get('log_format') == 'macos' or loc.startswith(('/Library', '/Users', '/private/var')) \
            or re.search(r'\b(top -l|launchctl|sw_vers|log show)\b', cmd): return 'darwin'
    if loc.startswith('/') or cmd or e.get('log_format') in ('audit', 'journald'): return 'linux'
    return ''

def entries_of(block):
    """Entradas estruturadas de um bloco; cada uma guarda o XML original para ir tal e qual para o agent.conf."""
    root = etree.fromstring(('<r>' + block + '</r>').encode(), etree.XMLParser(recover=True, remove_comments=True))
    if root is None: return []
    out = []
    def add(el, hint):
        tag = el.tag
        xml = re.sub(r'\n\s*\n', '\n', etree.tostring(el, encoding='unicode').strip())
        if tag == 'localfile':
            e = {'kind': 'localfile', 'log_format': _t(el, 'log_format'), 'location': _t(el, 'location'), 'command': _t(el, 'command'),
                 'query': _t(el, 'query'), 'xml': xml}
            e['side'] = 'manager' if e['location'].startswith('/var/ossec') else 'agent'
        elif tag == 'wodle':
            name = el.get('name') or ''
            e = {'kind': 'wodle', 'name': name, 'command': _t(el, 'command'), 'xml': xml,
                 'side': 'manager' if name in MANAGER_WODLES else 'agent'}
        elif tag in ('integration', 'office365', 'github', 'ms-graph'):
            e = {'kind': 'integration' if tag == 'integration' else 'module', 'name': _t(el, 'name') if tag == 'integration' else tag,
                 'xml': xml, 'side': 'manager'}
        else:
            return
        e['os'] = (infer_os(e, hint) or WODLE_OS.get(e.get('name'), '')) if e['side'] == 'agent' else ''
        e['placeholder'] = bool(PLACEHOLDER_RE.search(' '.join(e.get(k, '') for k in ('location', 'command', 'query', 'name'))))
        e['incomplete'] = not any(e.get(k) for k in ('location', 'command', 'name'))
        # XML partido na origem (p.ex. <localfile> fechado com outro <localfile>) ou marcadores como <SHA_256_HASH>
        e['malformed'] = any(d.tag == el.tag for d in el.iter() if d is not el)
        e['placeholder'] = e['placeholder'] or any(isinstance(d.tag, str) and re.fullmatch(r'[A-Z0-9_]{3,}', d.tag) for d in el.iter())
        out.append(e)
    for el in root:
        if not isinstance(el.tag, str): continue
        if el.tag == 'agent_config':
            hint = ' '.join(el.get(k, '') for k in ('os', 'profile', 'name'))
            for c in el:
                if isinstance(c.tag, str): add(c, hint)
        else:
            add(el, '')
    return out

def entry_key(e):
    return (e['side'], e['kind'], e.get('os', ''), e.get('log_format', ''), e.get('location', '') or e.get('name', ''),
            e.get('command', ''), e.get('query', ''))

# ---------- grupos
GROUP_ALIASES = {'windows-defender': 'defender', 'windows-firewall-with-advanced-security-firewall': 'firewall'}
# entradas partilhadas por muitos packs: um grupo próprio, reutilizável
SHARED_LOCATIONS = {'/var/log/audit/audit.log': 'linux-auditd', '/var/log/suricata/eve.json': 'linux-suricata',
                    '/var/log/apache2/access.log': 'linux-apache', '/var/log/nginx/access.log': 'linux-nginx'}
SHARED_WODLES = {'docker-listener': 'linux-docker', 'osquery': 'osquery'}
WODLE_OS = {'docker-listener': 'linux'}
DEFAULT_WODLES = {'syscollector'}   # já ativo por omissão no agente

SYSLOG_AREAS = ('07-network-perimeter', '14-ot-ics-iot', '15-infra-virt-storage-backup')   # equipamentos que enviam syslog

def group_name(e, topic, shared_channels):
    """Grupo de uma entrada do lado do agente: partilhado (canal/ficheiro/wodle comum) ou pack-<tópico> com blocos por SO."""
    if e['kind'] == 'localfile' and e.get('log_format') == 'eventchannel' and e['location'] in shared_channels:
        ch = re.sub(r'^Microsoft-Windows-', '', e['location'], flags=re.I)
        ch = re.sub(r'/Operational$', '', ch, flags=re.I)
        return 'win-' + GROUP_ALIASES.get(slug(ch), slug(ch))
    if e['kind'] == 'localfile' and e.get('location') in SHARED_LOCATIONS: return SHARED_LOCATIONS[e['location']]
    if e['kind'] == 'wodle' and e.get('name') in SHARED_WODLES: return SHARED_WODLES[e['name']]
    return 'pack-' + slug(topic)

def merge_key(e):
    """Duas entradas com a mesma chave leem a mesma fonte de eventos: num agent.conf só pode ficar uma."""
    if e['kind'] == 'localfile':
        return ('localfile', e.get('os', ''), e.get('log_format') if e.get('command') else '', e.get('location') or e.get('command'))
    return (e['kind'], e.get('os', ''), e.get('name', ''), e.get('command', ''))

def merge(entries):
    """Uma entrada por fonte de eventos; canais com <query> diferentes passam a recolha completa (sem query)."""
    out = {}
    for e in sorted(entries, key=entry_key):
        k = merge_key(e)
        if k not in out:
            out[k] = e
        elif out[k].get('query') != e.get('query') and e.get('log_format') == 'eventchannel':
            out[k] = {**{x: y for x, y in e.items() if x != 'xml'}, 'query': '', 'merged': True}
    # a mesma entrada sem SO e com SO: fica só a versão específica (senão o agente desse SO recebe-a duas vezes)
    specific = {(k[0],) + k[2:] for k in out if k[1]}
    return [out[k] for k in sorted(out) if k[1] or (k[0],) + k[2:] not in specific]

def entry_xml(e):
    if e.get('xml'): return e['xml']
    if e['kind'] == 'localfile':
        note = '<!-- fontes pedem queries diferentes para este canal: recolha completa -->\n' if e.get('merged') else ''
        return f"{note}<localfile>\n  <location>{e['location']}</location>\n  <log_format>{e['log_format']}</log_format>\n</localfile>"
    if e['kind'] == 'wodle' and e['name'] == 'docker-listener':
        return '<wodle name="docker-listener">\n  <disabled>no</disabled>\n</wodle>'
    if e['kind'] == 'wodle' and e['name'] == 'osquery':
        return '<wodle name="osquery">\n  <disabled>no</disabled>\n  <run_daemon>yes</run_daemon>\n</wodle>'
    return ''

AGENT_OS = {'windows': 'Windows', 'linux': 'Linux', 'darwin': 'Darwin'}

def render_group(name, entries):
    by_os = defaultdict(list)
    for e in entries: by_os[e.get('os', '')].append(e)
    parts = [f'<!-- Grupo {name}: gerado por tools/build.py a partir de catalog/collection_entries.csv; rever caminhos antes de usar -->']
    for os_ in sorted(by_os):
        attr = f' os="{AGENT_OS[os_]}"' if os_ in AGENT_OS else ''
        body = '\n'.join('  ' + entry_xml(e).replace('\n', '\n  ') for e in by_os[os_])
        parts.append(f'<agent_config{attr}>\n{body}\n</agent_config>')
    return '\n'.join(parts) + '\n'
