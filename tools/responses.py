"""Camada de resposta: <active-response>, <command> e <integration> que as fontes trazem, ligados ao script e às regras que os disparam.

Para cada resposta: ação (bloquear IP, apagar ficheiro, desativar conta...), impacto, salvaguardas e se está partida
(script em falta, regra inexistente, IDs renumerados pelo autor, gatilho ambíguo, definida num agent.conf onde o Wazuh a ignora).
"""
import os, re, json
from collections import defaultdict

BLOCK_RE = re.compile(r'<(active-response|command|integration)>(.*?)</\1\s*>', re.S)
SKIP_EXT = ('.html', '.htm', '.jsonl', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.gz', '.zip', '.exe', '.dll', '.pdf', '.tmp', '.ndjson')
MAX_BYTES = 1_000_000
SCRIPT_EXT = ('', '.sh', '.py', '.ps1', '.cmd', '.bat', '.exe', '.go', '.rb', '.pl')

# scripts e integrações que vêm com o Wazuh
BUILTIN_AR = {'firewall-drop', 'firewalld-drop', 'host-deny', 'route-null', 'win_route-null', 'netsh', 'disable-account', 'restart-wazuh',
              'restart.sh', 'restart.cmd', 'ipfw', 'npf', 'pf', 'kaspersky', 'wazuh-slack', 'default-firewall-drop', 'remove-threat'}
BUILTIN_INTEGRATIONS = {'slack', 'pagerduty', 'virustotal', 'shuffle', 'maltiverse'}

# (ação, regex sobre nome + script, impacto) — a primeira que corresponde ganha
ACTIONS = [
    ('selar Vault', r'vault\s+operator\s+seal|vault-seal', 'destrutivo'),
    ('reiniciar host', r'\breboot\b|shutdown\s+/?-?r\b|Restart-Computer', 'destrutivo'),
    ('desativar conta', r'disable-account|Disable-ADAccount|disable.?user|userAccountControl|usermod\s+-L|passwd\s+-l|ldap.*modify', 'destrutivo'),
    ('isolar host', r'isolat|Disable-NetAdapter|netsh\s+interface\s+set|ifconfig\s+\S+\s+down|ip\s+link\s+set\s+\S+\s+down', 'destrutivo'),
    ('apagar ficheiro', r'os\.remove|Remove-Item|\brm\s+-[a-z]*f|unlink\(|remove-threat|remove-malware|del\s+/f', 'destrutivo'),
    ('matar processo', r'Stop-Process|taskkill|\bkill\s+-9|os\.kill|psutil.*kill', 'destrutivo'),
    ('quarentena', r'quarantin', 'contenção reversível'),
    ('bloquear IP', r'firewall-drop|host-deny|route-null|netsh|iptables|\bufw\b|nft\b|address-list|block|drop|deny', 'contenção reversível'),
    ('scan', r'yara|clamscan|clamav|\bscan', 'não destrutivo'),
    ('caso/SOAR', r'thehive|iris|shuffle|n8n|servicenow|jira|rootly|incident|keep|tracecat|ticket', 'não destrutivo'),
    ('enriquecimento', r'virustotal|misp|opencti|abuseipdb|otx|alienvault|malwarebazaar|bazzar|urlhaus|criminalip|maltiverse|yeti|'
                       r'threat_intel|socradar|gemini|chatgpt|openai|whisper|threatlens|ioc', 'não destrutivo'),
    ('notificação', r'telegram|slack|teams|discord|mail|smtp|webhook|vkteams|pagerduty|splunk|hec|chronicle', 'não destrutivo'),
]

def _t(block, tag):
    m = re.search(rf'<{tag}>(.*?)</{tag}>', block, re.S)
    return ' '.join(m.group(1).split()) if m else ''

def scan(src_dir):
    for dp, dn, fn in os.walk(src_dir):
        dn[:] = sorted(x for x in dn if x != '.git')
        for f in sorted(fn):
            p = os.path.join(dp, f)
            if f.lower().endswith(SKIP_EXT) or os.path.getsize(p) > MAX_BYTES: continue
            txt = open(p, errors='ignore').read()
            if BLOCK_RE.search(txt):
                yield os.path.relpath(p, src_dir), txt

def blocks(txt):
    """Blocos fora de comentários XML (os comentados são exemplos desativados)."""
    txt = re.sub(r'<!--.*?-->', '', txt, flags=re.S)
    out = []
    for m in BLOCK_RE.finditer(txt):
        kind, b = m.group(1), m.group(2)
        if kind == 'command' and '<executable>' not in b: continue       # <command> de <localfile>/<wodle>, não de AR
        if kind == 'active-response' and '<command>' not in b: continue  # <active-response> global de ossec.conf (disabled/ca_store)
        out.append({'kind': kind, 'raw': m.group(0), **{t: _t(b, t) for t in (
            'name', 'command', 'executable', 'rules_id', 'rules_group', 'level', 'location', 'timeout', 'agent_id',
            'hook_url', 'group', 'rule_id', 'alert_format')}})
    return out

def find_script(files_by_base, name, conf_file=''):
    """-> (caminho, problema). Exato ou com extensão comum; com o nome do artigo/ficheiro de configuração (wazuh.blog);
    ou com um nome parecido, que o Wazuh não encontra (problema)."""
    if not name: return '', ''
    base = os.path.basename(name)
    stem = os.path.splitext(base)[0] if not base.endswith('.exe') else base[:-4]
    for cand in [base] + [stem + e for e in SCRIPT_EXT]:
        if cand in files_by_base: return files_by_base[cand][0], ''
    if conf_file:   # integrations/<so>/<artigo>.conf -> scripts/<so>/<artigo>.py
        cstem = re.sub(r'_\d+$', '', os.path.splitext(os.path.basename(conf_file))[0])
        for cand in [cstem + e for e in SCRIPT_EXT if e]:
            if cand in files_by_base: return files_by_base[cand][0], ''
    variants = {stem.replace('-', '_'), stem.removeprefix('custom-'), stem.removeprefix('custom_'), 'custom-' + stem}
    for v in sorted(variants - {stem}):
        for cand in [v + e for e in SCRIPT_EXT]:
            if cand in files_by_base: return '', f'nome não coincide: {base} chama um script que se chama {cand}'
    if base.endswith('.exe') and stem + '.py' in files_by_base:
        return '', f'só existe o código-fonte {stem}.py; falta o binário {base}'
    return '', ''

def classify(text):
    for action, rx, impact in ACTIONS:
        if re.search(rx, text, re.I): return action, impact
    return 'outra', 'desconhecido'

def classify_response(kind, names, script_text):
    """Ação pelo nome; o conteúdo do script só pode agravar para uma ação destrutiva (um AR 'yara' que apaga o ficheiro,
    uma integração 'soar' que desativa contas) — não a partir de limpezas de temporários (os.remove) em integrações."""
    action, impact = classify(names)
    if not script_text: return action, impact
    strong = [x for x in ACTIONS if x[2] == 'destrutivo']
    if kind == 'integration': strong = [x for x in strong if x[0] in ('desativar conta', 'isolar host', 'selar Vault')]
    if impact != 'destrutivo' or kind == 'active-response':
        for a2, rx, i2 in strong:
            if re.search(rx, script_text, re.I): return a2, i2
    if action == 'outra': return classify(script_text)
    return action, impact

def load_remap(src_dir):
    """rule_id_remap.json que alguns autores publicam ao renumerar (antigo -> novos IDs)."""
    remap = defaultdict(set)
    for dp, dn, fn in os.walk(src_dir):
        dn[:] = [x for x in dn if x != '.git']
        if 'rule_id_remap.json' in fn:
            data = json.load(open(os.path.join(dp, 'rule_id_remap.json')))
            stack = [data]
            while stack:
                d = stack.pop()
                for k, v in d.items():
                    if isinstance(v, dict): stack.append(v)
                    else: remap[str(k).rsplit(':', 1)[-1]].add(str(v))
    return remap

def split_ids(s):
    return [x for x in re.split(r'[,\s]+', s or '') if x]
