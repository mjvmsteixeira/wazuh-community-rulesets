#!/usr/bin/env python3
"""Carrega cada pasta de fonte num wazuh-manager (Docker) e corre `wazuh-analysisd -t` sobre o ruleset oficial + a pasta.

Uso: python3 tools/validate.py [--image wazuh/wazuh-manager:4.14.8] [--only <regex de pasta>]
Escreve catalog/validation.csv: uma linha por pasta, com o primeiro erro e o primeiro aviso.
Valida também, com verify-agent-conf, cada groups/<grupo>/agent.conf e cada agent.conf copiado das fontes para collection/
(catalog/validation_agent_conf.csv).
Cada pasta é testada sozinha: rules/, decoders/ e lists/ da pasta. Se a pasta tem ficheiros em decoder_replacements.csv,
testa com e sem os <decoder_exclude> e regista qual das duas configurações carrega (coluna decoder_exclude).
"""
import os, re, csv, json, base64, argparse, subprocess, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
stats = json.load(open(os.path.join(ROOT, 'catalog/stats.json')))
ap = argparse.ArgumentParser()
ap.add_argument('--image', default='wazuh/wazuh-manager:' + stats['official_reference'].split()[1].lstrip('v'))
ap.add_argument('--only', default='')
a = ap.parse_args()
NAME = 'wcr-validate'

folders = [r['folder'] for r in csv.DictReader(open(os.path.join(ROOT, 'catalog/folders.csv'))) if re.search(a.only, r['folder'])]
excl = {}
for r in csv.DictReader(open(os.path.join(ROOT, 'catalog/decoder_replacements.csv'))):
    fo = os.path.join(*r['file'].split('/')[:4])
    excl.setdefault(fo, set()).update(r['official_files'].split(';'))

# o container arranca sem o entrypoint do manager: só precisamos do binário e do ruleset
INNER = r'''
set -u
cd /var/ossec
cp -a data_tmp/exclusion/var/ossec/etc/. etc/
rm -f etc/rules/local_rules.xml etc/decoders/local_decoder.xml
chown -R wazuh:wazuh etc
cp -a etc /tmp/etc.orig
while IFS=$'\t' read -r folder mode excludes; do
  rm -rf etc && cp -a /tmp/etc.orig etc
  src="/tmp/areas/$folder"
  [ -d "$src/rules" ] && cp "$src"/rules/*.xml etc/rules/
  [ -d "$src/decoders" ] && cp "$src"/decoders/*.xml etc/decoders/
  extra=""
  if [ -d "$src/lists" ]; then
    while read -r l; do
      mkdir -p "etc/lists/$(dirname "$l")"; cp "$src/lists/$l" "etc/lists/$l"; extra="$extra<list>etc/lists/$l</list>"
    done < <(cd "$src/lists" && find . -type f | sed 's#^\./##' | sort)
  fi
  for x in $excludes; do extra="$extra<decoder_exclude>ruleset/decoders/$x</decoder_exclude>"; done
  [ -n "$extra" ] && sed -i "s#<decoder_dir>etc/decoders</decoder_dir>#&$extra#" etc/ossec.conf
  chown -R wazuh:wazuh etc
  out=$(timeout 120 bin/wazuh-analysisd -t 2>&1); rc=$?
  printf '%s\t%s\t%s\t%s\n' "$folder" "$mode" "$rc" "$(printf '%s' "$out" | base64 -w0)"
done < /tmp/manifest.tsv
rm -rf etc && cp -a /tmp/etc.orig etc
while read -r f; do
  out=$(bin/verify-agent-conf -f "/tmp/$f" 2>&1); rc=$?
  printf 'AGENTCONF\t%s\t%s\t%s\n' "$f" "$rc" "$(printf '%s' "$out" | base64 -w0)"
done < /tmp/agentconf.txt
'''
# mensagens do ambiente (limites do container), não da pasta
ENV_NOISE = re.compile(r'Could not set resource limit|Unable to connect to socket .queue/db/wdb|Wazuh-DB for Mitre')
AGENT_CONF_RE = re.compile(r'^\s*(<!--.*?-->\s*)*<agent_config\b', re.S)

with tempfile.TemporaryDirectory() as tmp:
    with open(os.path.join(tmp, 'manifest.tsv'), 'w') as fh:
        for fo in folders:
            fh.write(f"{fo.removeprefix('areas/')}\tsem\t\n")
            if fo in excl: fh.write(f"{fo.removeprefix('areas/')}\tcom\t{' '.join(sorted(excl[fo]))}\n")
    open(os.path.join(tmp, 'inner.sh'), 'w').write(INNER)
    confs = sorted(os.path.relpath(os.path.join(dp, f), ROOT) for top in ('groups', 'areas') for dp, dn, fn in os.walk(os.path.join(ROOT, top))
                   for f in fn if (top == 'groups' or '/collection/' in dp + '/') and not f.endswith('.extracted.xml')
                   and AGENT_CONF_RE.match(open(os.path.join(dp, f), errors='ignore').read()))
    open(os.path.join(tmp, 'agentconf.txt'), 'w').write(''.join(c + '\n' for c in confs))
    subprocess.run(['docker', 'rm', '-f', NAME], capture_output=True)
    subprocess.run(['docker', 'run', '-d', '--init', '--name', NAME, '--ulimit', 'nofile=458752:458752', '--entrypoint', 'sleep', a.image, 'infinity'], check=True, capture_output=True)
    try:
        for src, dst in ((os.path.join(ROOT, 'areas'), '/tmp/areas'), (os.path.join(ROOT, 'groups'), '/tmp/groups'),
                         (os.path.join(tmp, 'manifest.tsv'), '/tmp/manifest.tsv'), (os.path.join(tmp, 'agentconf.txt'), '/tmp/agentconf.txt'),
                         (os.path.join(tmp, 'inner.sh'), '/tmp/inner.sh')):
            subprocess.run(['docker', 'cp', src, f'{NAME}:{dst}'], check=True, capture_output=True)
        res = subprocess.run(['docker', 'exec', NAME, 'bash', '/tmp/inner.sh'], check=True, capture_output=True, text=True).stdout
    finally:
        subprocess.run(['docker', 'rm', '-f', NAME], capture_output=True)

runs, conf_rows = {}, []
for line in res.splitlines():
    if line.startswith('AGENTCONF\t'):
        _, f, rc, b64 = line.split('\t')
        errs = [re.sub(r'^\S+ \S+ verify-agent-conf: ', '', l) for l in base64.b64decode(b64).decode(errors='replace').splitlines() if 'ERROR' in l]
        conf_rows.append({'file': f, 'kind': 'grupo' if f.startswith('groups/') else 'fonte', 'ok': rc == '0' and not errs,
                          'first_error': errs[0][:300] if errs else ''})
        continue
    fo, mode, rc, b64 = line.split('\t')
    log = [re.sub(r'^\S+ \S+ wazuh-analysisd: ', '', l) for l in base64.b64decode(b64).decode(errors='replace').splitlines()]
    errs = [l for l in log if l.startswith(('ERROR', 'CRITICAL')) and not ENV_NOISE.search(l)]
    warns = [l for l in log if l.startswith('WARNING')]
    runs[('areas/' + fo, mode)] = {'folder': 'areas/' + fo, 'loads_ok': rc == '0' and not errs, 'rc': rc, 'errors': len(errs),
                                  'warnings': len(warns), 'first_error': errs[0][:300] if errs else '', 'first_warning': warns[0][:300] if warns else ''}
rows = []
for fo in folders:
    sem, com = runs[(fo, 'sem')], runs.get((fo, 'com'))
    if com is None:
        rows.append({**sem, 'decoder_exclude': ''}); continue
    verdict = {(True, True): 'opcional', (True, False): 'necessário', (False, True): 'não usar', (False, False): 'indiferente (falha)'}
    best = com if com['loads_ok'] or not sem['loads_ok'] else sem
    rows.append({**best, 'decoder_exclude': verdict[(com['loads_ok'], sem['loads_ok'])]})
out = os.path.join(ROOT, 'catalog/validation.csv')
if a.only and os.path.exists(out):   # corrida parcial: substitui só as pastas testadas
    done = {r['folder'] for r in rows}
    rows = sorted([r for r in csv.DictReader(open(out)) if r['folder'] not in done] + rows, key=lambda r: r['folder'])
    for r in rows: r['loads_ok'] = str(r['loads_ok']) == 'True'; r['warnings'] = int(r['warnings'])
with open(out, 'w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
if not a.only:
    with open(os.path.join(ROOT, 'catalog/validation_agent_conf.csv'), 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=['file', 'kind', 'ok', 'first_error']); w.writeheader(); w.writerows(conf_rows)
    for k in ('grupo', 'fonte'):
        cr = [r for r in conf_rows if r['kind'] == k]
        print(f"agent.conf ({k}): {sum(r['ok'] for r in cr)} de {len(cr)} válidos")
ok = sum(r['loads_ok'] for r in rows)
print(f"{ok} de {len(rows)} pastas carregam ({sum(1 for r in rows if r['loads_ok'] and not r['warnings'])} sem avisos); imagem {a.image}")
