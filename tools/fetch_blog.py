#!/usr/bin/env python3
"""Captura os blocos XML (regras, decoders e configuração) dos artigos do blog da Wazuh para snapshots/wazuh-blog/.

Uso: python3 tools/fetch_blog.py            # recaptura tudo (o CI não corre isto: reconstrói a partir da captura guardada)

Cada artigo com XML fica em snapshots/wazuh-blog/<slug>/: NN-rules.xml, NN-decoders.xml, NN-config.xml (blocos
<localfile>/<wodle>/<integration>/<active-response>/...) e post.json com o link, o título, as datas e o hash dos
ficheiros. O conteúdo é © Wazuh, Inc.: cada pasta do registo cita o artigo de origem com o link.
"""
import os, re, json, html, shutil, hashlib, datetime, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'snapshots', 'wazuh-blog')
BLOG = 'https://wazuh.com/blog/'
UA = {'User-Agent': 'Mozilla/5.0 (wazuh-community-rulesets; +https://github.com/mjvmsteixeira/wazuh-community-rulesets)'}
CONFIG_TAGS = r'<(localfile|wodle|integration|active-response|command|agent_config|ossec_config|ruleset|syscheck|rootcheck|sca|office365|github|ms-graph|remote)\b'

def get(url):
    for _ in range(3):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40).read().decode('utf-8', 'ignore')
        except Exception:
            pass
    return ''

def post_urls():
    posts, page = set(), 1
    while page < 200:
        h = get(BLOG if page == 1 else f'{BLOG}page/{page}/')
        found = {u for u in re.findall(r'href="(https://wazuh\.com/blog/[a-z0-9-]+/)"', h)
                 if u != BLOG and not re.search(r'/(page|category|tag)/', u)}
        if not found - posts: break
        posts |= found; page += 1
    return sorted(posts)

def blocks(page):
    for attrs, body in re.findall(r'<pre([^>]*)>(.*?)</pre>', page, re.S):
        code = html.unescape(re.sub(r'<[^>]+>', '', body)).strip('\n') + '\n'
        if re.search(r'<rule\s[^>]*id=', code): yield 'rules', code
        elif re.search(r'<decoder\s[^>]*name=', code): yield 'decoders', code
        elif re.search(CONFIG_TAGS, code): yield 'config', code

def capture(url):
    page = get(url)
    if not page: return url, None
    got = list(blocks(page))
    if not got: return url, []
    meta = lambda k: (re.search(rf'"{k}"\s*:\s*"([^"]+)"', page) or [None, ''])[1]
    title = html.unescape(re.sub(r'\s*\|\s*Wazuh\s*$', '', (re.search(r'<title>([^<]+)', page) or [None, ''])[1])).strip()
    return url, {'title': title, 'published': meta('datePublished')[:10], 'modified': meta('dateModified')[:10], 'blocks': got}

urls = post_urls()
with ThreadPoolExecutor(8) as ex:
    res = dict(ex.map(capture, urls))
failed = [u for u, v in res.items() if v is None]
if len(failed) > len(urls) / 4:
    raise SystemExit(f'demasiados artigos falharam ({len(failed)} de {len(urls)}): captura anterior mantida')
shutil.rmtree(OUT, ignore_errors=True); os.makedirs(OUT)
n_posts = n_files = 0
for url, v in sorted(res.items()):
    if not v: continue
    slug = url.rstrip('/').split('/')[-1]
    d = os.path.join(OUT, slug); os.makedirs(d)
    files = {}
    for i, (kind, code) in enumerate(v['blocks'], 1):
        name = f'{i:02d}-{kind}.xml'
        open(os.path.join(d, name), 'w').write(code)
        files[name] = hashlib.sha256(code.encode()).hexdigest()[:16]
    json.dump({'url': url, 'title': v['title'], 'published': v['published'], 'modified': v['modified'], 'files': files},
              open(os.path.join(d, 'post.json'), 'w'), indent=1, ensure_ascii=False)
    n_posts += 1; n_files += len(files)
json.dump({'repo': 'wazuh.com/blog', 'url': BLOG, 'license': '© Wazuh, Inc. (blog; origem citada)', 'retrieved': datetime.date.today().isoformat(),
           'posts': n_posts, 'failed': failed}, open(os.path.join(OUT, 'SNAPSHOT.json'), 'w'), indent=1)
print(f'{len(urls)} artigos, {n_posts} com XML, {n_files} blocos; {len(failed)} falharam')
