#!/usr/bin/env bash
# Clona as fontes (tools/sources.txt) para .cache/src, as bibliotecas de playbooks (tools/playbooks.txt) para .cache/playbooks
# e as referências de cobertura (tools/references.txt, p.ex. SigmaHQ) para .cache/refs,
# no commit fixado em tools/sources.lock, e o ruleset oficial 4.x para .cache/official.
# UPDATE=1 ./tools/fetch.sh avança todas as fontes para o HEAD atual e reescreve o lock (e a data as-of).
# Clones sem blobs (--filter=blob:none): histórico completo e barato, necessário para datar a introdução de cada ficheiro.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="$ROOT/.cache"; mkdir -p "$CACHE/src"
LOCK="$ROOT/tools/sources.lock"; touch "$LOCK"
OFFICIAL_TAG="${OFFICIAL_TAG:-v4.14.8}"
UPDATE="${UPDATE:-0}"
pinned() { awk -v r="$1" '$1==r {print $2}' "$LOCK"; }
asof="$(awk '/^# as-of:/ {print $3}' "$LOCK")"
[[ "$UPDATE" == 1 || -z "$asof" ]] && asof="$(date +%F)"
new_lock="$(mktemp)"; : > "$CACHE/failed.txt"

fetch_list() {   # $1 = lista de repositórios, $2 = diretório de destino
mkdir -p "$2"
while read -r repo; do
  [[ -z "$repo" || "$repo" == \#* ]] && continue
  dir="$2/${repo//\//_}"
  pin="$(pinned "$repo")"
  # caches antigos (clone --depth 1) não têm histórico: recomeçar
  if [[ -d "$dir/.git" && "$(git -C "$dir" rev-parse --is-shallow-repository)" == true ]]; then rm -rf "$dir"; fi
  if [[ -d "$dir/.git" ]]; then
    git -C "$dir" fetch -q origin || echo "WARN: fetch falhou em $repo"
  elif ! GIT_TERMINAL_PROMPT=0 git clone -q --filter=blob:none --no-checkout "https://github.com/$repo.git" "$dir"; then
    echo "WARN: clone falhou em $repo"; echo "$repo" >> "$CACHE/failed.txt"; rm -rf "$dir"
    [[ -n "$pin" ]] && echo "$repo $pin" >> "$new_lock"
    continue
  fi
  if [[ "$UPDATE" == 1 || -z "$pin" ]]; then
    [[ -z "$pin" && "$UPDATE" != 1 ]] && echo "WARN: $repo sem commit fixado; a usar o HEAD"
    target="origin/HEAD"
  else
    target="$pin"
  fi
  if ! git -C "$dir" -c advice.detachedHead=false checkout -q --detach "$target"; then
    echo "WARN: commit $target inexistente em $repo"; echo "$repo" >> "$CACHE/failed.txt"
    echo "$repo $pin" >> "$new_lock"; continue
  fi
  echo "$repo $(git -C "$dir" rev-parse HEAD)" >> "$new_lock"
done < "$1"
}
fetch_list "$ROOT/tools/sources.txt" "$CACHE/src"
fetch_list "$ROOT/tools/playbooks.txt" "$CACHE/playbooks"
fetch_list "$ROOT/tools/references.txt" "$CACHE/refs"

{ echo "# as-of: $asof"
  echo "# <repo> <commit> — gerado por tools/fetch.sh; UPDATE=1 ./tools/fetch.sh avança para o HEAD atual"
  sort -f "$new_lock"; } > "$LOCK"
rm -f "$new_lock"

if [[ ! -d "$CACHE/official/.git" ]]; then
  git clone -q --depth 1 --filter=blob:none --sparse -b "$OFFICIAL_TAG" https://github.com/wazuh/wazuh.git "$CACHE/official"
  git -C "$CACHE/official" sparse-checkout set ruleset
fi
echo "OK ($(wc -l < "$CACHE/failed.txt" | tr -d ' ') falhas). Agora: python3 tools/build.py --src .cache/src --official .cache/official/ruleset --out ."
