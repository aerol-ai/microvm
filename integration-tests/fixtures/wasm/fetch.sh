#!/usr/bin/env bash
# fetch.sh — download + verify the curated WASM language runtimes listed in
# modules.yml into this directory. The .wasm files are gitignored, so run this
# once locally if you want the modules on disk (e.g. to push them to AOCR or to
# inspect them). Deployment does NOT need this — run.sh splices the same
# url+digest into config wasm.standard_modules and nodes fetch them at boot.
#
# Idempotent: a file already present with the right sha256 is skipped.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${HERE}/modules.yml"
command -v yq >/dev/null || { echo "yq required" >&2; exit 1; }

sha_cmd() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

count=$(yq -r '.standard_modules | length' "$MANIFEST")
for i in $(seq 0 $((count - 1))); do
  ref=$(yq -r ".standard_modules[$i].ref" "$MANIFEST")
  digest=$(yq -r ".standard_modules[$i].digest" "$MANIFEST" | sed 's/^sha256://')
  file="${HERE}/$(basename "${ref%\?*}")"

  if [[ -f "$file" && "$(sha_cmd "$file")" == "$digest" ]]; then
    echo "ok (cached) $(basename "$file")"
    continue
  fi
  echo "fetching $(basename "$file") ..."
  curl -fsSL --max-time 300 -o "$file" "$ref"
  got=$(sha_cmd "$file")
  if [[ "$got" != "$digest" ]]; then
    echo "DIGEST MISMATCH for $file: got $got, want $digest" >&2
    rm -f "$file"
    exit 1
  fi
  echo "ok (verified) $(basename "$file")"
done
echo "all modules present and verified in ${HERE}"
