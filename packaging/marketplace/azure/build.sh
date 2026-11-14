#!/usr/bin/env bash
# build.sh <release tag>: lays the Azure Marketplace package out in ./build
# (the chart, manifest.yaml, createUiDefinition.json, mainTemplate.json),
# names every image by the release's linux/amd64 digest under
# global.azure.images, and runs `cpa verify`, Microsoft's packaging check,
# in Docker. Uploading (`cpa buildbundle`) is the seller's step
# (../README.md).
set -euo pipefail
tag="${1:?usage: build.sh <release tag, such as v0.7.3>}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
out="$here/build"
fail() { echo "build.sh: $*" >&2; exit 1; }

rm -rf "$out"
mkdir -p "$out"
cp -R "$root/charts/aerolvm" "$out/aerolvm"
cp "$here/manifest.yaml" "$here/createUiDefinition.json" "$here/mainTemplate.json" "$out/"

# The amd64 image of each release image (the Marketplace takes amd64 only).
# From the registry's API with an anonymous pull token: the images are
# public, and no local docker login or buildx is needed. Each answer is
# read into a variable before python3 parses it: curl piped into python3
# reads to Scorecard as a download run by an interpreter (Pinned-Dependencies,
# "downloadThenRun"), though python3 only reads JSON here.
amd64_digest() {
  local tok index
  tok="$(curl -fsSL "https://ghcr.io/token?scope=repository:aerol-ai/$1:pull")" || return 1
  tok="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])' <<<"$tok")" || return 1
  index="$(curl -fsSL -H "Authorization: Bearer $tok" \
    -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
    "https://ghcr.io/v2/aerol-ai/$1/manifests/$tag")" || return 1
  python3 -c '
import json, sys
d = json.load(sys.stdin)
for m in d.get("manifests", []):
    p = m.get("platform", {})
    if p.get("os") == "linux" and p.get("architecture") == "amd64":
        print(m["digest"]); break
else:
    sys.exit("no linux/amd64 image")' <<<"$index"
}
values="$(cat "$here/values-azure.yaml")"
for img in aerolvm aerolvm-runtime aerolvm-edge aerolvm-operator; do
  d="$(amd64_digest "$img")" || fail "ghcr.io/aerol-ai/$img:$tag has no linux/amd64 image"
  values="$(VALUES="$values" python3 - "$img" "$d" <<'PY'
import os, re, sys
img, digest = sys.argv[1], sys.argv[2]
s = os.environ["VALUES"]
s = re.sub(r'(?m)(^      ' + re.escape(img) + r':\n(?:        .*\n)*?        digest: )""', lambda m: m.group(1) + '"' + digest + '"', s, count=1)
sys.stdout.write(s)
PY
)"
done
grep -q 'digest: ""' <<<"$values" && fail "an image has no digest"
# The chart's own values have no global key; the package's gain one.
printf '\n%s\n' "$values" >> "$out/aerolvm/values.yaml"

docker run --rm -v "$out":/data/aerolvm-cnab -w /data/aerolvm-cnab \
  --entrypoint cpa mcr.microsoft.com/container-package-app:latest verify
echo "build.sh: $out is verified; run cpa buildbundle there to upload it"
