#!/usr/bin/env bash
# check.sh <marketplace ECR registry>: renders the chart the way an EKS
# add-on is rendered (helm template, no cluster) with this folder's values,
# and checks what AWS's add-on tooling checks before a listing: no Helm
# hooks, no .Capabilities, lookup only where these values never render it,
# every image from the Marketplace registry, and a configuration schema
# whose settings the chart has.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
chart="$root/charts/aerolvm"
reg="${1:?usage: check.sh <marketplace ECR registry, such as 709825985650.dkr.ecr.us-east-1.amazonaws.com/aerol>}"
helm="${HELM:-helm}"
fail() { echo "check.sh: $*" >&2; exit 1; }

grep -rn "helm.sh/hook" "$chart/templates" && fail "a Helm hook: EKS add-ons do not run hooks"
grep -rnE "\.Capabilities" "$chart/templates" && fail ".Capabilities: an add-on renders without the cluster"
for f in $(grep -rlE "(^|[^a-zA-Z])lookup " "$chart/templates"); do
  [ "$(basename "$f")" = secret.yaml ] || fail "lookup in $f: an add-on renders without the cluster"
done

render() { "$helm" template aerolvm "$chart" --namespace aerolvm-system -f "$here/values.yaml" --set image.registry="$reg" "$@"; }
for args in "" "--set edge.enabled=true --set edge.domain=sandbox.example.com --set edge.certManager.issuerRef.name=letsencrypt" "-f $here/values-cluster-example.yaml"; do
  # shellcheck disable=SC2086
  out="$(render $args)" || fail "helm template failed with: ${args:-the add-on values}"
  if grep -q "SB_PAT_TOKEN: " <<<"$out"; then
    fail "the chart made its own API token (the lookup path) with: ${args:-the add-on values}"
  fi
  while read -r img; do
    [ -z "$img" ] && continue
    case "$img" in "$reg"/*) ;; *) fail "image $img is not from $reg" ;; esac
  done < <(grep -oE 'image: *"?[^" ]+' <<<"$out" | sed -E 's/image: *"?//' | sort -u)
done

python3 - "$here/configuration-schema.json" "$chart/values.yaml" <<'PY'
import json, re, sys
schema = json.load(open(sys.argv[1]))
values = open(sys.argv[2]).read()
def keys(props, path):
    for k, v in props.items():
        yield path + [k]
        if v.get("type") == "object" and "properties" in v:
            yield from keys(v["properties"], path + [k])
missing = []
for path in keys(schema["properties"], []):
    # Each key must appear in values.yaml at its depth (two spaces a level).
    indent = "  " * (len(path) - 1)
    if not re.search(r"(?m)^" + re.escape(indent) + re.escape(path[-1]) + r":", values):
        missing.append(".".join(path))
if missing:
    sys.exit("check.sh: the schema names settings the chart does not have: " + ", ".join(missing))
PY
echo "check.sh: the chart renders as an EKS add-on, every image from $reg"
