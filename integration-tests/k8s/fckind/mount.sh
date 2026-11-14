#!/bin/bash
# mount.sh: external storage in the split worker pod, checked live on kind.
# userdata.sh sources it for AEROL_FCKIND_PROOF=mount, after
# scripts/k8s-dev.sh brought up single mode (one worker pod, aerolvm-0).
#
# proof_mount (finding F13, eng review OV-E2): a gVisor sandbox gets an
# rclone mount of a folder in the agent container (rclone's local backend,
# standing in for a remote store, as OV-E2 did). What it writes must reach
# the store, keep reaching it across an agent restart (the helper runs in
# the runtime container's group and the next agent adopts it), and the
# pod's end must leave no mount on the machine.
proof_mount() {
  local k="kubectl --context kind-aerolvm -n aerolvm" pod=aerolvm-0 port=21294 pf="" tok id out body
  tok=$($k get secret -o json | python3 -c 'import json,sys,base64
for s in json.load(sys.stdin)["items"]:
    d=s.get("data") or {}
    if "SB_PAT_TOKEN" in d: print(base64.b64decode(d["SB_PAT_TOKEN"]).decode()); break')
  fwdm() {
    for _ in $(seq 1 30); do
      [ -n "$pf" ] && kill $pf 2>/dev/null
      $k port-forward pod/$pod $port:21212 >/dev/null 2>&1 & pf=$!
      sleep 2
      curl -fsS -m 3 -o /dev/null http://127.0.0.1:$port/health 2>/dev/null && return 0
    done
    return 1
  }
  fwdm || { say "RESULT FAIL: mount: the API never answered"; return; }
  api() { curl -sS -m 300 -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
  ex() { api -X POST http://127.0.0.1:$port/v1/sandboxes/$id/toolbox/process/execute \
    -d "$(python3 -c 'import json, sys; print(json.dumps({"command": sys.argv[1]}))' "$1")" | head -c 400; }
  storelines() { $k exec $pod -c agent -- sh -c 'wc -l < /var/lib/sandboxd/ext-store/log.txt 2>/dev/null || echo 0' 2>/dev/null | tr -d ' \r'; }
  helper() { $k exec $pod -c agent -- sh -c 'for p in $(pgrep -f "^rclone mount"); do echo "pid $p cgroup $(sed -n "s/^0:://p" /proc/$p/cgroup)"; done' 2>&1 | tr '\n' ' '; }
  say "mount tools in the agent image: $($k exec $pod -c agent -- sh -c 'for t in rclone sshfs mount-s3 fusermount3 mount.nfs; do command -v $t >/dev/null && printf "%s " $t || printf "MISSING-%s " $t; done' 2>&1)"
  $k exec $pod -c agent -- sh -c 'mkdir -p /var/lib/sandboxd/ext-store && echo seed-ok > /var/lib/sandboxd/ext-store/seed.txt'
  body=$(python3 -c 'import json; print(json.dumps({"runtime": "gvisor", "image": "alpine:3.20", "mounts": [{"type": "rclone", "source": "store:/var/lib/sandboxd/ext-store", "target": "/mnt/ext", "credentials": {"rclone_conf": "[store]\ntype = local\n"}}]}))')
  out=$(api -X POST http://127.0.0.1:$port/v1/sandboxes -d "$body")
  id=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("id",""))' "$out" 2>/dev/null)
  say "mount create: $(head -c 300 <<<"$out")"
  if [ -z "$id" ]; then
    $k logs $pod -c agent 2>&1 | grep -iE 'mount|rclone|fuse' | tail -8 | cut -c1-300 | sed 's/^/FCK   agent: /'
    say "RESULT FAIL: mount: the create was refused"
    return
  fi
  local seed1 s1 s2 s3 seed2 h1 h2
  seed1=$(ex 'cat /mnt/ext/seed.txt')
  ex 'setsid nohup sh -c "i=0; while true; do i=\$((i+1)); echo \$i >> /mnt/ext/log.txt; sleep 1; done" </dev/null >/dev/null 2>&1 &' >/dev/null
  sleep 15
  s1=$(storelines)
  h1=$(helper)
  say "before the agent restart: the sandbox reads the store's seed: $seed1; the store has $s1 lines from it; helper: $h1"
  local node cid n r
  node=$($k get pod $pod -o jsonpath='{.spec.nodeName}')
  cid=$($k get pod $pod -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].containerID}' | sed 's#containerd://##')
  docker exec "$node" crictl --timeout 60s stop --timeout 30 "$cid" >/dev/null 2>&1
  for _ in $(seq 1 90); do
    n=$($k get pod $pod -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')
    r=$($k get pod $pod -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].ready}')
    [ "${n:-0}" -ge 1 ] && [ "$r" = true ] && break
    sleep 2
  done
  fwdm
  sleep 10
  s2=$(storelines)
  sleep 10
  s3=$(storelines)
  seed2=$(ex 'cat /mnt/ext/seed.txt')
  h2=$(helper)
  say "after the agent restart (restarts $n, ready $r): the store went $s2 -> $s3 lines; helper: $h2; the sandbox reads: $seed2"
  $k logs $pod -c agent 2>&1 | grep -iE 'adopt|reestablish|mount' | grep -v 'request complete' | tail -4 | cut -c1-260 | sed 's/^/FCK   agent after: /'
  if grep -q seed-ok <<<"$seed1" && [ "${s1:-0}" -ge 5 ] && grep -q '/sandboxes/aerolvm-mounts' <<<"$h1" && [ "$h1" = "$h2" ] &&
    [ "${s3:-0}" -gt "${s2:-0}" ] && [ "${s2:-0}" -gt "${s1:-0}" ] && grep -q seed-ok <<<"$seed2"; then
    say "RESULT PASS: mount: the sandbox's writes reach the store, before and across the agent restart, through one helper in the runtime container's group"
  else
    say "RESULT FAIL: mount: seed $seed1 / $seed2, store $s1 -> $s2 -> $s3, helper $h1 -> $h2"
  fi
  # The pod's end leaves no mount on the machine (as F8 for netns): the
  # supervisor unmounts the propagated ones.
  local uid t0 left
  uid=$($k get pod $pod -o jsonpath='{.metadata.uid}')
  t0=$(date +%s)
  $k delete pod $pod --wait=true --timeout=180s >/dev/null 2>&1
  left=$(docker exec "$node" sh -c "grep '$uid' /proc/self/mountinfo | grep -c fuse" 2>/dev/null)
  say "pod deleted in $(( $(date +%s) - t0 ))s; FUSE mounts of it left on the machine: ${left:-?}"
  if [ "${left:-1}" = 0 ] && [ $(( $(date +%s) - t0 )) -lt 180 ]; then say "RESULT PASS: mount: the pod's end left no mount on the machine"
  else say "RESULT FAIL: mount: pod end left ${left:-?} FUSE mounts"; fi
  kill $pf 2>/dev/null
}
