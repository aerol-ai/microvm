#!/bin/bash
# userdata.sh: Firecracker in the worker pod (Phase 5), on one EC2 machine
# with nested virtualization (spike S6's setting): kind, the chart built
# from the commit fckind.sh staged, and a proof that prints FCK lines to
# the serial console. No SSH and no inbound rule; the machine powers off
# when done, or after 100 minutes whatever happens (shutdown behaviour:
# terminate).
exec > >(tee /dev/console) 2>&1
shutdown -h +100
say() { echo "FCK $*"; }
# The console is read every 20 s from outside: stay up long enough after
# the last line for it to be read.
finish() { say "DONE"; sync; sleep 180; poweroff; }
export HOME=/root
cd /root

# The snapshot move (plan §10.5): a Firecracker VM on a worker that is
# decommissioned moves to another worker with its memory: the same guest
# boot ID answers there.
proof_move() {
  local kc="kubectl --context kind-aerolvm-cluster -n aerolvm-system"
  # Worker pods run in their own namespace (k8s-dev's cluster values).
  local kw="kubectl --context kind-aerolvm-cluster -n aerolvm-workers"
  local tok port=21298 pf=""
  tok="$($kc get secret aerolvm-admin -o jsonpath='{.data.token}' | base64 -d)"
  for _ in $(seq 1 30); do
    [ -n "$pf" ] && kill $pf 2>/dev/null
    $kc port-forward svc/aerolvm-gateway $port:21212 >/dev/null 2>&1 & pf=$!
    sleep 2
    curl -fsS -m 3 -o /dev/null http://127.0.0.1:$port/health 2>/dev/null && break
  done
  api() { curl -sS -m 900 -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
  members() { api http://127.0.0.1:$port/v1/cluster/members | python3 -c 'import json,sys; d=json.load(sys.stdin); m=d.get("members", d); print(" ".join(x["node_id"]+"/"+x.get("role","")+("/alive" if x.get("alive") else "") for x in m))'; }
  # The AerolCluster is Ready before every worker has joined gossip: a
  # move needs two.
  local m="" n=0 i
  for i in $(seq 1 120); do
    m=$(members 2>/dev/null)
    n=$(tr ' ' '\n' <<<"$m" | grep -c '/worker/alive')
    [ "$n" -ge 2 ] && break
    [ $((i % 12)) -eq 0 ] && say "waiting for workers ($((i * 5))s): $($kc get aerolnodes --no-headers 2>/dev/null | awk '$2 == "worker" {printf "%s/%s/%s ", $1, $4, $NF}')"
    sleep 5
  done
  say "members: $m"
  if [ "$n" -lt 2 ]; then
    $kc get aerolnodes -o wide 2>&1 | sed 's/^/FCK   /'
    $kw get pods -o wide 2>&1 | sed 's/^/FCK   /'
    $kw get events --sort-by=.lastTimestamp 2>&1 | tail -15 | cut -c1-250 | sed 's/^/FCK   event: /'
    for w in $($kw get pods -o name | head -2); do
      $kw describe $w 2>&1 | grep -A12 -E '^\s*(State|Last State):' | head -30 | sed "s|^|FCK   ${w#pod/} describe: |"
      $kw logs $w -c preflight 2>&1 | tail -8 | sed "s|^|FCK   ${w#pod/} preflight: |"
      { $kw logs $w -c setup 2>&1; $kw logs $w -c setup --previous 2>&1; } | tail -12 | cut -c1-300 | sed "s|^|FCK   ${w#pod/} setup: |"
      $kw logs $w -c agent 2>&1 | tail -15 | cut -c1-300 | sed "s|^|FCK   ${w#pod/} agent: |"
      $kw logs $w -c agent --previous 2>&1 | tail -10 | cut -c1-300 | sed "s|^|FCK   ${w#pod/} agent (previous): |"
    done
    $kc logs deploy/aerolvm-operator 2>&1 | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        d = json.loads(line)
    except ValueError:
        continue
    if d.get("level") == "error":
        print((d.get("AerolNode") or d.get("AerolCluster") or {}).get("name", "?"), d.get("error", "")[:240])' | sort | uniq -c | tail -8 | sed 's/^/FCK   operator error: /'
    return
  fi
  local out id="" owner owner2
  # A worker that just joined has not reported its capacity yet: the
  # create waits for one that has.
  for i in $(seq 1 18); do
    out=$(api -X POST http://127.0.0.1:$port/v1/sandboxes -d '{"runtime":"firecracker","image":"alpine:3.20","cpu":1,"memory_mb":512}')
    id=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("id",""))' "$out" 2>/dev/null)
    [ -n "$id" ] && break
    grep -q "no worker placement target" <<<"$out" || break
    sleep 10
  done
  say "create (try $i): $(head -c 240 <<<"$out")"
  if [ -z "$id" ]; then
    api http://127.0.0.1:$port/v1/cluster/members | python3 -c '
import json, sys
d = json.load(sys.stdin)
for m in d.get("members", d):
    if m.get("role") != "worker":
        continue
    c = m.get("capacity") or {}
    print(m["node_id"], "alive" if m.get("alive") else "dead", "stale" if m.get("capacity_stale") else "fresh",
          "can_admit=%s" % c.get("can_admit"), "runtimes=%s" % c.get("supported_runtimes"), "labels=%s" % c.get("labels"))' | sed 's/^/FCK   worker: /'
    return
  fi
  ex() { api -X POST http://127.0.0.1:$port/v1/sandboxes/$id/toolbox/process/execute \
    -d "$(python3 -c 'import json, sys; print(json.dumps({"command": sys.argv[1]}))' "$1")" | head -c 300; }
  # A process that counts on, to show it kept running across the move.
  ex 'nohup sh -c "i=0; while true; do i=\$((i+1)); echo \$i > /tmp/counter; sleep 1; done" >/dev/null 2>&1 &' >/dev/null
  sleep 3
  say "before: $(ex 'echo boot-$(cut -c1-8 /proc/sys/kernel/random/boot_id) counter-$(cat /tmp/counter)')"
  owner=$(api http://127.0.0.1:$port/v1/cluster/placements/$id | python3 -c 'import json,sys; d=json.load(sys.stdin); o=d.get("owner"); print(o.get("node_id") if isinstance(o, dict) else (o or d.get("owner_node_id","")))')
  say "owner before: $owner"
  say "cordon: $(api -X POST http://127.0.0.1:$port/v1/cluster/nodes/$owner/cordon | head -c 200)"
  local t0=$(date +%s)
  for i in $(seq 1 20); do
    out=$(api -X POST http://127.0.0.1:$port/v1/cluster/nodes/$owner/evacuate -d '{"max":8}')
    say "evacuate pass $i: $(head -c 300 <<<"$out")"
    grep -q '"moved":\["'"$id"'"\]\|"done":true' <<<"$out" && break
    sleep 5
  done
  say "move took $(( $(date +%s) - t0 ))s"
  # What a move carries: each snapshot file's allocated and full size.
  $kw exec "$owner" -c agent -- sh -c "ls -ls /var/lib/sandboxd/firecracker/templates/_sandboxes/$id/ 2>&1" 2>&1 | tail -6 | sed 's/^/FCK   source files: /'
  owner2=$(api http://127.0.0.1:$port/v1/cluster/placements/$id | python3 -c 'import json,sys; d=json.load(sys.stdin); o=d.get("owner"); print(o.get("node_id") if isinstance(o, dict) else (o or d.get("owner_node_id","")))')
  say "owner after: $owner2"
  local after
  after=$(api http://127.0.0.1:$port/v1/sandboxes/$id)
  say "sandbox after: $(head -c 200 <<<"$after")"
  # The leader logs the move's steps (it runs on a server).
  for sv in aerolvm-server-0 aerolvm-server-1 aerolvm-server-2; do
    $kc logs $sv 2>/dev/null | grep -E 'snapshot move|decommission pass' | tail -4 | cut -c1-400 | sed "s|^|FCK   $sv: |"
  done
  if grep -q '"status":"stopped"' <<<"$after"; then
    # Moved but not started: a start restores it on the target.
    say "start on the target: $(api -X POST http://127.0.0.1:$port/v1/sandboxes/$id/start | head -c 200)"
  fi
  say "after: $(ex 'echo boot-$(cut -c1-8 /proc/sys/kernel/random/boot_id) counter-$(cat /tmp/counter)')"
  for w in $($kw get pods -o name); do
    $kw logs $w -c agent 2>/dev/null | grep -E 'snapshot move|move (import|export)|moved' | tail -3 | cut -c1-300 | sed "s|^|FCK   ${w#pod/}: |"
  done
}

[ -e /dev/kvm ] || modprobe kvm_intel 2>/dev/null
if [ -e /dev/kvm ]; then say "machine: /dev/kvm present, $(grep -c -w vmx /proc/cpuinfo) cpus with vmx, kernel $(uname -r)"; else say "machine: /dev/kvm ABSENT"; finish; fi

say "installing docker and the tools"
dnf -y -q install docker git tar gzip iptables perl-Digest-SHA >/dev/null 2>&1 || say "dnf install failed"
systemctl start docker || { say "docker did not start"; finish; }
pinned() { # <file> <url> <sha256>
  curl -fsSL --retry 5 -o "$1" "$2" && echo "$3  $1" | sha256sum -c --quiet - || { say "download failed or checksum wrong: $2"; finish; }
}
pinned go.tgz https://go.dev/dl/go1.26.11.linux-amd64.tar.gz 9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec
tar -C /usr/local -xzf go.tgz
pinned helm.tgz https://get.helm.sh/helm-v3.22.1-linux-amd64.tar.gz 896cf63684a42a723d61c980369d6e588330927deb13676ca0d85006dd6da0ea
tar -xzf helm.tgz linux-amd64/helm && install -m 0755 linux-amd64/helm /usr/local/bin/helm
pinned /usr/local/bin/kind https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64 aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
pinned /usr/local/bin/kubectl https://dl.k8s.io/release/v1.37.0/bin/linux/amd64/kubectl 6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f
mkdir -p /usr/local/lib/docker/cli-plugins
pinned /usr/local/lib/docker/cli-plugins/docker-buildx https://github.com/docker/buildx/releases/download/v0.39.0/buildx-v0.39.0.linux-amd64 5fb31a097304fbf6dd4038649a0decf32c2b9510e4047acd7d68b9d700c46194
chmod 0755 /usr/local/bin/kind /usr/local/bin/kubectl /usr/local/lib/docker/cli-plugins/docker-buildx
export PATH=/usr/local/go/bin:/usr/local/bin:$PATH GOTOOLCHAIN=auto

say "tools ready: $(go version | cut -d' ' -f3), helm $(helm version --short), kind $(kind version | cut -d' ' -f2), $(docker buildx version | cut -d' ' -f2)"
mkdir -p src && curl -fsSL --retry 5 '@SRC_URL@' | tar -xz -C src || { say "source download failed"; finish; }
cd src
proof='@PROOF@'
if [ "$proof" = move ]; then
  # Cluster mode, every worker a Firecracker worker: this machine is one
  # KVM pool. The chart's defaults change in this copy only.
  python3 - <<'PY'
import re
p = "charts/aerolvm/values.yaml"
s = open(p).read()
s = s.replace("  firecracker:\n    enabled: false", "  firecracker:\n    enabled: true", 1)
s = re.sub(r'(?m)^  diskFloorRatio: "[0-9.]+"', '  diskFloorRatio: "0"', s, count=1)
open(p, "w").write(s)
PY
  grep -A1 '^  firecracker:' charts/aerolvm/values.yaml | sed 's/^/FCK chart: /'
  # The dev pool advertises its runtimes (SB_HOST_RUNTIMES); placement
  # sends a Firecracker create only to a pool that names it.
  sed -i 's/runtimes: \[runc, gvisor\]/runtimes: [runc, gvisor, firecracker]/' scripts/k8s-dev.sh
  grep 'runtimes:' scripts/k8s-dev.sh | sed 's/^/FCK pool: /'
  export AEROL_K8S_MODE=cluster
fi
git init -q && git add -A >/dev/null 2>&1 && git -c user.email=fck@localhost -c user.name=fck commit -qm src >/dev/null 2>&1
say "building the images and starting kind ($proof)"
t0=$(date +%s)
if ! scripts/k8s-dev.sh > /root/k8s-dev.log 2>&1; then say "k8s-dev failed:"; tail -20 /root/k8s-dev.log | sed 's/^/FCK   /'; finish; fi
say "built and installed in $(( $(date +%s) - t0 ))s"
[ "$proof" = move ] && { proof_move; finish; }

k() { kubectl --context kind-aerolvm -n aerolvm "$@"; }
pod=aerolvm-0
helm --kube-context kind-aerolvm upgrade aerolvm charts/aerolvm -n aerolvm --reuse-values \
  --set worker.firecracker.enabled=true --set worker.diskFloorRatio=0 >/dev/null
k delete pod $pod --wait=true >/dev/null
sleep 5
if ! k wait --for=condition=Ready pod/$pod --timeout=300s >/dev/null; then
  say "worker not ready:"; k describe pod $pod | tail -15 | sed 's/^/FCK   /'
  k logs $pod -c preflight 2>&1 | tail -10 | sed 's/^/FCK   preflight: /'
  k logs $pod -c agent 2>&1 | tail -15 | sed 's/^/FCK   agent: /'
  finish
fi
say "pod: shareProcessNamespace=$(k get pod $pod -o jsonpath='{.spec.shareProcessNamespace}')"
k logs $pod -c preflight 2>&1 | grep -i kvm | sed 's/^/FCK preflight: /'
say "agent: $(k exec $pod -c agent -- firecracker --version 2>&1 | head -1); $(k exec $pod -c agent -- sh -c 'ls -l /dev/kvm' 2>&1)"

tok=$(k get secret -o json | python3 -c 'import json,sys,base64
for s in json.load(sys.stdin)["items"]:
    d=s.get("data") or {}
    if "SB_PAT_TOKEN" in d: print(base64.b64decode(d["SB_PAT_TOKEN"]).decode()); break')
port=21299
fwd() {
  for _ in $(seq 1 30); do
    [ -n "${pf:-}" ] && kill $pf 2>/dev/null
    k port-forward pod/$pod $port:21212 >/dev/null 2>&1 & pf=$!
    sleep 2
    curl -fsS -m 3 -o /dev/null http://127.0.0.1:$port/health 2>/dev/null && return 0
  done
  return 1
}
fwd || { say "the API never answered"; finish; }
api() { curl -sS -m 600 -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
say "health: $(api http://127.0.0.1:$port/health | head -c 300)"
t0=$(date +%s%N)
out=$(api -X POST http://127.0.0.1:$port/v1/sandboxes -d '{"runtime":"firecracker","image":"alpine:3.20","cpu":1,"memory_mb":512}')
id=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("id",""))' "$out" 2>/dev/null)
say "create (cold, image to disk): $(( ($(date +%s%N) - t0) / 1000000 )) ms: $(head -c 300 <<<"$out")"
if [ -z "$id" ]; then
  k logs $pod -c agent 2>&1 | grep -iE 'firecracker|vmm|tap|jailer|error' | grep -v 'request complete\|ssh handshake' | tail -8 | cut -c1-400 | sed 's/^/FCK   agent: /'
  k exec $pod -c agent -- sh -c 'ip -d link show 2>&1 | grep -A2 fctap; echo "sandboxd netns $(readlink /proc/$(pgrep -x sandboxd | head -1)/ns/net), agent netns $(readlink /proc/self/ns/net)"; ls -ln /dev/net/tun' 2>&1 | sed 's/^/FCK   diag: /'
  finish
fi
ex() { api -X POST http://127.0.0.1:$port/v1/sandboxes/$id/toolbox/process/execute -d "{\"command\":\"$1\"}" | head -c 300; }
say "exec before: $(ex 'echo booted-$(cat /proc/sys/kernel/random/boot_id | cut -c1-8) && uname -r')"
vmm() { k exec $pod -c agent -- sh -c 'for p in $(pgrep -x firecracker); do echo "$p=$(sed -n "s#^0::.*/sandboxes/##p" /proc/$p/cgroup)"; done' | tr '\n' ' '; }
before=$(vmm)
say "VMs before: $before"

node=$(k get pod $pod -o jsonpath='{.spec.nodeName}')
cid=$(k get pod $pod -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].containerID}' | sed 's#containerd://##')
t0=$(date +%s); docker exec "$node" crictl --timeout 60s stop --timeout 30 "$cid" >/dev/null 2>&1; say "agent stop took $(( $(date +%s) - t0 ))s"
for _ in $(seq 1 60); do
  n=$(k get pod $pod -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')
  r=$(k get pod $pod -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].ready}')
  [ "${n:-0}" -ge 1 ] && [ "$r" = true ] && break
  sleep 2
done
after=$(vmm)
say "agent restarts $n, ready $r; VMs after: $after"
fwd
say "sandbox after: $(api http://127.0.0.1:$port/v1/sandboxes/$id | head -c 200)"
say "exec after: $(ex 'echo still-$(cat /proc/sys/kernel/random/boot_id | cut -c1-8)')"
say "adoption: $(k logs $pod -c agent 2>&1 | grep -iE 'adopt|taken over' | grep -i -E 'vm|firecracker' | tail -3 | tr '\n' ' ')"
if [ "${n:-0}" -ge 1 ] && [ "$r" = true ] && [ -n "$before" ] && [ "$before" = "$after" ]; then say "RESULT PASS: the agent restarted and the same VM runs on"; else say "RESULT FAIL"; fi
finish
