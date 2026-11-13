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
# proof_move <runtime>: a sandbox of that runtime (firecracker, or gvisor
# for C21) moves to another worker with its memory during a decommission.
proof_move() {
  local runtime="$1"
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
    out=$(api -X POST http://127.0.0.1:$port/v1/sandboxes -d '{"runtime":"'"$runtime"'","image":"alpine:3.20","cpu":1,"memory_mb":512}')
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
  # setsid: out of the exec's session, so nothing that ends the exec's
  # process group ends the counter.
  ex 'setsid nohup sh -c "i=0; while true; do i=\$((i+1)); echo \$i > /tmp/counter; sleep 1; done" </dev/null >/dev/null 2>&1 &' >/dev/null
  sleep 3
  say "before: $(ex 'echo boot-$(cut -c1-8 /proc/sys/kernel/random/boot_id) counter-$(cat /tmp/counter)')"
  sleep 3
  say "before, 3 s on: $(ex 'echo boot-$(cut -c1-8 /proc/sys/kernel/random/boot_id) counter-$(cat /tmp/counter)')"
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
  local dir=/var/lib/sandboxd/firecracker/templates/_sandboxes/$id
  [ "$runtime" = gvisor ] && dir=/var/lib/sandboxd/containerd/moves/out/$id
  $kw exec "$owner" -c agent -- sh -c "ls -ls $dir/ 2>&1" 2>&1 | tail -6 | sed 's/^/FCK   source files: /'
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
  # A gateway's owner view and the resumed guest's network both settle
  # within seconds of the swap.
  local res
  for i in $(seq 1 15); do
    res=$(ex 'echo boot-$(cut -c1-8 /proc/sys/kernel/random/boot_id) counter-$(cat /tmp/counter)')
    grep -q '"exit_code":0' <<<"$res" && break
    sleep 2
  done
  say "after (try $i): $res"
  sleep 3
  say "after, 3 s on: $(ex 'echo boot-$(cut -c1-8 /proc/sys/kernel/random/boot_id) counter-$(cat /tmp/counter)')"
  if ! grep -q '"exit_code":0' <<<"$res"; then
    for w in $($kw get pods -o name); do
      $kw logs $w -c agent 2>&1 | grep -iE 'restore|resume|toolbox|firecracker|snapshot|move' | grep -v 'request complete' | tail -6 | cut -c1-300 | sed "s|^|FCK   ${w#pod/}: |"
    done
  fi
  for w in $($kw get pods -o name); do
    $kw logs $w -c agent 2>/dev/null | grep -E 'snapshot move|move (import|export)|moved|restore|checkpoint' | tail -4 | cut -c1-300 | sed "s|^|FCK   ${w#pod/}: |"
  done
}

# The agent-sandbox API (C17): with cluster.agentSandboxAPI on, kubectl
# reaches the gateways through the APIService: create a Sandbox, wait for
# Ready, watch it stop and start again (the workers' run-state reports),
# check RBAC refuses a viewer's delete, delete it.
proof_kubeapi() {
  local kk="kubectl --context kind-aerolvm-cluster"
  local kc="$kk -n aerolvm-system"
  local ok=1 i
  dumpapi() {
    $kk get apiservice v1beta1.agents.x-k8s.io -o yaml 2>&1 | sed -n '/^status:/,$p' | head -20 | sed 's/^/FCK   apiservice: /'
    $kc get certificate,secret 2>&1 | grep -i agent-sandbox | sed 's/^/FCK   cert: /'
    for g in $($kc get pods -l app.kubernetes.io/component=gateway -o name); do
      $kc logs $g -c agent 2>&1 | grep -iE 'agent-sandbox|kubeapi|front-proxy|subjectaccess' | tail -8 | cut -c1-300 | sed "s|^|FCK   ${g#pod/}: |"
    done
  }
  for i in $(seq 1 60); do
    [ "$($kk get apiservice v1beta1.agents.x-k8s.io -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' 2>/dev/null)" = True ] && break
    sleep 5
  done
  say "APIService available after $((i * 5))s: $($kk get apiservice v1beta1.agents.x-k8s.io --no-headers 2>&1 | head -1)"
  say "api-resources: $($kk api-resources --api-group=agents.x-k8s.io --no-headers 2>&1 | tr -s ' ' | head -3 | tr '\n' ';')"
  $kk create namespace dev >/dev/null 2>&1
  # A worker that just joined has not reported its capacity yet: retry the
  # create (the API answers what AerolVM's create answers).
  local out
  for i in $(seq 1 18); do
    out=$($kk apply -f - 2>&1 <<'YAML'
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata: { name: web, namespace: dev, labels: { app: proof } }
spec:
  podTemplate:
    spec:
      runtimeClassName: gvisor
      containers:
        - name: main
          image: alpine:3.20
          command: ["sleep", "infinity"]
          resources: { limits: { cpu: "1", memory: 512Mi } }
YAML
)
    grep -q created <<<"$out" && break
    sleep 10
  done
  say "create (try $i): $(tr '\n' ' ' <<<"$out" | head -c 300)"
  grep -q created <<<"$out" || { ok=0; dumpapi; }
  $kk -n dev wait --for=condition=Ready sandbox/web --timeout=180s 2>&1 | sed 's/^/FCK wait ready: /'
  say "get: $($kk -n dev get sandboxes -o wide 2>&1 | tr -s ' ' | tr '\n' ';' | head -c 400)"
  say "all namespaces: $($kk get sandboxes -A --no-headers 2>&1 | tr -s ' ' | tr '\n' ';' | head -c 300)"
  # Watch while it stops and starts again.
  timeout 120 $kk -n dev get sandboxes --watch -o custom-columns=NAME:.metadata.name,RV:.metadata.resourceVersion,MODE:.spec.operatingMode,READY:'.status.conditions[?(@.type=="Ready")].status' > /root/watch.log 2>&1 &
  local wpid=$!
  sleep 3
  say "suspend: $($kk -n dev patch sandbox web --type merge -p '{"spec":{"operatingMode":"Suspended"}}' 2>&1 | head -c 200)"
  $kk -n dev wait --for=condition=Suspended sandbox/web --timeout=120s 2>&1 | sed 's/^/FCK wait suspended: /'
  say "resume: $($kk -n dev patch sandbox web --type merge -p '{"spec":{"operatingMode":"Running"}}' 2>&1 | head -c 200)"
  $kk -n dev wait --for=condition=Ready sandbox/web --timeout=120s 2>&1 | sed 's/^/FCK wait ready again: /'
  sleep 3
  kill $wpid 2>/dev/null
  sed 's/^/FCK watch: /' /root/watch.log | head -20
  # RBAC: a viewer may read, not delete.
  $kk -n dev create serviceaccount viewer >/dev/null 2>&1
  $kk -n dev create role sandbox-viewer --verb=get,list,watch --resource=sandboxes.agents.x-k8s.io >/dev/null 2>&1
  $kk -n dev create rolebinding viewer --role=sandbox-viewer --serviceaccount=dev:viewer >/dev/null 2>&1
  sleep 2
  say "viewer get: $($kk -n dev --as=system:serviceaccount:dev:viewer get sandbox web --no-headers 2>&1 | tr -s ' ' | head -c 200)"
  say "viewer delete: $($kk -n dev --as=system:serviceaccount:dev:viewer delete sandbox web 2>&1 | head -c 250)"
  # Another team's namespace sees nothing of dev's.
  $kk create namespace other >/dev/null 2>&1
  say "other namespace: $($kk -n other get sandboxes 2>&1 | head -c 200)"
  local uid1
  uid1=$($kk -n dev get sandbox web -o jsonpath='{.metadata.uid}' 2>/dev/null)
  say "delete: $($kk -n dev delete sandbox web --timeout=120s 2>&1 | head -c 200)"
  for i in $(seq 1 24); do
    $kk -n dev get sandbox web >/dev/null 2>&1 || break
    sleep 5
  done
  say "after delete: $($kk -n dev get sandboxes 2>&1 | head -c 200)"
  # The same name again with another image (kubectl delete, then create):
  # the same sandbox ID, a new incarnation, shown with its own image.
  say "re-create: $($kk apply -f - 2>&1 <<'YAML' | tr '\n' ' '
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata: { name: web, namespace: dev }
spec:
  podTemplate:
    spec:
      runtimeClassName: gvisor
      containers:
        - { name: main, image: "busybox:1.36", command: ["sleep", "infinity"] }
YAML
)"
  $kk -n dev wait --for=condition=Ready sandbox/web --timeout=180s 2>&1 | sed 's/^/FCK wait re-created: /'
  say "re-created: uid $uid1 -> $($kk -n dev get sandbox web -o jsonpath='{.metadata.uid} {.spec.podTemplate.spec.containers[0].image}' 2>&1 | head -c 200)"
  say "re-created delete: $($kk -n dev delete sandbox web --timeout=120s 2>&1 | head -c 200)"
  # Upstream's own hello-world, from the release the API follows, with a
  # public image for its ${IMAGE}.
  local up=890de53a4dd18e35313173e6dc34d9559b1a9733
  if curl -fsSL "https://raw.githubusercontent.com/kubernetes-sigs/agent-sandbox/$up/examples/hello-world-sandbox/hello-world.yaml" -o /root/hello-world.yaml; then
    sed -i 's|\${IMAGE}|busybox:1.36|' /root/hello-world.yaml
    say "upstream hello-world: $($kk -n dev apply -f /root/hello-world.yaml 2>&1 | tr '\n' ' ' | head -c 200)"
    $kk -n dev wait --for=condition=Ready sandbox/hello-world --timeout=180s 2>&1 | sed 's/^/FCK wait hello-world: /'
    say "hello-world delete: $($kk -n dev delete sandbox hello-world --timeout=120s 2>&1 | head -c 200)"
  else
    say "upstream hello-world: could not fetch it"
  fi
  # The claim flow: a template, a warm pool, a claim that makes a sandbox.
  say "template and pool: $($kk apply -f - 2>&1 <<'YAML' | tr '\n' ' '
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxTemplate
metadata: { name: python, namespace: dev }
spec:
  # Claims may set env only when the template says so (upstream's default
  # is Disallowed; p6-kubeapi-7 showed the refusal).
  envVarsInjectionPolicy: Allowed
  podTemplate:
    spec:
      runtimeClassName: gvisor
      containers:
        - name: main
          image: python:3.12-alpine
          command: ["sleep", "infinity"]
---
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxWarmPool
metadata: { name: pool, namespace: dev }
spec: { replicas: 1, sandboxTemplateRef: { name: python } }
YAML
)"
  say "claim: $($kk apply -f - 2>&1 <<'YAML' | tr '\n' ' '
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata: { name: job, namespace: dev }
spec:
  warmPoolRef: { name: pool }
  env: [{ name: TASK, value: proof }]
YAML
)"
  $kk -n dev wait --for=condition=Ready sandboxclaim/job --timeout=240s 2>&1 | sed 's/^/FCK wait claim: /'
  say "claims: $($kk -n dev get sandboxclaims 2>&1 | tr -s ' ' | tr '\n' ';' | head -c 300)"
  say "claims by name: $($kk -n dev get sandboxclaims --field-selector metadata.name=nope --no-headers 2>&1 | head -c 200)"
  say "its sandbox: $($kk -n dev get sandbox job -o jsonpath='{.metadata.labels}' 2>&1 | head -c 300)"
  say "templates and pools: $($kk -n dev get sandboxtemplates,sandboxwarmpools --no-headers 2>&1 | tr -s ' ' | tr '\n' ';' | head -c 300)"
  say "claim delete: $($kk -n dev delete sandboxclaim job --timeout=120s 2>&1 | head -c 200)"
  [ "$ok" = 1 ] || return
  dumpapi
}

# External-CA mode (C23, plan §15.2.1): every node's certificate comes from
# a cert-manager CA issuer standing in for the bank's; no CA key and no
# join token anywhere. The cluster works on those certificates, a renewal
# keeps the key, and the join port refuses a second key for a node, a
# certificate with no role and one from another CA.
proof_externalca() {
  local kk="kubectl --context kind-aerolvm-cluster"
  local kc="$kk -n aerolvm-system" kw="$kk -n aerolvm-workers"
  local pass=1 i
  ok() { say "OK $*"; }
  bad() { say "BAD $*"; pass=0; }
  local mode
  mode=$($kc get aerolcluster aerolvm -o jsonpath='{.status.conditions[?(@.type=="ExternalCA")].status} {.status.conditions[?(@.type=="ExternalCA")].message}')
  [ "${mode%% *}" = True ] && ok "mode recorded: $mode" || bad "mode not recorded: $mode"
  say "nodes: $($kc get aerolnodes --no-headers 2>&1 | awk '{printf "%s/%s/%s ", $1, $2, $4}')"
  local nodes certs ready
  nodes=$($kc get aerolnodes --no-headers 2>/dev/null | wc -l)
  certs=$($kk get certificates -A -l app.kubernetes.io/managed-by=aerolvm-operator --no-headers 2>/dev/null | wc -l)
  ready=$($kk get certificates -A -l app.kubernetes.io/managed-by=aerolvm-operator --no-headers 2>/dev/null | awk '$3 == "True"' | wc -l)
  [ "$certs" -eq "$nodes" ] && [ "$ready" -eq "$nodes" ] && ok "certificates: $ready of $nodes nodes, all ready" || bad "certificates: $certs made, $ready ready, $nodes nodes"
  local waited
  waited=$($kc get events --field-selector involvedObject.kind=AerolNode -o jsonpath='{range .items[*]}{.message}{"\n"}{end}' 2>/dev/null | grep -c 'waiting for its certificate')
  say "nodes that waited for their certificate (events): $waited"
  local joins tokvols
  joins=$($kk get secrets -A --no-headers 2>/dev/null | awk '$2 ~ /-join$/' | wc -l)
  tokvols=$({ $kc get pods -o jsonpath='{range .items[*]}{range .spec.volumes[*]}{.name}{"\n"}{end}{end}'; $kw get pods -o jsonpath='{range .items[*]}{range .spec.volumes[*]}{.name}{"\n"}{end}{end}'; } 2>/dev/null | grep -cx join)
  [ "$joins" -eq 0 ] && [ "$tokvols" -eq 0 ] && ok "no join token: no -join Secret, no pod with a join volume" || bad "join tokens: $joins Secrets, $tokvols pod volumes"
  local s0=aerolvm-server-0
  say "server 0 TLS dir: $($kc exec $s0 -c agent -- ls /var/run/aerolvm-tls 2>&1 | tr '\n' ' ')"
  say "server 0 settings: $($kc exec $s0 -c agent -- sh -c 'grep -h "^SB_CLUSTER_EXTERNAL_CA\|^SB_CLUSTER_TLS_DIR" /etc/sandboxd/*.env' 2>&1 | sort -u | tr '\n' ' ')"
  # Counted in the pod, which always prints one number: arithmetic on
  # anything else would make bash drop the rest of this proof.
  local cakeys=0 p c
  for p in $($kc get pods -l app.kubernetes.io/component=server -o name); do
    c=$($kc exec ${p#pod/} -c agent -- sh -c 'ls -R /etc/sandboxd /var/lib/sandboxd /var/run/aerolvm-tls 2>/dev/null | grep -c "^ca\.key$"; true' 2>/dev/null | head -1)
    [[ "$c" =~ ^[0-9]+$ ]] || { bad "could not look for a CA key in ${p#pod/}"; c=0; }
    cakeys=$((cakeys + c))
  done
  [ "$cakeys" -eq 0 ] && ok "no CA key on any server" || bad "$cakeys ca.key files on the servers"
  local w
  w=$($kw get pods -l app.kubernetes.io/component=worker -o jsonpath='{.items[0].metadata.name}')
  crt() { $kw get secret "$w-cert" -o jsonpath='{.data.tls\.crt}' | base64 -d; }
  say "worker $w certificate: $(crt | openssl x509 -noout -issuer -serial -ext subjectAltName 2>&1 | tr -s ' \n' ' ' | head -c 400)"

  # The cluster works on these certificates: members, and a create through
  # a gateway to a worker (gateway-worker mutual TLS).
  local tok port=21297 pf=""
  tok="$($kc get secret aerolvm-admin -o jsonpath='{.data.token}' | base64 -d)"
  for _ in $(seq 1 30); do
    [ -n "$pf" ] && kill $pf 2>/dev/null
    $kc port-forward svc/aerolvm-gateway $port:21212 >/dev/null 2>&1 & pf=$!
    sleep 2
    curl -fsS -m 3 -o /dev/null http://127.0.0.1:$port/health 2>/dev/null && break
  done
  api() { curl -sS -m 300 -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
  members() { api http://127.0.0.1:$port/v1/cluster/members | python3 -c 'import json,sys; d=json.load(sys.stdin); m=d.get("members", d); print(" ".join(x["node_id"]+"/"+x.get("role","")+("/alive" if x.get("alive") else "") for x in m))'; }
  local m n
  for i in $(seq 1 60); do
    m=$(members 2>/dev/null); n=$(tr ' ' '\n' <<<"$m" | grep -c '/alive$')
    [ "$n" -ge "$nodes" ] && break
    sleep 5
  done
  [ "$n" -ge "$nodes" ] && ok "members: $n alive" || bad "members: $n alive of $nodes: $m"
  create() { # prints the new sandbox's ID, or nothing
    local out id
    for i in $(seq 1 18); do
      out=$(api -X POST http://127.0.0.1:$port/v1/sandboxes -d '{"runtime":"gvisor","image":"alpine:3.20","cpu":1,"memory_mb":256}')
      id=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("id",""))' "$out" 2>/dev/null)
      [ -n "$id" ] && break
      sleep 10
    done
    [ -n "$id" ] || say "create failed: $(head -c 300 <<<"$out")" >&2
    echo "$id"
  }
  exec_in() { api -X POST "http://127.0.0.1:$port/v1/sandboxes/$1/toolbox/process/execute" -d '{"command":"echo hello-from-$(hostname)"}' | head -c 200; }
  local id
  id=$(create)
  if [ -n "$id" ]; then
    local e; e=$(exec_in "$id")
    grep -q hello-from <<<"$e" && ok "create and exec through a gateway: $e" || bad "exec: $e"
    api -X DELETE "http://127.0.0.1:$port/v1/sandboxes/$id" >/dev/null
  else
    bad "no sandbox"
  fi
  local tj
  local tj
  tj=$(api -o /root/tj.out -w '%{http_code}' -X POST http://127.0.0.1:$port/v1/cluster/join-tokens -d '{"role":"worker","ttl":"10m","reusable":false}')
  [[ "$tj" != 20* ]] && ok "a join token is refused: HTTP $tj $(head -c 160 /root/tj.out)" || bad "a join token was made: HTTP $tj"

  # A renewal keeps the key; the pod sees the new certificate; the node
  # stays a live member.
  local serial1 key1 serial2 key2 now
  serial1=$(crt | openssl x509 -noout -serial); key1=$(crt | openssl x509 -noout -pubkey | sha256sum | cut -c1-16)
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  $kw patch certificate "$w-cert" --subresource=status --type=json \
    -p '[{"op":"add","path":"/status/conditions/-","value":{"type":"Issuing","status":"True","reason":"ManuallyTriggered","message":"proof renewal","lastTransitionTime":"'"$now"'"}}]' 2>&1 | sed 's/^/FCK renew: /'
  for i in $(seq 1 30); do
    serial2=$(crt | openssl x509 -noout -serial); [ "$serial2" != "$serial1" ] && break; sleep 4
  done
  key2=$(crt | openssl x509 -noout -pubkey | sha256sum | cut -c1-16)
  [ "$serial2" != "$serial1" ] && [ "$key1" = "$key2" ] && ok "renewed: $serial1 -> $serial2, key $key1 kept" || bad "renewal: $serial1 -> $serial2, key $key1 -> $key2"
  local want got
  want=$(crt | sha256sum | cut -c1-16)
  for i in $(seq 1 45); do
    got=$($kw exec "$w" -c agent -- cat /var/run/aerolvm-tls/node.crt 2>/dev/null | sha256sum | cut -c1-16)
    [ "$got" = "$want" ] && break; sleep 4
  done
  [ "$got" = "$want" ] && ok "the pod reads the renewed certificate after $((i * 4))s" || bad "the pod still has the old certificate"
  sleep 20
  m=$(members 2>/dev/null)
  grep -q "$w/worker/alive" <<<"$m" && ok "$w is still a live member after its renewal" || bad "$w after renewal: $m"
  id=$(create)
  if [ -n "$id" ]; then ok "a create after the renewal: $(exec_in "$id")"; api -X DELETE "http://127.0.0.1:$port/v1/sandboxes/$id" >/dev/null; else bad "no create after the renewal"; fi
  kill $pf 2>/dev/null

  # The join port, straight to server 0: the worker's own certificate is a
  # replay; a second key for that node, a certificate with no role and one
  # from another CA are refused.
  $kk create namespace probe >/dev/null 2>&1
  $kk -n probe apply -f - >/dev/null <<YAML
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: second-key }
spec:
  secretName: second-key
  commonName: $w
  uris: ["node:$w", "aerolvm-role:worker"]
  usages: [digital signature, client auth]
  privateKey: { algorithm: ECDSA, size: 256 }
  issuerRef: { kind: ClusterIssuer, name: aerolvm-dev-bank-ca }
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: no-role }
spec:
  secretName: no-role
  commonName: probe-no-role
  uris: ["node:probe-no-role"]
  usages: [digital signature, client auth]
  privateKey: { algorithm: ECDSA, size: 256 }
  issuerRef: { kind: ClusterIssuer, name: aerolvm-dev-bank-ca }
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: other-ca }
spec:
  secretName: other-ca
  commonName: probe-other-ca
  uris: ["node:probe-other-ca", "aerolvm-role:worker"]
  usages: [digital signature, client auth]
  privateKey: { algorithm: ECDSA, size: 256 }
  issuerRef: { kind: ClusterIssuer, name: aerolvm-dev }
YAML
  $kk -n probe wait --for=condition=Ready certificate --all --timeout=120s >/dev/null 2>&1
  mkdir -p /root/probe && cd /root/probe
  $kk -n cert-manager get secret aerolvm-dev-bank-ca -o jsonpath='{.data.ca\.crt}' 2>/dev/null | base64 -d > ca.crt
  [ -s ca.crt ] || $kw get secret "$w-cert" -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
  $kw get secret "$w-cert" -o jsonpath='{.data.tls\.crt}' | base64 -d > own.crt
  $kw get secret "$w-cert" -o jsonpath='{.data.tls\.key}' | base64 -d > own.key
  for c in second-key no-role other-ca; do
    $kk -n probe get secret $c -o jsonpath='{.data.tls\.crt}' | base64 -d > $c.crt
    $kk -n probe get secret $c -o jsonpath='{.data.tls\.key}' | base64 -d > $c.key
  done
  $kc port-forward pod/$s0 17003:7003 >/dev/null 2>&1 & pf=$!
  sleep 3
  # The version the cluster runs, so a refusal is never the version's.
  local ver
  ver=$($kc get aerolcluster aerolvm -o jsonpath='{.spec.version}')
  join() { # <name>: HTTP status and the start of the answer (never the bundle)
    curl -sS -m 30 --cacert ca.crt --cert $1.crt --key $1.key --resolve aerolvm-cluster-node:17003:127.0.0.1 \
      -H 'Content-Type: application/json' -d '{"version":"'"$ver"'","fv":19}' -o $1.out -w '%{http_code}' \
      https://aerolvm-cluster-node:17003/v1/join/by-certificate 2>$1.err
    echo " $(python3 -c 'import json,sys
try:
    d = json.load(open(sys.argv[1]))
    print("replay=%s node=%s" % (d.get("replay"), d.get("node_id")) if "node_id" in d else json.dumps(d)[:200])
except Exception:
    print(open(sys.argv[1]).read()[:200])' $1.out 2>/dev/null) $(head -c 160 $1.err)"
  }
  local r
  r=$(join own); [[ "$r" == 200* && "$r" == *replay=True* ]] && ok "its own certificate: a replay ($r)" || bad "its own certificate: $r"
  r=$(join second-key); [[ "$r" != 200* ]] && ok "a second key for $w: refused ($r)" || bad "a second key for $w was admitted: $r"
  r=$(join no-role); [[ "$r" == 4* ]] && ok "no role: refused ($r)" || bad "no role: $r"
  r=$(join other-ca); [[ "$r" != 200* ]] && ok "another CA: refused ($r)" || bad "another CA was admitted: $r"
  kill $pf 2>/dev/null
  cd /root/src
  [ "$pass" = 1 ] && say "RESULT PASS: external-CA mode" || say "RESULT FAIL: external-CA mode"
}

# The docs' approver-policy example (charts/aerolvm/examples), live: with
# cert-manager's own approval off, it approves AerolVM's node certificates
# in its two namespaces (a worker's and a server's renewal) and nothing
# else: a request for those names from another namespace waits unsigned,
# and one in AerolVM's namespace that names something else is denied.
proof_externalca_policy() {
  local kk="kubectl --context kind-aerolvm-cluster"
  local kc="$kk -n aerolvm-system" kw="$kk -n aerolvm-workers"
  local pass=1 i v out
  ok() { say "OK $*"; }
  bad() { say "BAD $*"; pass=0; }
  # Installed first, so the cert-manager change below never leaves a
  # request with no approver at all.
  for v in v0.29.0 0.29.0; do
    out=$(helm --kube-context kind-aerolvm-cluster upgrade --install cert-manager-approver-policy \
      oci://quay.io/jetstack/charts/cert-manager-approver-policy --version $v -n cert-manager --wait --timeout 5m 2>&1) && break
  done
  say "approver-policy $v: $(tail -1 <<<"$out" | head -c 200)"
  $kk -n cert-manager patch deployment cert-manager --type=json \
    -p '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--controllers=*,-certificaterequests-approver"}]' >/dev/null
  $kk -n cert-manager rollout status deployment cert-manager --timeout=3m 2>&1 | tail -1 | sed 's/^/FCK cert-manager: /'
  sed 's/name: bank-ca$/name: aerolvm-dev-bank-ca/' charts/aerolvm/examples/approver-policy-external-ca.yaml | $kk apply -f - 2>&1 | tr '\n' ' ' | sed 's/^/FCK policy: /'; echo
  sleep 5
  crstate() { # <namespace> <certificate>: its newest request's verdict
    $kk -n "$1" get certificaterequests -o json 2>/dev/null | python3 -c '
import json, sys
items = [i for i in json.load(sys.stdin)["items"]
         if i["metadata"].get("annotations", {}).get("cert-manager.io/certificate-name") == sys.argv[1]]
items.sort(key=lambda i: i["metadata"]["creationTimestamp"])
if not items:
    print("none"); sys.exit()
c = {x["type"]: x for x in items[-1].get("status", {}).get("conditions", [])}
for t in ("Denied", "Approved"):
    if c.get(t, {}).get("status") == "True":
        print(t + ": " + c[t].get("message", "")[:160]); sys.exit()
print("pending")' "$2"
  }
  renew() { # <namespace> <certificate>
    $kk -n "$1" patch certificate "$2" --subresource=status --type=json \
      -p '[{"op":"add","path":"/status/conditions/-","value":{"type":"Issuing","status":"True","reason":"ManuallyTriggered","message":"policy proof","lastTransitionTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}]' >/dev/null
  }
  serial() { $kk -n "$1" get secret "$2" -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -serial; }
  local w s1 ns c before st
  w=$($kw get pods -l app.kubernetes.io/component=worker -o jsonpath='{.items[0].metadata.name}')
  for c in "aerolvm-workers $w-cert" "aerolvm-system aerolvm-server-1-cert"; do
    ns=${c% *}; c=${c#* }
    before=$(serial $ns $c)
    renew $ns $c
    for i in $(seq 1 30); do
      st=$(crstate $ns $c); [[ "$st" == Approved* || "$st" == Denied* ]] && [ "$(serial $ns $c)" != "$before" ] && break
      sleep 4
    done
    [[ "$st" == Approved* ]] && [ "$(serial $ns $c)" != "$before" ] && ok "$c renewed under the policy: $st" || bad "$c: $st, serial $before -> $(serial $ns $c)"
  done
  $kk create namespace outside >/dev/null 2>&1
  $kk -n outside apply -f - >/dev/null <<YAML
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: pretend-worker }
spec:
  secretName: pretend-worker
  commonName: pretend-worker
  uris: ["node:pretend-worker", "aerolvm-role:worker"]
  usages: [digital signature, server auth, client auth]
  privateKey: { algorithm: ECDSA, size: 256 }
  issuerRef: { kind: ClusterIssuer, name: aerolvm-dev-bank-ca }
YAML
  $kw apply -f - >/dev/null <<YAML
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: stray }
spec:
  secretName: stray
  commonName: stray
  uris: ["spiffe://elsewhere/stray"]
  usages: [digital signature, client auth]
  privateKey: { algorithm: ECDSA, size: 256 }
  issuerRef: { kind: ClusterIssuer, name: aerolvm-dev-bank-ca }
YAML
  sleep 45
  st=$(crstate outside pretend-worker)
  [ "$st" = pending ] && [ -z "$($kk -n outside get secret pretend-worker -o name 2>/dev/null)" ] && ok "node names from another namespace: unsigned ($st)" || bad "another namespace: $st"
  st=$(crstate aerolvm-workers stray)
  [[ "$st" == Denied* ]] && ok "other names in AerolVM's namespace: $st" || bad "stray in aerolvm-workers: $st"
  $kw delete certificate stray >/dev/null 2>&1; $kw delete secret stray >/dev/null 2>&1
  [ "$pass" = 1 ] && say "RESULT PASS: the approver-policy example" || say "RESULT FAIL: the approver-policy example"
}

# dump_externalca: why the AerolCluster did not get Ready.
dump_externalca() {
  local kk="kubectl --context kind-aerolvm-cluster"
  local kc="$kk -n aerolvm-system" kw="$kk -n aerolvm-workers"
  $kc get aerolcluster,aerolnodes 2>&1 | sed 's/^/FCK   /'
  $kk get certificates -A 2>&1 | sed 's/^/FCK   cert: /'
  $kc get aerolnodes -o jsonpath='{range .items[*]}{.metadata.name}: {.status.reason}{"\n"}{end}' 2>&1 | sed 's/^/FCK   reason: /'
  local p
  for p in $($kc get pods -l app.kubernetes.io/component=server -o name | head -2) $($kw get pods -o name | head -1); do
    local k="$kc"; [[ "$($kw get $p -o name 2>/dev/null)" ]] && k="$kw"
    { $k logs $p -c setup 2>&1; $k logs $p -c setup --previous 2>&1; } | tail -10 | cut -c1-300 | sed "s|^|FCK   ${p#pod/} setup: |"
    $k logs $p -c agent 2>&1 | grep -iE 'error|refus|join|tls|cert' | tail -10 | cut -c1-300 | sed "s|^|FCK   ${p#pod/} agent: |"
  done
  $kc logs deploy/aerolvm-operator 2>&1 | grep -iE '"level":"error"|certificate' | tail -8 | cut -c1-300 | sed 's/^/FCK   operator: /'
}

[ -e /dev/kvm ] || modprobe kvm_intel 2>/dev/null
if [ -e /dev/kvm ]; then say "machine: /dev/kvm present, $(grep -c -w vmx /proc/cpuinfo) cpus with vmx, kernel $(uname -r)"; else say "machine: /dev/kvm ABSENT"; finish; fi

say "installing docker and the tools"
dnf -y -q install docker git tar gzip iptables perl-Digest-SHA openssl >/dev/null 2>&1 || say "dnf install failed"
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
if [ "$proof" = gmove ]; then
  # C21: gVisor is in the dev pool already, and the chart turns
  # checkpoint moves on; the image runs on this machine as on any other.
  grep -A1 '^  gvisor:' charts/aerolvm/values.yaml | sed 's/^/FCK chart: /'
  export AEROL_K8S_MODE=cluster
fi
if [ "$proof" = kubeapi ]; then
  # C17: cluster mode with the agent-sandbox API on, in this copy only.
  python3 - <<'PY'
p = "charts/aerolvm/values.yaml"
s = open(p).read()
s = s.replace("  agentSandboxAPI:\n    enabled: false", "  agentSandboxAPI:\n    enabled: true", 1)
open(p, "w").write(s)
PY
  grep -A1 '^  agentSandboxAPI:' charts/aerolvm/values.yaml | sed 's/^/FCK chart: /'
  export AEROL_K8S_MODE=cluster
fi
if [ "$proof" = externalca ]; then
  # C23: cluster mode in external-CA mode, a cert-manager CA issuer
  # standing in for the bank's.
  export AEROL_K8S_MODE=cluster AEROL_K8S_EXTERNAL_CA=1
fi
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
if ! scripts/k8s-dev.sh > /root/k8s-dev.log 2>&1; then
  say "k8s-dev failed:"; tail -20 /root/k8s-dev.log | sed 's/^/FCK   /'
  [ "$proof" = externalca ] && dump_externalca
  finish
fi
say "built and installed in $(( $(date +%s) - t0 ))s"
[ "$proof" = move ] && { proof_move firecracker; finish; }
[ "$proof" = gmove ] && { proof_move gvisor; finish; }
[ "$proof" = kubeapi ] && { proof_kubeapi; finish; }
[ "$proof" = externalca ] && { proof_externalca; proof_externalca_policy; finish; }
# A proof that stops part way (bash drops the rest of a command on an
# expansion error) must not run on into the pod proof below.
[ "$proof" = pod ] || { say "the $proof proof stopped part way"; finish; }

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
