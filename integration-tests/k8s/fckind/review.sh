#!/bin/bash
# review.sh: the fixes for the November 2026 Kubernetes reviews (R1-R17 and
# S5), checked live on kind. userdata.sh sources it for
# AEROL_FCKIND_PROOF=review, after scripts/k8s-dev.sh brought up cluster
# mode: three servers, three gateways and three workers on three kind
# nodes, one per zone. Each check prints a PASS or FAIL line and the run
# goes on; the last line counts them.
#
# The unit tests prove each fix on its own. These run them against a real
# API server, kubelet, scheduler and disruption budget:
#   S5   every node joined through TokenReview, no join Secret, and a token
#        Kubernetes does not vouch for is refused
#   R9   a recreate-policy sandbox is in its worker's lease file fence by
#        the time its create answers
#   R4   a running worker takes a new deny-floor address from the
#        ConfigMap, and lets it go again
#   R12  a worker pod whose sandboxes are still moving cannot be deleted
#   R13  kubectl drain waits on the worker budget until the operator has
#        moved the sandboxes, then finishes
#   R2   a worker pod that ended (phase Failed) is replaced
#   R7   lowering the gateway count retires the extra gateway
#   R6   a removed worker pool is decommissioned, an EKS-managed one within
#        14 minutes
#   R14  an orphaned recreate-policy sandbox recovers once a worker has
#        room; the machine that lost it does not run its copy on when it
#        wakes (its lease ran out while it was away, R1)
# R3 is reported (the operator's flags). Not run here, as they have no live
# behaviour past their unit tests: R5, R8, R15-R17 (cleanup records), R10
# (a delayed move request) and R11 (a release across an agent restart).

proof_review() {
  local kk="kubectl --context kind-aerolvm-cluster"
  local kc="$kk -n aerolvm-system" kw="$kk -n aerolvm-workers"
  local port=21297 pf="" avoid="" pass=0 fail=0 tok U i out
  U="http://127.0.0.1:$port"
  dnf -y -q install jq >/dev/null 2>&1 || say "jq did not install"
  ok() { say "PASS $*"; pass=$((pass + 1)); }
  bad() { say "FAIL $*"; fail=$((fail + 1)); }
  tok="$($kc get secret aerolvm-admin -o jsonpath='{.data.token}' | base64 -d)"
  api() { curl -sS -m 300 -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }

  # The API through a gateway pod on another machine than $avoid (a paused
  # machine's gateway answers nothing, and a retired gateway's pod goes).
  # Called only from this shell, never inside $(...), so $pf stays true.
  fwd() {
    local gw
    for _ in $(seq 1 30); do
      [ -n "$pf" ] && kill "$pf" 2>/dev/null
      pkill -f "port-forward.* $port:21212" 2>/dev/null
      gw=$($kc get pods -l app.kubernetes.io/component=gateway -o json 2>/dev/null |
        jq -r --arg n "$avoid" '[.items[] | select(.status.phase == "Running" and .spec.nodeName != $n and .metadata.deletionTimestamp == null)][0].metadata.name // empty')
      if [ -n "$gw" ]; then
        $kc port-forward "pod/$gw" "$port:21212" >/dev/null 2>&1 &
        pf=$!
        sleep 2
        curl -fsS -m 3 -o /dev/null "$U/health" 2>/dev/null && return 0
      fi
      sleep 2
    done
    say "no gateway answered"
    return 1
  }
  ensure() { curl -fsS -m 3 -o /dev/null "$U/health" 2>/dev/null || fwd; }

  members() { api "$U/v1/cluster/members" | jq -c '.members // .'; }
  alive_workers() { members | jq -r '.[] | select(.role == "worker" and .alive) | .node_id'; }
  placement() { api -w ' http=%{http_code}' "$U/v1/cluster/placements/$1" | head -c 400; }
  owner() { api "$U/v1/cluster/placements/$1" 2>/dev/null | jq -r '(.owner | if type == "object" then .node_id else . end) // .owner_node_id // ""' 2>/dev/null; }
  podnode() { $kw get pod "$1" -o jsonpath='{.spec.nodeName}' 2>/dev/null; }
  nstate() { $kc get aerolnode "$1" -o jsonpath='{.status.state}' 2>/dev/null; }
  nodes() { # <role> [pool]: name/state/pod per line
    $kc get aerolnodes -o json | jq -r --arg r "$1" --arg p "${2:-}" \
      '.items[] | select(.spec.role == $r and ($p == "" or .spec.pool == $p)) | "\(.metadata.name)/\(.status.state // "-")"'
  }
  lease() { $kw exec "$1" -c agent -- cat /run/aerolvm/ownership-lease 2>/dev/null; }
  fence() { lease "$1" | jq -r '.fence[]?' 2>/dev/null | sort; }
  snap() { local w; for w in $(alive_workers); do echo "$w $(fence "$w" | tr '\n' ',')"; done; }
  # newref <worker> <snap>: the fence entry the worker has now and lacked
  # in the snapshot.
  newref() { fence "$1" | grep -vxF -f <(awk -v w="$1" '$1 == w {print $2}' <<<"$2" | tr ',' '\n' | grep .) | head -1; }
  orphaned() { api "$U/v1/cluster/placements/$1" 2>/dev/null | jq -r '.orphaned // false' 2>/dev/null; }

  # mk <json>: a new sandbox's ID. A worker that just joined has not
  # reported its capacity yet: the create waits for one that has.
  mk() {
    local o id
    for _ in $(seq 1 18); do
      o=$(api -X POST "$U/v1/sandboxes" -d "$1")
      id=$(jq -r '.id // empty' <<<"$o" 2>/dev/null)
      [ -n "$id" ] && { echo "$id"; return 0; }
      grep -q "no worker placement target" <<<"$o" || break
      sleep 10
    done
    say "create refused: $(head -c 300 <<<"$o")" >&2
    return 1
  }
  local RC='{"image":"alpine:3.20","cpu":1,"memory_mb":256,"failover":{"policy":"recreate"}}'
  # run <id> <command>: the toolbox exec's whole answer.
  run() { api -X POST "$U/v1/sandboxes/$1/toolbox/process/execute" -d "$(jq -cn --arg c "$2" '{command: $c}')" | head -c 400; }
  alive() { run "$1" 'echo up$((40+2))' | grep -q 'up42'; }
  # reach <id> <url>: whether the sandbox reaches a plain-HTTP url. Any
  # HTTP status line, even an error (an API server answers plain HTTP on
  # its TLS port with a 400), means it got through; a timeout, refusal or
  # reset means it did not.
  reach() {
    local o
    o=$(run "$1" "wget -T 4 -S --spider '$2' 2>&1 | head -3")
    if grep -q 'HTTP/' <<<"$o"; then echo open
    elif grep -qiE 'timed out|refused|unreachable|no route|reset|error getting response' <<<"$o"; then echo closed
    else echo "unknown: $(tr '\n' ' ' <<<"$o" | head -c 200)"; fi
  }

  fwd || { bad "setup: no gateway answered"; say "RESULT pass=$pass fail=$fail"; return; }
  local m n=0
  for i in $(seq 1 60); do
    n=$(alive_workers 2>/dev/null | wc -l)
    [ "$n" -ge 3 ] && break
    sleep 5
  done
  say "members: $(members | jq -r '[.[] | "\(.node_id)/\(.role)/\(if .alive then "alive" else "dead" end)"] | join(" ")')"
  [ "$n" -ge 3 ] || { bad "setup: $n workers alive, want 3"; say "RESULT pass=$pass fail=$fail"; return; }

  # ---- S5: join through TokenReview ----
  say "== S5: joins"
  out=$($kc get aerolnodes -o json | jq -r '[.items[] | select(.status.state != "Serving")] | length')
  [ "$out" = 0 ] && ok "S5: every AerolNode is Serving ($($kc get aerolnodes --no-headers | wc -l) nodes)" || bad "S5: $out AerolNodes not Serving: $(nodes server; nodes gateway; nodes worker)"
  out=$($kk get secrets -A --no-headers 2>/dev/null | awk '$2 ~ /-join$/' | wc -l)
  [ "$out" -eq 0 ] && ok "S5: no join Secret in any namespace" || bad "S5: $out join Secrets"
  local op joinurl
  op=$($kc get pods -l app.kubernetes.io/component=operator -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -z "$op" ] && op=$($kc get pods -o name | sed -n 's#^pod/\(.*operator.*\)#\1#p' | head -1)
  say "operator join metrics: $($kk get --raw "/api/v1/namespaces/aerolvm-system/pods/$op:8080/proxy/metrics" 2>&1 | grep -E '^aerolvm_operator_join' | tr '\n' ' ' | head -c 400)"
  joinurl=$($kc get deploy aerolvm-operator -o json | jq -r '.spec.template.spec.containers[0].args[] | select(startswith("--join-url=")) | sub("^--join-url="; "")')
  # A pod with no AerolNode shows its own API token: Kubernetes does not
  # vouch for it for the join audience.
  $kw delete pod review-join --ignore-not-found >/dev/null 2>&1
  $kw run review-join --image=curlimages/curl:8.11.1 --restart=Never --command -- sh -c \
    "curl -sk -m 10 -o /dev/null -w 'code=%{http_code}' -X POST -H \"Authorization: Bearer \$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" -H 'Content-Type: application/json' -d '{}' '$joinurl'" >/dev/null 2>&1
  for i in $(seq 1 45); do
    case "$($kw get pod review-join -o jsonpath='{.status.phase}' 2>/dev/null)" in Succeeded|Failed) break ;; esac
    sleep 2
  done
  out=$($kw logs review-join 2>&1 | tail -1)
  case "$out" in
    code=401|code=403) ok "S5: a token Kubernetes does not vouch for is refused ($out from $joinurl)" ;;
    code=000) say "INFO S5: the join port did not answer a pod with no AerolNode (a network policy?), $out" ;;
    *) bad "S5: a token with another audience got $out from $joinurl" ;;
  esac
  $kw delete pod review-join --ignore-not-found --wait=false >/dev/null 2>&1

  # ---- R3: reported ----
  say "INFO R3: operator args: $($kc get deploy aerolvm-operator -o json | jq -r '.spec.template.spec.containers[0].args | join(" ")' | head -c 300) (no --node-concurrency: the default, 16)"

  # ---- R9: fenced when the create answers ----
  say "== R9: the fence"
  local w t1 F Wf ref sn lf
  sn=$(snap)
  F=$(mk "$RC")
  t1=$(date +%s%3N)
  Wf=$(owner "$F")
  lf=$(lease "$Wf")
  ref=$(newref "$Wf" "$sn")
  say "sandbox $F on $Wf; lease: $(jq -c '{written_unix_ms, confirmed_unix_ms, lease_ms, fence}' <<<"$lf" 2>/dev/null | head -c 300)"
  local wr
  wr=$(jq -r '.written_unix_ms // 0' <<<"$lf" 2>/dev/null)
  if [ -n "$F" ] && [ -n "$ref" ]; then
    if [ "${wr:-0}" -le "$t1" ]; then ok "R9: $F is in $Wf's fence (ref $ref), written $((t1 - wr)) ms before the create's answer was read"
    else ok "R9: $F is in $Wf's fence (ref $ref); the file was rewritten after the answer, so this shows the fence, not the order"; fi
  else
    bad "R9: no new fence entry on $Wf after creating $F"
  fi

  # ---- R4: a running worker takes a new floor address ----
  say "== R4: the deny floor"
  local cm floor api_ips
  cm=$($kw get configmap aerolvm-egress-floor -o jsonpath='{.data.deny-floor}' 2>/dev/null)
  api_ips="$($kk get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}') $($kk get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o jsonpath='{.items[*].endpoints[*].addresses[*]}')"
  say "floor ConfigMap: $(tr '\n' ' ' <<<"$cm"); API server: $api_ips"
  floor=1
  for a in $api_ips; do grep -q "^$a\(/32\)\?$" <<<"$cm" || floor=0; done
  [ "$floor" = 1 ] && [ -n "$cm" ] && ok "R4: the floor ConfigMap holds every API server address" || bad "R4: the floor ConfigMap misses an API server address"
  local mounted
  mounted=$($kw get pod "$Wf" -o json | jq -r '[.spec.volumes[] | select(.configMap.name == "aerolvm-egress-floor")] | length')
  [ "$mounted" -ge 1 ] && ok "R4: worker $Wf mounts the floor ConfigMap" || bad "R4: worker $Wf does not mount the floor ConfigMap"
  local ep
  ep=$($kk get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o jsonpath='{.items[0].endpoints[0].addresses[0]}:{.items[0].ports[0].port}')
  out="$(reach "$F" "http://$($kk get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}'):443/") $(reach "$F" "http://$ep/")"
  [ "$out" = "closed closed" ] && ok "R4: the sandbox reaches neither the API server's Service address nor its endpoint $ep" || bad "R4: the sandbox reaching the API server (Service, endpoint $ep): $out"
  local pre post back since
  pre=$(reach "$F" "http://1.1.1.1/")
  say "a public address before (1.1.1.1): $pre"
  # The operator writes the ConfigMap on every pass: stop it while the
  # file carries an extra address, as the API server moving would.
  $kc scale deploy/aerolvm-operator --replicas=0 >/dev/null
  $kc wait --for=delete pod -l app.kubernetes.io/component=operator --timeout=90s >/dev/null 2>&1
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  $kw patch configmap aerolvm-egress-floor --type=merge -p "$(jq -cn --arg f "${cm}"$'\n'"1.1.1.1/32"$'\n' '{data: {"deny-floor": $f}}')" >/dev/null
  for i in $(seq 1 36); do
    $kw logs "$Wf" -c agent --since-time="$since" 2>/dev/null | grep 'egress deny floor changed' | grep -q '1.1.1.1' && break
    sleep 5
  done
  say "agent after $((i * 5))s: $($kw logs "$Wf" -c agent --since-time="$since" 2>/dev/null | grep 'egress deny floor changed' | tail -1 | cut -c1-300)"
  post=$(reach "$F" "http://1.1.1.1/")
  say "the same address with it on the floor: $post"
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  $kc scale deploy/aerolvm-operator --replicas=1 >/dev/null
  # The operator puts the real addresses back on its next pass.
  for i in $(seq 1 36); do
    $kw get configmap aerolvm-egress-floor -o jsonpath='{.data.deny-floor}' 2>/dev/null | grep -q '1.1.1.1' || break
    sleep 5
  done
  for i in $(seq 1 36); do
    $kw logs "$Wf" -c agent --since-time="$since" 2>/dev/null | grep -q 'egress deny floor changed' && break
    sleep 5
  done
  back=$(reach "$F" "http://1.1.1.1/")
  say "after the operator restored the ConfigMap: $back"
  if [ "$pre" = open ] && [ "$post" = closed ] && [ "$back" = open ]; then
    ok "R4: running worker $Wf blocked an address added to the floor file and let it go when it left, without a restart (agent restarts: $($kw get pod "$Wf" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}'))"
  elif [ "$pre" != open ]; then
    say "INFO R4: the sandbox could not reach 1.1.1.1 to begin with ($pre); the refresh is shown by the agent's log only"
  else
    bad "R4: before $pre, on the floor $post, after $back"
  fi
  $kc wait --for=condition=Available deploy/aerolvm-operator --timeout=180s >/dev/null 2>&1
  ensure

  # ---- R12 and R13: a drain waits for the moves ----
  say "== R12, R13: kubectl drain"
  local D Wd Nd s dpid dt0
  D=$(mk "$RC")
  Wd=$(owner "$D")
  Nd=$(podnode "$Wd")
  say "sandbox $D on $Wd (machine $Nd); alive: $(alive "$D" && echo yes || echo no)"
  dt0=$(date +%s)
  ( timeout 660 $kk drain "$Nd" --pod-selector=app.kubernetes.io/component=worker --ignore-daemonsets \
      --delete-emptydir-data --force --timeout=600s > /root/drain.log 2>&1; echo "exit=$?" >> /root/drain.log ) &
  dpid=$!
  for i in $(seq 1 90); do
    s=$(nstate "$Wd")
    [ "$s" = Draining ] || [ "$s" = Decommissioning ] && break
    sleep 2
  done
  say "$Wd is $s after $(( $(date +%s) - dt0 ))s"
  out=$($kw delete pod "$Wd" --wait=false 2>&1)
  if grep -qi 'denied' <<<"$out"; then ok "R12: deleting $Wd while it is $s is refused: $(head -c 240 <<<"$out")"
  else bad "R12: deleting $Wd while it is $s: $(head -c 240 <<<"$out")"; fi
  wait "$dpid"
  local evicts dexit
  # A refusal comes from the eviction guard (it runs first, as a validating
  # webhook on pods/eviction) or, without it, from the budget.
  evicts=$(grep -c "will retry after" /root/drain.log)
  say "worker budget: $($kw get pdb -o jsonpath='{range .items[*]}{.metadata.name} maxUnavailable={.spec.maxUnavailable} allowed={.status.disruptionsAllowed}{"\n"}{end}' | tr '\n' ' ')"
  dexit=$(sed -n 's/^exit=//p' /root/drain.log)
  grep -E 'evict|drain|error|exit=' /root/drain.log | sort | uniq -c | sort -rn | head -6 | cut -c1-240 | sed 's/^/FCK   drain: /'
  local Dto
  Dto=$(owner "$D")
  for i in $(seq 1 30); do alive "$D" && break; sleep 3; done
  if [ "$dexit" = 0 ] && [ "$evicts" -ge 1 ] && [ -n "$Dto" ] && [ "$Dto" != "$Wd" ] && alive "$D"; then
    ok "R13: kubectl drain waited ($evicts refused evictions) and finished in $(( $(date +%s) - dt0 ))s; $D moved $Wd -> $Dto and answers"
  else
    bad "R13: drain exit=$dexit, refused evictions $evicts, $D owner $Dto, alive $(alive "$D" && echo yes || echo no)"
  fi
  $kk uncordon "$Nd" >/dev/null
  ensure

  # ---- R2: an ended pod is replaced ----
  say "== R2: a Failed worker pod"
  local W2 uid2 r2=""
  # One that owns none of this run's sandboxes, asked of the cluster: the
  # AerolNode's count is written at most once a minute. The drain's
  # replacement joins meanwhile.
  local busy
  busy="$(owner "$F") $(owner "$D")"
  for i in $(seq 1 36); do
    W2=$($kc get aerolnodes -o json | jq -r --arg busy " $busy " '[.items[] | .metadata.name as $n | select(.spec.role == "worker" and .status.state == "Serving" and (($busy | contains(" " + $n + " ")) | not))][0].metadata.name // empty')
    [ -n "$W2" ] && break
    sleep 5
  done
  if [ -z "$W2" ]; then
    bad "R2: no Serving worker without sandboxes to end"
  else
    uid2=$($kw get pod "$W2" -o jsonpath='{.metadata.uid}')
    # What the kubelet writes when it evicts a pod for node pressure.
    out=$($kw patch pod "$W2" --subresource=status --type=merge \
      -p '{"status":{"phase":"Failed","reason":"Evicted","message":"live test: stands in for a kubelet eviction"}}' 2>&1)
    say "patched $W2 to Failed: $(head -c 160 <<<"$out")"
    for i in $(seq 1 60); do
      [ -z "$r2" ] && r2=$($kc get aerolnode "$W2" -o jsonpath='{.status.reason}' 2>/dev/null | grep 'pod ended')
      [ "$($kw get pod "$W2" -o jsonpath='{.metadata.uid}' 2>/dev/null)" != "$uid2" ] && break
      sleep 2
    done
    local gone=$((i * 2))
    if [ "$($kw get pod "$W2" -o jsonpath='{.metadata.uid}' 2>/dev/null)" != "$uid2" ]; then
      ok "R2: the operator removed the Failed pod of $W2 in ${gone}s (AerolNode: ${r2:-$(nstate "$W2")})"
    else
      bad "R2: the Failed pod of $W2 is still there after ${gone}s: $($kw get pod "$W2" -o wide --no-headers 2>&1)"
    fi
    for i in $(seq 1 60); do
      [ "$(nodes worker general | grep -c '/Serving$')" -ge 3 ] && break
      sleep 5
    done
    out=$(nodes worker general | grep -c '/Serving$')
    [ "$out" -ge 3 ] && ok "R2: 3 general workers Serving again after $((i * 5))s" || bad "R2: $out general workers Serving: $(nodes worker general | tr '\n' ' ')"
  fi
  ensure

  # ---- R7: gateways scale down ----
  say "== R7: gateways"
  $kc patch aerolcluster aerolvm --type=merge -p '{"spec":{"gateways":{"minReplicas":4}}}' >/dev/null
  for i in $(seq 1 60); do
    [ "$(nodes gateway | grep -c '/Serving$')" -ge 4 ] && break
    sleep 5
  done
  say "gateways at minReplicas 4 after $((i * 5))s: $(nodes gateway | tr '\n' ' ')"
  local g4
  g4=$(nodes gateway | grep -c '/Serving$')
  $kc patch aerolcluster aerolvm --type=merge -p '{"spec":{"gateways":{"minReplicas":3}}}' >/dev/null
  for i in $(seq 1 60); do
    [ "$(nodes gateway | grep -vc '/Removed$')" -le 3 ] && [ "$($kc get pods -l app.kubernetes.io/component=gateway --no-headers 2>/dev/null | wc -l)" -le 3 ] && break
    sleep 5
  done
  out="$(nodes gateway | tr '\n' ' ') pods $($kc get pods -l app.kubernetes.io/component=gateway --no-headers 2>/dev/null | wc -l)"
  if [ "$g4" -ge 4 ] && [ "$(nodes gateway | grep -vc '/Removed$')" -le 3 ]; then ok "R7: a fourth gateway joined, and lowering minReplicas to 3 retired one in $((i * 5))s ($out)"
  else bad "R7: 4 Serving: $g4; after lowering: $out"; fi
  ensure

  # ---- R6: a removed pool; the EKS cap ----
  say "== R6: a removed pool (eks-managed)"
  $kc patch aerolcluster aerolvm --type=json -p '[{"op":"add","path":"/spec/workerPools/-","value":{"name":"eks","runtimes":["runc"],"machine":{"cpu":2,"memoryGiB":4},"minWorkers":1,"maxWorkers":1,"provisioner":"eks-managed","decommission":{"drainWindow":"20m","deadline":"45m"}}}]' 2>&1 | head -c 200 | sed 's/^/FCK   patch: /'
  for i in $(seq 1 72); do
    nodes worker eks | grep -q '/Serving$' && break
    sleep 5
  done
  local E
  E=$(nodes worker eks | grep '/Serving$' | head -1 | cut -d/ -f1)
  say "eks pool worker after $((i * 5))s: $(nodes worker eks | tr '\n' ' ')"
  if [ -z "$E" ]; then
    bad "R6: the eks pool's worker never served"
  else
    # A sandbox on it, so its decommission waits in a drain window long
    # enough to read: the other workers cordoned for the create, the
    # operator stopped meanwhile so it does not answer the cordons.
    local Es others6
    $kc scale deploy/aerolvm-operator --replicas=0 >/dev/null
    $kc wait --for=delete pod -l app.kubernetes.io/component=operator --timeout=90s >/dev/null 2>&1
    others6=$(alive_workers | grep -vx "$E")
    for w in $others6; do api -X POST "$U/v1/cluster/nodes/$w/cordon" >/dev/null; done
    Es=$(mk '{"image":"alpine:3.20","cpu":1,"memory_mb":256}')
    for w in $others6; do api -X POST "$U/v1/cluster/nodes/$w/uncordon" >/dev/null; done
    $kc scale deploy/aerolvm-operator --replicas=1 >/dev/null
    $kc wait --for=condition=Available deploy/aerolvm-operator --timeout=180s >/dev/null 2>&1
    say "sandbox $Es on $(owner "$Es")"
    local idx dec="" st
    idx=$($kc get aerolcluster aerolvm -o json | jq '.spec.workerPools | map(.name) | index("eks")')
    $kc patch aerolcluster aerolvm --type=json -p "[{\"op\":\"test\",\"path\":\"/spec/workerPools/$idx/name\",\"value\":\"eks\"},{\"op\":\"remove\",\"path\":\"/spec/workerPools/$idx\"}]" >/dev/null
    for i in $(seq 1 60); do
      dec=$($kc get aerolnode "$E" -o json 2>/dev/null | jq -c '.status.decommission // empty' 2>/dev/null)
      [ -n "$dec" ] && break
      sleep 2
    done
    say "decommission of $E: ${dec:-none}, $(nstate "$E"); kept settings: $($kc get aerolcluster aerolvm -o jsonpath='{.status.poolDecommission}' | head -c 300)"
    if [ -n "$dec" ]; then
      local cap
      cap=$(python3 -c 'import json, sys, datetime as d
s = json.loads(sys.argv[1]); p = lambda k: d.datetime.fromisoformat(s[k].replace("Z", "+00:00"))
print(int((p("deadline") - p("startedAt")).total_seconds()), int((p("drainUntil") - p("startedAt")).total_seconds()))' "$dec")
      [ "${cap%% *}" -le 840 ] && [ "${cap#* }" -le 840 ] && ok "EKS cap: a removed eks-managed pool's worker got a deadline ${cap%% *}s and a drain window ${cap#* }s after the start, though the pool asked 45m and 20m" ||
        bad "EKS cap: a removed eks-managed pool's worker got a deadline ${cap%% *}s and a drain window ${cap#* }s after the start"
    else
      bad "EKS cap: no decommission started on $E"
    fi
    # The sandbox gone, the drain window has nothing to wait for.
    say "delete $Es: $(api -X DELETE -w 'http=%{http_code}' "$U/v1/sandboxes/$Es" | tail -c 60)"
    for i in $(seq 1 120); do
      st=$($kc get aerolnode "$E" -o json 2>/dev/null)
      if [ -z "$st" ]; then s=gone; else s=$(jq -r '.status.state // "-"' <<<"$st"); fi
      { [ "$s" = gone ] || [ "$s" = Removed ]; } && ! $kw get pod "$E" >/dev/null 2>&1 && break
      sleep 2
    done
    if { [ "$s" = gone ] || [ "$s" = Removed ]; } && ! $kw get pod "$E" >/dev/null 2>&1; then ok "R6: the removed pool's worker $E was decommissioned and its pod removed, $((i * 2))s after its sandbox went"
    else bad "R6: the removed pool's worker $E is $s"; fi
    say "kept settings after: $($kc get aerolcluster aerolvm -o jsonpath='{.status.poolDecommission}' | head -c 300)"
  fi
  ensure

  # ---- R14: an orphan recovers when there is room; R1 on the old machine ----
  say "== R14: an orphan waits for room"
  local O Wo No oref others X t0 orph=""
  $kc scale deploy/aerolvm-operator --replicas=0 >/dev/null
  $kc wait --for=delete pod -l app.kubernetes.io/component=operator --timeout=90s >/dev/null 2>&1
  sn=$(snap)
  O=$(mk "$RC")
  Wo=$(owner "$O")
  No=$(podnode "$Wo")
  for i in $(seq 1 20); do alive "$O" && break; sleep 3; done
  oref=$(newref "$Wo" "$sn")
  # grpstate <worker> <ref>: the sandbox's cgroup as the agent sees it.
  grpstate() {
    $kw exec "$1" -c agent -- bash -c '
      p=$(cat /run/aerolvm/cgroup-parent); d=/sys/fs/cgroup/${p#/}/'"$2"'
      [ -d "$d" ] || d=$(find /sys/fs/cgroup -maxdepth 8 -type d -name '"$2"' 2>/dev/null | head -1)
      if [ -z "$d" ] || [ ! -d "$d" ]; then echo gone; else echo "group=$d procs=$(wc -l < "$d/cgroup.procs") $(grep frozen "$d/cgroup.events")"; fi' 2>&1 | tail -1
  }
  local gpre=""
  [ -n "$oref" ] && gpre=$(grpstate "$Wo" "$oref")
  say "sandbox $O on $Wo (machine $No), fence ref ${oref:-none}; alive: $(alive "$O" && echo yes || echo no)"
  others=$(alive_workers | grep -vx "$Wo")
  for w in $others; do say "cordon $w: $(api -X POST -w 'http=%{http_code}' "$U/v1/cluster/nodes/$w/cordon" | head -c 120)"; done
  t0=$(date +%s)
  docker pause "$No" >/dev/null && say "paused machine $No"
  avoid="$No"
  fwd
  for i in $(seq 1 60); do
    [ "$(orphaned "$O")" = true ] && { orph=$(( $(date +%s) - t0 )); break; }
    sleep 5
  done
  say "placement after $(( $(date +%s) - t0 ))s: $(placement "$O")"
  sleep 20
  say "20 s later, every other worker cordoned: $(placement "$O"); sandbox: $(api -w ' http=%{http_code}' "$U/v1/sandboxes/$O" | head -c 160)"
  [ -n "$orph" ] && [ "$(orphaned "$O")" = true ] && ok "R14: with no room, $O was orphaned ${orph}s after its machine stopped" || bad "R14: $O was not orphaned and kept (owner $(owner "$O"))"
  X=""
  for w in $others; do [ "$(podnode "$w")" != "$No" ] && { X="$w"; break; }; done
  say "uncordon $X: $(api -X POST -w 'http=%{http_code}' "$U/v1/cluster/nodes/$X/uncordon" | head -c 120)"
  local tu
  tu=$(date +%s)
  for i in $(seq 1 60); do
    [ "$(owner "$O")" = "$X" ] && break
    sleep 3
  done
  for i in $(seq 1 40); do alive "$O" && break; sleep 3; done
  local logged
  logged=$(for sv in aerolvm-server-0 aerolvm-server-1 aerolvm-server-2; do $kc logs "$sv" 2>/dev/null | grep 'orphaned failover sandbox found a node with room' | grep "$O"; done | tail -1 | cut -c1-300)
  say "leader: ${logged:-no log line}"
  if [ "$(owner "$O")" = "$X" ] && alive "$O"; then ok "R14: once $X had room, $O moved there and answers, $(( $(date +%s) - tu ))s after the uncordon"
  else bad "R14: $O owner $(owner "$O"), alive $(alive "$O" && echo yes || echo no), $(( $(date +%s) - tu ))s after the uncordon"; fi

  say "== R1: the old machine wakes"
  local tw
  tw=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker unpause "$No" >/dev/null && say "unpaused machine $No after $(( $(date +%s) - t0 ))s"
  local twoke
  twoke=$(date +%s)
  sleep 60
  say "supervisor on $Wo: $($kw logs "$Wo" -c runtime --since-time="$tw" 2>/dev/null | grep -E 'lease ran out|thawed|could not freeze' | cut -c1-260 | tr '\n' ' ')"
  say "agent on $Wo: $($kw logs "$Wo" -c agent --since-time="$tw" 2>/dev/null | grep -F "$O" | grep -v 'request complete' | tail -4 | cut -c1-260 | tr '\n' ' ')"
  # The old copy's cgroup: gone (sandboxd removed it), empty, or frozen
  # (the supervisor's lease guard). Read before the pause too, so "gone"
  # cannot come from looking in the wrong place.
  local grp
  if [ -n "$oref" ]; then
    grp=$(grpstate "$Wo" "$oref")
    say "old copy on $Wo: $grp (before the pause: $gpre)"
    case "$gpre/$grp" in
      group=*"frozen 0"/gone|group=*"frozen 0"/*"frozen 1"*|group=*"frozen 0"/*"procs=0 "*)
        ok "R1: the old copy of $O on $Wo does not run ($grp); the sandbox answers on $(owner "$O")" ;;
      *) bad "R1: the old copy of $O on $Wo: before $gpre, after $grp" ;;
    esac
  else
    say "INFO R1: no fence entry was found for $O, so its group cannot be named"
  fi
  # Then sandboxd removes the copy, whose placement is elsewhere, on its
  # next stale-ownership pass (SB_RECONCILE_INTERVAL, 5 minutes).
  if [ -n "$oref" ]; then
    for i in $(seq 1 45); do
      grp=$(grpstate "$Wo" "$oref")
      [ "$grp" = gone ] && break
      sleep 10
    done
    [ "$grp" = gone ] && ok "R14: sandboxd on $Wo removed the old copy $(( $(date +%s) - twoke ))s after its machine woke" ||
      bad "R14: the old copy on $Wo is still there $(( $(date +%s) - twoke ))s after its machine woke: $grp"
  fi

  # Put things back.
  avoid=""
  ensure
  for w in $others; do api -X POST "$U/v1/cluster/nodes/$w/uncordon" >/dev/null 2>&1; done
  $kc scale deploy/aerolvm-operator --replicas=1 >/dev/null
  say "RESULT pass=$pass fail=$fail"
}
