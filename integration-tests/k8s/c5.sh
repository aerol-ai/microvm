#!/usr/bin/env bash
# c5.sh: C5's measurement (plans/kubernetes-v2-architecture.md §8, "Gateways
# and servers run with no special rights"): a cluster server pod and an
# ingress (gateway) pod in a namespace that enforces `restricted` pod
# security, set up with `sandboxd init --files-only` and `sandboxd join
# --files-only` (finding F14's fix) and no other help.
#
#   c5.sh <kube-context> [image tag]     # writes .state/c5-<context>/c5-report.txt
#
# Every container runs as uid 65532 with no capabilities, no privilege
# escalation, the runtime's default seccomp profile and a read-only root
# file system; the API server refuses anything else in the namespace.
# Recorded: whether the server leads, whether the ingress joins and is a
# member, whether both answer /ready, and what each logs as missing.
set -euo pipefail
ctx="${1:?usage: c5.sh <kube-context> [image tag]}"
tag="${2:-dev}"
ns=aerolvm-c5
img="ghcr.io/aerol-ai/aerolvm:$tag"
root="$(git rev-parse --show-toplevel)"
sd="$root/integration-tests/k8s/.state/c5-$ctx"
mkdir -p "$sd"
report="$sd/c5-report.txt"
: > "$report"
say() { echo "$*" | tee -a "$report"; }
k() { kubectl --context "$ctx" -n "$ns" "$@"; }
# tr dies of SIGPIPE when head has enough; with pipefail that is not an error here.
rand() { (LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c "$1") 2>/dev/null || true; }

kubectl --context "$ctx" delete namespace "$ns" --wait=true --ignore-not-found >/dev/null
kubectl --context "$ctx" create namespace "$ns" >/dev/null
kubectl --context "$ctx" label namespace "$ns" pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/audit=restricted --overwrite >/dev/null
pat="$(rand 40)"
k create configmap sandboxd-env --from-literal=sandboxd.env="SB_PAT_TOKEN=$pat
SB_API_HOST=0.0.0.0
SB_API_PORT=21212
SB_DB_PATH=/var/lib/sandboxd/db/state.db
SB_ENABLE_CADDY=false
SB_ENABLE_NETWORK_RULES=false
SB_DOCKER_ENABLED=false
SB_CONTAINER_ENGINE=containerd
SB_CREDENTIAL_ENCRYPTION_KEY_PATH=/var/lib/sandboxd/credential_encryption.key
SB_TOOLBOX_BINARY_PATH=/usr/local/bin/toolboxd
SB_MOUNTS_ROOT=/var/lib/sandboxd/mounts
SB_MOUNTS_CRED_DIR=/var/lib/sandboxd/mount-creds
" >/dev/null

# pod <name> <setup command>: one node. An init container copies
# sandboxd.env into place, a second writes the cluster files, and sandboxd
# runs with both env files loaded, as systemd loads them on a VM.
pod() {
  local name="$1" setup="$2"
  cat <<YAML | k apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: { name: $name, labels: { app: c5, node: $name } }
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile: { type: RuntimeDefault }
  initContainers:
    - name: env
      image: $img
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "cp /config/sandboxd.env /etc/sandboxd/sandboxd.env && chmod 0600 /etc/sandboxd/sandboxd.env"]
      securityContext: &locked
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
      volumeMounts:
        - { name: config, mountPath: /config }
        - { name: etc, mountPath: /etc/sandboxd }
    - name: setup
      image: $img
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          $setup
      env:
        - name: POD_IP
          valueFrom: { fieldRef: { fieldPath: status.podIP } }
      securityContext: *locked
      volumeMounts:
        - { name: etc, mountPath: /etc/sandboxd }
        - { name: state, mountPath: /var/lib/sandboxd }
        - { name: tmp, mountPath: /tmp }
  containers:
    - name: sandboxd
      image: $img
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "set -a; . /etc/sandboxd/sandboxd.env; . /etc/sandboxd/cluster.env; set +a; exec sandboxd"]
      env:
        - name: SB_NODE_NAME
          value: $name
      securityContext: *locked
      ports:
        - { name: api, containerPort: 21212 }
        - { name: raft, containerPort: 7000 }
        - { name: gossip, containerPort: 7001 }
        - { name: internal, containerPort: 7002 }
        - { name: join, containerPort: 7003 }
      volumeMounts:
        - { name: etc, mountPath: /etc/sandboxd }
        - { name: state, mountPath: /var/lib/sandboxd }
        - { name: tmp, mountPath: /tmp }
        - { name: run, mountPath: /run/sandboxd }
  volumes:
    - { name: config, configMap: { name: sandboxd-env } }
    - { name: etc, emptyDir: {} }
    - { name: state, emptyDir: {} }
    - { name: tmp, emptyDir: {} }
    - { name: run, emptyDir: {} }
YAML
}

state() { k get pod "$1" -o jsonpath='{.status.phase} init={.status.initContainerStatuses[*].state} main={.status.containerStatuses[0].state}' | cut -c1-400; }
wait_running() {
  for _ in $(seq 1 90); do
    [[ "$(k get pod "$1" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null)" == true ]] && return 0
    [[ "$(k get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null)" =~ ^(Failed|Succeeded)$ ]] && break
    sleep 2
  done
  return 1
}
api() { k exec "$1" -c sandboxd -- bash -c "exec 3<>/dev/tcp/127.0.0.1/21212; printf 'GET $2 HTTP/1.0\r\nAuthorization: Bearer $pat\r\n\r\n' >&3; cat <&3" 2>/dev/null | tr -d '\r'; }
logs() { say "--- $1 logs ($2)"; k logs "$1" -c "$2" 2>&1 | grep -iE 'error|warn|denied|permission|fail|refus|cluster|leader|member' | cut -c1-240 | head -20 | tee -a "$report" >/dev/null; }

say "namespace $ns enforces restricted; image $img"
say "--- 1. the server: sandboxd init --files-only"
pod server-0 'sandboxd init --files-only --role server --node-id server-0 --advertise "$POD_IP"'
if wait_running server-0; then
  say "server-0 Ready: $(state server-0)"
else
  say "server-0 not Ready: $(state server-0)"
  logs server-0 setup; logs server-0 sandboxd
  exit 1
fi
say "server-0 /ready: $(api server-0 /ready | head -1)"
say "server-0 leader: $(api server-0 /v1/cluster/leader | tail -1 | cut -c1-200)"
logs server-0 setup

say "--- 2. sandboxd init again inside the running pod (not root): admit the node, make an ingress token"
tok="$(rand 6).$(rand 32)"
out="$(k exec server-0 -c sandboxd -- sh -c "set -a; . /etc/sandboxd/sandboxd.env; . /etc/sandboxd/cluster.env; set +a; sandboxd init --token ingress=$tok:1h" 2>&1 || true)"
echo "$out" | grep -vE "$pat" | tail -6 | tee -a "$report" >/dev/null
join="$(grep -o "join https://[^ ]* --token $tok --ca-cert-hash [^ ]*" <<<"$out" | head -1)"
[[ -n "$join" ]] || { say "no join command for the ingress token"; exit 1; }
say "join command: ${join%%--token*}--token <ingress token> --ca-cert-hash ${join##*--ca-cert-hash }"

say "--- 3. the gateway: sandboxd join --files-only, role ingress"
pod ingress-0 "sandboxd $join --role ingress --node-id ingress-0 --advertise \"\$POD_IP\" --files-only"
if wait_running ingress-0; then
  say "ingress-0 Ready: $(state ingress-0)"
else
  say "ingress-0 not Ready: $(state ingress-0)"
  logs ingress-0 setup; logs ingress-0 sandboxd
  exit 1
fi
sleep 10
say "ingress-0 /ready: $(api ingress-0 /ready | head -1)"
say "members (from server-0): $(api server-0 /v1/cluster/members | tail -1 | grep -o '"node_id":"[^"]*"\|"role":"[^"]*"\|"status":"[^"]*"' | tr '\n' ' ')"
logs ingress-0 setup
logs ingress-0 sandboxd
say "--- pod security: what the API server holds for each pod"
for p in server-0 ingress-0; do
  say "$p: uid $(k get pod $p -o jsonpath='{.spec.securityContext.runAsUser}'), privileged none, capabilities $(k get pod $p -o jsonpath='{.spec.containers[0].securityContext.capabilities}'), restarts $(k get pod $p -o jsonpath='{.status.containerStatuses[0].restartCount}')"
done
say "--- done; report in $report"
