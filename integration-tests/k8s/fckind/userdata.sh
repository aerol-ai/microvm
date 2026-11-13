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

[ -e /dev/kvm ] || modprobe kvm_intel 2>/dev/null
if [ -e /dev/kvm ]; then say "machine: /dev/kvm present, $(grep -c -w vmx /proc/cpuinfo) cpus with vmx, kernel $(uname -r)"; else say "machine: /dev/kvm ABSENT"; finish; fi

say "installing docker and the tools"
dnf -y -q install docker git tar gzip iptables >/dev/null 2>&1 || say "dnf install failed"
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
git init -q && git add -A >/dev/null 2>&1 && git -c user.email=fck@localhost -c user.name=fck commit -qm src >/dev/null 2>&1
say "building the images and starting kind"
t0=$(date +%s)
if ! scripts/k8s-dev.sh > /root/k8s-dev.log 2>&1; then say "k8s-dev failed:"; tail -20 /root/k8s-dev.log | sed 's/^/FCK   /'; finish; fi
say "built and installed in $(( $(date +%s) - t0 ))s"

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
