#!/usr/bin/env bash
# cellbench.sh: the Phase 3 cell-ceiling bench with stand-in workers
# (plans/kubernetes-v2-architecture.md §9.5, §19 "Cell ceiling"; C18).
#
#   AEROL_BUILD_REF=<commit> cellbench.sh <name> [worker machines] [stand-ins per machine]
#   # default 10 machines × 50 = 500 workers
#
# Three real servers, and many real sandboxd workers that run only WASM
# sandboxes, so a worker costs tens of MB and a machine holds 50. Every
# create, reservation, promote, gossip message, capacity poll and failover
# is the real one; only the sandboxes are light (an empty WASM module).
# Stand-ins get one IP each (join and gossip use fixed ports): every worker
# machine takes four IPv4 /28 prefixes on its network interface, and each
# stand-in runs in its own network namespace (ipvlan, an address from the
# prefixes) and mount namespace (its own /etc/sandboxd and /var/lib/sandboxd).
#
# A driver machine then measures, and prints BENCH lines to its console:
#   1. failover: every other worker cordoned, 1,000 recreate sandboxes on
#      one victim, cordons lifted, the victim killed: how many are back
#      every 10 s up to a minute, then at 2 and 5 minutes (§9.5: 1,000 in
#      60 s; E7);
#   2. throughput: one aerolvm-bench per gateway (machine 1 also runs 3
#      gateways: more than 10 members need the ingress tier), summed, at
#      rising concurrency (creates per second, p50, p99; §9.5: 1,000 per
#      second). Each run has a time limit that makes a stuck one print
#      every goroutine's stack;
#   3. the leader's metrics around it (Raft applies and snapshots,
#      placement, capacity polls);
#   4. with AEROL_BENCH_PROFILE_STEP=<c>: 30 s CPU profiles of the servers
#      and one gateway, and s1's allocations, during that step, uploaded to
#      the artifact bucket and copied to the state folder (prof/).
# Servers and worker machines print LOAD lines (CPU and memory of their
# sandboxd processes) every 30 s: the capacity polling's cost (E5).
#
# Nothing goes from this machine to a node directly: the binaries go through
# the artifact bucket (presigned URLs). Machines talk to each other on the
# private network only (tokens from s1, the kill signal from the driver).
# Every resource carries aerol:ttl for reap.sh, and the run tears itself down.
set -euo pipefail
name="${1:?usage: cellbench.sh <name> [worker machines] [stand-ins per machine]}"
machines="${2:-10}" per="${3:-50}"
server_type="${AEROL_BENCH_SERVER_TYPE:-m7i.xlarge}"
worker_type="${AEROL_BENCH_WORKER_TYPE:-m7i.4xlarge}"
driver_type="${AEROL_BENCH_DRIVER_TYPE:-m7i.2xlarge}"
victim_sandboxes="${AEROL_BENCH_VICTIM_SANDBOXES:-1000}"
steps="${AEROL_BENCH_STEPS:-32 128 512}"
step_seconds="${AEROL_BENCH_STEP_SECONDS:-120}"
profile_step="${AEROL_BENCH_PROFILE_STEP:-}"
(( per <= 61 )) || { echo "cellbench: at most 61 stand-ins per machine (4 × /28, and machine 1 also holds the 3 gateways)" >&2; exit 2; }
(( machines <= 15 )) || { echo "cellbench: at most 15 worker machines (their prefixes sit in one /20)" >&2; exit 2; }
region=us-east-1
root="$(git rev-parse --show-toplevel)"
sd="$root/integration-tests/k8s/.state/$name"
mkdir -p "$sd"
report="$sd/cellbench-report.txt"
: > "$report"
say() { echo "[$(date -u +%T)] $*" | tee -a "$report"; }
aws() { command aws --region "$region" "$@"; }

# AEROL_BENCH_DRY=1 writes the machines' user data with stand-in values to
# the state folder and stops: no build, no AWS (checked with bash -n).
dry="${AEROL_BENCH_DRY:-}"
if [[ -n "$dry" ]]; then
  bin_url=https://example.invalid/bench-bin.tgz s1=10.0.0.1 s2=10.0.0.2 s3=10.0.0.3 drv=10.0.0.4 admin=dry-admin cidr=10.0.0.0/20
  declare -A prof_url=([cpu-s1]=https://example.invalid/1 [cpu-s2]=https://example.invalid/2 [cpu-s3]=https://example.invalid/3
    [cpu-g1]=https://example.invalid/4 [allocs-s1]=https://example.invalid/5)
else
# --- build -------------------------------------------------------------------
ref="$(git -C "$root" rev-parse "${AEROL_BUILD_REF:-HEAD}^{commit}")"
target="$(sed -n 's/^ZIG_TARGET_amd64="\(.*\)"/\1/p' "$root/integration-tests/lib/build.sh")"
wt="$(mktemp -d)"
git -C "$root" worktree add --detach --force "$wt" "$ref" >/dev/null 2>&1
mkdir -p "$sd/bin"
(cd "$wt" && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC="zig cc -target $target" CXX="zig c++ -target $target" \
  go build -trimpath -ldflags "-X github.com/aerol-ai/microvm/internal/version.Version=bench-${ref:0:12}" \
  -o "$sd/bin/sandboxd" ./cmd/sandboxd &&
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$sd/bin/toolboxd" ./cmd/toolboxd &&
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$sd/bin/aerolvm-bench" ./cmd/aerolvm-bench)
git -C "$root" worktree remove --force "$wt"
# The smallest valid WASM module: the stand-ins' only "workload".
printf '\x00asm\x01\x00\x00\x00' > "$sd/bin/bench.wasm"
tar -C "$sd/bin" -czf "$sd/bench-bin.tgz" sandboxd toolboxd aerolvm-bench bench.wasm
bucket="aerol-itest-artifacts-$(aws sts get-caller-identity --query Account --output text)"
key="builds/cellbench-${ref:0:12}/bench-bin.tgz"
aws s3 cp --only-show-errors "$sd/bench-bin.tgz" "s3://$bucket/$key"
bin_url="$(aws s3 presign "s3://$bucket/$key" --expires-in 14400)"
say "build ${ref:0:12}: binaries staged"
# presign_put <key>: a link that lets the driver upload one object with
# curl -T (SigV4 query signing; aws s3 presign only makes GET links).
presign_put() {
  ( eval "$(command aws configure export-credentials --format env)"
    python3 - "$bucket" "$1" 14400 "$region" <<'PY'
import datetime, hashlib, hmac, os, sys, urllib.parse as u
bucket, key, expires, region = sys.argv[1:5]
host = f"{bucket}.s3.{region}.amazonaws.com"
now = datetime.datetime.now(datetime.timezone.utc)
amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
scope = f"{day}/{region}/s3/aws4_request"
q = {"X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": f"{os.environ['AWS_ACCESS_KEY_ID']}/{scope}",
     "X-Amz-Date": amz, "X-Amz-Expires": expires, "X-Amz-SignedHeaders": "host"}
if os.environ.get("AWS_SESSION_TOKEN"):
    q["X-Amz-Security-Token"] = os.environ["AWS_SESSION_TOKEN"]
qs = "&".join(f"{u.quote(k, safe='-_.~')}={u.quote(v, safe='-_.~')}" for k, v in sorted(q.items()))
path = "/" + u.quote(key, safe="/-_.~")
creq = f"PUT\n{path}\n{qs}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD"
sts = f"AWS4-HMAC-SHA256\n{amz}\n{scope}\n{hashlib.sha256(creq.encode()).hexdigest()}"
k = ("AWS4" + os.environ["AWS_SECRET_ACCESS_KEY"]).encode()
for part in (day, region, "s3", "aws4_request"):
    k = hmac.new(k, part.encode(), hashlib.sha256).digest()
print(f"https://{host}{path}?{qs}&X-Amz-Signature={hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()}")
PY
  )
}
prof_prefix="cellbench/$name-$(date -u +%Y%m%dT%H%M%S)"
declare -A prof_url
if [[ -n "$profile_step" ]]; then
  for p in cpu-s1 cpu-s2 cpu-s3 cpu-g1 allocs-s1; do prof_url[$p]="$(presign_put "$prof_prefix/$p.pb.gz")"; done
fi

# --- network -----------------------------------------------------------------
vpc="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
read -r subnet cidr <<<"$(aws ec2 describe-subnets --filters Name=vpc-id,Values="$vpc" Name=availability-zone,Values=${region}a \
  --query 'Subnets[0].[SubnetId,CidrBlock]' --output text)"
# Fixed addresses deep in the subnet for the servers and the driver.
mapfile -t ips < <(python3 -c "import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); [print(n.network_address+i) for i in (2581,2582,2583,2584)]" "$cidr")
s1="${ips[0]}" s2="${ips[1]}" s3="${ips[2]}" drv="${ips[3]}"
# The worker machines' own addresses are fixed too (offset 2600 on): left
# to AWS, one landed inside another machine's prefix and the launch failed
# (run bench-full-1).
mapfile -t wips < <(python3 -c "import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); [print(n.network_address+2600+m) for m in range(1, int(sys.argv[2])+1)]" "$cidr" "$machines")
ttl="$(date -u -v+4H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+4 hours' +%Y-%m-%dT%H:%M:%SZ)"
tags="ResourceType=%s,Tags=[{Key=Name,Value=aerol-cellbench-$name},{Key=aerol:ttl,Value=$ttl},{Key=aerol:run,Value=$name}]"
sg="$(aws ec2 create-security-group --group-name "aerol-cellbench-$name" --description "cell bench $name" --vpc-id "$vpc" \
  --tag-specifications "$(printf "$tags" security-group)" --query GroupId --output text)"
aws ec2 authorize-security-group-ingress --group-id "$sg" --ip-permissions "IpProtocol=-1,UserIdGroupPairs=[{GroupId=$sg}]" >/dev/null
instances=""
cleanup() {
  [[ -n "$instances" ]] && aws ec2 terminate-instances --instance-ids $instances >/dev/null 2>&1 &&
    aws ec2 wait instance-terminated --instance-ids $instances 2>/dev/null || true
  aws ec2 delete-security-group --group-id "$sg" >/dev/null 2>&1 || echo "cellbench: delete security group $sg by hand" >&2
}
trap cleanup EXIT
ami="$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --query Parameter.Value --output text)"
admin="$(openssl rand -hex 24)"
used="$(aws ec2 describe-network-interfaces --filters Name=subnet-id,Values="$subnet" \
  --query 'NetworkInterfaces[].[PrivateIpAddresses[].PrivateIpAddress, Ipv4Prefixes[].Ipv4Prefix][]' --output text | tr '\t' '\n')"
printf '%s\n' "$used" > "$sd/used-addresses.txt"
free_prefixes="$(python3 - "$cidr" "$machines" "${ips[*]} ${wips[*]}" "$sd/used-addresses.txt" <<'FREE'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1]); want = 4 * int(sys.argv[2])
taken = [ipaddress.ip_network(x if '/' in x else x + '/32', strict=False)
         for x in open(sys.argv[4]).read().split() + sys.argv[3].split() if x not in ('None',)]
out = []
for off in range(3072, net.num_addresses - 16, 16):
    block = ipaddress.ip_network(f"{net.network_address + off}/28")
    if not any(block.overlaps(t) for t in taken):
        out.append(str(block))
    if len(out) == want:
        break
if len(out) < want:
    sys.exit(f"cellbench: only {len(out)} free /28 prefixes in {net}, need {want}")
print(' '.join(out))
FREE
)"
fi

# --- user data ---------------------------------------------------------------
# Common to every machine: fetch and unpack the binaries, and a LOAD line
# every 30 s (the sandboxd processes' summed CPU and memory).
common() {
  cat <<EOF
#!/bin/bash
exec > >(tee /var/log/bench.log /dev/console) 2>&1
set -u
dnf -y -q install jq >/dev/null 2>&1 || true
mkdir -p /opt/bench && cd /opt/bench
curl -fsSL --retry 8 -o bin.tgz '$bin_url' && tar xzf bin.tgz && install -m 0755 sandboxd toolboxd aerolvm-bench /usr/local/bin/
load() { while :; do
  read -r cpu rss n < <(ps -C sandboxd -o %cpu=,rss= | awk '{c+=\$1; r+=\$2; n++} END {printf "%.0f %.0f %d", c, r/1024, n}')
  echo "LOAD \$1 \$(date -u +%T) sandboxd=\$n cpu=\${cpu}% rss=\${rss}MB loadavg=\$(cut -d' ' -f1 /proc/loadavg)"
  sleep 30
done; }
start_sandboxd() { # start one sandboxd from /etc/sandboxd, as the chart's agent does
  pod_env="\$(export -p)"; set -a; . /etc/sandboxd/sandboxd.env; [ -s /etc/sandboxd/cluster.env ] && . /etc/sandboxd/cluster.env; set +a; eval "\$pod_env"
  exec sandboxd
}
EOF
}
server_env="SB_PAT_TOKEN=$admin SB_API_HOST=0.0.0.0 SB_API_PORT=21212 SB_DB_PATH=/var/lib/sandboxd/db/state.db \
SB_CREDENTIAL_ENCRYPTION_KEY_PATH=/var/lib/sandboxd/credential_encryption.key SB_DOCKER_ENABLED=false \
SB_ENABLE_NETWORK_RULES=false SB_ENABLE_CADDY=false SB_CONTAINER_ENGINE=containerd SB_CLUSTER_OWNER_CACHE=true SB_ENABLE_PPROF=true \
SB_TOOLBOX_BINARY_PATH=/usr/local/bin/toolboxd SB_MOUNTS_ROOT=/var/lib/sandboxd/mounts SB_MOUNTS_CRED_DIR=/run/sandboxd"

server_ud() { # <id> <ip>
  common
  cat <<EOF
mkdir -p /etc/sandboxd /var/lib/sandboxd/db /var/lib/sandboxd/mounts /run/sandboxd /srv/www
export $server_env
env | grep '^SB_' > /etc/sandboxd/sandboxd.env
if [ "$1" = s1 ]; then
  sandboxd init --files-only --role server --node-id s1 --advertise $2
else
  until tok="\$(curl -fsS http://$s1:8080/token-$1)" && [ -n "\$tok" ]; do sleep 2; done
  until sandboxd join https://$s1:7003 --token "\$tok" --role server --node-id $1 --advertise $2 --files-only; do sleep 5; done
fi
(start_sandboxd) > /var/log/sandboxd.log 2>&1 &
until curl -fsS -o /dev/null http://127.0.0.1:21212/health; do sleep 1; done
echo "BENCHNODE $1 up \$(date -u +%T)"
if [ "$1" = s1 ]; then
  # A token only once one comes back: right after /health the node may not
  # lead yet (503), and an empty answer must never be published.
  mint() { # <file> <body>
    local out t
    for try in \$(seq 1 120); do
      out="\$(curl -sS -H "Authorization: Bearer $admin" -H 'Content-Type: application/json' -X POST \
        http://127.0.0.1:21212/v1/cluster/join-tokens -d "\$2")"
      t="\$(jq -r '.token // empty' <<<"\$out" 2>/dev/null)"
      [ -n "\$t" ] && { echo "\$t" > /srv/www/\$1.tmp && mv /srv/www/\$1.tmp /srv/www/\$1; return 0; }
      echo "BENCHNODE s1 mint \$1 try \$try: \$(head -c 200 <<<"\$out")"; sleep 2
    done
    return 1
  }
  mint token-s2 '{"role":"server","ttl":"4h","reusable":false,"created_by":"bench"}'
  mint token-s3 '{"role":"server","ttl":"4h","reusable":false,"created_by":"bench"}'
  mint token-worker '{"role":"worker","ttl":"4h","reusable":true,"created_by":"bench"}'
  mint token-ingress '{"role":"ingress","ttl":"4h","reusable":true,"created_by":"bench"}'
  echo "BENCHNODE s1 tokens published \$(date -u +%T)"
  (cd /srv/www && python3 -m http.server 8080 >/dev/null 2>&1 &)
fi
load $1
EOF
}

# prefixes_of <machine number>: its four /28 prefixes, chosen before the
# launch so the machine's script knows them without asking the metadata
# service. free_prefixes picks them from offset 3072 on, skipping every /28
# that holds an address already in use in the subnet (an address or a
# prefix of any network interface there: run bench-full-1 hit one).
free_prefixes=""
prefixes_of() {
  if [[ -z "$free_prefixes" ]]; then
    python3 -c "import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); b=3072+64*(int(sys.argv[2])-1); print(' '.join(f'{n.network_address+b+16*k}/28' for k in range(4)))" "$cidr" "$1"
    return
  fi
  tr ' ' '\n' <<<"$free_prefixes" | sed -n "$(( ($1 - 1) * 4 + 1 )),$(( $1 * 4 ))p" | paste -sd' ' -
}

worker_ud() { # <machine number>
  local m prefixes; m=$(printf %02d "$1"); prefixes="$(prefixes_of "$1")"
  common
  cat <<EOF
modprobe ipvlan
# The mount points each stand-in binds its own folders over.
mkdir -p /etc/sandboxd /var/lib/sandboxd /run/sandboxd
tok=; until tok="\$(curl -fsS http://$s1:8080/token-worker)" && [ -n "\$tok" ]; do sleep 3; done
prefixes="$prefixes"
dev=\$(ip route show default | awk '{print \$5; exit}'); gw=\$(ip route show default | awk '{print \$3; exit}')
plen=\$(ip -o -4 addr show dev \$dev | awk '{print \$4}' | head -1 | cut -d/ -f2)
mapfile -t addrs < <(python3 -c 'import ipaddress,sys; [print(a) for p in sys.argv[1:] for a in ipaddress.ip_network(p)]' \$prefixes)
# A cell of more than 10 nodes needs a gateway tier (LargeClusterTopologyError,
# run bench-full-2): machine 1 also runs the 3 gateways, after its workers.
gtok=; total=$per
if [ "$m" = 01 ]; then
  until gtok="\$(curl -fsS http://$s1:8080/token-ingress)" && [ -n "\$gtok" ]; do sleep 3; done
  total=\$(( $per + 3 ))
fi
zones=(z-a z-b z-c)
for i in \$(seq 1 \$total); do
  n=\$(printf %02d \$i) ip=\${addrs[\$((i-1))]} ns=sb\$n d=/srv/sb\$n
  if [ \$i -le $per ]; then role=worker node=w$m-\$n tk=\$tok wasm="SB_ENABLE_WASM=true SB_HOST_RUNTIMES=wasm SB_WASM_MODULES_DIR=/var/lib/sandboxd/wasm/modules SB_WASM_STANDARD_MODULES=bench=bench.wasm"
  else role=ingress node=g\$(( i - $per )) tk=\$gtok wasm=""; fi
  mkdir -p \$d/etc \$d/lib/db \$d/lib/mounts \$d/lib/wasm/modules \$d/run
  cp /opt/bench/bench.wasm \$d/lib/wasm/modules/bench.wasm
  ip netns add \$ns
  ip link add ipv\$n link \$dev type ipvlan mode l2
  ip link set ipv\$n netns \$ns
  ip netns exec \$ns ip addr add \$ip/\$plen dev ipv\$n
  ip netns exec \$ns ip link set lo up
  ip netns exec \$ns ip link set ipv\$n up
  ip netns exec \$ns ip route add default via \$gw
  cat > \$d/standin.sh <<STANDIN
#!/bin/bash
set -u
mount --bind \$d/etc /etc/sandboxd && mount --bind \$d/lib /var/lib/sandboxd && mount --bind \$d/run /run/sandboxd || exit 1
export SB_API_HOST=0.0.0.0 SB_API_PORT=21212 SB_DB_PATH=/var/lib/sandboxd/db/state.db \\\\
  SB_CREDENTIAL_ENCRYPTION_KEY_PATH=/var/lib/sandboxd/credential_encryption.key SB_DOCKER_ENABLED=false \\\\
  SB_ENABLE_NETWORK_RULES=false SB_ENABLE_CADDY=false SB_CONTAINER_ENGINE=containerd SB_ENABLE_SSH_GATEWAY=false SB_ENABLE_PPROF=true \\\\
  \$wasm SB_NODE_ZONE=\${zones[\$(( (i-1) % 3 ))]} \\\\
  SB_TOOLBOX_BINARY_PATH=/usr/local/bin/toolboxd SB_MOUNTS_ROOT=/var/lib/sandboxd/mounts SB_MOUNTS_CRED_DIR=/run/sandboxd
if [ ! -s /etc/sandboxd/cluster.env ]; then
  env | grep '^SB_' > /etc/sandboxd/sandboxd.env
  for try in 1 2 3 4 5 6 7 8 9 10; do
    sandboxd join https://$s1:7003 --token \$tk --role \$role --node-id \$node --advertise \$ip --files-only && break
    sleep \\\$((try * 3))
  done
fi
pod_env="\\\$(export -p)"; set -a; . /etc/sandboxd/sandboxd.env; [ -s /etc/sandboxd/cluster.env ] && . /etc/sandboxd/cluster.env; set +a; eval "\\\$pod_env"
exec sandboxd
STANDIN
  chmod +x \$d/standin.sh
  (ip netns exec \$ns unshare -m --propagation private \$d/standin.sh > \$d/sandboxd.log 2>&1 &)
  sleep 0.3
done
echo "BENCHNODE m$m started $per stand-ins \$(date -u +%T)"
if [ "$m" = 01 ]; then
  ( until curl -fs -o /dev/null http://$drv:8080/kill 2>/dev/null; do sleep 1; done
    pids=\$(ip netns pids sb01); kill -9 \$pids
    echo "KILLED w01-01 \$(date -u +%s.%N) pids=\$pids" ) &
fi
# Every minute, one line per stand-in that is not up: the last line of its
# log, so a failure shows on the console.
( while :; do
    sleep 60
    for d in /srv/sb*; do
      n=\${d##*/sb}
      ip netns pids sb\$n 2>/dev/null | grep -q . && grep -q 'member joined' \$d/sandboxd.log 2>/dev/null && continue
      echo "STANDIN m$m-\$n down: \$(grep -v 'request complete' \$d/sandboxd.log 2>/dev/null | tail -1 | cut -c1-220)"
    done
  done ) &
load m$m
EOF
}

driver_ud() {
  # The gateways: machine 1's addresses after its workers.
  local gws
  mapfile -t gws < <(python3 -c "import ipaddress,sys; a=[str(x) for p in sys.argv[2:] for x in ipaddress.ip_network(p)]; print(chr(10).join(a[int(sys.argv[1]):int(sys.argv[1])+3]))" "$per" $(prefixes_of 1))
  common
  cat <<EOF
mkdir -p /srv/www && (cd /srv/www && python3 -m http.server 8080 >/dev/null 2>&1 &)
api() { curl -fsS -m 30 -H "Authorization: Bearer $admin" -H 'Content-Type: application/json' "\$@"; }
S=http://$s1:21212
# Creates go through the gateways, as a client's would; admin calls to s1.
G1=http://${gws[0]}:21212 G2=http://${gws[1]}:21212 G3=http://${gws[2]}:21212
want=\$((6 + $machines * $per))
t0=\$(date +%s)
while :; do
  n=\$(api \$S/v1/cluster/members 2>/dev/null | jq '[(.members // .)[] | select(.alive)] | length' 2>/dev/null || echo 0)
  [ "\${n:-0}" -ge \$want ] && break
  [ \$(( \$(date +%s) - t0 )) -gt 1800 ] && break
  echo "BENCH members \$n of \$want \$(date -u +%T)"; sleep 20
done
echo "BENCH members \$n of \$want after \$(( \$(date +%s) - t0 ))s"
# Only what the bench reads: the console keeps its last 64 KB.
# Empty buckets are left out. The steps of a commit come from the leader
# (s1 starts the cluster) and, for a follower's own write, from s2.
metrics() {
  api \$S/v1/metrics | grep -E '^aerolvm_(raft_apply|raft_snapshot|raft_leader_store|raft_append_rpc|raft_commit|raft_fsm_enqueue|cluster_placement|scheduler|capacity_lease|cluster_capacity|go_goroutines|cluster_reserve|create)' | grep -v '^#' | grep -v ' 0\$' | sed "s/^/BENCH metric \$1 /"
  api http://$s2:21212/v1/metrics | grep -E '^aerolvm_raft_(follower_store|apply_wait|apply_fsm)' | grep -v ' 0\$' | sed "s/^/BENCH metric \$1 s2:/"
}
# A member is not a placement target until a server has its capacity
# (polled every few seconds): wait for one create to go through.
probe() { api -X POST \$G1/v1/sandboxes -d '{"runtime":"wasm","module_ref":"bench","tags":{"bench":"probe"}}' 2>/dev/null | jq -r '.id // empty'; }
for try in \$(seq 1 60); do id=\$(probe); [ -n "\$id" ] && break; sleep 5; done
echo "BENCH placement ready after \$(( \$(date +%s) - t0 ))s (probe \${id:-none})"
[ -n "\${id:-}" ] && api -X DELETE \$S/v1/sandboxes/\$id -o /dev/null
metrics idle

# 1. Failover of $victim_sandboxes sandboxes from one dead worker.
workers=\$(api \$S/v1/cluster/members | jq -r '(.members // .)[] | select(.role=="worker") | .node_id')
for w in \$workers; do [ "\$w" = w01-01 ] || echo \$w; done | xargs -P 32 -I{} curl -fsS -m 30 -o /dev/null -H "Authorization: Bearer $admin" -X POST \$S/v1/cluster/nodes/{}/cordon
sleep 10
cat > /srv/create-one.sh <<'ONE'
#!/bin/bash
# One recreate sandbox, tried up to 5 times; the failure's answer on stderr.
for try in 1 2 3 4 5; do
  out=\$(curl -sS -m 60 -H "Authorization: Bearer \$ADMIN" -H 'Content-Type: application/json' -X POST "\$C/v1/sandboxes" \\
    -d '{"runtime":"wasm","module_ref":"bench","cpu":0.1,"memory_mb":16,"failover":{"policy":"recreate"},"tags":{"bench":"failover"}}')
  id=\$(jq -r '.id // empty' <<<"\$out" 2>/dev/null); [ -n "\$id" ] && { echo "\$id"; exit 0; }
  sleep 2
done
echo "create failed: \$(head -c 200 <<<"\$out")" >&2
ONE
chmod +x /srv/create-one.sh
export ADMIN=$admin C=\$G1
seq 1 $victim_sandboxes | xargs -P 32 -I{} /srv/create-one.sh 2> >(sort | uniq -c | head -3 | sed 's/^/BENCH failover-create-error /') > /srv/ids.txt
for w in \$workers; do [ "\$w" = w01-01 ] || echo \$w; done | xargs -P 32 -I{} curl -fsS -m 30 -o /dev/null -H "Authorization: Bearer $admin" -X POST \$S/v1/cluster/nodes/{}/uncordon
# owner_of <ids file>: "<id> <owner>" per line.
owner_of() { xargs -P 32 -I{} sh -c "echo {} \\\$(curl -fsS -m 10 -H 'Authorization: Bearer $admin' \$S/v1/cluster/placements/{} | jq -r '.owner.node_id // .owner // \"none\"')" < "\$1"; }
owner_of /srv/ids.txt > /srv/owners.txt
awk '\$2 == "w01-01" {print \$1}' /srv/owners.txt > /srv/victims.txt
echo "BENCH failover created \$(grep -c . /srv/ids.txt), \$(grep -c . /srv/victims.txt) on the victim; owners: \$(awk '{print \$2}' /srv/owners.txt | sort | uniq -c | sort -rn | head -3 | tr '\n' ' ')"
touch /srv/www/kill; tk=\$(date +%s)
for at in 10 20 30 40 50 60 120 300; do
  sleep \$(( tk + at - \$(date +%s) ))
  away=\$(owner_of /srv/victims.txt | awk '\$2 != "w01-01" && \$2 != "none"' | grep -c .)
  echo "BENCH failover \${at}s: \$away of \$(grep -c . /srv/victims.txt) moved to a live worker"
done
metrics after-failover
xargs -P 32 -I{} curl -fsS -m 30 -o /dev/null -H "Authorization: Bearer $admin" -X DELETE \$S/v1/sandboxes/{} < /srv/ids.txt

# 2. Throughput.
# One aerolvm-bench per gateway, a third of the concurrency each; summed.
for c in $steps; do
  # SIGQUIT makes a stuck one print every goroutine's stack (exit 2).
  pids=""
  for g in \$G1 \$G2 \$G3; do
    timeout -s QUIT \$(( ${step_seconds} + 900 )) aerolvm-bench -api \$g -token $admin -runtime wasm -image bench -concurrency \$(( (c + 2) / 3 )) -duration ${step_seconds}s -json > /srv/bench-\${g##*/}.json 2> /srv/bench-\${g##*/}.err &
    pids="\$pids \$!"
  done
  prof=""
  if [ "\$c" = "${profile_step:-none}" ]; then
    # Half a minute in, so the profile sees the steady state.
    ( sleep 30
      pp() { curl -fsS -m 90 -H "Authorization: Bearer $admin" -o /srv/\$1.pb.gz "\$2" && curl -fsS -m 120 -T /srv/\$1.pb.gz "\$3" && echo "BENCH profile \$1 \$(stat -c %s /srv/\$1.pb.gz) bytes uploaded" || echo "BENCH profile \$1 failed"; }
      pp cpu-s1 "\$S/debug/pprof/profile?seconds=30" '${prof_url[cpu-s1]:-}' &
      pp cpu-s2 "http://$s2:21212/debug/pprof/profile?seconds=30" '${prof_url[cpu-s2]:-}' &
      pp cpu-s3 "http://$s3:21212/debug/pprof/profile?seconds=30" '${prof_url[cpu-s3]:-}' &
      pp cpu-g1 "\$G1/debug/pprof/profile?seconds=30" '${prof_url[cpu-g1]:-}' &
      wait
      pp allocs-s1 "\$S/debug/pprof/allocs" '${prof_url[allocs-s1]:-}' ) &
    prof=\$!
  fi
  for p in \$pids; do wait \$p || echo "BENCH bench-exit c=\$c pid=\$p rc=\$?"; done
  [ -n "\$prof" ] && wait \$prof
  for e in /srv/bench-*.err; do
    if grep -q '^goroutine ' "\$e"; then
      echo "BENCH bench-hang \$e"; grep -A2 '^goroutine ' "\$e" | grep -v '^--' | head -60 | sed 's/^/BENCH stack /'
    else
      tail -2 "\$e" | sed "s|^|BENCH bench-log \${e##*/} |"
    fi
  done
  echo "BENCH throughput c=\$c \$(jq -s -c '{creates_per_second: (map(.creates_per_second) | add), ok: (map(.creates.succeeded) | add), failed: (map(.creates.failed) | add), p50_ms: map(.create_latency_ms.p50), p99_ms: map(.create_latency_ms.p99), errors: (map(.errors[0].example // empty) | .[0:2])}' /srv/bench-*.json 2>/dev/null)"
  rm -f /srv/bench-*.json /srv/bench-*.err
  metrics after-c\$c
done
echo "BENCH DONE"
EOF
}

if [[ -n "$dry" ]]; then
  for s in s1 s2 s3; do ip="${!s}"; server_ud "$s" "$ip" > "$sd/ud-$s.sh"; done
  for m in $(seq 1 "$machines"); do worker_ud "$m" > "$sd/ud-m$m.sh"; done
  driver_ud > "$sd/ud-driver.sh"
  echo "cellbench: dry run, user data in $sd"; exit 0
fi

# --- launch ------------------------------------------------------------------
run() { # <ud file> <type> <ip or ""> [prefixes] [disk]
  local ni="DeviceIndex=0,SubnetId=$subnet,Groups=$sg,AssociatePublicIpAddress=true"
  [[ -n "$3" ]] && ni+=",PrivateIpAddress=$3"
  [[ -n "${4:-}" ]] && ni+=",Ipv4Prefixes=[$(for p in $4; do printf '{Ipv4Prefix=%s},' "$p"; done | sed 's/,$//')]"
  aws ec2 run-instances --image-id "$ami" --instance-type "$2" --network-interfaces "$ni" \
    --instance-initiated-shutdown-behavior terminate --user-data "file://$1" \
    --block-device-mappings "DeviceName=/dev/xvda,Ebs={VolumeSize=40,VolumeType=gp3,DeleteOnTermination=true${5:-}}" \
    --tag-specifications "$(printf "$tags" instance)" "$(printf "$tags" volume)" \
    --query 'Instances[0].InstanceId' --output text
}
declare -A ids
# AEROL_BENCH_SERVER_IOPS: the servers' gp3 IOPS and MB/s (3000/125 is
# gp3's floor), to tell a disk limit from the code's (F29).
server_disk=""
if [[ -n "${AEROL_BENCH_SERVER_IOPS:-}" ]]; then
  server_disk=",Iops=$AEROL_BENCH_SERVER_IOPS,Throughput=${AEROL_BENCH_SERVER_MBPS:-1000}"
fi
for s in s1 s2 s3; do
  ip="${!s}"
  server_ud "$s" "$ip" > "$sd/ud-$s.sh"
  ids[$s]="$(run "$sd/ud-$s.sh" "$server_type" "$ip" "" "$server_disk")"; instances+=" ${ids[$s]}"
done
for m in $(seq 1 "$machines"); do
  worker_ud "$m" > "$sd/ud-m$m.sh"
  ids[m$m]="$(run "$sd/ud-m$m.sh" "$worker_type" "${wips[$((m - 1))]}" "$(prefixes_of "$m")")"; instances+=" ${ids[m$m]}"
done
driver_ud > "$sd/ud-driver.sh"
ids[driver]="$(run "$sd/ud-driver.sh" "$driver_type" "$drv")"; instances+=" ${ids[driver]}"
say "machines: 3 × $server_type${server_disk:+ (gp3$server_disk)}, $machines × $worker_type ($per stand-ins each), driver $driver_type; $(aws ec2 describe-images --image-ids "$ami" --query 'Images[0].Name' --output text)"

# --- results -----------------------------------------------------------------
console() { aws ec2 get-console-output --instance-id "$1" --latest --query Output --output text 2>/dev/null || true; }
start=$(date +%s)
while (( $(date +%s) - start < 7200 )); do
  out="$(console "${ids[driver]}")"
  grep -q 'BENCH DONE' <<<"$out" && break
  sleep 60
done
# Each line reaches the console twice (as written, and through cloud-init's
# log with a prefix): keep the bare ones.
grep -E '^BENCH ' <<<"$out" | tee -a "$report"
for s in s1 s2 s3 m1; do console "${ids[$s]}" | grep -E '^(LOAD|KILLED|BENCHNODE|STANDIN)' | tail -14 | sed "s/^/$s: /" >> "$report"; done
grep -q 'BENCH DONE' "$report" || say "cellbench: the driver did not finish within two hours"
if [[ -n "$profile_step" ]]; then
  aws s3 cp --only-show-errors --recursive "s3://$bucket/$prof_prefix/" "$sd/prof/" && say "profiles in $sd/prof: $(ls "$sd/prof" 2>/dev/null | tr '\n' ' ')"
fi
say "--- done in $(( ($(date +%s) - start) / 60 )) min; report in $report"
