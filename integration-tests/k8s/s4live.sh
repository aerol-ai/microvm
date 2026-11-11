#!/usr/bin/env bash
# s4live.sh: S4's live half (plans/kubernetes-v2-architecture.md §18). The
# reserve benchmark on three real server machines: the production Raft setup
# on each machine's own disk, TCP between them (internal/cluster
# s4_live_test.go, build tag s4live).
#
#   AEROL_BUILD_REF=<commit> s4live.sh <name> [instance type]   # default m7i.xlarge
#
# 1. Builds the test binary (cgo, zig, glibc 2.31 floor, as build.sh does)
#    and stages it in the artifact bucket (rule 3: nothing goes from this
#    machine to a node directly).
# 2. Launches three Amazon Linux 2023 machines in the default VPC with fixed
#    private addresses and a security group open to itself on 7400 only. Each
#    fetches the binary and runs its part; s1 leads and runs the reserves.
# 3. Reads s1's "S4" lines from its console, then terminates all three and
#    deletes the group. Every resource carries aerol:ttl for reap.sh.
set -euo pipefail
name="${1:?usage: s4live.sh <name> [instance type]}"
type="${2:-m7i.xlarge}"
region=us-east-1
root="$(git rev-parse --show-toplevel)"
sd="$root/integration-tests/k8s/.state/$name"
mkdir -p "$sd"
report="$sd/s4live-report.txt"
: > "$report"
say() { echo "$*" | tee -a "$report"; }
aws() { command aws --region "$region" "$@"; }

ref="$(git -C "$root" rev-parse "${AEROL_BUILD_REF:-HEAD}^{commit}")"
target="$(sed -n 's/^ZIG_TARGET_amd64="\(.*\)"/\1/p' "$root/integration-tests/lib/build.sh")"
wt="$(mktemp -d)"
git -C "$root" worktree add --detach --force "$wt" "$ref" >/dev/null 2>&1
(cd "$wt" && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC="zig cc -target $target" CXX="zig c++ -target $target" \
  go test -c -tags s4live -o "$sd/cluster.test" ./internal/cluster/)
git -C "$root" worktree remove --force "$wt"
gzip -kf "$sd/cluster.test"
bucket="aerol-itest-artifacts-$(aws sts get-caller-identity --query Account --output text)"
key="builds/s4live-${ref:0:12}/cluster.test.gz"
aws s3 cp --only-show-errors "$sd/cluster.test.gz" "s3://$bucket/$key"
bin_url="$(aws s3 presign "s3://$bucket/$key" --expires-in 10800)"
say "build ${ref:0:12}: test binary staged"

vpc="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
read -r subnet cidr <<<"$(aws ec2 describe-subnets --filters Name=vpc-id,Values="$vpc" Name=availability-zone,Values=${region}a \
  --query 'Subnets[0].[SubnetId,CidrBlock]' --output text)"
# Three addresses deep in the subnet, away from the ones AWS hands out first.
mapfile -t ips < <(python3 -c "import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); [print(n.network_address+i) for i in (2571,2572,2573)]" "$cidr")
ttl="$(date -u -v+3H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+3 hours' +%Y-%m-%dT%H:%M:%SZ)"
tags="ResourceType=%s,Tags=[{Key=Name,Value=aerol-s4live-$name},{Key=aerol:ttl,Value=$ttl},{Key=aerol:run,Value=$name}]"
sg="$(aws ec2 create-security-group --group-name "aerol-s4live-$name" --description "S4 live $name" --vpc-id "$vpc" \
  --tag-specifications "$(printf "$tags" security-group)" --query GroupId --output text)"
aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port 7400 --source-group "$sg" >/dev/null
cleanup() {
  [[ -n "${instances:-}" ]] && aws ec2 terminate-instances --instance-ids $instances >/dev/null 2>&1 &&
    aws ec2 wait instance-terminated --instance-ids $instances 2>/dev/null || true
  aws ec2 delete-security-group --group-id "$sg" >/dev/null 2>&1 || echo "s4live: delete security group $sg by hand" >&2
}
trap cleanup EXIT
ami="$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --query Parameter.Value --output text)"
peers="s1=${ips[0]}:7400,s2=${ips[1]}:7400,s3=${ips[2]}:7400"
instances=""
for i in 0 1 2; do
  id="s$((i + 1))"
  cat > "$sd/user-data-$id.sh" <<EOF
#!/bin/bash
exec > >(tee /var/log/s4.log /dev/console) 2>&1
curl -fsSL --retry 5 -o /tmp/cluster.test.gz '$bin_url'
gunzip -f /tmp/cluster.test.gz && chmod +x /tmp/cluster.test
mkdir -p /var/lib/s4
cd /tmp && S4_ID=$id S4_ADDR=${ips[$i]}:7400 S4_PEERS=$peers S4_DIR=/var/lib/s4 S4_HOLD=45m \\
  ./cluster.test -test.run '^TestS4Live\$' -test.v -test.timeout 60m 2>&1 | grep -E '^(S4|---|ok|FAIL|PASS|panic)|s4_live_test'
echo "S4 DONE $id"
EOF
  instances+=" $(aws ec2 run-instances --image-id "$ami" --instance-type "$type" --subnet-id "$subnet" \
    --private-ip-address "${ips[$i]}" --security-group-ids "$sg" --associate-public-ip-address \
    --instance-initiated-shutdown-behavior terminate --user-data "file://$sd/user-data-$id.sh" \
    --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=30,VolumeType=gp3,DeleteOnTermination=true}' \
    --tag-specifications "$(printf "$tags" instance)" "$(printf "$tags" volume)" \
    --query 'Instances[0].InstanceId' --output text)"
done
read -r -a list <<<"$instances"
say "machines: $type × 3 (${list[*]}), $(aws ec2 describe-images --image-ids "$ami" --query 'Images[0].Name' --output text), gp3 30 GiB root; addresses ${ips[*]}"

# s1's console: the S4 lines arrive as it runs (console output can lag a few
# minutes behind).
start=$(date +%s)
while (( $(date +%s) - start < 3600 )); do
  out="$(aws ec2 get-console-output --instance-id "${list[0]}" --latest --query Output --output text 2>/dev/null || true)"
  if grep -q 'S4 DONE s1' <<<"$out"; then
    grep -E 'S4 |--- |FAIL|panic' <<<"$out" | sed 's/^\[[^]]*\] //' | grep -v 'S4 DONE' | tee -a "$report"
    break
  fi
  sleep 30
done
grep -q 'S4 snapshot' "$report" || { say "s4live: no result from s1 within an hour"; exit 1; }
say "--- done in $(( ($(date +%s) - start) / 60 )) min; report in $report"
