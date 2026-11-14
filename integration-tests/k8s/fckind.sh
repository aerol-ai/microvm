#!/usr/bin/env bash
# fckind.sh: Firecracker sandboxes in the worker pod (plans/kubernetes-v2-
# architecture.md Phase 5, "Firecracker pools"), proven on kind on one EC2
# machine with nested virtualization, the setting spike S6 tested.
#
#   AEROL_BUILD_REF=<commit> [AEROL_FCKIND_PROOF=pod|move|gmove|kubeapi|externalca|review|mount] fckind.sh <name>
#
# pod (the default): one worker, a VM survives an agent restart. move:
# cluster mode, every worker a Firecracker worker; a VM's worker is
# cordoned and evacuated, and the VM must answer on another worker with the
# same guest boot ID and a counter that kept counting (a snapshot move,
# plan §10.5). Use an m8i.4xlarge for move (AEROL_FCKIND_TYPE). externalca:
# cluster mode with every node's certificate from a cert-manager CA issuer
# (C23); no CA key and no join token, a renewal keeps the key, and the join
# port refuses a second key, a certificate with no role and another CA.
# review: the Kubernetes review fixes (R1-R17, S5) on cluster mode, one
# check per fix with live behaviour (fckind/review.sh); m8i.4xlarge.
# mount: single mode; an rclone mount reaches a gVisor sandbox, keeps
# serving across an agent restart, and the pod's end leaves no mount
# (finding F13, fckind/mount.sh).
#
# The commit's source goes to the artifact bucket (a presigned link; nothing
# goes from this machine to the instance directly). The instance builds the
# images, runs scripts/k8s-dev.sh, turns worker.firecracker on, creates a
# Firecracker sandbox, restarts the agent container and checks the VM runs
# on and is taken over. It prints FCK lines to its serial console, which
# this script reads; it needs no SSH and no inbound rule. The instance
# carries aerol:ttl, powers itself off when done, and is terminated here on
# any exit.
#
# Needs a boto3 new enough to send CpuOptions.NestedVirtualization
# (AEROL_PYTHON names its python; the AWS CLI 2.27 cannot).
set -euo pipefail
name="${1:?usage: fckind.sh <name>}"
region=us-east-1
itype="${AEROL_FCKIND_TYPE:-m8i.2xlarge}"
py="${AEROL_PYTHON:-python3}"
root="$(git rev-parse --show-toplevel)"
ref="$(git -C "$root" rev-parse "${AEROL_BUILD_REF:-HEAD}^{commit}")"
sd="$root/integration-tests/k8s/.state/$name"
mkdir -p "$sd"
report="$sd/fckind-report.txt"
: > "$report"
say() { echo "[$(date -u +%T)] $*" | tee -a "$report"; }
aws() { command aws --region "$region" "$@"; }
"$py" -c 'import botocore.session as s; m=s.get_session().get_service_model("ec2"); assert "NestedVirtualization" in m.shape_for("CpuOptionsRequest").members' 2>/dev/null ||
  { echo "fckind: $py's boto3 cannot ask for nested virtualization; set AEROL_PYTHON to one that can" >&2; exit 2; }

bucket="aerol-itest-artifacts-$(aws sts get-caller-identity --query Account --output text)"
key="builds/fckind-${ref:0:12}/src.tgz"
git -C "$root" archive --format=tar.gz -o "$sd/src.tgz" "$ref"
aws s3 cp --only-show-errors "$sd/src.tgz" "s3://$bucket/$key"
url="$(aws s3 presign "s3://$bucket/$key" --expires-in 7200)"
# Not sed: a presigned link is full of "&", which sed reads as the match.
URL="$url" PROOF="${AEROL_FCKIND_PROOF:-pod}" python3 -c 'import os, sys; sys.stdout.write(open(sys.argv[1]).read().replace("@SRC_URL@", os.environ["URL"]).replace("@PROOF@", os.environ["PROOF"]))' \
  "$root/integration-tests/k8s/fckind/userdata.sh" > "$sd/userdata.sh"
say "source ${ref:0:12} staged; launching $itype with nested virtualization"

id="$(REGION="$region" ITYPE="$itype" NAME="$name" UD="$sd/userdata.sh" "$py" - <<'PY'
import boto3, datetime, gzip, os
region, itype, name = os.environ["REGION"], os.environ["ITYPE"], os.environ["NAME"]
ec2 = boto3.client("ec2", region_name=region)
ssm = boto3.client("ssm", region_name=region)
ami = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]
ttl = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
tags = [{"Key": "Name", "Value": "aerol-fckind-" + name}, {"Key": "aerol:owner", "Value": "itest"},
        {"Key": "aerol:ttl", "Value": ttl}, {"Key": "aerol:run", "Value": name}]
r = ec2.run_instances(ImageId=ami, InstanceType=itype, MinCount=1, MaxCount=1,
    CpuOptions={"NestedVirtualization": "enabled"}, InstanceInitiatedShutdownBehavior="terminate",
    # Gzipped: EC2 takes 16 KB of user data, and cloud-init unpacks it.
    UserData=gzip.compress(open(os.environ["UD"], "rb").read()),
    BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 60, "VolumeType": "gp3", "DeleteOnTermination": True}}],
    TagSpecifications=[{"ResourceType": "instance", "Tags": tags}, {"ResourceType": "volume", "Tags": tags}])
print(r["Instances"][0]["InstanceId"])
PY
)"
trap 'aws ec2 terminate-instances --instance-ids "$id" >/dev/null 2>&1 || true' EXIT
say "instance $id"

# Each FCK line as it comes, until DONE or the instance is gone. The console
# keeps its last 64 KB, so once a long run rolls past its start, a line's
# position moves: follow the last line printed, by its text.
start=$(date +%s) last="" done=""
while (( $(date +%s) - start < 6000 )); do
  out="$(aws ec2 get-console-output --instance-id "$id" --latest --query Output --output text 2>/dev/null || true)"
  mapfile -t lines < <(grep -E '^FCK ' <<<"$out" || true)
  # After the last line printed; all of them when it has rolled out too.
  from=0
  if [[ -n "$last" ]]; then
    for (( i = ${#lines[@]} - 1; i >= 0; i-- )); do
      [[ "${lines[$i]}" == "$last" ]] && { from=$((i + 1)); break; }
    done
  fi
  for (( i = from; i < ${#lines[@]}; i++ )); do echo "${lines[$i]}" | tee -a "$report"; done
  (( ${#lines[@]} > 0 )) && last="${lines[${#lines[@]} - 1]}"
  grep -q '^FCK DONE' <<<"$out" && { done=1; break; }
  state="$(aws ec2 describe-instances --instance-ids "$id" --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || true)"
  [[ "$state" == shutting-down || "$state" == terminated ]] && { say "fckind: the instance is $state"; break; }
  sleep 20
done
[[ -n "$done" ]] || say "fckind: no DONE line"
say "--- done in $(( ($(date +%s) - start) / 60 )) min; report in $report"
