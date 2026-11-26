# lib.sh: shared by the M2 spike scripts (spa.sh, spb.sh, leak-check.sh).
# Sourced, never run. Works on macOS's bash 3.2.
#
# What every launch here does (plans/security-gaps-m1-m4.md §4.2, §7):
#   - prints its cost (cost.py) before anything, and refuses past the ceiling;
#   - makes no AWS call at all unless --i-have-owner-approval is given, and
#     with --dry-run prints every AWS call instead of making it;
#   - tags every instance, volume, network interface and security group
#     owner=aerolvm-spike (plus aerol:run, aerol:ttl, itest=true and ttl,
#     which `make integration-reap` reads);
#   - moves files only through S3: the machine fetches presigned links and
#     checks each file's SHA-256; nothing is copied over SSH, and no machine
#     has an inbound rule;
#   - puts each machine on a hard deadline: it powers itself off at its ttl
#     and powering off terminates it; the script terminates it on any exit;
#   - lists what is left with this run's tags at the end (m2_leak_check).

M2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S="$(cd "$M2_DIR/.." && pwd)"
REPO="$(cd "$K8S/../.." && pwd)"
M2_REGION=us-east-1
M2_OWNER=aerolvm-spike
M2_PY="${AEROL_PYTHON:-python3}"
# Each run's folder (report, user data, results); the safety tests move it.
M2_STATE="${M2_STATE:-$K8S/.state}"

# Set by m2_parse_flags.
dry=0
approved=0
run=""
ceiling=""
legs_arg=""

# Per launched leg, index-aligned (bash 3.2 has no associative arrays).
leg_names=()
leg_ids=()
leg_prefix=()
leg_state=()
leg_last=()
leg_seen=()
# S3 keys this run made that are deleted at the end (the per-run kit).
m2_tmp_keys=()
m2_sg=""
m2_bucket=""
m2_finished=0

# m2_out <line>: to the report and the terminal. It never fails: the
# cleanup must go on when the terminal is gone (a closed SSH session).
m2_out() {
  printf '%s\n' "$*" >>"$report" 2>/dev/null || true
  # stdout to the terminal (fd 2), then the shell's own write-error message
  # to /dev/null; in this order fd 1 keeps the terminal.
  printf '%s\n' "$*" >&2 2>/dev/null || true
}
say() { m2_out "[$(date -u +%T)] $*"; }

# x runs an AWS (or other) command, or with --dry-run prints it.
x() {
  if [[ "$dry" == 1 ]]; then m2_out "dry-run:$(printf ' %q' "$@")"; return 0; fi
  "$@"
}

# xq is x with the command's own output dropped: the cleanup's calls, whose
# failures are reported by say (which cannot fail) instead.
xq() {
  if [[ "$dry" == 1 ]]; then x "$@"; return 0; fi
  "$@" >/dev/null 2>&1
}

m2_parse_flags() { # "$@" of the script; usage() comes from the script
  case "${DRY_RUN:-0}" in 0 | 1) dry="${DRY_RUN:-0}" ;; *) echo "DRY_RUN must be 0 or 1" >&2; exit 2 ;; esac
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) dry=1 ;;
      --i-have-owner-approval) approved=1 ;;
      --run) run="${2:?--run needs a name}"; shift ;;
      --ceiling) ceiling="${2:?--ceiling needs dollars}"; shift ;;
      --legs) legs_arg="${2:?--legs needs a list}"; shift ;;
      -h | --help) usage; exit 0 ;;
      *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
  done
  [[ "$run" =~ ^[a-z][a-z0-9-]{2,40}$ ]] || { echo "run name must match ^[a-z][a-z0-9-]{2,40}\$ (got \"$run\")" >&2; exit 2; }
  [[ "$ceiling" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "--ceiling must be dollars, e.g. 10" >&2; exit 2; }
}

# m2_in_min <minutes>: the UTC time that many minutes from now, ISO 8601.
m2_in_min() {
  python3 -I -c 'import datetime, sys; print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=int(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$1"
}

m2_sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# m2_gate <cost.py --leg args...>: the cost first, then the approval. Exits
# 3 past the ceiling (or a type with no price), 4 without approval. Nothing
# before this line has called AWS.
m2_gate() {
  local rc=0
  python3 -I "$M2_DIR/cost.py" --ceiling "$ceiling" --json "$sd/cost.json" "$@" >"$sd/cost.txt" 2>&1 || rc=$?
  tee -a "$report" <"$sd/cost.txt" >&2
  [[ "$rc" == 0 ]] || exit "$rc"
  if [[ "$dry" == 1 ]]; then
    say "dry run: every AWS call below is printed, none is made"
  elif [[ "$approved" != 1 ]]; then
    say "REFUSED: this run spends real AWS money; the owner must approve it first."
    say "Run again with --i-have-owner-approval once they have, or --dry-run to see every call."
    exit 4
  fi
}

# m2_tags <leg> <ttl min>: key=value lines for launch.py --tag. The ttl tag
# (whole hours, read by `make integration-reap`) leaves 15 minutes for the
# machine to boot before its own deadline starts.
m2_tags() {
  local leg="$1" ttl_min="$2" ttl_h
  ttl_h=$(( (ttl_min + 15 + 59) / 60 ))
  printf '%s\n' "Name=aerolvm-spike-$run-$leg" "owner=$M2_OWNER" "aerol:run=$run" "aerol:leg=$leg" \
    "aerol:ttl=$(m2_in_min "$ttl_min")" "itest=true" "ttl=$ttl_h"
}

m2_account() {
  if [[ "$dry" == 1 ]]; then echo 111122223333; else aws sts get-caller-identity --query Account --output text; fi
}

# m2_put <local file> <key>: into the artifact bucket, tagged.
m2_put() {
  x aws s3api put-object --region "$M2_REGION" --bucket "$m2_bucket" --key "$2" --body "$1" \
    --tagging "owner=$M2_OWNER&run=$run" >/dev/null
}

# m2_get_url <key>: a 4 h presigned GET link.
m2_get_url() {
  if [[ "$dry" == 1 ]]; then echo "https://$m2_bucket.s3.amazonaws.com/$1?X-Amz-Signature=dry"; return 0; fi
  aws s3 presign "s3://$m2_bucket/$1" --expires-in 14400 --region "$M2_REGION"
}

# m2_put_url <key>: a 4 h presigned PUT link the machine sends results to.
m2_put_url() {
  local d=()
  [[ "$dry" == 1 ]] && d=(--dry-run)
  "$M2_PY" -I "$M2_DIR/launch.py" presign-put --bucket "$m2_bucket" --key "$1" ${d[@]+"${d[@]}"}
}

# m2_stage_src <commit>: the commit's source, put once per commit and kept
# (like every harness's builds/): ~14 MB over this machine's uplink is
# minutes, so a copy already in S3 with the same SHA-256 (its metadata) is
# used again. Sets M2_KEY and M2_SUM (globals: not in a subshell, so a
# failure stops the script under set -e).
m2_stage_src() {
  local key="builds/spike-m2/src-${1:0:12}.tgz" f="$sd/src.tgz" sum have
  git -C "$REPO" archive --format=tar.gz -o "$f" "$1"
  sum="$(m2_sha256 "$f")"
  if [[ "$dry" == 1 ]]; then
    m2_out "dry-run: aws s3api head-object --bucket $m2_bucket --key $key; put it unless its sha256 metadata is $sum"
  else
    have="$(aws s3api head-object --region "$M2_REGION" --bucket "$m2_bucket" --key "$key" --query Metadata.sha256 --output text 2>/dev/null || true)"
    if [[ "$have" != "$sum" ]]; then
      aws s3api put-object --region "$M2_REGION" --bucket "$m2_bucket" --key "$key" --body "$f" \
        --metadata "sha256=$sum" --tagging "owner=$M2_OWNER" >/dev/null
    fi
  fi
  M2_KEY="$key" M2_SUM="$sum"
}

# m2_stage_kit <name> <dir> <files...>: a tarball of the kit for this run,
# deleted at the end. Sets M2_KEY and M2_SUM.
m2_stage_kit() {
  local key="builds/spike-m2/$run/$1.tgz" f="$sd/$1.tgz" dir="$2"
  shift 2
  COPYFILE_DISABLE=1 tar --no-xattrs -czf "$f" -C "$dir" "$@" 2>/dev/null || COPYFILE_DISABLE=1 tar -czf "$f" -C "$dir" "$@"
  m2_tmp_keys+=("$key")
  m2_put "$f" "$key"
  M2_KEY="$key" M2_SUM="$(m2_sha256 "$f")"
}

# m2_render <template> <out> KEY=VALUE...: @KEY@ becomes VALUE (not sed: a
# presigned link is full of "&"). Refuses a placeholder left unfilled.
m2_render() {
  local tpl="$1" out="$2"
  shift 2
  python3 -I -c '
import re, sys
t = open(sys.argv[1]).read()
for kv in sys.argv[3:]:
    k, v = kv.split("=", 1)
    t = t.replace("@%s@" % k, v)
left = sorted(set(re.findall(r"@[A-Z_]+@", t)))
if left:
    sys.exit("render: %s left unfilled in %s" % (" ".join(left), sys.argv[1]))
open(sys.argv[2], "w").write(t)' "$tpl" "$out" "$@"
}

# m2_sg_create: one security group for the run in the default VPC, with no
# inbound rule (a new group lets everything out and nothing in).
m2_sg_create() {
  local vpc tags="ResourceType=security-group,Tags=[{Key=Name,Value=aerolvm-spike-$run},{Key=owner,Value=$M2_OWNER},{Key=aerol:run,Value=$run},{Key=itest,Value=true}]"
  if [[ "$dry" == 1 ]]; then
    x aws ec2 describe-vpcs --region "$M2_REGION" --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text
    x aws ec2 create-security-group --region "$M2_REGION" --group-name "aerolvm-spike-$run" --vpc-id vpc-dry \
      --description "M2 spike $run: no inbound rule" --tag-specifications "$tags"
    m2_sg=sg-dry
    return 0
  fi
  vpc="$(aws ec2 describe-vpcs --region "$M2_REGION" --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)"
  [[ "$vpc" == vpc-* ]] || { say "no default VPC in $M2_REGION (got \"$vpc\")"; exit 1; }
  m2_sg="$(aws ec2 create-security-group --region "$M2_REGION" --group-name "aerolvm-spike-$run" --vpc-id "$vpc" \
    --description "M2 spike $run: no inbound rule" --tag-specifications "$tags" --query GroupId --output text)"
  echo "$m2_sg" >"$sd/security-group"
}

# m2_launch <leg> <type> <ami ssm param> <user data> <root dev> <disk GB>
#           <nested 0|1> <enclave 0|1> <ttl min> <console prefix>
m2_launch() {
  local leg="$1" itype="$2" ami="$3" ud="$4" rootdev="$5" disk="$6" nested="$7" enclave="$8" ttl="$9" prefix="${10}"
  local args=(run --name "$leg" --type "$itype" --ami-param "$ami" --userdata "$ud" --sg "$m2_sg"
    --root-dev "$rootdev" --disk-gb "$disk") t id
  [[ "$nested" == 1 ]] && args+=(--nested)
  [[ "$enclave" == 1 ]] && args+=(--enclave)
  [[ "$dry" == 1 ]] && args+=(--dry-run)
  while IFS= read -r t; do args+=(--tag "$t"); done < <(m2_tags "$leg" "$ttl")
  id="$("$M2_PY" -I "$M2_DIR/launch.py" "${args[@]}")" || { say "launch of $leg failed"; return 1; }
  leg_names+=("$leg")
  leg_ids+=("$id")
  leg_prefix+=("$prefix")
  leg_state+=(open)
  leg_last+=("")
  leg_seen+=(0)
  [[ "$dry" == 1 ]] || echo "$leg $id" >>"$sd/instances"
  say "$leg: instance $id ($itype$([[ "$nested" == 1 ]] && echo ', nested virtualization')$([[ "$enclave" == 1 ]] && echo ', Nitro Enclaves'); powers off by $ttl min)"
}

# m2_follow <max min>: each leg's "<prefix> ..." console lines as they come,
# until every leg has printed "<prefix> DONE" or is gone, or max min pass.
# The console keeps its last 64 KB. While it has not rolled over, the lines
# already printed are the first leg_seen of it (so a line printed twice is
# shown twice); once it has, the last line printed is found again by text.
m2_follow() {
  local max_min="$1" start i j out state n_open from lines l seen
  if [[ "$dry" == 1 ]]; then
    for ((i = 0; i < ${#leg_names[@]}; i++)); do
      m2_out "dry-run: aws ec2 get-console-output --region $M2_REGION --instance-id ${leg_ids[$i]} --latest every 20 s, '${leg_prefix[$i]} ' lines, until '${leg_prefix[$i]} DONE' or the machine is gone (at most $max_min min)"
    done
    return 0
  fi
  start=$(date +%s)
  while :; do
    n_open=0
    for ((i = 0; i < ${#leg_names[@]}; i++)); do
      [[ "${leg_state[$i]}" == open ]] || continue
      n_open=$((n_open + 1))
      out="$(aws ec2 get-console-output --region "$M2_REGION" --instance-id "${leg_ids[$i]}" --latest --query Output --output text 2>/dev/null || true)"
      lines=()
      while IFS= read -r l; do lines+=("$l"); done < <(sed 's/\r$//' <<<"$out" | grep -E "^${leg_prefix[$i]} " || true)
      from=0
      seen="${leg_seen[$i]}"
      if [[ -n "${leg_last[$i]}" ]]; then
        if ((seen > 0 && seen <= ${#lines[@]})) && [[ "${lines[seen - 1]}" == "${leg_last[$i]}" ]]; then
          from=$seen
        else
          for ((j = ${#lines[@]} - 1; j >= 0; j--)); do
            [[ "${lines[$j]}" == "${leg_last[$i]}" ]] && { from=$((j + 1)); break; }
          done
        fi
      fi
      for ((j = from; j < ${#lines[@]}; j++)); do
        echo "${lines[$j]}" >>"$sd/${leg_names[$i]}.txt"
        m2_out "[${leg_names[$i]}] ${lines[$j]}"
      done
      leg_seen[i]=${#lines[@]}
      ((${#lines[@]} > 0)) && leg_last[i]="${lines[${#lines[@]} - 1]}"
      if grep -q "${leg_prefix[$i]} DONE" <<<"$out"; then
        leg_state[i]=finished
        continue
      fi
      state="$(aws ec2 describe-instances --region "$M2_REGION" --instance-ids "${leg_ids[$i]}" --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || true)"
      if [[ "$state" == shutting-down || "$state" == terminated ]]; then
        say "${leg_names[$i]}: the machine is $state before DONE"
        leg_state[i]=gone
      fi
    done
    ((n_open == 0)) && break
    if (($(date +%s) - start >= max_min * 60)); then
      say "follow: $max_min min passed; ending the run"
      break
    fi
    sleep 20
  done
}

# m2_leak_check [--all]: what is left with owner=aerolvm-spike, this run's
# only unless --all: machines, disks, network interfaces, security groups,
# and the per-run kit in S3 (builds/spike-m2/<run>/; the source copies and
# the results under spike-m2/<run>/ are kept on purpose and not counted).
# Read-only: describe and list calls, nothing deleted. Returns 1 when
# anything is left or could not be listed.
m2_leak_left=0
m2_leak_list() { # <what> <aws args...>
  local what="$1" got
  shift
  if [[ "$dry" == 1 ]]; then m2_out "dry-run: leak check $what: aws$(printf ' %q' "$@")"; return 0; fi
  if got="$(aws "$@" 2>&1)"; then
    got="$(tr -s '\t\n ' ' ' <<<"$got" | sed -e 's/^ //' -e 's/ $//' -e 's/^None$//')"
  else
    got="could not list: ${got:0:160}"
  fi
  m2_out "leak check $what: ${got:-none}"
  [[ -z "$got" ]] || m2_leak_left=1
}

m2_leak_check() {
  local scope=("Name=tag:owner,Values=$M2_OWNER") who="run $run" all=0
  if [[ "${1:-}" == --all ]]; then all=1 who="any $M2_OWNER run"; else scope+=("Name=tag:aerol:run,Values=$run"); fi
  m2_leak_left=0
  m2_leak_list instances ec2 describe-instances --region "$M2_REGION" --filters "${scope[@]}" \
    Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down \
    --query 'Reservations[].Instances[].InstanceId' --output text
  m2_leak_list volumes ec2 describe-volumes --region "$M2_REGION" --filters "${scope[@]}" \
    --query 'Volumes[].VolumeId' --output text
  m2_leak_list "network interfaces" ec2 describe-network-interfaces --region "$M2_REGION" --filters "${scope[@]}" \
    --query 'NetworkInterfaces[].NetworkInterfaceId' --output text
  m2_leak_list "security groups" ec2 describe-security-groups --region "$M2_REGION" --filters "${scope[@]}" \
    --query 'SecurityGroups[].GroupId' --output text
  if [[ -z "$m2_bucket" ]]; then
    m2_out "leak check S3 kit: not checked (the run stopped before it put anything in S3)"
  elif [[ "$all" == 1 ]]; then
    m2_leak_list "S3 kit" s3api list-objects-v2 --region "$M2_REGION" --bucket "$m2_bucket" --prefix builds/spike-m2/ \
      --query "Contents[?!starts_with(Key, 'builds/spike-m2/src-')].Key" --output text
  else
    m2_leak_list "S3 kit" s3api list-objects-v2 --region "$M2_REGION" --bucket "$m2_bucket" --prefix "builds/spike-m2/$run/" \
      --query 'Contents[].Key' --output text
  fi
  [[ "$dry" == 1 ]] && return 0
  if [[ "$m2_leak_left" == 0 ]]; then
    m2_out "leak check: nothing of $who is left"
  else
    m2_out "leak check: something of $who is LEFT (above); end it by hand, or make integration-reap after its ttl"
  fi
  return "$m2_leak_left"
}

# m2_finish (the EXIT trap): every machine terminated and waited for, the
# group deleted, the per-run kit deleted, then the leak check. The exit code
# is the run's own (130 Ctrl-C, 143 TERM, 129 hangup, 5 a finished run whose
# verdict is no-go, a failed command's code), or 1 when the run was fine but
# something is left.
m2_finish() {
  local rc=$? i ids=() key
  [[ "$m2_finished" == 0 ]] || exit "$rc"
  m2_finished=1
  # The cleanup runs to its end: a second Ctrl-C, a TERM, a hangup (the
  # terminal closed) or a dead pipe on stderr stops nothing, and no failed
  # command ends it early (every output goes through m2_out or xq).
  trap '' INT TERM HUP PIPE
  set +e
  for ((i = 0; i < ${#leg_ids[@]}; i++)); do ids+=("${leg_ids[$i]}"); done
  if ((${#ids[@]} > 0)); then
    xq aws ec2 terminate-instances --region "$M2_REGION" --instance-ids "${ids[@]}" ||
      say "terminate failed: aws ec2 terminate-instances --region $M2_REGION --instance-ids ${ids[*]}"
    xq aws ec2 wait instance-terminated --region "$M2_REGION" --instance-ids "${ids[@]}" || say "wait for termination failed"
  fi
  if [[ -n "$m2_sg" ]]; then
    # A terminated machine's network interface can hold the group for a
    # few seconds more.
    for i in 1 2 3 4 5 6; do
      xq aws ec2 delete-security-group --region "$M2_REGION" --group-id "$m2_sg" && { m2_sg=""; break; }
      sleep 10
    done
    [[ -z "$m2_sg" ]] || say "security group $m2_sg is left: aws ec2 delete-security-group --region $M2_REGION --group-id $m2_sg"
  fi
  for ((i = 0; i < ${#m2_tmp_keys[@]}; i++)); do
    key="${m2_tmp_keys[$i]}"
    xq aws s3 rm --only-show-errors --region "$M2_REGION" "s3://$m2_bucket/$key" ||
      say "kit $key may be left: aws s3 rm s3://$m2_bucket/$key"
  done
  # A leak turns a clean exit into a failure; it never hides an earlier one.
  if ! m2_leak_check && [[ "$rc" == 0 ]]; then rc=1; fi
  say "--- $run ended (exit $rc); report $report"
  exit "$rc"
}
