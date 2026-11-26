#!/usr/bin/env bash
# leak-check.sh: what an M2 spike run left in AWS. Read-only: describe and
# list calls only; it deletes nothing. spa.sh and spb.sh run the same check
# at their end.
#
#   leak-check.sh <run name>     # what carries owner=aerolvm-spike and aerol:run=<run name>,
#                                # and the run's kit in S3 (builds/spike-m2/<run name>/)
#   leak-check.sh --all          # anything that carries owner=aerolvm-spike, every run's kit
#   leak-check.sh --dry-run ...  # print the calls, make none
#
# Exit 1 when anything is left. To end a machine that is left:
# aws ec2 terminate-instances, or `make integration-reap` once its ttl tag
# has passed; a group: aws ec2 delete-security-group once its machines are
# gone; a kit: aws s3 rm.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"
case "${DRY_RUN:-0}" in 0 | 1) dry="${DRY_RUN:-0}" ;; *) echo "DRY_RUN must be 0 or 1" >&2; exit 2 ;; esac
all=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry=1 ;;
    --all) all=--all ;;
    -h | --help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown argument: $1" >&2; exit 2 ;;
    *) run="$1" ;;
  esac
  shift
done
if [[ -z "$all" ]]; then
  [[ "$run" =~ ^[a-z][a-z0-9-]{2,40}$ ]] || { echo "usage: leak-check.sh <run name> | --all [--dry-run]" >&2; exit 2; }
fi
mkdir -p "$M2_STATE"
report="$M2_STATE/m2-leak-check.txt"
: >"$report"
# The artifact bucket, for the per-run kit (sts is read-only).
m2_bucket="aerol-itest-artifacts-$(m2_account)"
m2_leak_check $all
