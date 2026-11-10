#!/usr/bin/env bash
# stage.sh — move files from this machine to a test node through S3.
#
# Never scp a build to a node. One scp is one TCP stream over this laptop's
# uplink (10-170 KB/s to us-east-1): the adopt gate's 129 MB build took 20+
# minutes per node and starved every other session's uploads. Through S3 the
# laptop uploads once, with many connections, or not at all when the build is
# already published; each node then downloads inside AWS in seconds. Why and
# how S3 is used: lib/build.sh's cmd_stage.
#
# Source it (needs SSH_OPTS, e.g. from lib/common.sh) and call
#
#   stage_to_node ubuntu@<ip> <remote-dir> <local-file>...
#
# Each file lands as <remote-dir>/<its basename>, mode 0755 when executable
# here and 0644 otherwise, only after its SHA-256 matches this machine's copy.
# scripts/stage-to-node.sh is the same for a person or an agent at a prompt.

STAGE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# stage_remote_script reads cmd_stage's lines ("<sha256> <mode> <name> <url>")
# on stdin and prints the bash the node runs. Each file is fetched to a
# .part name, checked, then moved into place, so a failed or wrong download
# never leaves a file a later step would trust.
stage_remote_script() {
  local dir="$1" sha mode name url part
  printf 'set -euo pipefail\n'
  printf 'mkdir -p %q\n' "$dir"
  while read -r sha mode name url; do
    [[ -n "$sha" ]] || continue
    part="${dir}/.${name}.part"
    printf 'curl -fsS --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 10 -o %q %q\n' "$part" "$url"
    printf 'if ! printf "%%s  %%s\\n" %q %q | sha256sum -c --quiet - >/dev/null 2>&1; then rm -f %q; echo %q >&2; exit 1; fi\n' \
      "$sha" "$part" "$part" "stage: ${name} does not match its SHA-256 after download"
    printf 'chmod %q %q\nmv -f %q %q\n' "$mode" "$part" "$part" "${dir}/${name}"
  done
}

# stage_to_node puts the files in S3 (lib/build.sh stage) and has the node
# fetch and check them. It returns non-zero if any file did not arrive intact.
stage_to_node() {
  local target="${1:?stage_to_node needs ubuntu@<ip>}" dir="${2:?stage_to_node needs a remote dir}"
  shift 2
  [[ $# -gt 0 ]] || { echo "stage_to_node: no files" >&2; return 2; }
  local lines
  lines="$(bash "${STAGE_LIB_DIR}/build.sh" stage "$@")" || { echo "stage_to_node: could not stage $* in S3" >&2; return 1; }
  # The script goes on stdin, so the presigned URLs never show in the node's
  # process list, and a caller's `while read` loop keeps its own stdin.
  stage_remote_script "$dir" <<<"$lines" | ssh "${SSH_OPTS[@]}" "$target" 'bash -s'
}
