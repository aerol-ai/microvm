#!/usr/bin/env bash
# rootd-program-layouts.sh: the root helper's check of the programs it runs
# as root (internal/rootd TestRootProgramsOnThisHostsLayout), on the real
# file layouts of the distributions privilege mode split runs on: every
# path the helper's defaults, Terraform, Ansible, install.sh and the chart
# give it (internal/rootd/testdata/split_programs.txt).
#
#   scripts/rootd-program-layouts.sh [image...]
#
# Default images: ubuntu:22.04 ubuntu:24.04 debian:13 amazonlinux:2023.
# Each image gets the packages mkfs.ext4 and ip come from (e2fsprogs,
# iproute2), and a root-owned placeholder at each path where firecracker,
# the jailer, runsc and workerd go, as an install puts them; the test then
# runs as root there and fails on any path the helper would refuse. Needs
# Docker and Go; pulls only the images. The test binary is built for each
# image's own architecture.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
cd "$root"
images=("$@")
[[ ${#images[@]} -eq 0 ]] && images=(ubuntu:22.04 ubuntu:24.04 debian:13 amazonlinux:2023)
out="$(mktemp -d)"
# The programs no package installs: an install puts them at these paths.
placeholders="$(awk '!/^#/ && NF == 3 && $2 ~ /^(SB_FIRECRACKER_BINARY|SB_JAILER_BINARY|SB_ROOTD_RUNSC|SB_ISOLATE_WORKERD_PATH)$/ {print $3}' \
  internal/rootd/testdata/split_programs.txt | sort -u | tr '\n' ' ')"
failed=0
for img in "${images[@]}"; do
  arch="$(docker image inspect --format '{{.Architecture}}' "$img" 2>/dev/null)" || {
    docker pull -q "$img" >/dev/null
    arch="$(docker image inspect --format '{{.Architecture}}' "$img")"
  }
  bin="$out/rootd.test-$arch"
  [[ -x "$bin" ]] || CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$bin" ./internal/rootd
  echo "== $img ($arch)"
  if ! docker run --rm --platform "linux/$arch" -e "PLACEHOLDERS=$placeholders" -e AEROL_ROOT_PROGRAM_LAYOUT=require \
    -v "$bin:/t/rootd.test:ro" -v "$root/internal/rootd/testdata:/w/testdata:ro" -w /w "$img" sh -ec '
      if command -v apt-get >/dev/null; then
        apt-get update -qq >/dev/null
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq e2fsprogs iproute2 >/dev/null
      else
        dnf install -y -q e2fsprogs iproute >/dev/null
      fi
      for p in $PLACEHOLDERS; do
        [ -e "$p" ] && continue
        install -d -m 0755 "$(dirname "$p")"
        printf "#!/bin/sh\n" > "$p"
        chmod 0755 "$p"
      done
      . /etc/os-release
      echo "   $PRETTY_NAME: mkfs.ext4 $(readlink /usr/sbin/mkfs.ext4 || echo file), ip $(command -v ip) -> $(readlink -f "$(command -v ip)")"
      rc=0
      /t/rootd.test -test.run "^TestRootProgramsOnThisHostsLayout$" -test.v >/tmp/rootd-test.out 2>&1 || rc=$?
      grep -E "^(---|    ---|ok|PASS|FAIL)|_test.go:" /tmp/rootd-test.out || true
      exit "$rc"
    '; then
    failed=1
  fi
done
rm -f "$out"/rootd.test-*
rmdir "$out"
[[ "$failed" == 0 ]] && echo "rootd-program-layouts: the helper takes every path on every image" || echo "rootd-program-layouts: some image failed"
exit "$failed"
