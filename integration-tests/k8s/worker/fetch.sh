#!/usr/bin/env bash
# fetch.sh: the worker pod's init container. Puts every binary the worker
# needs into /opt/aerolvm, each checked before it is used.
#
# sandboxd and toolboxd are this branch's build, published to S3 by
# integration-tests/lib/build.sh and handed over as presigned URLs (env from
# the worker-urls Secret). Everything else comes from its upstream release,
# downloaded inside AWS. Nothing is built into an image and nothing is
# uploaded from a laptop (plans/kubernetes-v2-phase0.md, rule 3).
set -euo pipefail

# Pinned versions. containerd and runc are checked against the SHA-256 their
# release pages publish, copied here; the CNI hash is the one scripts/install.sh
# pins. gVisor follows install.sh: the latest release, checked against the
# SHA-512 published next to it.
CONTAINERD_VERSION="2.1.4"
CONTAINERD_SHA256="50e53500800f4f74d0d8b2e57e939297eab68b0fe11a0957b771d5faa61fae5b"
RUNC_VERSION="v1.3.0"
RUNC_SHA256="028986516ab5646370edce981df2d8e8a8d12188deaf837142a02097000ae2f2"
CNI_PLUGINS_VERSION="v1.5.1"
CNI_PLUGINS_SHA256="77baa2f669980a82255ffa2f2717de823992480271ee778aa51a9c60ae89ff9b"
GVISOR_BASE="https://storage.googleapis.com/gvisor/releases/release/latest/x86_64"

: "${SANDBOXD_URL:?}" "${TOOLBOXD_URL:?}" "${CHECKSUMS_URL:?}"

dnf -y -q install tar bzip2 gzip findutils >/dev/null

BIN=/opt/aerolvm/bin
CNI=/opt/aerolvm/cni
mkdir -p "$BIN" "$CNI"
work="$(mktemp -d)"
cd "$work"

get() { curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 10 -o "$1" "$2"; }
check256() { echo "$1  $2" | sha256sum -c --quiet - || { echo "fetch: $2 failed its SHA-256" >&2; exit 1; }; }

# This branch's sandboxd and toolboxd, checked against the build's own list.
get checksums.txt "$CHECKSUMS_URL"
get sandboxd "$SANDBOXD_URL"
get toolboxd "$TOOLBOXD_URL"
check256 "$(awk '$2 == "sandboxd_linux_amd64" {print $1}' checksums.txt)" sandboxd
check256 "$(awk '$2 == "toolboxd_linux_amd64" {print $1}' checksums.txt)" toolboxd
install -m 0755 sandboxd toolboxd "$BIN/"

get containerd.tgz "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-static-${CONTAINERD_VERSION}-linux-amd64.tar.gz"
check256 "$CONTAINERD_SHA256" containerd.tgz
tar -xzf containerd.tgz -C "$BIN" --strip-components=1 bin/

get runc "https://github.com/opencontainers/runc/releases/download/${RUNC_VERSION}/runc.amd64"
check256 "$RUNC_SHA256" runc
install -m 0755 runc "$BIN/runc"

get cni.tgz "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-amd64-${CNI_PLUGINS_VERSION}.tgz"
check256 "$CNI_PLUGINS_SHA256" cni.tgz
tar -xzf cni.tgz -C "$CNI"

get gvisor.tar.bz2 "${GVISOR_BASE}/gvisor.tar.bz2"
get gvisor.tar.bz2.sha512 "${GVISOR_BASE}/gvisor.tar.bz2.sha512"
# The published line names the file; rewrite it so a rename upstream cannot
# turn the check into a no-op.
echo "$(awk '{print $1}' gvisor.tar.bz2.sha512)  gvisor.tar.bz2" | sha512sum -c --quiet -
mkdir gvisor && tar -xjf gvisor.tar.bz2 -C gvisor
runsc_src="$(find gvisor -type f -name runsc | head -1)"
install -m 0755 "$runsc_src" "$BIN/runsc"
install -m 0755 "$(find gvisor -type f -name containerd-shim-runsc-v1 | head -1)" "$BIN/containerd-shim-runsc-v1"
# runsc now ships a gvisor-bin/ payload beside it (gvisor_sentry and others)
# and looks for it next to its own path, as scripts/install.sh installs it.
if [[ -d "$(dirname "$runsc_src")/gvisor-bin" ]]; then
  install -d -m 0755 "$BIN/gvisor-bin"
  find "$(dirname "$runsc_src")/gvisor-bin" -maxdepth 1 -type f -exec install -m 0755 {} "$BIN/gvisor-bin/" \;
fi

# OV-E2 (S2's external-mount check) only: rclone, for a FUSE mount.
RCLONE_VERSION="v1.75.2"
RCLONE_SHA256="349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702"
if [[ "${AEROL_FETCH_RCLONE:-0}" == 1 ]]; then
  dnf -y -q install unzip >/dev/null
  get rclone.zip "https://github.com/rclone/rclone/releases/download/${RCLONE_VERSION}/rclone-${RCLONE_VERSION}-linux-amd64.zip"
  check256 "$RCLONE_SHA256" rclone.zip
  unzip -q -j rclone.zip "rclone-${RCLONE_VERSION}-linux-amd64/rclone" -d .
  install -m 0755 rclone "$BIN/rclone"
  "$BIN/rclone" version | head -1
fi

"$BIN/containerd" --version
"$BIN/runc" --version | head -1
"$BIN/runsc" --version | head -1
echo "fetch: done"
