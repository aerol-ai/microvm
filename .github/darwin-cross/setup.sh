#!/usr/bin/env bash
# Sets up a Linux GitHub runner to build the darwin sandboxd with cgo. GitHub
# no longer gives this org macOS runners, so the darwin rows of test.yml and
# release.yml cross-compile instead. The row's cc is `zig cc -target
# <arch>-macos.14.0`: zig ships the macOS libc headers and a libSystem link
# stub, which is all go-sqlite3 and miekg/pkcs11 need. 14.0 is the minimum
# macOS the old macos-14 runner build carried, so users see no change.
#
# Go itself links three more Apple libraries (crypto/x509 uses Security and
# CoreFoundation, net uses libresolv). zig has no stubs for them, so stubs/
# holds hand-written ones that name only the symbols Go imports. On a Go
# upgrade that imports a new symbol, the darwin link fails with an undefined
# symbol; add it to the matching stub. The full list is in
#   $(go env GOROOT)/src/crypto/x509/internal/macos/{security,corefoundation}.go
#   $(go env GOROOT)/src/internal/syscall/unix/net_darwin.go
# (the //go:cgo_import_dynamic lines).
#
# Needs the llvm package first (the row's apt_pkgs). Adds zig and the LLVM
# Mach-O tools to GITHUB_PATH and points CGO_LDFLAGS at the stubs.
set -euo pipefail

# Bump the version and both hashes together, from
# https://ziglang.org/download/index.json.
ZIG_VERSION=0.16.0
ZIG_SHA256_x86_64=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
ZIG_SHA256_aarch64=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17

host_arch="$(uname -m)"
case "$host_arch" in
  x86_64) want_sha="$ZIG_SHA256_x86_64" ;;
  aarch64) want_sha="$ZIG_SHA256_aarch64" ;;
  *) echo "::error::no pinned zig for runner arch ${host_arch}"; exit 1 ;;
esac

for tool in dsymutil llvm-strip; do
  if ! command -v "$tool" >/dev/null; then
    echo "::error::${tool} not found; install the llvm package before this script"
    exit 1
  fi
done

work="${RUNNER_TEMP:-$(mktemp -d)}/darwin-cross"
tarball="zig-${host_arch}-linux-${ZIG_VERSION}.tar.xz"
mkdir -p "$work/zig" "$work/tools"

# ziglang.org asks automated downloads to use a community mirror first. Trust
# comes from the pinned SHA-256, not from the host, so any matching copy works.
fetched=0
for url in \
  "https://ziglang.freetls.fastly.net/${tarball}" \
  "https://pkg.alexrp.com/zig/${tarball}" \
  "https://ziglang.org/download/${ZIG_VERSION}/${tarball}"; do
  if curl -fsSL --retry 2 --max-time 300 -o "$work/$tarball" "${url}?source=aerolvm-ci" &&
    echo "${want_sha}  $work/$tarball" | sha256sum -c --status -; then
    fetched=1
    break
  fi
  echo "::warning::zig from ${url} failed to download or did not match the pinned SHA-256"
done
if [[ "$fetched" != 1 ]]; then
  echo "::error::no zig ${ZIG_VERSION} download matched the pinned SHA-256"
  exit 1
fi
tar -xJf "$work/$tarball" -C "$work/zig" --strip-components=1

# Go keeps DWARF in darwin binaries by running `dsymutil` and `strip -S`
# after the link, the same as a native macOS build. GNU strip cannot read
# Mach-O, so llvm-strip shadows it here; this PATH entry exists only in the
# darwin job.
ln -sf "$(command -v dsymutil)" "$work/tools/dsymutil"
ln -sf "$(command -v llvm-strip)" "$work/tools/strip"

stubs="$(cd "$(dirname "${BASH_SOURCE[0]}")/stubs" && pwd)"
echo "$work/zig" >>"$GITHUB_PATH"
echo "$work/tools" >>"$GITHUB_PATH"
echo "CGO_LDFLAGS=-L${stubs} -F${stubs}" >>"$GITHUB_ENV"
"$work/zig/zig" version
