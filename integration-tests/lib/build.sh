#!/usr/bin/env bash
# build.sh — build the daemon artifacts LOCALLY and hand the integration
# harness presigned URLs to provision from. See plans/integration-test-security.md §4.
#
#   build.sh build   [--ref <commit>] [--arch amd64,arm64] [--with-caddy] [--with-receiver]
#   build.sh publish [--ref <commit>] [--ttl 12h] [--arch ...]
#   build.sh urls    [--ref <commit>] [--ttl 12h] [--arch ...]
#   build.sh artifacts-init
#
# WHY this exists: every scenario until now provisioned from
# `releases/latest`, so a branch under test could only be exercised after it
# merged and released. The security-hardening matrix has to run against an
# unmerged branch, which means the harness owns the build.
#
# Content addressing is the whole trick. AEROL_BUILD_ID is derived from the
# tree, so an unchanged tree re-uses the previous build AND the previous S3
# objects — that is what makes re-running against a `--keep` cluster free
# instead of a 50s cross-compile plus an 80MB upload every time.
#
# Prereqs: go, zig (cross-compile CC), aws. xcaddy only for --with-caddy.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
BUILD_ROOT="${REPO_ROOT}/integration-tests/.build"
WORKTREE_ROOT="${BUILD_ROOT}/.worktrees"

# Pinned zig cross-targets. The glibc floor (2.31 == Ubuntu 20.04) must stay at
# or below the oldest AMI the harness provisions; raising it silently breaks
# nodes with a "GLIBC_2.xx not found" at exec time, long after provisioning
# reported success. zig's target triple spelling has churned across releases,
# so the exact pair that produced a binary is recorded in buildinfo.json.
ZIG_TARGET_amd64="x86_64-linux-gnu.2.31"
ZIG_TARGET_arm64="aarch64-linux-gnu.2.31"

# Go's GOARCH names happen to match ours; kept explicit so the mapping is
# greppable if that ever stops being true.
GOARCH_amd64="amd64"
GOARCH_arm64="arm64"

VERSION_PKG="github.com/aerol-ai/microvm/internal/version"

# Bootstrap scripts published next to the binaries. §4.3: a node that installs
# a branch daemon with RELEASED scripts is exactly the mismatch that broke
# cluster bootstrap on plans/secrets-hardening — the scripts and the binary
# must come from one tree.
#
# REQUIRED are the three Terraform names a URL var for; their absence is a
# broken tree and must fail the build.
BOOTSTRAP_SCRIPTS=(install.sh cluster-init.sh cluster-join.sh)
# OPTIONAL scripts exist on some refs and not others. cluster-sign-node.sh
# arrived with the secrets-hardening CSR rendezvous, so requiring it would make
# `--ref main` unbuildable — and the `main` arm is exactly what UC-165's
# latency baseline needs (D5). Staged when present, skipped when not.
BOOTSTRAP_SCRIPTS_OPTIONAL=(cluster-sign-node.sh)

ARCHES=()
WITH_CADDY=0
WITH_RECEIVER=0
REF=""
TTL_SECONDS=43200 # 12h — covers a slow *.metal provision (§4.2)

###############################################################################
# Small portability + preflight helpers
###############################################################################

log() { printf '%s\n' "$*" >&2; }
die() { printf 'build.sh: %s\n' "$*" >&2; exit 1; }

# sha256_stdin / sha256_file — the harness runs on macOS (shasum) but the
# checksums it emits are verified on Linux nodes with `sha256sum -c`. Both
# tools print the same `<hex>  <name>` two-space format, which is what
# install.sh's verify_downloads greps with `awk '$2 == name'`.
sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
  else shasum -a 256 | cut -d' ' -f1; fi
}

sha256_file_line() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then (cd "$(dirname "$f")" && sha256sum "$(basename "$f")")
  else (cd "$(dirname "$f")" && shasum -a 256 "$(basename "$f")"); fi
}

require_bin() {
  local bin="$1" fix="$2"
  command -v "$bin" >/dev/null 2>&1 || die "'${bin}' not found on PATH. Fix: ${fix}"
}

# preflight fails loudly with the fix command rather than letting `go build`
# produce a confusing linker error 40 seconds in.
preflight() {
  require_bin go "install Go 1.26+ (brew install go)"
  require_bin zig "brew install zig   # provides the cross-compiling C toolchain sandboxd's CGO sqlite needs"
  require_bin git "xcode-select --install"
  (( WITH_CADDY )) && require_bin xcaddy "go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest"
  return 0
}

# parse_ttl accepts 12h / 45m / 900 and echoes seconds. AWS SigV4 presigning
# caps at 7 days; anything above that is rejected here with a clear message
# rather than by a generic AWS error at upload time.
parse_ttl() {
  local raw="$1" n unit
  case "$raw" in
    *h) n="${raw%h}"; unit=3600 ;;
    *m) n="${raw%m}"; unit=60 ;;
    *s) n="${raw%s}"; unit=1 ;;
    *)  n="$raw";     unit=1 ;;
  esac
  [[ "$n" =~ ^[0-9]+$ ]] || die "unparseable --ttl '${raw}' (use 12h, 45m, or seconds)"
  local secs=$(( n * unit ))
  (( secs > 0 ))      || die "--ttl must be positive"
  (( secs <= 604800 )) || die "--ttl ${raw} exceeds the 7-day SigV4 presign maximum"
  echo "$secs"
}

parse_common_flags() {
  local arch_csv=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ref)           REF="${2:?--ref needs a commit-ish}"; shift 2 ;;
      --arch)          arch_csv="${2:?--arch needs amd64[,arm64]}"; shift 2 ;;
      --with-caddy)    WITH_CADDY=1; shift ;;
      --with-receiver) WITH_RECEIVER=1; shift ;;
      --ttl)           TTL_SECONDS=$(parse_ttl "${2:?--ttl needs a duration}"); shift 2 ;;
      *) die "unknown flag: $1" ;;
    esac
  done
  if [[ -n "$arch_csv" ]]; then
    local a
    IFS=',' read -r -a ARCHES <<<"$arch_csv"
    for a in "${ARCHES[@]}"; do
      [[ "$a" == "amd64" || "$a" == "arm64" ]] || die "unsupported --arch '${a}' (amd64|arm64)"
    done
  else
    # D7: arm64 stays out of the default matrix until x86 is green, but the
    # flag exists from day one so adding it later is one word.
    ARCHES=(amd64)
  fi
}

###############################################################################
# Build identity
###############################################################################

# tree_delta emits a stable byte stream describing everything this working tree
# has that its HEAD commit does not.
#
# `git diff HEAD` alone is NOT enough: it covers tracked modifications but is
# blind to untracked files. A brand-new .go file would then leave the build id
# unchanged, so the pipeline would "cache hit" and quietly publish the PREVIOUS
# binary — a wrong-artifact bug that looks like a test failure. Untracked,
# non-ignored files are therefore folded in by content hash (hash, not content,
# so one stray large file can't make this pathological).
tree_delta() {
  git -C "$REPO_ROOT" diff HEAD
  local f
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    f="${REPO_ROOT}/${line}"
    [[ -f "$f" ]] || continue
    printf 'untracked %s %s\n' "$line" "$(sha256_stdin <"$f")"
  done < <(git -C "$REPO_ROOT" ls-files --others --exclude-standard)
}

# resolve_build_id echoes AEROL_BUILD_ID for the current invocation.
#   --ref <commit>  ->  <short-sha>            (a commit is immutable; never dirty)
#   default (HEAD)  ->  <short-sha>[-dirty-<tree-hash>]
resolve_build_id() {
  if [[ -n "$REF" ]]; then
    git -C "$REPO_ROOT" rev-parse --short=12 "${REF}^{commit}" 2>/dev/null \
      || die "--ref '${REF}' is not a commit in this repository"
    return
  fi
  local sha delta
  sha=$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)
  delta=$(tree_delta)
  if [[ -n "$delta" ]]; then
    printf '%s-dirty-%s\n' "$sha" "$(printf '%s' "$delta" | sha256_stdin | cut -c1-12)"
  else
    printf '%s\n' "$sha"
  fi
}

# source_tree_for echoes the directory to compile from.
#
# With --ref we build in a detached worktree so the operator's dirty tree is
# never stashed or disturbed — UC-165's `main` baseline (D5) is measured this
# way while the branch stays checked out and editable.
source_tree_for() {
  local build_id="$1"
  if [[ -z "$REF" ]]; then
    printf '%s\n' "$REPO_ROOT"
    return
  fi
  local wt="${WORKTREE_ROOT}/${build_id}"
  if [[ ! -d "${wt}/.git" && ! -f "${wt}/.git" ]]; then
    mkdir -p "$WORKTREE_ROOT"
    rm -rf "$wt"
    log "build: creating detached worktree for ${REF} at ${wt}"
    git -C "$REPO_ROOT" worktree add --detach --force "$wt" "$REF" >&2
  fi
  printf '%s\n' "$wt"
}

###############################################################################
# build
###############################################################################

# assert_linux_elf refuses to publish a host binary. A missing CC or a silently
# dropped GOOS turns the cross-compile into a native darwin build that uploads
# fine and then fails on the node with "cannot execute binary file" — a failure
# that surfaces 5 minutes into provisioning with no useful message.
assert_linux_elf() {
  local f="$1" arch="$2" desc
  desc=$(file -b "$f")
  case "$desc" in
    *"ELF 64-bit LSB"*) : ;;
    *) die "$(basename "$f") is not a Linux ELF binary (got: ${desc}) — cross-compile did not take effect" ;;
  esac
  local want
  case "$arch" in
    amd64) want="x86-64" ;;
    arm64) want="ARM aarch64" ;;
  esac
  [[ "$desc" == *"$want"* ]] || die "$(basename "$f") is not ${arch} (got: ${desc})"
}

build_one_arch() {
  local src="$1" out="$2" arch="$3" build_id="$4"
  local goarch zig_target ldflags
  goarch="$(eval "echo \$GOARCH_${arch}")"
  zig_target="$(eval "echo \$ZIG_TARGET_${arch}")"

  # Mirrors release.yml's stamping so /health and reports/*.json both name the
  # exact tree that produced the numbers.
  ldflags="-X ${VERSION_PKG}.Version=itest-${build_id}"

  # sandboxd needs CGO: mattn/go-sqlite3 is a C library, and the store is not
  # optional. zig cc supplies the cross-linking C toolchain Apple's clang can't.
  log "build: sandboxd_linux_${arch} (CGO=1, zig cc -target ${zig_target})"
  ( cd "$src" && CGO_ENABLED=1 GOOS=linux GOARCH="$goarch" \
      CC="zig cc -target ${zig_target}" CXX="zig c++ -target ${zig_target}" \
      go build -trimpath -ldflags "$ldflags" \
      -o "${out}/sandboxd_linux_${arch}" ./cmd/sandboxd )
  assert_linux_elf "${out}/sandboxd_linux_${arch}" "$arch"

  # toolboxd keeps CGO off and -s -w: it is bind-mounted into EVERY sandbox and
  # exec'd as the entrypoint, so its page count is on the boot path (Makefile
  # carries the same rationale).
  log "build: toolboxd_linux_${arch} (CGO=0, stripped)"
  ( cd "$src" && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
      go build -trimpath -ldflags "-s -w ${ldflags}" \
      -o "${out}/toolboxd_linux_${arch}" ./cmd/toolboxd )
  assert_linux_elf "${out}/toolboxd_linux_${arch}" "$arch"

  if (( WITH_RECEIVER )); then
    # Under integration-tests/, never cmd/ — it is a scenario fixture, not a
    # shipped binary, and nothing in a release should build it.
    if [[ ! -d "${src}/integration-tests/cmd/audit-receiver" ]]; then
      die "--with-receiver: integration-tests/cmd/audit-receiver does not exist on this ref (added in T9)"
    fi
    log "build: audit-receiver_linux_${arch} (CGO=0)"
    ( cd "$src" && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
        go build -trimpath -ldflags "-s -w ${ldflags}" \
        -o "${out}/audit-receiver_linux_${arch}" ./integration-tests/cmd/audit-receiver )
    assert_linux_elf "${out}/audit-receiver_linux_${arch}" "$arch"
  fi

  if (( WITH_CADDY )); then
    # D5: Caddy is normally REUSED from the release, because this program does
    # not touch pkg/caddy. Building it is opt-in for the case where it does.
    log "build: caddy_linux_${arch} (xcaddy)"
    ( cd "$src" && GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 \
        xcaddy build \
          --with github.com/mholt/caddy-l4 \
          --with github.com/caddy-dns/cloudflare \
          --with github.com/ss098/certmagic-s3 \
          --output "${out}/caddy_linux_${arch}" )
    assert_linux_elf "${out}/caddy_linux_${arch}" "$arch"
  fi
}

cmd_build() {
  parse_common_flags "$@"
  preflight

  local build_id out src
  build_id=$(resolve_build_id)
  out="${BUILD_ROOT}/${build_id}"

  # Content-addressed cache hit. buildinfo.json is written LAST, so its presence
  # is the completion marker: a build killed halfway leaves no stamp and is
  # redone rather than published in pieces.
  if [[ -f "${out}/buildinfo.json" ]] && build_matches_request "$out"; then
    log "build: ${build_id} already built (cache hit) — ${out}"
    printf '%s\n' "$build_id"
    return 0
  fi

  src=$(source_tree_for "$build_id")
  rm -rf "$out"
  mkdir -p "$out"
  log "build: AEROL_BUILD_ID=${build_id}  arch=${ARCHES[*]}  src=${src}"

  local arch
  for arch in "${ARCHES[@]}"; do
    build_one_arch "$src" "$out" "$arch" "$build_id"
  done

  # §4.3: publish the bootstrap scripts from the SAME tree as the binaries.
  local s
  for s in "${BOOTSTRAP_SCRIPTS[@]}"; do
    [[ -f "${src}/scripts/${s}" ]] || die "scripts/${s} missing from ${src}"
    cp "${src}/scripts/${s}" "${out}/${s}"
  done
  for s in "${BOOTSTRAP_SCRIPTS_OPTIONAL[@]}"; do
    if [[ -f "${src}/scripts/${s}" ]]; then
      cp "${src}/scripts/${s}" "${out}/${s}"
    else
      log "build: scripts/${s} absent from this ref — skipping (optional)"
    fi
  done

  write_checksums "$out"
  write_buildinfo "$out" "$build_id" "$src"
  prune_build_cache "$build_id"

  log "build: done — ${out}"
  printf '%s\n' "$build_id"
}

# prune_build_cache caps local disk.
#
# Content addressing means EVERY edit-and-build cycle on a dirty tree mints a
# new ~106MB directory, and nothing else ever deletes them — a day of iterating
# is tens of GB. S3 has a 7-day lifecycle rule for exactly this reason; this is
# its local counterpart. Keeps the most recently built ids (the current one
# always survives, since it was just stamped) so a re-provision against a
# --keep cluster still hits the cache.
prune_build_cache() {
  local keep_id="$1"
  local keep="${AEROL_BUILD_CACHE_KEEP:-5}"
  [[ "$keep" =~ ^[0-9]+$ ]] || return 0
  [[ -d "$BUILD_ROOT" ]] || return 0

  # Newest first by buildinfo.json mtime, which is written last and therefore
  # marks completion. Incomplete dirs have none and sort to the end, so a build
  # killed halfway is the first thing reclaimed.
  local dirs=() d
  while IFS= read -r d; do
    [[ -n "$d" ]] && dirs+=("$d")
  done < <(
    for d in "${BUILD_ROOT}"/*/; do
      [[ -d "$d" ]] || continue
      d="${d%/}"
      # .worktrees holds git worktrees, not builds; removing one behind git's
      # back leaves a stale registration that breaks the next `worktree add`.
      [[ "$(basename "$d")" == ".worktrees" ]] && continue
      if [[ -f "${d}/buildinfo.json" ]]; then
        printf '%s\t%s\n' "$(file_mtime "${d}/buildinfo.json")" "$d"
      else
        printf '0\t%s\n' "$d"
      fi
    done | LC_ALL=C sort -rn -k1,1 | cut -f2-
  )

  local i removed=0
  for (( i = 0; i < ${#dirs[@]}; i++ )); do
    (( i < keep )) && continue
    [[ "$(basename "${dirs[$i]}")" == "$keep_id" ]] && continue
    rm -rf "${dirs[$i]}"
    removed=$(( removed + 1 ))
  done
  (( removed > 0 )) && log "build: pruned ${removed} old build(s) from the local cache (keeping ${keep})"
  return 0
}

# file_mtime echoes a file's modification time as a unix timestamp. BSD stat
# (macOS, where the harness runs) and GNU stat (Linux CI) disagree on flags.
file_mtime() {
  stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null || echo 0
}

# build_matches_request guards the cache: the id covers the SOURCE, not the
# requested output set, so a cached amd64-only build must not satisfy a later
# `--arch amd64,arm64` or `--with-caddy` request.
build_matches_request() {
  local out="$1" arch
  for arch in "${ARCHES[@]}"; do
    [[ -f "${out}/sandboxd_linux_${arch}" ]] || return 1
    [[ -f "${out}/toolboxd_linux_${arch}" ]] || return 1
    (( WITH_CADDY ))    && { [[ -f "${out}/caddy_linux_${arch}" ]]          || return 1; }
    (( WITH_RECEIVER )) && { [[ -f "${out}/audit-receiver_linux_${arch}" ]] || return 1; }
  done
  return 0
}

# write_checksums emits GNU two-space format over every published file.
# install.sh's verify_downloads selects the line whose SECOND field equals the
# URL basename, so the names here must match the object keys exactly — and
# extra entries are harmless because selection is per-asset, not whole-file.
write_checksums() {
  local out="$1" f
  : >"${out}/checksums.txt"
  for f in "${out}"/*; do
    [[ -f "$f" ]] || continue
    case "$(basename "$f")" in checksums.txt | buildinfo.json) continue ;; esac
    sha256_file_line "$f" >>"${out}/checksums.txt"
  done
  LC_ALL=C sort -k2,2 -o "${out}/checksums.txt" "${out}/checksums.txt"
}

write_buildinfo() {
  local out="$1" build_id="$2" src="$3"
  local sha dirty
  sha=$(git -C "$src" rev-parse HEAD)
  if [[ -z "$REF" && "$build_id" == *-dirty-* ]]; then dirty=true; else dirty=false; fi

  # The zig target pair is recorded because zig's triple spelling has changed
  # across releases: when a future zig rejects these strings, buildinfo.json
  # from the last good run is the reference for what to migrate to.
  cat >"${out}/buildinfo.json" <<EOF
{
  "build_id": "${build_id}",
  "git_sha": "${sha}",
  "git_ref": "${REF:-HEAD}",
  "dirty": ${dirty},
  "version": "itest-${build_id}",
  "arches": [$(printf '"%s",' "${ARCHES[@]}" | sed 's/,$//')],
  "with_caddy": $( ((WITH_CADDY)) && echo true || echo false ),
  "with_receiver": $( ((WITH_RECEIVER)) && echo true || echo false ),
  "zig_version": "$(zig version)",
  "zig_target_amd64": "${ZIG_TARGET_amd64}",
  "zig_target_arm64": "${ZIG_TARGET_arm64}",
  "go_version": "$(go version | awk '{print $3}')",
  "built_by": "$(id -un)@$(hostname -s)",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

###############################################################################
# AWS coordinates (shared by artifacts-init / publish / urls)
###############################################################################

# tfvar_scalar mirrors provision.sh: pull the two non-secret AWS coordinates out
# of the operator's existing config/terraform.tfvars without a full HCL parse.
tfvar_scalar() {
  local file="$1" key="$2"
  sed -nE "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*\"([^\"]*)\".*/\1/p" "$file" | head -1
}

AWSCLI=()
AWS_REGION_RESOLVED=""
ARTIFACT_BUCKET=""

resolve_aws() {
  local tfvars="${REPO_ROOT}/config/terraform.tfvars"
  [[ -f "$tfvars" ]] || die "${tfvars} missing (copy from terraform.tfvars.example)"
  require_bin aws "brew install awscli"

  local profile
  profile=$(tfvar_scalar "$tfvars" aws_profile)
  AWS_REGION_RESOLVED=$(tfvar_scalar "$tfvars" aws_region)
  [[ -n "$AWS_REGION_RESOLVED" ]] || die "aws_region not set in ${tfvars}"

  AWSCLI=(aws)
  [[ -n "$profile" ]] && AWSCLI+=(--profile "$profile")

  local account
  account=$("${AWSCLI[@]}" sts get-caller-identity --query Account --output text 2>/dev/null) \
    || die "could not resolve AWS account (check creds / profile '${profile:-default}')"

  # Same account as the nodes' instance roles, same naming shape as the
  # persistent cert bucket, so the reaper and an operator both recognise it.
  ARTIFACT_BUCKET="aerol-itest-artifacts-${account}"
}

# cmd_artifacts_init mirrors provision.sh's cert_store_init: a LONG-LIVED bucket
# outside every scenario's Terraform state, so a per-scenario `destroy` can
# never wipe the artifacts a concurrent scenario is still installing from.
cmd_artifacts_init() {
  resolve_aws
  local region="$AWS_REGION_RESOLVED" bucket="$ARTIFACT_BUCKET"
  log "artifacts-init: ensuring s3://${bucket} (region ${region})"

  if "${AWSCLI[@]}" --region "$region" s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    log "  bucket exists"
  else
    if [[ "$region" == "us-east-1" ]]; then
      "${AWSCLI[@]}" --region "$region" s3api create-bucket --bucket "$bucket" >/dev/null
    else
      "${AWSCLI[@]}" --region "$region" s3api create-bucket --bucket "$bucket" \
        --create-bucket-configuration "LocationConstraint=${region}" >/dev/null
    fi
    log "  bucket created"
  fi

  "${AWSCLI[@]}" --region "$region" s3api put-public-access-block --bucket "$bucket" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" >/dev/null
  "${AWSCLI[@]}" --region "$region" s3api put-bucket-encryption --bucket "$bucket" \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' >/dev/null
  "${AWSCLI[@]}" --region "$region" s3api put-bucket-versioning --bucket "$bucket" \
    --versioning-configuration "Status=Enabled" >/dev/null
  log "  hardened (public-access-block + AES256 + versioning)"

  # 7-day expiry: unlike the cert bucket (whose whole purpose is to outlive
  # runs), these are throwaway test binaries at ~80MB each. Without a lifecycle
  # rule a few months of iteration quietly becomes tens of GB of storage spend.
  "${AWSCLI[@]}" --region "$region" s3api put-bucket-lifecycle-configuration --bucket "$bucket" \
    --lifecycle-configuration '{
      "Rules": [{
        "ID": "expire-itest-builds",
        "Status": "Enabled",
        "Filter": {"Prefix": "builds/"},
        "Expiration": {"Days": 7},
        "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}
      }]
    }' >/dev/null
  log "  lifecycle: builds/ expire after 7 days"

  log "artifacts-init: done — s3://${bucket}/builds/"
}

###############################################################################
# publish / urls
###############################################################################

cmd_publish() {
  parse_common_flags "$@"
  local build_id out
  build_id=$(resolve_build_id)
  out="${BUILD_ROOT}/${build_id}"
  [[ -f "${out}/buildinfo.json" ]] || die "no completed build for ${build_id} — run 'build.sh build' first"

  resolve_aws
  local region="$AWS_REGION_RESOLVED" bucket="$ARTIFACT_BUCKET"
  "${AWSCLI[@]}" --region "$region" s3api head-bucket --bucket "$bucket" >/dev/null 2>&1 \
    || die "s3://${bucket} does not exist — run 'build.sh artifacts-init' once per account"

  local prefix="builds/${build_id}"
  # Re-upload is skipped on an id we already published: the id IS the content
  # hash, so identical id means identical bytes. This is what makes an iterate-
  # against---keep loop cost nothing.
  if "${AWSCLI[@]}" --region "$region" s3api head-object \
      --bucket "$bucket" --key "${prefix}/buildinfo.json" >/dev/null 2>&1; then
    log "publish: ${build_id} already in s3://${bucket}/${prefix} — skipping upload"
  else
    log "publish: uploading ${build_id} → s3://${bucket}/${prefix}"
    # buildinfo.json is uploaded LAST for the same reason it is written last:
    # it is the completion marker the skip-check above reads, so an interrupted
    # upload must not look complete.
    local f
    for f in "${out}"/*; do
      [[ -f "$f" ]] || continue
      [[ "$(basename "$f")" == "buildinfo.json" ]] && continue
      "${AWSCLI[@]}" --region "$region" s3 cp --only-show-errors \
        "$f" "s3://${bucket}/${prefix}/$(basename "$f")"
    done
    "${AWSCLI[@]}" --region "$region" s3 cp --only-show-errors \
      "${out}/buildinfo.json" "s3://${bucket}/${prefix}/buildinfo.json"
    log "publish: uploaded"
  fi

  emit_urls "$build_id" "$bucket" "$region"
}

# presign echoes a presigned GET URL for one object.
#
# D4: this URL lands in EC2 user-data, readable via IMDS by anything on the box.
# Accepted because the PAT and the Cloudflare token are already there and these
# are throwaway ttl=4 scenario clusters. The mitigations that cost nothing are
# applied: short expiry (not 7d), GET-only, and a bucket holding nothing but
# test binaries.
presign() {
  local bucket="$1" region="$2" key="$3"
  "${AWSCLI[@]}" --region "$region" s3 presign "s3://${bucket}/${key}" \
    --expires-in "$TTL_SECONDS"
}

# emit_urls writes ready-to-chain tfvars to STDOUT (status goes to stderr), so
# `build.sh urls > artifacts.tfvars` composes directly into run.sh's
# -var-file chain.
emit_urls() {
  local build_id="$1" bucket="$2" region="$3"
  local prefix="builds/${build_id}"
  # The harness only ever provisions x86 nodes today (D7), so the tfvars name
  # the amd64 assets. arm64 objects are published when asked for and consumed
  # by an arm64 scenario's own var-file.
  local arch="${ARCHES[0]}"

  local required=(
    "sandboxd_linux_${arch}"
    "toolboxd_linux_${arch}"
    checksums.txt
    "${BOOTSTRAP_SCRIPTS[@]}"
  )
  # Present on this branch, absent on older refs. When it IS published it must
  # be the URL the seed uses: the CSR signing rendezvous needs the branch's
  # signer, not whatever releases/latest happens to hold.
  local have_sign_node=0
  if "${AWSCLI[@]}" --region "$region" s3api head-object \
      --bucket "$bucket" --key "${prefix}/cluster-sign-node.sh" >/dev/null 2>&1; then
    have_sign_node=1
  fi
  local k
  for k in "${required[@]}"; do
    "${AWSCLI[@]}" --region "$region" s3api head-object \
      --bucket "$bucket" --key "${prefix}/${k}" >/dev/null 2>&1 \
      || die "s3://${bucket}/${prefix}/${k} is missing — run 'build.sh publish'"
  done

  log "urls: presigning ${build_id} (ttl ${TTL_SECONDS}s)"

  printf '# generated by integration-tests/lib/build.sh — AEROL_BUILD_ID=%s\n' "$build_id"
  printf 'sandboxd_url            = "%s"\n' "$(presign "$bucket" "$region" "${prefix}/sandboxd_linux_${arch}")"
  printf 'toolboxd_url            = "%s"\n' "$(presign "$bucket" "$region" "${prefix}/toolboxd_linux_${arch}")"
  printf 'checksums_url           = "%s"\n' "$(presign "$bucket" "$region" "${prefix}/checksums.txt")"
  printf 'install_script_url      = "%s"\n' "$(presign "$bucket" "$region" "${prefix}/install.sh")"
  printf 'cluster_init_script_url = "%s"\n' "$(presign "$bucket" "$region" "${prefix}/cluster-init.sh")"
  printf 'cluster_join_script_url = "%s"\n' "$(presign "$bucket" "$region" "${prefix}/cluster-join.sh")"
  if (( have_sign_node )); then
    printf 'cluster_sign_node_script_url = "%s"\n' "$(presign "$bucket" "$region" "${prefix}/cluster-sign-node.sh")"
  fi

  # §3.3, the caddy trap. install.sh checksum-verifies the Caddy download
  # against OUR checksums.txt unless --caddy-binary-url was passed explicitly.
  # A checksums.txt carrying only sandboxd+toolboxd therefore BREAKS the Caddy
  # install. Two escapes, and exactly one of them must always be taken:
  #   --with-caddy  -> caddy_linux_<arch> is in checksums.txt, presign ours;
  #   otherwise     -> name the release URL explicitly, which sets
  #                    CADDY_BINARY_URL_EXPLICIT and skips the check (D5).
  if (( WITH_CADDY )); then
    printf 'caddy_binary_url        = "%s"\n' "$(presign "$bucket" "$region" "${prefix}/caddy_linux_${arch}")"
  else
    printf 'caddy_binary_url        = "https://github.com/aerol-ai/microvm/releases/latest/download/caddy_linux_%s"\n' "$arch"
  fi
}

cmd_urls() {
  parse_common_flags "$@"
  local build_id
  build_id=$(resolve_build_id)
  resolve_aws
  emit_urls "$build_id" "$ARTIFACT_BUCKET" "$AWS_REGION_RESOLVED"
}

# cmd_build_id prints the id and nothing else, so run.sh can label a report
# without paying for a build or an AWS round-trip.
cmd_build_id() {
  parse_common_flags "$@"
  resolve_build_id
}

###############################################################################

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    build)          cmd_build "$@" ;;
    publish)        cmd_publish "$@" ;;
    urls)           cmd_urls "$@" ;;
    build-id)       cmd_build_id "$@" ;;
    artifacts-init) cmd_artifacts_init ;;
    *)
      cat >&2 <<'USAGE'
usage: build.sh <command> [flags]

  build   [--ref <commit>] [--arch amd64,arm64] [--with-caddy] [--with-receiver]
          Cross-compile into integration-tests/.build/<AEROL_BUILD_ID>/.
  publish [--ref <commit>] [--ttl 12h] [--arch ...]
          Upload that build and print presigned tfvars on stdout.
  urls    [--ref <commit>] [--ttl 12h] [--arch ...]
          Re-presign an already-published build (stdout = tfvars).
  build-id [--ref <commit>]
          Print AEROL_BUILD_ID only.
  artifacts-init
          One-time per-account artifacts bucket bootstrap.
USAGE
      exit 2
      ;;
  esac
}

# Run main only when EXECUTED, not when sourced. Sourcing is how the offline
# tests in integration-tests/safety/ reach the pure helpers (parse_ttl,
# assert_linux_elf, resolve_build_id) without an AWS account or a 50-second
# cross-compile. An unverified guard is not a guard — same rationale as
# provision.sh's check-safety mode.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
