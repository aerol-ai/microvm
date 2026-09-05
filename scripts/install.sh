#!/usr/bin/env bash

set -euo pipefail

DOMAIN=""
PUBLIC_HOST=""
PAT_TOKEN=""
INSTALL_PREFIX="/usr/local/bin"
BUILD_FROM_SOURCE="auto"
GITHUB_REPO="aerol-ai/microvm"
VERSION="latest"
SANDBOXD_URL=""
TOOLBOXD_URL=""
CHECKSUMS_URL=""
IDLE_TIMEOUT_MIN="0"
DNS_PROVIDER=""
DNS_API_TOKEN=""
ACME_EMAIL=""
CADDY_BUILD_URL_BASE="https://caddyserver.com/api/download"
CADDY_BINARY_URL=""
CADDY_BINARY_URL_EXPLICIT="false"
WITH_GVISOR="false"
RUNSC_PATH=""
WITH_ISOLATE="false"
WORKERD_PATH=""
# Version-pinned workerd release for --with-isolate (plans/isolate-runtime.md
# Phase 1). Upstream ships gzipped standalone binaries with no checksum
# sidecar, so the per-arch SHA-256 is pinned here and MUST be bumped together
# with the version — see setup/runbooks for the upgrade recipe.
WORKERD_VERSION="v1.20260717.1"
WORKERD_SHA256_LINUX_64="7ff61e052347ab3122c43b1e2419ccd68bd91e3c766f9770320591798e0e89a0"
WORKERD_SHA256_LINUX_ARM64="3ef71b4a692d2705fa4db0636724409be833402f1c9b99094294a5901989680d"
WITH_NVIDIA_GPU="false"
WITH_AMD_GPU="false"
WITH_CONTAINERD_ENGINE="false"
LOCAL_MODE="false"
NODE_NAME=""

# Bound every bootstrap download. Without low-speed and total timeouts, a dead
# CDN/GitHub connection can sit at 0 bytes forever and leave cloud-init running
# with no sandboxd.service installed.
DOWNLOAD_CONNECT_TIMEOUT="${AEROL_DOWNLOAD_CONNECT_TIMEOUT:-20}"
DOWNLOAD_MAX_TIME="${AEROL_DOWNLOAD_MAX_TIME:-300}"
DOWNLOAD_LOW_SPEED_LIMIT="${AEROL_DOWNLOAD_LOW_SPEED_LIMIT:-1024}"
DOWNLOAD_LOW_SPEED_TIME="${AEROL_DOWNLOAD_LOW_SPEED_TIME:-30}"
DOWNLOAD_RETRY="${AEROL_DOWNLOAD_RETRY:-60}"
DOWNLOAD_RETRY_DELAY="${AEROL_DOWNLOAD_RETRY_DELAY:-5}"
DOWNLOAD_RETRY_MAX_TIME="${AEROL_DOWNLOAD_RETRY_MAX_TIME:-900}"

# Shared Caddy cert storage (S3). All default empty / off; the feature is
# off unless --caddy-storage-s3 is passed. When enabled, every node points
# at the same S3 bucket so exactly one node holds the ACME lock and the
# rest read the cert from S3 — sidesteps Let's Encrypt rate limits at 10+
# ingress nodes. See setup/multi-node-cert-sharing.md.
CADDY_STORAGE_S3="false"
CADDY_STORAGE_S3_BUCKET=""
CADDY_STORAGE_S3_REGION=""
CADDY_STORAGE_S3_ENDPOINT=""
CADDY_STORAGE_S3_PREFIX="caddy"
CADDY_STORAGE_S3_ACCESS_KEY=""
CADDY_STORAGE_S3_SECRET_KEY=""
CADDY_STORAGE_S3_ENCRYPTION_KEY=""

usage() {
	cat <<'EOF'
Usage: install.sh [options]

Options:
  --domain <domain>            Base domain for wildcard sandbox routes
  --public-host <host-or-ip>   Public host used for IP mode or local URLs
	--pat-token <token>          PAT token required for sandbox API requests
  --github-repo <owner/repo>   GitHub repo used for release downloads
  --version <tag|latest>       Release tag to install (default: latest)
  --sandboxd-url <url>         Download URL for sandboxd binary
  --toolboxd-url <url>         Download URL for toolboxd binary
  --checksums-url <url>        Download URL for release checksums file
  --caddy-binary-url <url>     Download URL for a prebuilt custom Caddy binary
                               containing caddy-l4, caddy-dns/cloudflare, and
                               certmagic-s3. Defaults to the matching GitHub
                               release asset when available, then falls back to
                               Caddy's build service.
  --install-prefix <dir>       Binary install directory (default: /usr/local/bin)
  --idle-timeout-min <minutes> Idle auto-stop timeout in minutes
  --build-from-source          Build binaries from the current checkout
  --dns-provider <name>        DNS provider for wildcard TLS (DNS-01 ACME).
                               Currently supported: cloudflare. Required
                               whenever --domain is set, alongside
                               --dns-api-token. Operators that cannot run
                               DNS-01 should use --local (no TLS, 127.0.0.1
                               only) or omit --domain to fall back to
                               IP/path mode.
  --dns-api-token <token>      API token for the configured DNS provider.
                               For cloudflare: a scoped API token with
                               Zone:Read + DNS:Edit on the target zone.
  --acme-email <email>         Contact email registered with Let's Encrypt.
                               Lets ACME send cert-expiry and revocation
                               notices, and surfaces this account in any
                               future rate-limit/abuse triage. Optional but
                               strongly recommended in domain mode; without
                               it Caddy creates an anonymous account and
                               you get no warnings before things break.
  --with-gvisor                Install gVisor's runsc and register it as an
                               alternative OCI runtime in
                               /etc/docker/daemon.json so sandboxes can opt
                               into gVisor isolation via runtime: "runsc" on
                               create. Also installs containerd-shim-runsc-v1
                               so the containerd engine can serve the same
                               runtime via the io.containerd.runsc.v1 shim.
                               Downloads both from the upstream release
                               bucket (verified by SHA-512) if not already on
                               PATH. Restarts Docker if daemon.json actually
                               changed.
  --with-containerd-engine     Opt into SB_CONTAINER_ENGINE=containerd
                               (dark default remains docker). Installs CNI
                               bridge + host-local plugins under /opt/cni/bin
                               and writes SB_CONTAINER_ENGINE=containerd into
                               sandboxd.env. Requires a system containerd
                               socket (usually /run/containerd/containerd.sock).
  --runsc-path <path>          Absolute path to a pre-installed runsc binary.
                               Skips the download step and registers this
                               binary instead. Only consulted with
                               --with-gvisor.
  --with-isolate               Install Cloudflare's workerd (version-pinned,
                               SHA-256 verified against hashes embedded in
                               this script) to /usr/local/bin/workerd and
                               write SB_ENABLE_ISOLATE=true so sandboxes can
                               opt into the V8-isolate runtime via
                               runtime:"isolate" on create
                               (plans/isolate-runtime.md).
  --workerd-path <path>        Absolute path to a pre-installed workerd
                               binary. Skips the download and points
                               SB_ISOLATE_WORKERD_PATH at it. Only consulted
                               with --with-isolate.
  --with-nvidia-gpu            Install nvidia-container-toolkit and register
                               the nvidia OCI runtime in daemon.json. Requires
                               NVIDIA drivers already installed on the host
                               (nvidia-smi must be present). Downloads the
                               toolkit from the official NVIDIA package repo
                               and runs nvidia-ctk to configure Docker.
                               Restarts Docker on completion.
  --with-amd-gpu               Install AMD ROCm from the official AMD package
                               repository so containers can access AMD GPUs via
                               /dev/kfd and /dev/dri. Only supported on x86_64.
                               Requires the amdgpu kernel module loaded on the
                               host (the GPU must already be recognized by the
                               OS — /dev/kfd must exist).
  --node-name <name>           Human-readable identifier broadcast to the
                               cluster (shown in the dashboard's CLUSTER
                               table). Persisted as SB_NODE_NAME in
                               sandboxd.env. Defaults to empty, in which
                               case the dashboard falls back to the
                               hostname-derived node_id.
  --caddy-storage-s3           Enable S3-backed shared Caddy cert storage.
                               One node issues + renews the wildcard cert
                               via DNS-01; every node reads it from S3.
                               Requires --domain and --dns-provider.
                               Off by default; each node issues its own
                               cert when off (fine up to a handful of
                               ingress nodes, brittle at 10+ because of
                               Let's Encrypt rate limits).
  --caddy-storage-s3-bucket <name>
                               S3 bucket holding the encrypted cert
                               objects. Required when --caddy-storage-s3
                               is set.
  --caddy-storage-s3-region <region>
                               AWS region of the bucket (or the region
                               header for non-AWS endpoints). Required
                               when --caddy-storage-s3 is set.
  --caddy-storage-s3-endpoint <url>
                               Optional S3-compatible endpoint URL for
                               Cloudflare R2, MinIO, etc. Empty selects
                               the default AWS S3 endpoint for the region.
  --caddy-storage-s3-prefix <path>
                               Key prefix inside the bucket. Default
                               "caddy". All nodes must agree.
  --caddy-storage-s3-access-key <key>
                               Static access key. Optional — empty falls
                               back to the AWS default credential chain
                               (env vars, EC2 instance role, IRSA).
  --caddy-storage-s3-secret-key <secret>
                               Static secret key. Pair with access key.
  --caddy-storage-s3-encryption-key <b64>
                               Base64-encoded 32-byte key used to encrypt
                               cert + private key bytes before upload.
                               Generate once with
                               'openssl rand -base64 32' and use the
                               SAME value on every node. Required when
                               --caddy-storage-s3 is set; losing it
                               renders stored certs unrecoverable.
  --local                      Local development mode. The server binds to
                               127.0.0.1:21212 with no Caddy or TLS. Supported
                               on both macOS and Linux. Docker Desktop (macOS)
                               or Docker Engine (Linux) must already be running.
                               No domain name required. On macOS a launchd
                               daemon is registered; on Linux a systemd unit
                               without a Caddy dependency is used.
  --help                       Show this help

Examples:
	curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- --domain sandbox.example.com --pat-token my-pat-token
  ./scripts/install.sh --version v0.1.0 --public-host 203.0.113.42
	./scripts/install.sh --public-host 203.0.113.42 --pat-token dev-token --build-from-source
	./scripts/install.sh --domain sandbox.example.com --pat-token my-pat-token \
	    --dns-provider cloudflare --dns-api-token cf-scoped-token
EOF
}

detect_platform() {
	local os
	local arch

	os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	if [[ "$os" == "darwin" ]] && [[ "$LOCAL_MODE" != "true" ]]; then
		echo "macOS is only supported with --local mode; for a VPS install use a Linux host" >&2
		exit 1
	fi
	if [[ "$os" != "linux" && "$os" != "darwin" ]]; then
		echo "Only Linux (and macOS with --local) hosts are supported by this installer" >&2
		exit 1
	fi

	case "$(uname -m)" in
		x86_64|amd64)
			arch="amd64"
			;;
		i686|i386)
			arch="386"
			;;
		aarch64|arm64)
			arch="arm64"
			;;
		armv7l|armv7)
			arch="armv7"
			;;
		armv6l|armv6)
			arch="armv6"
			;;
		*)
			echo "Unsupported architecture: $(uname -m)" >&2
			exit 1
			;;
	esac

	echo "${os}_${arch}"
}

resolve_release_urls() {
	local platform
	local release_base

	platform="$(detect_platform)"
	release_base="https://github.com/${GITHUB_REPO}/releases"

	if [[ "$VERSION" == "latest" ]]; then
		SANDBOXD_URL="${SANDBOXD_URL:-${release_base}/latest/download/sandboxd_${platform}}"
		TOOLBOXD_URL="${TOOLBOXD_URL:-${release_base}/latest/download/toolboxd_${platform}}"
		CHECKSUMS_URL="${CHECKSUMS_URL:-${release_base}/latest/download/checksums.txt}"
		CADDY_BINARY_URL="${CADDY_BINARY_URL:-${release_base}/latest/download/caddy_${platform}}"
	else
		SANDBOXD_URL="${SANDBOXD_URL:-${release_base}/download/${VERSION}/sandboxd_${platform}}"
		TOOLBOXD_URL="${TOOLBOXD_URL:-${release_base}/download/${VERSION}/toolboxd_${platform}}"
		CHECKSUMS_URL="${CHECKSUMS_URL:-${release_base}/download/${VERSION}/checksums.txt}"
		CADDY_BINARY_URL="${CADDY_BINARY_URL:-${release_base}/download/${VERSION}/caddy_${platform}}"
	fi
}

download_asset() {
	local url="$1"
	local output="$2"

	curl_download "$url" -o "$output"
}

curl_download() {
	local url="$1"
	shift

	curl -fL \
		--retry "$DOWNLOAD_RETRY" \
		--retry-delay "$DOWNLOAD_RETRY_DELAY" \
		--retry-all-errors \
		--retry-max-time "$DOWNLOAD_RETRY_MAX_TIME" \
		--retry-connrefused \
		--connect-timeout "$DOWNLOAD_CONNECT_TIMEOUT" \
		--max-time "$DOWNLOAD_MAX_TIME" \
		--speed-limit "$DOWNLOAD_LOW_SPEED_LIMIT" \
		--speed-time "$DOWNLOAD_LOW_SPEED_TIME" \
		"$url" "$@"
}

verify_downloads() {
	local tmp_dir="$1"
	shift

	if [[ -z "$CHECKSUMS_URL" ]]; then
		echo "Checksum URL is required for prebuilt release installation" >&2
		return 1
	fi

	if ! download_asset "$CHECKSUMS_URL" "$tmp_dir/checksums.txt"; then
		echo "Failed to download release checksums; refusing unverified installation" >&2
		return 1
	fi

	(
		cd "$tmp_dir"
		: > selected-checksums.txt
		local asset
		for asset in "$@"; do
			if ! awk -v name="$asset" '$2 == name { print }' checksums.txt > "checksum-${asset}.txt" \
				|| [[ "$(wc -l < "checksum-${asset}.txt")" -ne 1 ]]; then
				echo "Missing or ambiguous checksum for release asset: $asset" >&2
				exit 1
			fi
			cat "checksum-${asset}.txt" >> selected-checksums.txt
		done
		sha256sum -c selected-checksums.txt
	)
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--domain)
			DOMAIN="$2"
			shift 2
			;;
		--public-host)
			PUBLIC_HOST="$2"
			shift 2
			;;
		--pat-token)
			PAT_TOKEN="$2"
			shift 2
			;;
		--github-repo)
			GITHUB_REPO="$2"
			shift 2
			;;
		--version)
			VERSION="$2"
			shift 2
			;;
		--sandboxd-url)
			SANDBOXD_URL="$2"
			BUILD_FROM_SOURCE="false"
			shift 2
			;;
		--toolboxd-url)
			TOOLBOXD_URL="$2"
			BUILD_FROM_SOURCE="false"
			shift 2
			;;
		--checksums-url)
			CHECKSUMS_URL="$2"
			BUILD_FROM_SOURCE="false"
			shift 2
			;;
		--caddy-binary-url)
			CADDY_BINARY_URL="$2"
			CADDY_BINARY_URL_EXPLICIT="true"
			shift 2
			;;
		--install-prefix)
			INSTALL_PREFIX="$2"
			shift 2
			;;
		--idle-timeout-min)
			IDLE_TIMEOUT_MIN="$2"
			shift 2
			;;
		--build-from-source)
			BUILD_FROM_SOURCE="true"
			shift
			;;
		--dns-provider)
			DNS_PROVIDER="$2"
			shift 2
			;;
		--dns-api-token)
			DNS_API_TOKEN="$2"
			shift 2
			;;
		--acme-email)
			ACME_EMAIL="$2"
			shift 2
			;;
		--with-gvisor)
			WITH_GVISOR="true"
			shift
			;;
		--with-containerd-engine)
			WITH_CONTAINERD_ENGINE="true"
			shift
			;;
		--runsc-path)
			RUNSC_PATH="$2"
			shift 2
			;;
		--with-isolate)
			WITH_ISOLATE="true"
			shift
			;;
		--workerd-path)
			WORKERD_PATH="$2"
			shift 2
			;;
		--with-nvidia-gpu)
			WITH_NVIDIA_GPU="true"
			shift
			;;
		--with-amd-gpu)
			WITH_AMD_GPU="true"
			shift
			;;
		--local)
			LOCAL_MODE="true"
			shift
			;;
		--node-name)
			NODE_NAME="$2"
			shift 2
			;;
		--caddy-storage-s3)
			CADDY_STORAGE_S3="true"
			shift
			;;
		--caddy-storage-s3-bucket)
			CADDY_STORAGE_S3_BUCKET="$2"
			shift 2
			;;
		--caddy-storage-s3-region)
			CADDY_STORAGE_S3_REGION="$2"
			shift 2
			;;
		--caddy-storage-s3-endpoint)
			CADDY_STORAGE_S3_ENDPOINT="$2"
			shift 2
			;;
		--caddy-storage-s3-prefix)
			CADDY_STORAGE_S3_PREFIX="$2"
			shift 2
			;;
		--caddy-storage-s3-access-key)
			CADDY_STORAGE_S3_ACCESS_KEY="$2"
			shift 2
			;;
		--caddy-storage-s3-secret-key)
			CADDY_STORAGE_S3_SECRET_KEY="$2"
			shift 2
			;;
		--caddy-storage-s3-encryption-key)
			CADDY_STORAGE_S3_ENCRYPTION_KEY="$2"
			shift 2
			;;
		--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown argument: $1" >&2
			usage
			exit 1
			;;
	esac
done

if [[ -z "$PAT_TOKEN" ]]; then
	if command -v openssl >/dev/null 2>&1; then
		PAT_TOKEN="$(openssl rand -hex 24)"
	else
		echo "--pat-token is required when openssl is unavailable" >&2
		exit 1
	fi
fi

if [[ -z "$PUBLIC_HOST" ]]; then
	PUBLIC_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
	PUBLIC_HOST="${PUBLIC_HOST:-127.0.0.1}"
fi

if [[ -n "$DNS_PROVIDER" ]]; then
	if [[ -z "$DOMAIN" ]]; then
		echo "--dns-provider requires --domain" >&2
		exit 1
	fi
	if [[ -z "$DNS_API_TOKEN" ]]; then
		echo "--dns-provider requires --dns-api-token" >&2
		exit 1
	fi
	case "$DNS_PROVIDER" in
		cloudflare)
			;;
		*)
			echo "Unsupported --dns-provider: $DNS_PROVIDER (currently supported: cloudflare)" >&2
			exit 1
			;;
	esac
fi

# Domain mode requires DNS-01 wildcard issuance. The previous HTTP-01
# on-demand fallback was removed because Caddy's `ask` endpoint accepts any
# subdomain under the configured domain — random probes can burn the Let's
# Encrypt 50-cert/week quota for the registered domain and DoS real sandbox
# provisioning. Operators who can't run DNS-01 should use --local (no TLS,
# 127.0.0.1 only) or omit --domain to fall back to IP/path mode.
if [[ -n "$DOMAIN" && -z "$DNS_PROVIDER" ]]; then
	echo "--domain requires --dns-provider and --dns-api-token (DNS-01 wildcard TLS)." >&2
	echo "HTTP-01 on-demand TLS is no longer supported because it exposes the" >&2
	echo "Let's Encrypt cert-issuance quota to arbitrary-subdomain probes." >&2
	echo "Re-run with --dns-provider cloudflare --dns-api-token <token>, or use --local." >&2
	exit 1
fi

# TLS-SNI multiplexing piggy-backs on the DNS-01 wildcard cert. With DNS-01
# in place ACME never needs :443, so caddy-l4 can own it and the regular
# Caddy HTTPS site moves to 127.0.0.1:8443. In IP/path mode (no --domain)
# there is no TLS at all and the multiplexer stays off.
if [[ -n "$DNS_PROVIDER" ]]; then
	L4_TLS_LISTEN_DEFAULT=":443"
else
	L4_TLS_LISTEN_DEFAULT=""
fi

# Shared cert storage validation. The feature only makes sense alongside
# DNS-01 wildcard issuance — sharing has no benefit in IP/local mode (no
# TLS) and HTTP-01 isn't supported here anyway. Missing required values
# should fail at install time with a paste-able remediation, never at
# first cert-renewal hours/days later.
if [[ "$CADDY_STORAGE_S3" == "true" ]]; then
	if [[ -z "$DOMAIN" || -z "$DNS_PROVIDER" ]]; then
		echo "--caddy-storage-s3 requires --domain and --dns-provider (DNS-01 wildcard TLS)." >&2
		echo "Shared cert storage only matters when there is a wildcard cert to share." >&2
		exit 1
	fi
	missing=()
	[[ -z "$CADDY_STORAGE_S3_BUCKET" ]] && missing+=("--caddy-storage-s3-bucket")
	[[ -z "$CADDY_STORAGE_S3_REGION" ]] && missing+=("--caddy-storage-s3-region")
	[[ -z "$CADDY_STORAGE_S3_ENCRYPTION_KEY" ]] && missing+=("--caddy-storage-s3-encryption-key")
	if [[ ${#missing[@]} -gt 0 ]]; then
		echo "--caddy-storage-s3 requires: ${missing[*]}" >&2
		echo "" >&2
		echo "Generate the encryption key ONCE for the whole cluster and reuse it on every node:" >&2
		echo "  openssl rand -base64 32" >&2
		echo "Losing the key means stored certs cannot be decrypted — keep it in a secrets manager." >&2
		exit 1
	fi
	if [[ -n "$CADDY_STORAGE_S3_ACCESS_KEY" && -z "$CADDY_STORAGE_S3_SECRET_KEY" ]] \
	   || [[ -z "$CADDY_STORAGE_S3_ACCESS_KEY" && -n "$CADDY_STORAGE_S3_SECRET_KEY" ]]; then
		echo "--caddy-storage-s3-access-key and --caddy-storage-s3-secret-key must be set together (or both omitted to use the default credential chain)." >&2
		exit 1
	fi
	# Default the S3 endpoint to the AWS regional host when none was passed.
	# The ss098/certmagic-s3 module wraps minio-go, which has no built-in AWS
	# default — an empty host fails immediately with "Endpoint: does not
	# follow ip address or domain name standards". The regional form works
	# for every region (us-east-1 included) and gives correct SigV4 region
	# inference inside minio-go.
	if [[ -z "$CADDY_STORAGE_S3_ENDPOINT" ]]; then
		CADDY_STORAGE_S3_ENDPOINT="s3.${CADDY_STORAGE_S3_REGION}.amazonaws.com"
	fi
fi

if [[ "$BUILD_FROM_SOURCE" == "auto" ]]; then
	if [[ -f ./go.mod ]]; then
		BUILD_FROM_SOURCE="true"
	else
		BUILD_FROM_SOURCE="false"
	fi
fi

if [[ "$BUILD_FROM_SOURCE" != "true" ]]; then
	resolve_release_urls
	if [[ -z "$SANDBOXD_URL" || -z "$TOOLBOXD_URL" ]]; then
		echo "download mode requires release asset URLs or a valid --github-repo/--version combination" >&2
		exit 1
	fi
fi

# ensure_docker installs and starts the Docker engine if it isn't already
# present. sandboxd's systemd unit hard-Requires docker.service, so this must
# run on every Linux install path — including --local, which otherwise skips
# install_packages entirely and leaves the daemon unable to start (the unit's
# Requires=docker.service can't be satisfied, so `enable --now` is a silent
# no-op: enabled but dead, no ExecStart, no journal). Idempotent.
ensure_docker() {
	if ! command -v docker >/dev/null 2>&1; then
		apt-get update
		apt-get install -y docker.io
		systemctl enable --now docker
	fi
}

install_packages() {
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update
		apt-get install -y build-essential ca-certificates curl gnupg lsb-release software-properties-common
		# Mount tooling for the host-managed external storage feature.
		# fuse3 is required by mountpoint-s3, sshfs, and rclone mount.
		# nfs-common provides mount.nfs. mountpoint-s3 ships as a .deb from AWS;
		# we attempt an apt install first and fall back to the AWS download.
		apt-get install -y fuse3 sshfs nfs-common rclone || true
		if ! command -v mount-s3 >/dev/null 2>&1; then
			local arch_suffix
			case "$(uname -m)" in
				x86_64|amd64) arch_suffix="x86_64" ;;
				aarch64|arm64) arch_suffix="arm64" ;;
				*) arch_suffix="" ;;
			esac
			if [[ -n "$arch_suffix" ]]; then
				local tmp_deb
				tmp_deb="$(mktemp --suffix=.deb)"
				if curl_download "https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch_suffix}/mount-s3.deb" -o "$tmp_deb"; then
					apt-get install -y "$tmp_deb" || \
						echo "Warning: mountpoint-s3 install failed; s3 mounts will be unavailable until installed manually" >&2
				else
					echo "Warning: failed to download mountpoint-s3; s3 mounts will be unavailable until installed manually" >&2
				fi
				rm -f "$tmp_deb"
			fi
		fi
		ensure_docker
		if ! command -v caddy >/dev/null 2>&1; then
			apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
			curl_download 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
			curl_download 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' -o /etc/apt/sources.list.d/caddy-stable.list
			apt-get update
			apt-get install -y caddy
		fi
		if [[ "$BUILD_FROM_SOURCE" == "true" ]] && ! command -v go >/dev/null 2>&1; then
			apt-get install -y golang-go make
		fi
	else
		echo "Only apt-based distributions are supported by this installer right now" >&2
		exit 1
	fi
}

verify_custom_caddy_binary() {
	local tmp_binary="$1"
	local source_label="$2"
	shift 2
	local required_modules=("$@")

	if [[ ! -s "$tmp_binary" ]]; then
		echo "${source_label} returned an empty binary" >&2
		return 1
	fi

	if ! file "$tmp_binary" 2>/dev/null | grep -q ELF; then
		echo "${source_label} did not return an ELF binary; first bytes:" >&2
		head -c 200 "$tmp_binary" >&2 || true
		echo "" >&2
		return 1
	fi

	chmod +x "$tmp_binary"

	# Verify every requested module is actually compiled in. Without this the
	# Caddyfile / admin API calls we make later would fail at runtime with a
	# cryptic "loading module 'X'" error long after install.sh exits.
	local module
	local present
	present="$("$tmp_binary" list-modules 2>/dev/null || true)"
	for module in "${required_modules[@]}"; do
		if ! grep -q "^${module}\$" <<<"$present"; then
			echo "${source_label} does not include required module: ${module}" >&2
			echo "Modules present (filtered):" >&2
			grep -E "^(layer4|dns\.providers|caddy\.storage)" <<<"$present" >&2 || true
			return 1
		fi
	done
}

install_custom_caddy() {
	# Replace the apt-installed Caddy binary with a custom build that includes
	# every plugin AerolVM needs. caddy-l4 is always required so sandboxes can
	# expose native TCP endpoints (Postgres, Redis, MySQL, etc.) via the
	# layer4 admin API. caddy-dns/$DNS_PROVIDER is added when --dns-provider
	# is set so DNS-01 wildcard TLS works.
	#
	# Prefer the pinned release artifact. The live Caddy build service is a
	# fallback only; if it stalls at 0 bytes, bounded curl timeouts fail
	# bootstrap cleanly instead of leaving cloud-init running forever.
	local provider="${1:-}"
	local arch_tag
	local arch_extra=""

	case "$(uname -m)" in
		x86_64|amd64)  arch_tag="amd64" ;;
		i686|i386)     arch_tag="386" ;;
		aarch64|arm64) arch_tag="arm64" ;;
		armv7l|armv7)  arch_tag="arm"; arch_extra="&arm=7" ;;
		armv6l|armv6)  arch_tag="arm"; arch_extra="&arm=6" ;;
		*)
			echo "Unsupported architecture for custom Caddy build: $(uname -m)" >&2
			exit 1
			;;
	esac

	local caddy_path
	caddy_path="$(command -v caddy 2>/dev/null || true)"
	if [[ -z "$caddy_path" ]]; then
		caddy_path="/usr/bin/caddy"
	fi

	local required_modules=("layer4" "layer4.handlers.proxy")
	if [[ -n "$provider" ]]; then
		required_modules+=("dns.providers.${provider}")
	fi
	if [[ "$CADDY_STORAGE_S3" == "true" ]]; then
		# The ss098 module registers under caddy.storage.s3.
		required_modules+=("caddy.storage.s3")
	fi

	local tmp_binary
	if [[ -n "$CADDY_BINARY_URL" ]]; then
		local prebuilt_dir
		local prebuilt_asset
		prebuilt_dir="$(mktemp -d)"
		prebuilt_asset="$(basename "${CADDY_BINARY_URL%%\?*}")"
		tmp_binary="$prebuilt_dir/$prebuilt_asset"
		echo "Downloading prebuilt custom Caddy from ${CADDY_BINARY_URL}"
		if curl_download "$CADDY_BINARY_URL" -o "$tmp_binary"; then
			if [[ "$CADDY_BINARY_URL_EXPLICIT" != "true" ]] \
				&& ! verify_downloads "$prebuilt_dir" "$prebuilt_asset"; then
				rm -rf "$prebuilt_dir"
				echo "Prebuilt custom Caddy checksum verification failed" >&2
				exit 1
			fi
			if ! verify_custom_caddy_binary "$tmp_binary" "Prebuilt custom Caddy binary" "${required_modules[@]}"; then
				rm -rf "$prebuilt_dir"
				exit 1
			fi
			systemctl stop caddy >/dev/null 2>&1 || true
			install -m 0755 "$tmp_binary" "$caddy_path"
			rm -rf "$prebuilt_dir"
			return
		fi
		rm -rf "$prebuilt_dir"
		if [[ "$CADDY_BINARY_URL_EXPLICIT" == "true" ]]; then
			echo "Failed to install custom Caddy from explicit --caddy-binary-url: ${CADDY_BINARY_URL}" >&2
			exit 1
		fi
		echo "Prebuilt custom Caddy release asset unavailable; falling back to Caddy build service" >&2
	fi

	# Caddy build server accepts repeated &p= for additional modules.
	local download_url="${CADDY_BUILD_URL_BASE}?os=linux&arch=${arch_tag}${arch_extra}&p=github.com/mholt/caddy-l4"
	if [[ -n "$provider" ]]; then
		download_url="${download_url}&p=github.com/caddy-dns/${provider}"
	fi
	# Shared cert storage adds the certmagic-s3 plugin so multiple ingress
	# nodes can pool ACME issuance via a single S3 object set. The plugin
	# handles distributed locking via S3 conditional writes — no
	# orchestration code lives in install.sh.
	if [[ "$CADDY_STORAGE_S3" == "true" ]]; then
		download_url="${download_url}&p=github.com/ss098/certmagic-s3"
	fi

	tmp_binary="$(mktemp)"

	if ! curl_download "$download_url" -o "$tmp_binary"; then
		rm -f "$tmp_binary"
		echo "Failed to download custom Caddy build from ${download_url}" >&2
		exit 1
	fi

	if ! verify_custom_caddy_binary "$tmp_binary" "Caddy build server" "${required_modules[@]}"; then
		rm -f "$tmp_binary"
		exit 1
	fi

	systemctl stop caddy >/dev/null 2>&1 || true
	install -m 0755 "$tmp_binary" "$caddy_path"
	rm -f "$tmp_binary"
}

install_binaries() {
	mkdir -p "$INSTALL_PREFIX"
	if [[ "$BUILD_FROM_SOURCE" == "true" ]]; then
		make build
		install -m 0755 ./bin/sandboxd "$INSTALL_PREFIX/sandboxd"
		install -m 0755 ./bin/toolboxd "$INSTALL_PREFIX/toolboxd"
	else
		local tmp_dir
		local sandboxd_asset
		local toolboxd_asset

		tmp_dir="$(mktemp -d)"
		sandboxd_asset="$(basename "${SANDBOXD_URL%%\?*}")"
		toolboxd_asset="$(basename "${TOOLBOXD_URL%%\?*}")"

		download_asset "$SANDBOXD_URL" "$tmp_dir/$sandboxd_asset"
		download_asset "$TOOLBOXD_URL" "$tmp_dir/$toolboxd_asset"
		verify_downloads "$tmp_dir" "$sandboxd_asset" "$toolboxd_asset"

		install -m 0755 "$tmp_dir/$sandboxd_asset" "$INSTALL_PREFIX/sandboxd"
		install -m 0755 "$tmp_dir/$toolboxd_asset" "$INSTALL_PREFIX/toolboxd"
		rm -rf "$tmp_dir"
	fi
}

write_environment() {
	mkdir -p /etc/sandboxd /var/lib/sandboxd /var/lib/sandboxd/mounts /run/sandboxd
	chmod 0700 /var/lib/sandboxd /var/lib/sandboxd/mounts /run/sandboxd
	cat > /etc/sandboxd/sandboxd.env <<EOF
SB_PAT_TOKEN=$PAT_TOKEN
SB_NODE_NAME=$NODE_NAME
SB_API_HOST=0.0.0.0
SB_API_PORT=21212
SB_DOMAIN=$DOMAIN
SB_PUBLIC_HOST=$PUBLIC_HOST
SB_CADDY_ADMIN_URL=http://127.0.0.1:2019
SB_CADDY_SERVER_ID=srv0
SB_DB_PATH=/var/lib/sandboxd/state.db
SB_DOCKER_NETWORK=bridge
SB_TOOLBOX_BINARY_PATH=$INSTALL_PREFIX/toolboxd
SB_TOOLBOX_MOUNT_PATH=/usr/local/bin/toolboxd
SB_TOOLBOX_PORT=2280
SB_IDLE_TIMEOUT_MIN=$IDLE_TIMEOUT_MIN
SB_ENABLE_CADDY=true
SB_ENABLE_NETWORK_RULES=true
SB_MOUNTS_ROOT=/var/lib/sandboxd/mounts
SB_MOUNTS_CRED_DIR=/run/sandboxd
SB_MOUNT_WAIT_TIMEOUT=30s
SB_RECORDING_DIR=/var/lib/toolboxd/recordings
SB_RECORDING_RETENTION=168h
SB_SESSION_BUFFER_BYTES=1048576
SB_L4_PORT_RANGE_START=22000
SB_L4_PORT_RANGE_END=23000
# TLS-SNI multiplexing. In domain mode (--dns-provider required) we bind
# caddy-l4 to :443 by default; the Caddyfile above moves the regular HTTPS
# site to 127.0.0.1:8443 so they don't collide. ACME goes via DNS so :443
# isn't needed for issuance. In IP/path mode (no --domain) this stays
# empty and the layer4 multiplexer is never started.
SB_L4_TLS_LISTEN=$L4_TLS_LISTEN_DEFAULT
SB_L4_TLS_FALLBACK=127.0.0.1:8443
EOF
	# gVisor has no SB_ENABLE_* flag of its own: registering runsc in
	# /etc/docker/daemon.json lets a sandbox opt into runtime:"runsc", but
	# the daemon still defaults SB_HOST_RUNTIMES to {"docker"} and only
	# appends firecracker/wasm from their enable flags. In cluster mode that
	# means a --with-gvisor node never advertises "gvisor" to placement, so
	# every gVisor create is rejected with ErrNoPlacementTarget even though
	# runsc is installed. Advertise it explicitly here so the host the runsc
	# binary landed on also tells the cluster it can place gVisor sandboxes.
	if [[ "$WITH_GVISOR" == "true" ]]; then
		echo "SB_HOST_RUNTIMES=docker,gvisor" >> /etc/sandboxd/sandboxd.env
	fi
	# Isolate runtime (plans/isolate-runtime.md). SB_ENABLE_ISOLATE is enough
	# for advertisement — the daemon appends "isolate" to SupportedRuntimes
	# from the flag itself. SB_ISOLATE_WORKERD_PATH only needs writing when
	# the binary is somewhere other than the daemon's default.
	if [[ "$WITH_ISOLATE" == "true" ]]; then
		echo "SB_ENABLE_ISOLATE=true" >> /etc/sandboxd/sandboxd.env
		if [[ -n "${WORKERD_BIN_RESOLVED:-}" && "$WORKERD_BIN_RESOLVED" != "/usr/local/bin/workerd" ]]; then
			echo "SB_ISOLATE_WORKERD_PATH=$WORKERD_BIN_RESOLVED" >> /etc/sandboxd/sandboxd.env
		fi
	fi
	# Containerd engine is opt-in and dark by default (plans/containerd-engine.md).
	# Flipping SB_CONTAINER_ENGINE here does not remove dockerd; coexistence is
	# intentional during migration (engine column keeps old sandboxes driveable).
	if [[ "$WITH_CONTAINERD_ENGINE" == "true" ]]; then
		cat >> /etc/sandboxd/sandboxd.env <<'EOF'
SB_CONTAINER_ENGINE=containerd
SB_CONTAINERD_SOCKET=/run/containerd/containerd.sock
SB_CONTAINERD_NAMESPACE=aerolvm
SB_CONTAINERD_CNI_PLUGIN_DIR=/opt/cni/bin
SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=true
EOF
	fi
	chmod 0600 /etc/sandboxd/sandboxd.env
}

write_caddyfile() {
	mkdir -p /etc/caddy
	if [[ -z "$DOMAIN" ]]; then
		cat > /etc/caddy/Caddyfile <<EOF
{
	admin localhost:2019
}

:80 {
	respond "Sandbox not found" 404
}
EOF
		return
	fi

	# Domain mode: DNS-01 wildcard issuance is the only supported path
	# (HTTP-01 on-demand was removed because the per-subdomain ask endpoint
	# could be abused to burn the Let's Encrypt 50-cert/week quota — argument
	# parsing has already required --dns-provider whenever --domain is set).
	#
	# Caddy issues exactly two certs that are renewed automatically:
	#   - one for $DOMAIN
	#   - one for *.$DOMAIN  (covers every sandbox subdomain forever)
	# {env.SB_DNS_API_TOKEN} is read from /etc/default/caddy.
	#
	# TLS-SNI multiplexing is on by default. caddy-l4 owns :443, peeks at the
	# ClientHello SNI, routes per-sandbox subdomains directly to the sandbox
	# container, and forwards unmatched SNI (the API host itself, stray
	# probes) to the Caddy HTTPS listener on 127.0.0.1:8443. Two implications:
	#   - The HTTPS sites below bind 127.0.0.1:8443, NOT :443. caddy-l4 gets
	#     :443, sandboxd writes the L4 server config via the admin API on
	#     first L4 expose call.
	#   - DNS-01 means we don't need :443 free for ACME (validation goes
	#     through DNS), so handing :443 to caddy-l4 is safe.
	#
	# Shared cert storage: when --caddy-storage-s3 is set, we inject a
	# `storage s3` directive so every node points at the same bucket.
	# certmagic-s3 holds a distributed lock during ACME, so exactly one
	# node issues / renews the wildcard while the others read from S3.
	# Optional lines (host, access_id/secret_key) are emitted only when
	# the operator supplied a value — empty strings would otherwise
	# override the AWS default credential chain / endpoint.
	# ACME account email lives in the global block. Without it Caddy creates
	# an anonymous LE account and operators get no advance notice of
	# expiring / revoked / rate-limited certs. Empty string omits the line
	# entirely (preserves prior behavior for installs that don't pass one).
	local email_line=""
	if [[ -n "$ACME_EMAIL" ]]; then
		email_line=$'\n\temail '"$ACME_EMAIL"
	fi
	local storage_block=""
	if [[ "$CADDY_STORAGE_S3" == "true" ]]; then
		storage_block=$'\n\tstorage s3 {'
		# host is always emitted: certmagic-s3 / minio-go reject an empty
		# endpoint. CADDY_STORAGE_S3_ENDPOINT was defaulted upstream to
		# s3.<region>.amazonaws.com when the operator didn't pass one.
		storage_block+=$'\n\t\thost {env.SB_CADDY_S3_ENDPOINT}'
		storage_block+=$'\n\t\tbucket {env.SB_CADDY_S3_BUCKET}'
		storage_block+=$'\n\t\tprefix {env.SB_CADDY_S3_PREFIX}'
		if [[ -n "$CADDY_STORAGE_S3_ACCESS_KEY" ]]; then
			storage_block+=$'\n\t\taccess_id {env.SB_CADDY_S3_ACCESS_KEY}'
			storage_block+=$'\n\t\tsecret_key {env.SB_CADDY_S3_SECRET_KEY}'
		else
			# No static creds → fall back to the AWS default credential
			# chain (EC2 instance role, IRSA, env vars, ~/.aws/credentials).
			# Without this line certmagic-s3 refuses to start with
			# "access_id is empty and use_iam_provider is false".
			storage_block+=$'\n\t\tuse_iam_provider true'
		fi
		storage_block+=$'\n\t\tencryption_key {env.SB_CADDY_S3_ENCRYPTION_KEY}'
		storage_block+=$'\n\t}'
	fi
	cat > /etc/caddy/Caddyfile <<EOF
{
	admin localhost:2019${email_line}
	# caddy-l4 owns :443; the HTTPS sites below run on 127.0.0.1:8443 and
	# only receive traffic forwarded from caddy-l4's SNI fallback route.
	# Disable Caddy's auto-managed :80 -> :443 redirect since :443 isn't ours.
	auto_https disable_redirects${storage_block}
}

https://$DOMAIN:8443 {
	bind 127.0.0.1
	tls {
		dns $DNS_PROVIDER {env.SB_DNS_API_TOKEN}
	}
	@api path /health /v1 /v1/* /daytona /daytona/* /e2b /e2b/*
	handle @api {
		reverse_proxy 127.0.0.1:21212
	}
	handle {
		respond "Sandbox API not found" 404
	}
}

https://*.$DOMAIN:8443 {
	bind 127.0.0.1
	tls {
		dns $DNS_PROVIDER {env.SB_DNS_API_TOKEN}
	}
	respond "Sandbox not found" 404
}
EOF
}

write_caddy_env() {
	if [[ -z "$DNS_PROVIDER" && "$CADDY_STORAGE_S3" != "true" ]]; then
		return
	fi
	# The stock Caddy debian unit from Cloudsmith does NOT load
	# /etc/default/caddy as an EnvironmentFile, so writing it alone is not
	# enough. write_caddy_systemd_dropin() installs a drop-in that wires it
	# in. 0600 root:root is fine — Caddy receives the value via process env.
	{
		echo "# Managed by AerolVM install.sh."
		echo "# Read by Caddy via {env.NAME} substitution in /etc/caddy/Caddyfile."
		if [[ -n "$DNS_PROVIDER" ]]; then
			echo "SB_DNS_API_TOKEN=$DNS_API_TOKEN"
		fi
		if [[ "$CADDY_STORAGE_S3" == "true" ]]; then
			# certmagic-s3 reads these via the {env.NAME} substitutions
			# emitted by write_caddyfile. Encryption key MUST match every
			# other node — losing it means the bucket's cert objects are
			# unreadable. See setup/multi-node-cert-sharing.md.
			echo "SB_CADDY_S3_BUCKET=$CADDY_STORAGE_S3_BUCKET"
			echo "SB_CADDY_S3_REGION=$CADDY_STORAGE_S3_REGION"
			echo "SB_CADDY_S3_ENDPOINT=$CADDY_STORAGE_S3_ENDPOINT"
			echo "SB_CADDY_S3_PREFIX=$CADDY_STORAGE_S3_PREFIX"
			# AWS_REGION lets minio-go (inside certmagic-s3) sign SigV4
			# with the correct region. The endpoint host alone isn't
			# enough — minio-go infers signing region from this env var.
			echo "AWS_REGION=$CADDY_STORAGE_S3_REGION"
			if [[ -n "$CADDY_STORAGE_S3_ACCESS_KEY" ]]; then
				echo "SB_CADDY_S3_ACCESS_KEY=$CADDY_STORAGE_S3_ACCESS_KEY"
				echo "SB_CADDY_S3_SECRET_KEY=$CADDY_STORAGE_S3_SECRET_KEY"
				# Also expose under the canonical AWS SDK names so the
				# default credential chain inside certmagic-s3 picks them
				# up even when the Caddyfile lines are omitted.
				echo "AWS_ACCESS_KEY_ID=$CADDY_STORAGE_S3_ACCESS_KEY"
				echo "AWS_SECRET_ACCESS_KEY=$CADDY_STORAGE_S3_SECRET_KEY"
			fi
			echo "SB_CADDY_S3_ENCRYPTION_KEY=$CADDY_STORAGE_S3_ENCRYPTION_KEY"
		fi
	} > /etc/default/caddy
	chmod 0600 /etc/default/caddy
	chown root:root /etc/default/caddy
}

write_caddy_systemd_dropin() {
	if [[ -z "$DNS_PROVIDER" && "$CADDY_STORAGE_S3" != "true" ]]; then
		return
	fi
	mkdir -p /etc/systemd/system/caddy.service.d
	cat > /etc/systemd/system/caddy.service.d/override.conf <<'EOF'
[Service]
EnvironmentFile=/etc/default/caddy
EOF
}

write_systemd_unit() {
	cat > /etc/systemd/system/sandboxd.service <<EOF
[Unit]
Description=AerolVM daemon
After=docker.service caddy.service network-online.target
Wants=network-online.target
Requires=docker.service
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
EnvironmentFile=/etc/sandboxd/sandboxd.env
ExecStartPre=/bin/mkdir -p /var/lib/sandboxd/mounts /run/sandboxd
ExecStartPre=/bin/chmod 0700 /var/lib/sandboxd/mounts /run/sandboxd
ExecStart=$INSTALL_PREFIX/sandboxd
# MountFlags=shared lets bind-mounts created by sandboxd (FUSE mounts under
# /var/lib/sandboxd/mounts/<id>/) propagate into the Docker daemon's view
# so containers actually see the storage. Without this some configurations
# leave the daemon with a private mount namespace and the bind appears empty.
MountFlags=shared
Restart=always
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=30
KillMode=control-group

[Install]
WantedBy=multi-user.target
EOF
}

write_healthcheck_script() {
	cat > "$INSTALL_PREFIX/sandboxd-healthcheck" <<'EOF'
#!/usr/bin/env bash

set -euo pipefail

ENV_FILE="/etc/sandboxd/sandboxd.env"
if [[ -f "$ENV_FILE" ]]; then
	# shellcheck disable=SC1091
	source "$ENV_FILE"
fi

if ! systemctl is-active --quiet sandboxd.service; then
	exit 0
fi

HEALTH_HOST="127.0.0.1"
HEALTH_PORT="${SB_API_PORT:-21212}"
HEALTH_URL="http://${HEALTH_HOST}:${HEALTH_PORT}/health"

if ! curl -fsS --max-time 10 "$HEALTH_URL" >/dev/null; then
	logger -t sandboxd-healthcheck "health check failed for ${HEALTH_URL}; restarting sandboxd.service"
	systemctl restart sandboxd.service
	logger -t sandboxd-healthcheck "sandboxd.service restart requested"
fi
EOF
	chmod 0755 "$INSTALL_PREFIX/sandboxd-healthcheck"
}

write_healthcheck_units() {
	cat > /etc/systemd/system/sandboxd-healthcheck.service <<EOF
[Unit]
Description=AerolVM health watchdog
After=sandboxd.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_PREFIX/sandboxd-healthcheck
EOF

	cat > /etc/systemd/system/sandboxd-healthcheck.timer <<EOF
[Unit]
Description=Run AerolVM health watchdog

[Timer]
OnBootSec=45s
OnUnitActiveSec=30s
AccuracySec=5s
Persistent=true
Unit=sandboxd-healthcheck.service

[Install]
WantedBy=timers.target
EOF
}

install_nvidia_gpu() {
	# Install nvidia-container-toolkit from the official NVIDIA repo and wire it
	# into Docker via nvidia-ctk. The host NVIDIA driver (and nvidia-smi) must
	# already be present — the toolkit only provides the container integration
	# layer on top of the driver. We warn but continue when nvidia-smi is absent
	# so pre-staging the toolkit before driver installation is also possible.
	if ! command -v nvidia-smi >/dev/null 2>&1; then
		echo "Warning: nvidia-smi not found — NVIDIA drivers may not be installed." >&2
		echo "  Install the NVIDIA drivers first (https://docs.nvidia.com/cuda/cuda-installation-guide-linux/)," >&2
		echo "  then re-run with --with-nvidia-gpu, or continue if drivers will be installed separately." >&2
	fi

	case "$(uname -m)" in
		x86_64|amd64|aarch64|arm64) ;;
		*)
			echo "--with-nvidia-gpu: unsupported architecture $(uname -m)" >&2
			exit 1
			;;
	esac

	local keyring="/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg"
	if [[ ! -f "$keyring" ]]; then
		curl_download "https://nvidia.github.io/libnvidia-container/gpgkey" \
			| gpg --dearmor -o "$keyring"
	fi

	# nvidia-container-toolkit.list uses plain https:// refs; rewrite to
	# include the signed-by pointer so apt can verify the packages.
	if [[ ! -f /etc/apt/sources.list.d/nvidia-container-toolkit.list ]]; then
		curl_download "https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list" \
			| sed "s#deb https://#deb [signed-by=${keyring}] https://#g" \
			> /etc/apt/sources.list.d/nvidia-container-toolkit.list
		apt-get update
	fi

	apt-get install -y nvidia-container-toolkit

	# nvidia-ctk handles the daemon.json merge and sets the default runtime
	# field so docker run --gpus just works out of the box.
	nvidia-ctk runtime configure --runtime=docker

	systemctl restart docker
	echo "NVIDIA container toolkit installed. Docker restarted."
	echo "Verify GPU access inside a container: docker run --rm --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi"
}

install_amd_gpu() {
	# Install AMD ROCm so containers can access AMD GPUs via /dev/kfd
	# (compute) and /dev/dri (render nodes). No Docker daemon.json changes
	# are needed — sandboxd uses device bind-mounts for AMD, not a custom OCI
	# runtime. Only x86_64 is supported by the ROCm stack.
	case "$(uname -m)" in
		x86_64|amd64) ;;
		*)
			echo "--with-amd-gpu: ROCm only supports x86_64; $(uname -m) is not supported" >&2
			exit 1
			;;
	esac

	if [[ ! -e /dev/kfd ]]; then
		echo "Warning: /dev/kfd not found — amdgpu kernel module may not be loaded." >&2
		echo "  Make sure the GPU is present and 'modprobe amdgpu' has run (or the" >&2
		echo "  driver is loaded automatically via /etc/modules-load.d/)." >&2
		echo "  Continuing; /dev/kfd will appear after the driver loads." >&2
	fi

	local dist_codename
	dist_codename="$(lsb_release -cs 2>/dev/null || echo "jammy")"

	# Try the amdgpu-install convenience package first — it's the approach AMD
	# documents and handles kernel module + ROCm library installation together.
	local tmp_deb
	tmp_deb="$(mktemp --suffix=.deb)"
	if curl_download \
		"https://repo.radeon.com/amdgpu-install/latest/ubuntu/${dist_codename}/amdgpu-install_latest_all.deb" \
		-o "$tmp_deb" 2>/dev/null; then
		apt-get install -y "$tmp_deb"
		rm -f "$tmp_deb"
		# --usecase=rocm installs the ROCm compute stack.
		# --no-dkms skips recompiling kernel modules (existing amdgpu driver is enough).
		amdgpu-install -y --usecase=rocm --no-dkms
	else
		rm -f "$tmp_deb"
		echo "amdgpu-install package unavailable for '${dist_codename}'; falling back to direct ROCm apt repo" >&2
		local keyring="/usr/share/keyrings/rocm-archive-keyring.gpg"
		curl_download "https://repo.radeon.com/rocm/rocm.gpg.key" | gpg --dearmor -o "$keyring"
		echo "deb [arch=amd64 signed-by=${keyring}] https://repo.radeon.com/rocm/apt/latest ${dist_codename} main" \
			> /etc/apt/sources.list.d/rocm.list
		apt-get update
		apt-get install -y rocm-hip-sdk || apt-get install -y rocm
	fi

	# Ensure the render group exists and add current user if running interactively.
	groupadd -f render
	groupadd -f video
	echo "AMD ROCm installed."
	echo "Note: container users need 'video' and 'render' group membership to access GPU devices."
	echo "Verify with: rocm-smi"
}

install_runsc_binary() {
	# Download the latest runsc release from gVisor's official storage bucket
	# and install it to /usr/local/bin. The bucket layout is:
	#   storage.googleapis.com/gvisor/releases/release/latest/<arch>/{runsc,runsc.sha512}
	# where <arch> is x86_64 or aarch64. We verify the SHA-512 published next
	# to the binary before installing — the upstream-recommended pattern from
	# https://gvisor.dev/docs/user_guide/install/.
	local arch
	case "$(uname -m)" in
		x86_64|amd64)   arch="x86_64" ;;
		aarch64|arm64)  arch="aarch64" ;;
		*)
			echo "--with-gvisor: unsupported architecture $(uname -m) for runsc" >&2
			exit 1
			;;
	esac

	local base="https://storage.googleapis.com/gvisor/releases/release/latest/${arch}"
	local tmp_dir
	tmp_dir="$(mktemp -d)"
	# shellcheck disable=SC2064  # capture tmp_dir at trap-install time, not at exit
	trap "rm -rf '$tmp_dir'" RETURN

	echo "Downloading runsc for ${arch} from ${base}"
	if ! curl_download "${base}/runsc" -o "${tmp_dir}/runsc"; then
		echo "--with-gvisor: failed to download runsc from ${base}/runsc" >&2
		exit 1
	fi
	if ! curl_download "${base}/runsc.sha512" -o "${tmp_dir}/runsc.sha512"; then
		echo "--with-gvisor: failed to download runsc.sha512 from ${base}/runsc.sha512" >&2
		exit 1
	fi

	# gVisor's published checksum file uses the binary path under the bucket,
	# not just the basename. Rewrite it to match what we have on disk so
	# sha512sum -c finds the file. Format is "<hash>  <path>".
	(
		cd "$tmp_dir"
		awk '{print $1"  runsc"}' runsc.sha512 > runsc.sha512.local
		if ! sha512sum -c runsc.sha512.local; then
			echo "--with-gvisor: runsc checksum verification failed" >&2
			exit 1
		fi
	)

	install -m 0755 "${tmp_dir}/runsc" /usr/local/bin/runsc
	echo "Installed runsc to /usr/local/bin/runsc"
}

install_runsc_shim() {
	# The containerd engine reaches gVisor through the io.containerd.runsc.v1
	# shim (internal/runtime/containerd/runtime_gvisor.go): containerd resolves
	# that runtime name by exec'ing containerd-shim-runsc-v1 from its PATH, so
	# the daemon.json registration below covers dockerd only. Install the shim
	# next to runsc so --with-gvisor works under both engines — without it a
	# runtime:"gvisor" create on a containerd node fails at shim launch.
	if command -v containerd-shim-runsc-v1 >/dev/null 2>&1; then
		echo "containerd-shim-runsc-v1 already installed"
		return 0
	fi

	local arch
	case "$(uname -m)" in
		x86_64|amd64)   arch="x86_64" ;;
		aarch64|arm64)  arch="aarch64" ;;
		*)
			echo "--with-gvisor: unsupported architecture $(uname -m) for containerd-shim-runsc-v1" >&2
			exit 1
			;;
	esac

	local base="https://storage.googleapis.com/gvisor/releases/release/latest/${arch}"
	local tmp_dir
	tmp_dir="$(mktemp -d)"
	# shellcheck disable=SC2064  # capture tmp_dir at trap-install time, not at exit
	trap "rm -rf '$tmp_dir'" RETURN

	echo "Downloading containerd-shim-runsc-v1 for ${arch} from ${base}"
	if ! curl_download "${base}/containerd-shim-runsc-v1" -o "${tmp_dir}/containerd-shim-runsc-v1"; then
		echo "--with-gvisor: failed to download containerd-shim-runsc-v1 from ${base}/containerd-shim-runsc-v1" >&2
		exit 1
	fi
	if ! curl_download "${base}/containerd-shim-runsc-v1.sha512" -o "${tmp_dir}/containerd-shim-runsc-v1.sha512"; then
		echo "--with-gvisor: failed to download containerd-shim-runsc-v1.sha512" >&2
		exit 1
	fi

	(
		cd "$tmp_dir"
		awk '{print $1"  containerd-shim-runsc-v1"}' containerd-shim-runsc-v1.sha512 > shim.sha512.local
		if ! sha512sum -c shim.sha512.local; then
			echo "--with-gvisor: containerd-shim-runsc-v1 checksum verification failed" >&2
			exit 1
		fi
	)

	install -m 0755 "${tmp_dir}/containerd-shim-runsc-v1" /usr/local/bin/containerd-shim-runsc-v1
	echo "Installed containerd-shim-runsc-v1 to /usr/local/bin/containerd-shim-runsc-v1"
}

install_workerd_binary() {
	# Download the version-pinned workerd release from GitHub and install it
	# to /usr/local/bin (plans/isolate-runtime.md Phase 1 — same recipe as the
	# runsc shim). Assets are gzipped standalone binaries
	# (workerd-linux-{64,arm64}.gz); upstream publishes no checksum sidecar,
	# so verification runs against the SHA-256 pinned next to WORKERD_VERSION
	# at the top of this script. Bump version + hashes together.
	local arch sha
	case "$(uname -m)" in
		x86_64|amd64)   arch="linux-64";    sha="$WORKERD_SHA256_LINUX_64" ;;
		aarch64|arm64)  arch="linux-arm64"; sha="$WORKERD_SHA256_LINUX_ARM64" ;;
		*)
			echo "--with-isolate: unsupported architecture $(uname -m) for workerd" >&2
			exit 1
			;;
	esac

	local url="https://github.com/cloudflare/workerd/releases/download/${WORKERD_VERSION}/workerd-${arch}.gz"
	local tmp_dir
	tmp_dir="$(mktemp -d)"
	# shellcheck disable=SC2064  # capture tmp_dir at trap-install time, not at exit
	trap "rm -rf '$tmp_dir'" RETURN

	echo "Downloading workerd ${WORKERD_VERSION} for ${arch} from ${url}"
	if ! curl_download "$url" -o "${tmp_dir}/workerd.gz"; then
		echo "--with-isolate: failed to download workerd from ${url}" >&2
		exit 1
	fi
	if ! echo "${sha}  ${tmp_dir}/workerd.gz" | sha256sum -c -; then
		echo "--with-isolate: workerd checksum verification failed (pinned ${sha} for ${WORKERD_VERSION}/${arch})" >&2
		exit 1
	fi
	gunzip -f "${tmp_dir}/workerd.gz"
	install -m 0755 "${tmp_dir}/workerd" /usr/local/bin/workerd
	echo "Installed workerd ${WORKERD_VERSION} to /usr/local/bin/workerd"
}

register_isolate_runtime() {
	# Resolve the workerd binary for SB_ISOLATE_WORKERD_PATH: an explicit
	# --workerd-path wins, then a binary already on PATH, then the pinned
	# download. Unlike gVisor there is no daemon.json registration — the
	# isolate driver execs workerd directly (host-mediated, no OCI runtime).
	if [[ -n "$WORKERD_PATH" ]]; then
		WORKERD_BIN_RESOLVED="$WORKERD_PATH"
	elif command -v workerd >/dev/null 2>&1; then
		WORKERD_BIN_RESOLVED="$(command -v workerd)"
	else
		install_workerd_binary
		WORKERD_BIN_RESOLVED="/usr/local/bin/workerd"
	fi
	if [[ ! -x "$WORKERD_BIN_RESOLVED" ]]; then
		echo "--with-isolate: workerd binary at $WORKERD_BIN_RESOLVED is not executable" >&2
		exit 1
	fi
}

install_cni_plugins() {
	# CNI bridge + host-local are required for containerd native netns
	# (plans/containerd-engine.md §4 / Phase 5). Install under /opt/cni/bin.
	local arch
	case "$(uname -m)" in
		x86_64|amd64)   arch="amd64" ;;
		aarch64|arm64)  arch="arm64" ;;
		*)
			echo "--with-containerd-engine: unsupported architecture $(uname -m) for CNI plugins" >&2
			exit 1
			;;
	esac

	local ver="v1.5.1"
	local url="https://github.com/containernetworking/plugins/releases/download/${ver}/cni-plugins-linux-${arch}-${ver}.tgz"
	local tmp_dir
	tmp_dir="$(mktemp -d)"
	# shellcheck disable=SC2064
	trap "rm -rf '$tmp_dir'" RETURN

	echo "Downloading CNI plugins ${ver} (${arch}) from ${url}"
	if ! curl_download "$url" -o "${tmp_dir}/cni.tgz"; then
		echo "--with-containerd-engine: failed to download CNI plugins from ${url}" >&2
		exit 1
	fi
	mkdir -p /opt/cni/bin
	tar -xzf "${tmp_dir}/cni.tgz" -C /opt/cni/bin
	for plugin in bridge host-local loopback; do
		if [[ ! -x "/opt/cni/bin/${plugin}" ]]; then
			echo "--with-containerd-engine: expected /opt/cni/bin/${plugin} after extract" >&2
			exit 1
		fi
	done
	echo "Installed CNI plugins to /opt/cni/bin (bridge, host-local, loopback)"
}

register_gvisor_runtime() {
	# Idempotently register gVisor's runsc as an alternative OCI runtime in
	# /etc/docker/daemon.json. If runsc isn't already present we download and
	# verify the upstream release first.
	local runsc_bin
	if [[ -n "$RUNSC_PATH" ]]; then
		runsc_bin="$RUNSC_PATH"
	elif command -v runsc >/dev/null 2>&1; then
		runsc_bin="$(command -v runsc)"
	else
		install_runsc_binary
		runsc_bin="/usr/local/bin/runsc"
	fi
	if [[ ! -x "$runsc_bin" ]]; then
		echo "--with-gvisor: runsc binary at $runsc_bin is not executable" >&2
		exit 1
	fi

	install_runsc_shim

	mkdir -p /etc/docker
	local daemon_json="/etc/docker/daemon.json"
	local desired
	desired="$(printf '{"runtimes":{"runsc":{"path":"%s","runtimeArgs":["--host-uds=open"]}}}' "$runsc_bin")"

	# Merge our runtimes.runsc entry into any existing daemon.json instead of
	# replacing the file. jq does this cleanly when present; a Python fallback
	# covers minimal hosts that don't have jq.
	local merged
	if [[ -s "$daemon_json" ]]; then
		if command -v jq >/dev/null 2>&1; then
			merged="$(jq --arg path "$runsc_bin" '.runtimes = (.runtimes // {}) | .runtimes.runsc = {"path": $path, "runtimeArgs": ["--host-uds=open"]}' "$daemon_json")"
		elif command -v python3 >/dev/null 2>&1; then
			merged="$(RUNSC_PATH="$runsc_bin" python3 - <<'PY'
import json, os, sys
path = "/etc/docker/daemon.json"
with open(path) as f:
    cfg = json.load(f)
cfg.setdefault("runtimes", {})
cfg["runtimes"]["runsc"] = {"path": os.environ["RUNSC_PATH"], "runtimeArgs": ["--host-uds=open"]}
print(json.dumps(cfg, indent=2))
PY
)"
		else
			echo "--with-gvisor: neither jq nor python3 available to merge $daemon_json" >&2
			exit 1
		fi
	else
		merged="$desired"
	fi

	# Skip the write+restart if the file already looks right. Avoids restarting
	# Docker for re-runs of the installer, which would kick every running
	# sandbox unnecessarily.
	if [[ -s "$daemon_json" ]] && diff -q <(printf '%s\n' "$merged") "$daemon_json" >/dev/null 2>&1; then
		echo "gVisor runsc runtime already registered in $daemon_json"
		return 0
	fi

	printf '%s\n' "$merged" > "$daemon_json"
	echo "Registered gVisor runtime in $daemon_json (path=$runsc_bin); restarting docker"
	systemctl restart docker
}

write_local_environment() {
	mkdir -p /etc/sandboxd /var/lib/sandboxd /var/lib/sandboxd/mounts /run/sandboxd
	chmod 0700 /var/lib/sandboxd /var/lib/sandboxd/mounts /run/sandboxd
	cat > /etc/sandboxd/sandboxd.env <<EOF
SB_PAT_TOKEN=$PAT_TOKEN
SB_NODE_NAME=$NODE_NAME
SB_API_HOST=127.0.0.1
SB_API_PORT=21212
SB_PUBLIC_HOST=127.0.0.1
SB_DB_PATH=/var/lib/sandboxd/state.db
SB_DOCKER_NETWORK=bridge
SB_TOOLBOX_BINARY_PATH=$INSTALL_PREFIX/toolboxd
SB_TOOLBOX_MOUNT_PATH=/usr/local/bin/toolboxd
SB_TOOLBOX_PORT=2280
SB_IDLE_TIMEOUT_MIN=$IDLE_TIMEOUT_MIN
SB_ENABLE_CADDY=false
SB_ENABLE_NETWORK_RULES=false
SB_MOUNTS_ROOT=/var/lib/sandboxd/mounts
SB_MOUNTS_CRED_DIR=/run/sandboxd
SB_MOUNT_WAIT_TIMEOUT=30s
SB_RECORDING_DIR=/var/lib/toolboxd/recordings
SB_RECORDING_RETENTION=168h
SB_SESSION_BUFFER_BYTES=1048576
SB_L4_PORT_RANGE_START=22000
SB_L4_PORT_RANGE_END=23000
# Local mode runs without Caddy, so TLS-SNI multiplexing is permanently off.
SB_L4_TLS_LISTEN=
SB_L4_TLS_FALLBACK=127.0.0.1:8443
EOF
	chmod 0600 /etc/sandboxd/sandboxd.env
}

write_local_systemd_unit() {
	cat > /etc/systemd/system/sandboxd.service <<EOF
[Unit]
Description=AerolVM daemon (local)
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
EnvironmentFile=/etc/sandboxd/sandboxd.env
ExecStartPre=/bin/mkdir -p /var/lib/sandboxd/mounts /run/sandboxd
ExecStartPre=/bin/chmod 0700 /var/lib/sandboxd/mounts /run/sandboxd
ExecStart=$INSTALL_PREFIX/sandboxd
MountFlags=shared
Restart=always
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=30
KillMode=control-group

[Install]
WantedBy=multi-user.target
EOF
}

write_launchd_plist() {
	mkdir -p /var/lib/sandboxd /var/lib/sandboxd/mounts /var/log/sandboxd
	chmod 0700 /var/lib/sandboxd /var/lib/sandboxd/mounts
	local plist_path="/Library/LaunchDaemons/com.aerol.sandboxd.plist"
	cat > "$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.aerol.sandboxd</string>
	<key>ProgramArguments</key>
	<array>
		<string>$INSTALL_PREFIX/sandboxd</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>SB_PAT_TOKEN</key>
		<string>$PAT_TOKEN</string>
		<key>SB_API_HOST</key>
		<string>127.0.0.1</string>
		<key>SB_API_PORT</key>
		<string>21212</string>
		<key>SB_PUBLIC_HOST</key>
		<string>127.0.0.1</string>
		<key>SB_DB_PATH</key>
		<string>/var/lib/sandboxd/state.db</string>
		<key>SB_DOCKER_NETWORK</key>
		<string>bridge</string>
		<key>SB_TOOLBOX_BINARY_PATH</key>
		<string>$INSTALL_PREFIX/toolboxd</string>
		<key>SB_TOOLBOX_MOUNT_PATH</key>
		<string>/usr/local/bin/toolboxd</string>
		<key>SB_TOOLBOX_PORT</key>
		<string>2280</string>
		<key>SB_IDLE_TIMEOUT_MIN</key>
		<string>$IDLE_TIMEOUT_MIN</string>
		<key>SB_ENABLE_CADDY</key>
		<string>false</string>
		<key>SB_ENABLE_NETWORK_RULES</key>
		<string>false</string>
		<key>SB_MOUNTS_ROOT</key>
		<string>/var/lib/sandboxd/mounts</string>
		<key>SB_RECORDING_DIR</key>
		<string>/var/lib/toolboxd/recordings</string>
		<key>SB_RECORDING_RETENTION</key>
		<string>168h</string>
		<key>SB_SESSION_BUFFER_BYTES</key>
		<string>1048576</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/var/log/sandboxd/sandboxd.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/sandboxd/sandboxd.err</string>
</dict>
</plist>
EOF
}

if [[ "$LOCAL_MODE" == "true" ]]; then
	if [[ -n "$DOMAIN" || -n "$DNS_PROVIDER" ]]; then
		echo "--local is incompatible with --domain and --dns-provider" >&2
		exit 1
	fi
	if [[ $EUID -ne 0 ]]; then
		echo "install.sh must run as root (use sudo)" >&2
		exit 1
	fi
	install_binaries
	write_local_environment
	if [[ "$(uname -s)" == "Darwin" ]]; then
		write_launchd_plist
		launchctl load /Library/LaunchDaemons/com.aerol.sandboxd.plist
	else
		# The local unit hard-Requires docker.service; on Linux we must install
		# the engine here since this branch skips install_packages. (macOS local
		# mode assumes Docker Desktop is already running.)
		ensure_docker
		write_local_systemd_unit
		write_healthcheck_script
		write_healthcheck_units
		systemctl daemon-reload
		systemctl enable --now sandboxd sandboxd-healthcheck.timer
	fi
	echo "AerolVM installed (local mode)"
	echo "PAT token: $PAT_TOKEN"
	echo "Use header: Authorization: Bearer <PAT token>"
	echo "API URL: http://127.0.0.1:21212"
	echo "Health URL: http://127.0.0.1:21212/health"
	if [[ "$(uname -s)" == "Darwin" ]]; then
		echo "Service: launchd daemon com.aerol.sandboxd (auto-starts on boot)"
		echo "Logs: /var/log/sandboxd/sandboxd.log"
		echo "Stop: sudo launchctl unload /Library/LaunchDaemons/com.aerol.sandboxd.plist"
	else
		echo "systemd restart policy: always (5 second backoff, 10 restarts per 5 minutes)"
		echo "Health watchdog: sandboxd-healthcheck.timer probes /health every 30 seconds"
	fi
	exit 0
fi

if [[ $EUID -ne 0 ]]; then
	echo "install.sh must run as root" >&2
	exit 1
fi

install_packages
if [[ "$WITH_GVISOR" == "true" ]]; then
	register_gvisor_runtime
fi
if [[ "$WITH_ISOLATE" == "true" ]]; then
	register_isolate_runtime
fi
if [[ "$WITH_CONTAINERD_ENGINE" == "true" ]]; then
	install_cni_plugins
fi
if [[ "$WITH_NVIDIA_GPU" == "true" ]]; then
	install_nvidia_gpu
fi
if [[ "$WITH_AMD_GPU" == "true" ]]; then
	install_amd_gpu
fi
# Always replace the apt-installed Caddy with a custom build that includes
# caddy-l4 (TCP routing for sandbox-exposed ports). DNS plugin gets folded
# into the same build when --dns-provider is set so we make exactly one
# trip to the Caddy build server.
install_custom_caddy "$DNS_PROVIDER"
install_binaries
write_environment
write_caddy_env
write_caddy_systemd_dropin
write_caddyfile
write_systemd_unit
write_healthcheck_script
write_healthcheck_units

systemctl daemon-reload
systemctl enable --now caddy sandboxd sandboxd-healthcheck.timer

echo "AerolVM installed"
echo "PAT token: $PAT_TOKEN"
echo "Use header: Authorization: Bearer <PAT token>"
if [[ -n "$DOMAIN" ]]; then
	echo "API URL: https://$DOMAIN"
	echo "Health URL: https://$DOMAIN/health"
	echo "Public sandbox URL pattern: https://<docker-short-id>.$DOMAIN"
	echo "TLS: wildcard DNS-01 via $DNS_PROVIDER (one cert covers all subdomains)"
	echo "TLS-SNI multiplexing: ENABLED on :443 (caddy-l4 routes by SNI)"
	echo "  Regular HTTPS sites moved to 127.0.0.1:8443; caddy-l4 forwards"
	echo "  unmatched SNI to that listener. exposeTLSPort() works out of the box."
else
	echo "API URL: http://$PUBLIC_HOST:21212"
	echo "Health URL: http://$PUBLIC_HOST:21212/health"
	echo "Public sandbox URL pattern: http://$PUBLIC_HOST/<docker-short-id>/"
fi
echo "TCP port pool: 22000-23000 (open these on the host firewall to publish native TCP ports)"
echo "  This range sits below the Linux ephemeral range (32768-60999) on purpose so the"
echo "  kernel never hands these out as outbound source ports — eliminates random EADDRINUSE"
echo "  failures on ExposeTCPPort. 1000 slots = max concurrent TCP exposures per host."
echo "systemd restart policy: always (5 second backoff, 10 restarts per 5 minutes)"
echo "Health watchdog: sandboxd-healthcheck.timer probes /health every 30 seconds"
