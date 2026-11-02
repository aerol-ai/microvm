#!/usr/bin/env bash

set -euo pipefail

DOMAIN=""
PUBLIC_HOST=""
PAT_TOKEN=""
INSTALL_PREFIX="/usr/local/bin"
INSTALL_PREFIX_EXPLICIT="false"
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
ACME_CA=""
ACME_CA_ROOT=""
TLS_ISSUER="acme"
CADDY_BUILD_URL_BASE="https://caddyserver.com/api/download"
# The stock Caddy package, which provides the caddy user, caddy.service and
# /etc/caddy; install_custom_caddy then swaps in the plugin build. It comes
# from Caddy's GitHub release, not the Cloudsmith apt repository: that
# answers 402 Payment Required whenever Cloudsmith's bandwidth quota runs
# out (2023, 2024, and from 2026-10-09), and then every install failed.
CADDY_PACKAGE_VERSION="2.11.7"
CADDY_PACKAGE_URL_BASE="https://github.com/caddyserver/caddy/releases/download"
CADDY_BINARY_URL=""
CADDY_BINARY_URL_EXPLICIT="false"
WITH_GVISOR="false"
RUNSC_PATH=""
WITH_ISOLATE="false"
# Routing without per-sandbox Caddy writes (plans/ingress-proxy-routing.md).
# Sets SB_INGRESS_PROXY_ROUTING and routes *.rt.internal to the sandboxd
# route responder via systemd-resolved.
INGRESS_PROXY_ROUTING="false"
ROUTE_DNS_ADDR="127.0.0.1:53053"
# The aerolvm-rt link's own address. systemd-resolved sends *.rt.internal
# here, not to ROUTE_DNS_ADDR (write_route_dns_resolver says why), and
# sandboxd listens here too (SB_ROUTE_DNS_LINK_ADDR).
ROUTE_DNS_LINK_IP="169.254.53.53"
ROUTE_DNS_LINK_ADDR="${ROUTE_DNS_LINK_IP}:53053"
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
# --cli-only installs just the aerolvm agent CLI: no daemon, Docker or root.
CLI_ONLY="false"
CLI_URL=""
NODE_NAME=""
PAT_TOKEN_EXPLICIT="false"
# macOS --local installs for the current user only — no sudo, nothing outside
# $HOME. Everything lives under one directory inside /Users, which Docker's
# Linux VM (OrbStack / Docker Desktop) shares with containers, so the Linux
# toolboxd bind-mounts into sandboxes from here (a /usr/local/bin path would
# arrive as an empty directory). sandboxd runs as a LaunchAgent.
DARWIN_HOME="$HOME/.aerolvm"
DARWIN_LAUNCH_AGENT="$HOME/Library/LaunchAgents/com.aerol.sandboxd.plist"

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

# Operator-token confinement and the real client address through Caddy
# (plans/identity-and-access.md §5.11). Both default off, so a default
# install writes exactly what it always did.
#   --pat-scope host     SB_PAT_SCOPE=host; Caddy proxies to the public
#                        Unix socket, where every request is public.
#   --l4-proxy-protocol  caddy-l4's fallback sends PROXY v2 to the 8443
#                        site, which gets the proxy_protocol listener
#                        wrapper; Caddy forwards the client address to
#                        sandboxd in X-AerolVM-Client-IP. Both halves are
#                        written in this one step: the flag without the
#                        wrapper breaks every HTTPS handshake.
PAT_SCOPE="any"
KEY_CUSTODY="file"
SECRET_PROVIDER_ENV=""
NO_START="false"
PUBLIC_API_SOCKET="/run/sandboxd-public/api.sock"
L4_PROXY_PROTOCOL="false"
# --lb-health-port: a plain-HTTP /health listener for a load balancer's
# health check (Terraform api_load_balancer = "nlb"). Empty writes none, so
# a default install opens no new port.
LB_HEALTH_PORT=""

# A re-run restarts a running sandboxd when it changed the daemon's settings
# file or unit (see restart_sandboxd_if_reconfigured). record_sandboxd_state
# fills the two state variables before anything is written.
SANDBOXD_ENV_FILE="/etc/sandboxd/sandboxd.env"
SANDBOXD_UNIT_FILE="/etc/systemd/system/sandboxd.service"
SANDBOXD_HEALTH_URL="http://127.0.0.1:21212/health"
SANDBOXD_READY_TRIES=60
SANDBOXD_WAS_ACTIVE="false"
SANDBOXD_CONFIG_BEFORE=""

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
  --acme-ca <url>              ACME directory to issue from instead of Let's
                               Encrypt: a bank PKI or step-ca on a network
                               with no route to the public CAs. Applies to
                               the wildcard certificates and to custom
                               domains (SB_TLS_ACME_CA). https only.
  --acme-ca-root <pem>         PEM file of roots to trust for --acme-ca
                               (SB_TLS_ACME_CA_ROOT). Absolute path.
  --tls-issuer <acme|internal> internal: Caddy's own CA issues every
                               certificate, for labs. No DNS provider is
                               needed; clients must trust Caddy's root.
                               Default acme.
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
  --ingress-proxy-routing      Route sandboxes without per-sandbox Caddy
                               writes (static routes + sandboxd route
                               responder; configures systemd-resolved for
                               *.rt.internal). Off by default.
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
  --pat-scope <any|host>       Where the operator token (PAT) works. "any"
                               (default) keeps today's behavior. "host"
                               accepts it only from this host
                               (127.0.0.1:21212) and from cluster peers, so
                               remote people must use SSO or a named token;
                               Caddy then proxies to the public socket
                               /run/sandboxd-public/api.sock. Enterprise
                               mode requires "host". Turn it on only after
                               every node runs a release that has it.
  --no-start                   Install and enable everything but leave sandboxd
                               stopped, for a node cluster-join.sh will start
                               once it has the cluster's config and server key.
                               Booting it before that, as a lone node, would
                               make a server key of its own. Not with --local.
  --key-custody <file|wrapped> "wrapped" keeps the server key only wrapped by
                               the customer's key store (AWS KMS, Vault or an
                               HSM): the first boot generates it and writes no
                               plaintext copy; a re-run over a plaintext key
                               wraps it. Needs --secret-provider-env.
                               (plans/customer-key-custody.md)
  --secret-provider-env <file> SB_SECRET_* lines naming the key store
                               (SB_SECRET_PROVIDER=awskms|vault|pkcs11 and its
                               settings), appended to sandboxd.env.
  --l4-proxy-protocol          Domain mode: send the real client address
                               from caddy-l4 to the HTTPS site (PROXY
                               protocol v2) and on to sandboxd, so audit
                               records and the "operator token used from
                               outside" alert see it instead of 127.0.0.1.
                               Writes the Caddy listener wrapper and
                               SB_L4_FALLBACK_PROXY_PROTOCOL=true together.
  --lb-health-port <port>      Domain mode: serve GET /health in plain HTTP
                               on <port> for a load balancer's health check.
                               It answers 200 only when the whole path a
                               client takes works (caddy-l4 on :443, the
                               HTTPS site and sandboxd), and 502 otherwise,
                               so the balancer drops this node while its
                               daemon is down. Open the port to the load
                               balancer only.
  --local                     Local development mode. The server binds to
                               127.0.0.1:21212 with no Caddy or TLS. Supported
                               on both macOS and Linux. No domain name required.
                               Linux: run with sudo; Docker Engine is installed
                               if missing and a systemd unit without a Caddy
                               dependency is used.
                               macOS: run WITHOUT sudo. Installs for the current
                               user into ~/.aerolvm and registers a LaunchAgent;
                               OrbStack or Docker Desktop must be running. Each
                               sandbox publishes only its toolbox port, on
                               127.0.0.1; every listener stays on 127.0.0.1.
  --cli-only                   Install only the aerolvm CLI (also an MCP
                               server: 'aerolvm mcp') on Linux or macOS. No
                               daemon, Docker or root needed; without root
                               it installs to ~/.local/bin unless
                               --install-prefix says otherwise. Ignores
                               every server option.
  --cli-url <url>              Download URL for the aerolvm binary
                               (--cli-only).
  --help                       Show this help

Examples:
	curl -fsSL https://aerolvm.aerol.ai | sudo bash -s -- --domain sandbox.example.com --pat-token my-pat-token
  ./scripts/install.sh --version v0.1.0 --public-host 203.0.113.42
	./scripts/install.sh --public-host 203.0.113.42 --pat-token dev-token --build-from-source
	curl -fsSL https://aerolvm.aerol.ai | bash -s -- --cli-only
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
	local toolbox_platform
	local release_base

	platform="$(detect_platform)"
	# toolboxd is the in-sandbox agent: it always runs inside a Linux
	# container (on macOS, Docker's Linux VM), so a darwin host still needs
	# the linux build of the same architecture.
	toolbox_platform="${platform/#darwin_/linux_}"
	release_base="https://github.com/${GITHUB_REPO}/releases"

	if [[ "$VERSION" == "latest" ]]; then
		SANDBOXD_URL="${SANDBOXD_URL:-${release_base}/latest/download/sandboxd_${platform}}"
		TOOLBOXD_URL="${TOOLBOXD_URL:-${release_base}/latest/download/toolboxd_${toolbox_platform}}"
		CHECKSUMS_URL="${CHECKSUMS_URL:-${release_base}/latest/download/checksums.txt}"
		CADDY_BINARY_URL="${CADDY_BINARY_URL:-${release_base}/latest/download/caddy_${platform}}"
	else
		SANDBOXD_URL="${SANDBOXD_URL:-${release_base}/download/${VERSION}/sandboxd_${platform}}"
		TOOLBOXD_URL="${TOOLBOXD_URL:-${release_base}/download/${VERSION}/toolboxd_${toolbox_platform}}"
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
		sha256_check selected-checksums.txt
	)
}

# sha256_check verifies a checksum file. macOS before 14 has no sha256sum,
# only shasum, and the --cli-only path runs there.
sha256_check() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -c "$1"
	else
		shasum -a 256 -c "$1"
	fi
}

# install_cli installs the aerolvm agent CLI alone
# (plans/mcp-server-and-agent-cli.md §5.8): the path for laptops and CI
# runners that drive a sandboxd running somewhere else.
install_cli() {
	local os
	local arch
	local dest
	os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	case "$os" in
		linux|darwin) ;;
		*)
			echo "--cli-only supports Linux and macOS; on Windows download aerolvm_windows_<arch>.exe from the release page" >&2
			exit 1
			;;
	esac
	case "$(uname -m)" in
		x86_64|amd64) arch="amd64" ;;
		aarch64|arm64) arch="arm64" ;;
		*)
			echo "aerolvm is released for amd64 and arm64, not $(uname -m)" >&2
			exit 1
			;;
	esac

	dest="$INSTALL_PREFIX"
	if [[ "$INSTALL_PREFIX_EXPLICIT" != "true" && $EUID -ne 0 && ! -w "$dest" ]]; then
		# One user-level binary is not worth a sudo prompt.
		dest="$HOME/.local/bin"
	fi
	mkdir -p "$dest"

	# Unlike the server path, "auto" builds from source only inside this
	# repo: piping the installer into bash from some other Go project must
	# not try to build ./cmd/aerolvm there.
	if [[ "$BUILD_FROM_SOURCE" == "true" || ( "$BUILD_FROM_SOURCE" == "auto" && -z "$CLI_URL" && -f ./go.mod && -d ./cmd/aerolvm ) ]]; then
		CGO_ENABLED=0 go build -trimpath -o "$dest/aerolvm" ./cmd/aerolvm
	else
		local release_base
		local asset
		local tmp_dir
		release_base="https://github.com/${GITHUB_REPO}/releases"
		if [[ "$VERSION" == "latest" ]]; then
			CLI_URL="${CLI_URL:-${release_base}/latest/download/aerolvm_${os}_${arch}}"
			CHECKSUMS_URL="${CHECKSUMS_URL:-${release_base}/latest/download/checksums.txt}"
		else
			CLI_URL="${CLI_URL:-${release_base}/download/${VERSION}/aerolvm_${os}_${arch}}"
			CHECKSUMS_URL="${CHECKSUMS_URL:-${release_base}/download/${VERSION}/checksums.txt}"
		fi
		asset="$(basename "${CLI_URL%%\?*}")"
		tmp_dir="$(mktemp -d)"
		download_asset "$CLI_URL" "$tmp_dir/$asset"
		verify_downloads "$tmp_dir" "$asset"
		install -m 0755 "$tmp_dir/$asset" "$dest/aerolvm"
		rm -rf "$tmp_dir"
	fi

	echo "aerolvm installed: $dest/aerolvm"
	case ":$PATH:" in
		*":$dest:"*) ;;
		*) echo "Add $dest to your PATH to run it as aerolvm." ;;
	esac
	echo "Point it at a sandboxd: aerolvm login <api url>"
	echo "Add it to an MCP client: aerolvm mcp config claude-code"
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
			PAT_TOKEN_EXPLICIT="true"
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
			INSTALL_PREFIX_EXPLICIT="true"
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
		--acme-ca)
			ACME_CA="$2"
			shift 2
			;;
		--acme-ca-root)
			ACME_CA_ROOT="$2"
			shift 2
			;;
		--tls-issuer)
			TLS_ISSUER="$2"
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
		--ingress-proxy-routing)
			INGRESS_PROXY_ROUTING="true"
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
		--cli-only)
			CLI_ONLY="true"
			shift
			;;
		--cli-url)
			CLI_URL="$2"
			shift 2
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
		--pat-scope)
			PAT_SCOPE="$2"
			shift 2
			;;
		--l4-proxy-protocol)
			L4_PROXY_PROTOCOL="true"
			shift
			;;
		--lb-health-port)
			LB_HEALTH_PORT="$2"
			shift 2
			;;
		--key-custody)
			KEY_CUSTODY="$2"
			shift 2
			;;
		--no-start)
			NO_START="true"
			shift
			;;
		--secret-provider-env)
			SECRET_PROVIDER_ENV="$2"
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

if [[ "$CLI_ONLY" == "true" ]]; then
	install_cli
	exit 0
fi

if [[ "$NO_START" == "true" && "$LOCAL_MODE" == "true" ]]; then
	echo "--no-start is for a node cluster-join.sh will start; --local never joins a cluster" >&2
	exit 1
fi

case "$KEY_CUSTODY" in
	file) ;;
	wrapped)
		if [[ "$LOCAL_MODE" == "true" ]]; then
			echo "--key-custody wrapped is not supported with --local" >&2
			exit 1
		fi
		if [[ -z "$SECRET_PROVIDER_ENV" || ! -f "$SECRET_PROVIDER_ENV" ]]; then
			echo "--key-custody wrapped needs --secret-provider-env <file> with SB_SECRET_PROVIDER and its settings" >&2
			exit 1
		fi
		if ! grep -Eq '^SB_SECRET_PROVIDER=(awskms|vault|pkcs11)$' "$SECRET_PROVIDER_ENV"; then
			echo "$SECRET_PROVIDER_ENV must set SB_SECRET_PROVIDER to awskms, vault or pkcs11" >&2
			exit 1
		fi
		;;
	*)
		echo "--key-custody must be file or wrapped (got $KEY_CUSTODY)" >&2
		exit 1
		;;
esac

if [[ -z "$PAT_TOKEN" ]]; then
	if command -v openssl >/dev/null 2>&1; then
		PAT_TOKEN="$(openssl rand -hex 24)"
	else
		echo "--pat-token is required when openssl is unavailable" >&2
		exit 1
	fi
fi

if [[ -z "$PUBLIC_HOST" ]]; then
	# macOS hostname has no -I; under pipefail the failed pipeline would
	# exit the script silently, so fall through to the default instead.
	PUBLIC_HOST="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
	PUBLIC_HOST="${PUBLIC_HOST:-127.0.0.1}"
fi

# Host path of the toolboxd binary bind-mounted into every sandbox.
TOOLBOX_BINARY_PATH="$INSTALL_PREFIX/toolboxd"
if [[ "$(uname -s)" == "Darwin" ]]; then
	if [[ "$INSTALL_PREFIX" == "/usr/local/bin" ]]; then
		INSTALL_PREFIX="$DARWIN_HOME/bin"
	fi
	TOOLBOX_BINARY_PATH="$DARWIN_HOME/toolbox/toolboxd"
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
# Certificates from an internal CA (plans/egress-domain-filtering.md §5.10
# PC-5): a private network can't reach Let's Encrypt. Checked here so a typo
# fails the install, not the first issuance.
case "$TLS_ISSUER" in
acme | internal) ;;
*)
	echo "--tls-issuer must be acme or internal, got '$TLS_ISSUER'." >&2
	exit 1
	;;
esac
if [[ "$TLS_ISSUER" != "acme" || -n "$ACME_CA" || -n "$ACME_CA_ROOT" ]] && [[ -z "$DOMAIN" ]]; then
	echo "--tls-issuer, --acme-ca and --acme-ca-root need --domain (there is no TLS without one)." >&2
	exit 1
fi
if [[ "$TLS_ISSUER" == "internal" && (-n "$ACME_CA" || -n "$ACME_CA_ROOT") ]]; then
	echo "--acme-ca and --acme-ca-root don't apply with --tls-issuer internal." >&2
	exit 1
fi
if [[ -n "$ACME_CA" && "$ACME_CA" != https://* ]]; then
	echo "--acme-ca must be an https ACME directory URL, got '$ACME_CA'." >&2
	exit 1
fi
if [[ -n "$ACME_CA_ROOT" && ("$ACME_CA_ROOT" != /* || ! -f "$ACME_CA_ROOT") ]]; then
	echo "--acme-ca-root must be an absolute path to an existing PEM file, got '$ACME_CA_ROOT'." >&2
	exit 1
fi

# Caddy's internal CA needs no DNS-01: it issues without a challenge.
if [[ -n "$DOMAIN" && -z "$DNS_PROVIDER" && "$TLS_ISSUER" != "internal" ]]; then
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
if [[ -n "$DNS_PROVIDER" || (-n "$DOMAIN" && "$TLS_ISSUER" == "internal") ]]; then
	L4_TLS_LISTEN_DEFAULT=":443"
else
	L4_TLS_LISTEN_DEFAULT=""
fi

case "$PAT_SCOPE" in
any | host) ;;
*)
	echo "--pat-scope must be any or host, got '$PAT_SCOPE'." >&2
	exit 1
	;;
esac
# PROXY protocol rides caddy-l4's SNI fallback to the 8443 site, which only
# exists in domain mode.
if [[ "$L4_PROXY_PROTOCOL" == "true" && -z "$L4_TLS_LISTEN_DEFAULT" ]]; then
	echo "--l4-proxy-protocol requires domain mode (--domain with --dns-provider, or --tls-issuer internal)." >&2
	exit 1
fi
# The load-balancer health listener probes through caddy-l4 on :443, which
# only exists in domain mode. Its port must not be one this node already
# listens on, or Caddy fails to start and takes the API down with it.
if [[ -n "$LB_HEALTH_PORT" ]]; then
	if [[ -z "$L4_TLS_LISTEN_DEFAULT" ]]; then
		echo "--lb-health-port requires domain mode (--domain with --dns-provider, or --tls-issuer internal)." >&2
		exit 1
	fi
	if ! [[ "$LB_HEALTH_PORT" =~ ^[1-9][0-9]{3,4}$ ]] || ((LB_HEALTH_PORT > 65535)); then
		echo "--lb-health-port must be a port from 1024 to 65535, got '$LB_HEALTH_PORT'." >&2
		exit 1
	fi
	case "$LB_HEALTH_PORT" in
	2019 | 2220 | 7000 | 7001 | 7002 | 8443 | 21212 | 21215 | 53053)
		echo "--lb-health-port $LB_HEALTH_PORT is already used on this node (Caddy admin, SSH gateway, cluster, HTTPS site, API, host-port redirect or route DNS)." >&2
		exit 1
		;;
	esac
	if ((LB_HEALTH_PORT >= 22000 && LB_HEALTH_PORT <= 23000)); then
		echo "--lb-health-port $LB_HEALTH_PORT is inside the raw-TCP port pool (22000-23000)." >&2
		exit 1
	fi
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

# drop_caddy_apt_source removes the Cloudsmith apt source earlier installers
# added. While that repository answers 402, every apt-get update on the host
# fails with it in place, so re-running this installer (an upgrade) failed
# too. An apt upgrade from it would also replace the plugin build with stock
# Caddy, losing layer4.
drop_caddy_apt_source() {
	rm -f /etc/apt/sources.list.d/caddy-stable.list /usr/share/keyrings/caddy-stable-archive-keyring.gpg
}

# install_caddy_package installs the stock Caddy .deb from Caddy's GitHub
# release, checked against the release's SHA-512 list. It is the same
# package Cloudsmith served: its postinst creates the caddy user, and it
# ships caddy.service and /etc/caddy, which the rest of this installer
# builds on.
install_caddy_package() {
	local arch
	case "$(uname -m)" in
		x86_64|amd64)  arch="amd64" ;;
		aarch64|arm64) arch="arm64" ;;
		armv7l|armv7)  arch="armv7" ;;
		armv6l|armv6)  arch="armv6" ;;
		*)
			echo "No Caddy package for architecture $(uname -m)" >&2
			exit 1
			;;
	esac
	local base="${CADDY_PACKAGE_URL_BASE}/v${CADDY_PACKAGE_VERSION}"
	local asset="caddy_${CADDY_PACKAGE_VERSION}_linux_${arch}.deb"
	local sums="caddy_${CADDY_PACKAGE_VERSION}_checksums.txt"
	local tmp_dir
	tmp_dir="$(mktemp -d)"
	if ! curl_download "${base}/${asset}" -o "${tmp_dir}/${asset}" \
		|| ! curl_download "${base}/${sums}" -o "${tmp_dir}/${sums}"; then
		rm -rf "$tmp_dir"
		echo "Failed to download the Caddy ${CADDY_PACKAGE_VERSION} package" >&2
		exit 1
	fi
	if ! (
		cd "$tmp_dir" \
			&& awk -v name="$asset" '$2 == name { print }' "$sums" > selected-checksum.txt \
			&& [[ "$(wc -l < selected-checksum.txt)" -eq 1 ]] \
			&& sha512sum -c selected-checksum.txt
	); then
		rm -rf "$tmp_dir"
		echo "Caddy package checksum verification failed; refusing to install it" >&2
		exit 1
	fi
	apt-get install -y "${tmp_dir}/${asset}"
	rm -rf "$tmp_dir"
}

# APT_UPDATED is "true" once this run has refreshed the apt package index,
# so install_mount_tools refreshes it only on the --local path, where
# install_packages (and its apt-get update) does not run.
APT_UPDATED="false"

# rpcbind_on_host is true when the rpcbind package is installed, or a unit
# of an rpcbind installed some other way is enabled.
rpcbind_on_host() {
	if [[ "$(dpkg-query -W -f='${Status}' rpcbind 2>/dev/null || true)" == "install ok installed" ]]; then
		return 0
	fi
	command -v systemctl >/dev/null 2>&1 || return 1
	systemctl is-enabled --quiet rpcbind.socket 2>/dev/null || systemctl is-enabled --quiet rpcbind.service 2>/dev/null
}

# install_mount_tools installs the programs that mount external storage and
# platform volumes. The mount runs on the host, not in the sandbox, so
# sandboxd needs them on its own PATH. Both Linux install paths call it:
# --local skips install_packages, and a local server used to fail every
# volume create with `exec: "mount-s3": executable file not found`. A tool
# that will not install costs only its own mount type, so nothing here fails
# the install.
install_mount_tools() {
	if [[ "$(uname -s)" != "Linux" ]]; then
		echo "Skipping the mount tools (fuse3, sshfs, nfs-common, rclone, mount-s3): Linux only" >&2
		return 0
	fi
	if ! command -v apt-get >/dev/null 2>&1; then
		echo "Warning: only apt-based distributions get the mount tools from this installer; install fuse3, sshfs, nfs-common, rclone and mount-s3 by hand for external storage and platform volumes" >&2
		return 0
	fi
	if [[ "${APT_UPDATED:-false}" != "true" ]]; then
		if apt-get update; then
			APT_UPDATED="true"
		else
			echo "Warning: apt-get update failed; installing the mount tools from the existing package index" >&2
		fi
	fi
	# nfs-common depends on rpcbind (the RPC portmapper), whose package
	# enables and starts it on port 111 on every address: a finding in any
	# port scan. The NFS client needs it only for an NFSv3 mount that locks,
	# and then mount.nfs starts rpc-statd.service, which Requires=
	# rpcbind.socket and so starts it on demand. So it is disabled, not
	# masked: a mask fails that start, and with it every such mount. A host
	# that had rpcbind before this run keeps it as it was; it may be in use.
	local rpcbind_before="false"
	if rpcbind_on_host; then
		rpcbind_before="true"
	fi
	# fuse3 is required by mountpoint-s3, sshfs, and rclone mount.
	# nfs-common provides mount.nfs. mountpoint-s3 ships as a .deb from AWS;
	# we attempt an apt install first and fall back to the AWS download.
	apt-get install -y fuse3 sshfs nfs-common rclone || true
	if [[ "$rpcbind_before" == "true" ]]; then
		echo "rpcbind was on this host before this run; leaving it as it is" >&2
	elif ! command -v systemctl >/dev/null 2>&1; then
		echo "Skipping the rpcbind disable: no systemctl on this host" >&2
	elif rpcbind_on_host; then
		systemctl disable --now rpcbind.socket rpcbind.service || \
			echo "Warning: could not disable rpcbind, so it may listen on port 111; run: systemctl disable --now rpcbind.socket rpcbind.service" >&2
	fi
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
}

install_packages() {
	if command -v apt-get >/dev/null 2>&1; then
		drop_caddy_apt_source
		apt-get update
		APT_UPDATED="true"
		apt-get install -y build-essential ca-certificates curl gnupg lsb-release software-properties-common
		# Mount tooling for the host-managed external storage feature.
		install_mount_tools
		ensure_docker
		if ! command -v caddy >/dev/null 2>&1; then
			install_caddy_package
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
	mkdir -p "$INSTALL_PREFIX" "$(dirname "$TOOLBOX_BINARY_PATH")"
	if [[ "$BUILD_FROM_SOURCE" == "true" ]]; then
		if [[ "$(uname -s)" == "Darwin" ]]; then
			# sandboxd runs on the Mac; toolboxd runs in Linux containers.
			local goarch
			goarch="$(detect_platform)"
			goarch="${goarch#*_}"
			make build-sandboxd
			GOOS=linux GOARCH="$goarch" make build-toolboxd
		else
			make build
		fi
		install -m 0755 ./bin/sandboxd "$INSTALL_PREFIX/sandboxd"
		install -m 0755 ./bin/toolboxd "$TOOLBOX_BINARY_PATH"
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
		install -m 0755 "$tmp_dir/$toolboxd_asset" "$TOOLBOX_BINARY_PATH"
		rm -rf "$tmp_dir"
	fi
}

write_environment() {
	mkdir -p /etc/sandboxd /var/lib/sandboxd /var/lib/sandboxd/mounts /run/sandboxd
	chmod 0700 /var/lib/sandboxd /var/lib/sandboxd/mounts /run/sandboxd
	local route_dns_link_addr=""
	if [[ "$INGRESS_PROXY_ROUTING" == "true" ]]; then
		route_dns_link_addr="$ROUTE_DNS_LINK_ADDR"
	fi
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
SB_INGRESS_PROXY_ROUTING=$INGRESS_PROXY_ROUTING
SB_ROUTE_DNS_ADDR=$ROUTE_DNS_ADDR
SB_ROUTE_DNS_LINK_ADDR=$route_dns_link_addr
SB_L4_TLS_FALLBACK=127.0.0.1:8443
EOF
	# The custom-domain certificate policy sandboxd installs follows the
	# same issuer as the Caddyfile (§5.10 PC-5).
	if [[ -n "$ACME_CA" ]]; then
		echo "SB_TLS_ACME_CA=$ACME_CA" >> /etc/sandboxd/sandboxd.env
	fi
	if [[ -n "$ACME_CA_ROOT" ]]; then
		echo "SB_TLS_ACME_CA_ROOT=$ACME_CA_ROOT" >> /etc/sandboxd/sandboxd.env
	fi
	if [[ "$TLS_ISSUER" != "acme" ]]; then
		echo "SB_TLS_ISSUER=$TLS_ISSUER" >> /etc/sandboxd/sandboxd.env
	fi
	# Written only when asked for, so a default install's env is unchanged.
	# write_caddyfile writes the matching Caddy half in the same run.
	if [[ "$PAT_SCOPE" == "host" ]]; then
		{
			echo "SB_PAT_SCOPE=host"
			echo "SB_PUBLIC_API_SOCKET=$PUBLIC_API_SOCKET"
		} >> /etc/sandboxd/sandboxd.env
	fi
	if [[ "$L4_PROXY_PROTOCOL" == "true" ]]; then
		echo "SB_L4_FALLBACK_PROXY_PROTOCOL=true" >> /etc/sandboxd/sandboxd.env
	fi
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
		# The jail drops each workerd group process to a dedicated system
		# user. The daemon's default (uid/gid 1000) is the first login user on
		# most images — on AWS Ubuntu that is `ubuntu`, with sudo — so give the
		# jail an identity that owns nothing and can log in nowhere.
		if ! getent passwd sandboxd-isolate >/dev/null 2>&1; then
			useradd --system --no-create-home --shell /usr/sbin/nologin --user-group sandboxd-isolate
		fi
		ISOLATE_JAIL_UID="$(id -u sandboxd-isolate)"
		ISOLATE_JAIL_GID="$(id -g sandboxd-isolate)"
		{
			echo "SB_ISOLATE_JAIL_UID=${ISOLATE_JAIL_UID}"
			echo "SB_ISOLATE_JAIL_GID=${ISOLATE_JAIL_GID}"
			echo "SB_ISOLATE_JAIL_CHROOT_BASE=/srv/isolate-jail"
			echo "SB_ISOLATE_JAIL_CGROUP_ROOT=/sys/fs/cgroup/aerolvm-isolate"
		} >> /etc/sandboxd/sandboxd.env
		install -d -m 0755 /srv/isolate-jail
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
	# The S3 audit witness (plans/open-audit-witness.md) is documented here and
	# never configured. It needs an Object Lock bucket, and the lock mode,
	# retention and IAM are the operator's decisions; in compliance mode nobody
	# can delete what the bucket holds until the lock ends, so an installer
	# that created one would leave an undeletable bucket nobody chose. The
	# lines are comments, so the daemon behaves exactly as before.
	cat >> /etc/sandboxd/sandboxd.env <<'EOF'

# S3 Object Lock audit witness: off while these lines stay commented out.
# Keeps each audit hash-chain head in a locked bucket off this server, so a
# later compromise cannot rewrite the audit history unnoticed. The bucket
# needs Object Lock, versioning, a default retention of at least
# SB_SECRET_AUDIT_RETENTION_DAYS (30), and a role that includes s3:ListBucket.
# sandboxd checks all of this at boot and refuses to start if one is missing.
# Recipe: setup/runbooks/secrets-and-audit.md, "S3 audit witness".
# SB_NODE_ID is required with a witness and must be unique among servers
# sharing the bucket; the default id, "standalone", is refused.
# Re-running install.sh rewrites this file, so keep a copy of these settings.
#SB_NODE_ID=
#SB_AUDIT_WITNESS_BACKEND=s3
#SB_AUDIT_WITNESS_S3_BUCKET=
#SB_AUDIT_WITNESS_S3_PREFIX=witness/
#SB_AUDIT_WITNESS_S3_REGION=
#SB_AUDIT_WITNESS_S3_ENDPOINT=
#SB_AUDIT_WITNESS_S3_PATH_STYLE=false
EOF
	if [[ "$KEY_CUSTODY" == "wrapped" ]]; then
		{
			echo "# Key custody (plans/customer-key-custody.md): the server key exists"
			echo "# only wrapped by the key store below; see sandboxd key status."
			# AWS_REGION too: the AWS KMS client needs it, and the SDK's
			# IMDS fallback turns a missing region into an opaque timeout.
			grep -E '^(SB_SECRET_[A-Z0-9_]+|AWS_REGION)=' "$SECRET_PROVIDER_ENV"
			echo "SB_CREDENTIAL_KEY_CUSTODY=wrapped"
		} >> /etc/sandboxd/sandboxd.env
	fi
	chmod 0600 /etc/sandboxd/sandboxd.env
}

# prepare_key_custody wraps a plaintext server key left by an earlier
# install, so the daemon (which refuses wrapped custody while a plaintext
# key file exists) starts. A fresh install has no key: the first boot
# generates it and writes only the wrapped file.
prepare_key_custody() {
	[[ "$KEY_CUSTODY" == "wrapped" ]] || return 0
	local plain=/var/lib/sandboxd/credential_encryption.key
	local wrapped=/var/lib/sandboxd/credential_encryption.key.wrapped
	if [[ -f "$plain" && ! -f "$wrapped" ]]; then
		echo "Wrapping the existing server key at $plain"
		"$INSTALL_PREFIX/sandboxd" key wrap --env-file /etc/sandboxd/sandboxd.env
		# Not a secure delete; `sandboxd key status` reports the migration
		# until `sandboxd key ack-migration`.
		rm -f "$plain"
	elif [[ -f "$plain" && -f "$wrapped" ]]; then
		"$INSTALL_PREFIX/sandboxd" key verify --env-file /etc/sandboxd/sandboxd.env
		rm -f "$plain"
	fi
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
	# An internal ACME CA (--acme-ca) issues the wildcard certificates as
	# well as custom domains; sandboxd sets the same CA on the on-demand
	# policy it installs (SB_TLS_ACME_CA). --tls-issuer internal skips ACME.
	if [[ -n "$ACME_CA" ]]; then
		email_line+=$'\n\tacme_ca '"$ACME_CA"
	fi
	if [[ -n "$ACME_CA_ROOT" ]]; then
		email_line+=$'\n\tacme_ca_root '"$ACME_CA_ROOT"
	fi
	local tls_block=$'\ttls {\n\t\tdns '"$DNS_PROVIDER"$' {env.SB_DNS_API_TOKEN}\n\t}'
	if [[ "$TLS_ISSUER" == "internal" ]]; then
		tls_block=$'\ttls internal'
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
	# --pat-scope host: Caddy reaches sandboxd on the public socket, where
	# every request is public, instead of on 127.0.0.1:21212, where a
	# loopback peer may present the operator token.
	local api_upstream="127.0.0.1:21212"
	if [[ "$PAT_SCOPE" == "host" ]]; then
		api_upstream="unix/${PUBLIC_API_SOCKET}"
	fi
	# --l4-proxy-protocol: the 8443 server accepts the PROXY v2 header
	# caddy-l4's fallback sends (only from 127.0.0.1; a connection with no
	# header is still accepted, so this half can land first), and the API
	# proxy stamps the client address it learned. {remote_host} replaces
	# whatever the client sent in that header, so it cannot be forged.
	local servers_block=""
	local client_ip_line=""
	if [[ "$L4_PROXY_PROTOCOL" == "true" ]]; then
		servers_block=$'\n\tservers 127.0.0.1:8443 {\n\t\tlistener_wrappers {\n\t\t\tproxy_protocol {\n\t\t\t\tallow 127.0.0.1/32\n\t\t\t}\n\t\t\ttls\n\t\t}\n\t}'
		client_ip_line=$'\n\t\t\theader_up X-AerolVM-Client-IP {remote_host}'
	fi
	cat > /etc/caddy/Caddyfile <<EOF
{
	admin localhost:2019${email_line}
	# caddy-l4 owns :443; the HTTPS sites below run on 127.0.0.1:8443 and
	# only receive traffic forwarded from caddy-l4's SNI fallback route.
	# Disable Caddy's auto-managed :80 -> :443 redirect since :443 isn't ours.
	auto_https disable_redirects${storage_block}${servers_block}
}

https://$DOMAIN:8443 {
	bind 127.0.0.1
${tls_block}
	@api path /health /v1 /v1/* /daytona /daytona/* /e2b /e2b/* /runloop /runloop/* /mcp /ui /ui/* /.well-known/aerolvm-auth /.well-known/oauth-protected-resource*
	handle @api {
		# stream_close_delay: every admin-API change reloads Caddy, and a
		# reload closes each WebSocket this proxy carries (exec streams,
		# aerolvm shell, session attach) with code 1001 unless a delay is set
		# (#712). A stream that outlives a reload keeps the old config in
		# memory until it closes or the delay ends. pkg/caddy sets the same
		# value on the routes sandboxd writes.
		reverse_proxy ${api_upstream} {
			stream_close_delay 10m${client_ip_line}
		}
	}
	handle {
		respond "Sandbox API not found" 404
	}
}

https://*.$DOMAIN:8443 {
	bind 127.0.0.1
${tls_block}
	# close: caddy-l4 picks a backend once per TCP connection, so a client
	# that connected before its sandbox's route existed would otherwise keep
	# reusing a connection pinned to this 404. Closing makes its next attempt
	# dial again and be routed afresh.
	respond "Sandbox not found" 404 {
		close
	}
}
EOF
	if [[ -n "$LB_HEALTH_PORT" ]]; then
		cat >> /etc/caddy/Caddyfile <<EOF

# Load-balancer health listener (--lb-health-port). Plain HTTP, so keep the
# port closed to everything but the balancer (Terraform opens it to the
# balancer's security group only). GET /health walks the path a client
# takes: caddy-l4 on :443, its SNI fallback, the HTTPS API site and
# sandboxd. Any of them down answers 502, and the balancer stops sending
# this node new connections. Bound to every address: Caddy numbers its
# servers by sorted listen address, so ":${LB_HEALTH_PORT}" sorts after
# "127.0.0.1:8443" and the API site stays srv0, where sandboxd writes routes.
http://:${LB_HEALTH_PORT} {
	handle /health {
		reverse_proxy https://127.0.0.1:443 {
			# The balancer's probe carries its own address as Host and no
			# SNI. Send the API site's name in both, or the probe matches
			# no site and Caddy answers an empty 200 with sandboxd down.
			header_up Host ${DOMAIN}
			# Required on every reverse_proxy here; the probe holds no stream.
			stream_close_delay 10m
			transport http {
				tls_server_name ${DOMAIN}
				# A loopback hop to this same Caddy: the probe checks that
				# the handshake works (certificate loaded), not who answers.
				tls_insecure_skip_verify
			}
		}
	}
	handle {
		respond 404
	}
}
EOF
	fi
}

write_caddy_env() {
	if [[ -z "$DNS_PROVIDER" && "$CADDY_STORAGE_S3" != "true" ]]; then
		return
	fi
	# The stock Caddy debian unit does NOT load
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

# write_route_dns_resolver routes the ingress zone (and ONLY that zone) to the
# sandboxd route responder. caddy-l4 dials "{sni}.rt.internal" through the
# system resolver; sandboxd refuses SB_INGRESS_PROXY_ROUTING at boot if this
# routing is missing (routedns.ProbeName), so a half-configured node stays on
# the per-sandbox route path.
#
# WHY a dedicated dummy link, not a resolved.conf.d drop-in: DNS servers in
# resolved's GLOBAL section serve every name, and Domains=~rt.internal there
# does not restrict them. The responder then answered general lookups, and
# Caddy's ACME zone detection broke ("expected 1 zone, got 0"), so no cert
# issued (found live on cluster-3-mixed-routing). Per-link DNS with
# DNSDefaultRoute=false is used ONLY for the link's routing domains.
#
# The link needs an address and no IPv6 autoconf, or networkd leaves it in
# "configuring" and resolved ignores its DNS settings. Requires
# systemd-networkd and systemd >= 249 (ActivationPolicy, DNS=ip:port).
#
# WHY the DNS server is the link's own address, not the loopback responder:
# resolved pins its socket for a link's DNS server to that link
# (IP_UNICAST_IF), so a UDP query to 127.0.0.1 leaves through the dummy link
# and is dropped. resolved then stalls every lookup for about 20s while it
# falls back to TCP, and it re-probes UDP every few minutes and stalls again.
# Each stall failed new connections through the ingress with EOF
# (cluster-bank-flagship UC-171, 2026-11-01). A query to the link's own
# address is delivered locally, and sandboxd answers there.
route_dns_network_unit() {
	cat <<EOF
[Match]
Name=aerolvm-rt

[Link]
RequiredForOnline=no
ActivationPolicy=always-up

[Network]
ConfigureWithoutCarrier=yes
DNS=$ROUTE_DNS_LINK_ADDR
Domains=~rt.internal
DNSDefaultRoute=false
Address=$ROUTE_DNS_LINK_IP/32
LinkLocalAddressing=no
IPv6AcceptRA=no
EOF
}

write_route_dns_resolver() {
	if [[ "$INGRESS_PROXY_ROUTING" != "true" ]]; then
		return
	fi
	# An earlier build wrote a global drop-in; it must go (see above).
	if [[ -f /etc/systemd/resolved.conf.d/aerolvm-route-dns.conf ]]; then
		rm -f /etc/systemd/resolved.conf.d/aerolvm-route-dns.conf
	fi
	if ! systemctl is-active --quiet systemd-networkd || ! systemctl is-active --quiet systemd-resolved; then
		echo "WARNING: --ingress-proxy-routing needs systemd-networkd + systemd-resolved to scope *.rt.internal;" >&2
		echo "         not configuring it. sandboxd will refuse the flag at boot and keep per-sandbox Caddy routes." >&2
		return
	fi
	mkdir -p /etc/systemd/network
	cat > /etc/systemd/network/10-aerolvm-rt.netdev <<'EOF'
[NetDev]
Name=aerolvm-rt
Kind=dummy
EOF
	route_dns_network_unit > /etc/systemd/network/10-aerolvm-rt.network
	systemctl restart systemd-networkd
	systemctl restart systemd-resolved
	local i
	for i in $(seq 1 30); do
		if resolvectl status aerolvm-rt 2>/dev/null | grep -q "Current Scopes: DNS"; then
			return
		fi
		sleep 1
	done
	echo "WARNING: aerolvm-rt never got a DNS scope; sandboxd will refuse --ingress-proxy-routing at boot." >&2
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

# sandboxd_config_fingerprint identifies the two files a running sandboxd
# read when it started and install.sh rewrites: its settings file and its
# unit. cksum, not sha256sum, because it is POSIX; it only has to notice a
# change. On a fresh install neither file exists yet, and under pipefail a
# failing cat would abort the install, hence the `|| true`.
sandboxd_config_fingerprint() {
	{ cat "$SANDBOXD_ENV_FILE" "$SANDBOXD_UNIT_FILE" 2>/dev/null || true; } | cksum | cut -d' ' -f1-2
}

# record_sandboxd_state notes, before any file is written, whether sandboxd
# is running and what its settings were.
record_sandboxd_state() {
	SANDBOXD_WAS_ACTIVE="false"
	if systemctl is-active --quiet sandboxd 2>/dev/null; then
		SANDBOXD_WAS_ACTIVE="true"
	fi
	SANDBOXD_CONFIG_BEFORE="$(sandboxd_config_fingerprint)"
}

# wait_for_sandboxd_ready waits until sandboxd answers /health and, under
# --pat-scope host, has made the public socket Caddy proxies to.
wait_for_sandboxd_ready() {
	local try
	for ((try = 0; try < SANDBOXD_READY_TRIES; try++)); do
		if curl -fsS --max-time 2 -o /dev/null "$SANDBOXD_HEALTH_URL" 2>/dev/null &&
			{ [[ "$PAT_SCOPE" != "host" ]] || [[ -S "$PUBLIC_API_SOCKET" ]]; }; then
			return 0
		fi
		sleep 1
	done
	return 1
}

# restart_sandboxd_if_reconfigured restarts sandboxd when it was running
# before this run and the run changed its settings file or unit.
# `systemctl enable --now` only starts a stopped unit, so before this a
# re-run left the old process on its old settings. Under --pat-scope host
# that was an outage: Caddy, restarted onto the public socket, proxied to a
# socket the old process never made. It runs before Caddy starts, and waits
# for the restarted sandboxd (and its socket) so Caddy never points at a
# socket that is not there yet. A fresh install, a stopped unit or a run
# that changed nothing is left to `enable --now`, as before.
restart_sandboxd_if_reconfigured() {
	if [[ "$SANDBOXD_WAS_ACTIVE" != "true" ]]; then
		return 0
	fi
	if [[ "$(sandboxd_config_fingerprint)" == "$SANDBOXD_CONFIG_BEFORE" ]]; then
		return 0
	fi
	echo "sandboxd settings changed; restarting sandboxd before Caddy"
	systemctl restart sandboxd
	if ! wait_for_sandboxd_ready; then
		echo "warning: sandboxd is not answering ${SANDBOXD_HEALTH_URL} (or has not made ${PUBLIC_API_SOCKET}) ${SANDBOXD_READY_TRIES}s after its restart; starting Caddy anyway. Check: journalctl -u sandboxd" >&2
	fi
}

write_healthcheck_script() {
	cat > "$INSTALL_PREFIX/sandboxd-healthcheck" <<'EOF'
#!/usr/bin/env bash
# sandboxd-healthcheck: run by sandboxd-healthcheck.timer every 30 s.
#
# It restarts sandboxd only when the process has stopped answering, never
# because it is busy. A restart kills every request in flight on the node,
# so on the bank flagship (2026-11-01) restarting an overloaded node after
# one slow /health turned overload into an outage. Hence:
#   - it probes the liveness socket, which the daemon answers from its own
#     listener with no I/O and no lock (pkg/daemon/liveness.go), not
#     /health, which reads the store and pings the engines;
#   - it restarts only after FAILS_TO_RESTART failed probes in a row of one
#     run of the daemon (its InvocationID), the first and the last at least
#     FAIL_WINDOW_SECONDS apart; the streak is kept between timer runs;
#   - it never restarts a daemon younger than BOOT_GRACE_SECONDS, nor while
#     a start, stop or restart of the unit is already under way, and it
#     asks systemd for the restart without waiting for it, so its next run
#     sees the restart in progress instead of probing a half-booted daemon.

set -euo pipefail

ENV_FILE="/etc/sandboxd/sandboxd.env"
if [[ -f "$ENV_FILE" ]]; then
	# shellcheck source=/dev/null
	source "$ENV_FILE"
fi

UNIT="sandboxd.service"
STATE_DIR="${SANDBOXD_HEALTHCHECK_STATE_DIR:-/run/sandboxd-healthcheck}"
STATE_FILE="$STATE_DIR/streak"
LIVENESS_SOCKET="${SB_LIVENESS_SOCKET:-/run/sandboxd/live.sock}"
FAILS_TO_RESTART=3
FAIL_WINDOW_SECONDS=90
BOOT_GRACE_SECONDS=120
PROBE_TIMEOUT_SECONDS=10

log() {
	logger -t sandboxd-healthcheck "$*"
}

clear_streak() {
	rm -f "$STATE_FILE"
}

unit_prop() {
	systemctl show -p "$1" --value "$UNIT" 2>/dev/null || true
}

mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"
# One watchdog at a time: a manual run beside the timer's must not ask for
# a second restart.
if command -v flock >/dev/null 2>&1; then
	exec 9>"$STATE_DIR/lock"
	flock -n 9 || exit 0
fi

# systemd stops restarting a unit that failed StartLimitBurst times within
# StartLimitIntervalSec. A node whose key store was unreachable at boot
# (wrapped server-key custody) fails that way and would stay down after the
# key store came back, so a failed unit is reset and started again here,
# every run of this timer. A unit an operator stopped is inactive, not
# failed, and is left alone.
if systemctl is-failed --quiet "$UNIT"; then
	log "sandboxd.service is failed; resetting it and starting it again"
	clear_streak
	systemctl reset-failed "$UNIT"
	systemctl start "$UNIT" || true
	exit 0
fi

# inactive: stopped by an operator. activating, deactivating, reloading: a
# start, stop or restart is already under way. Neither is ours to touch.
if [[ "$(unit_prop ActiveState)" != "active" ]]; then
	clear_streak
	exit 0
fi
# A job queued on the unit (a restart someone already asked for) is under
# way too: never stack a second restart on it.
if [[ -n "$(systemctl list-jobs --no-legend "$UNIT" 2>/dev/null || true)" ]]; then
	exit 0
fi
invocation="$(unit_prop InvocationID)"
main_pid="$(unit_prop MainPID)"

probe() {
	if [[ -S "$LIVENESS_SOCKET" ]]; then
		curl -fsS --max-time "$PROBE_TIMEOUT_SECONDS" --unix-socket "$LIVENESS_SOCKET" "http://localhost/livez" >/dev/null
		return
	fi
	# A daemon older than the liveness socket, or one run with
	# SB_LIVENESS_SOCKET=off: /health is the only signal it has.
	curl -fsS --max-time "$PROBE_TIMEOUT_SECONDS" "http://127.0.0.1:${SB_API_PORT:-21212}/health" >/dev/null
}

if probe; then
	clear_streak
	exit 0
fi

now="$(date +%s)"
streak_invocation=""
fails=0
first=0
if [[ -f "$STATE_FILE" ]]; then
	read -r streak_invocation fails first <"$STATE_FILE" || true
fi
# Failures of an earlier run of the daemon say nothing about this one.
if [[ "$streak_invocation" != "$invocation" || ! "$fails" =~ ^[0-9]+$ || ! "$first" =~ ^[0-9]+$ ]]; then
	fails=0
	first="$now"
fi
fails=$((fails + 1))
printf '%s %s %s\n' "$invocation" "$fails" "$first" >"$STATE_FILE.tmp"
mv -f "$STATE_FILE.tmp" "$STATE_FILE"
span=$((now - first))

age="$(ps -o etimes= -p "$main_pid" 2>/dev/null | tr -d ' ' || true)"
if [[ ! "$age" =~ ^[0-9]+$ ]]; then
	age=0
fi
if ((age < BOOT_GRACE_SECONDS)); then
	log "liveness probe failed ($fails in a row over ${span}s) for a daemon ${age}s old; a daemon in its first ${BOOT_GRACE_SECONDS}s is never restarted"
	exit 0
fi
if ((fails < FAILS_TO_RESTART || span < FAIL_WINDOW_SECONDS)); then
	log "liveness probe failed ($fails in a row over ${span}s); restarting only after $FAILS_TO_RESTART in a row over ${FAIL_WINDOW_SECONDS}s"
	exit 0
fi
# Last look before acting: a restart that began while we probed is not ours
# to repeat.
if [[ "$(unit_prop InvocationID)" != "$invocation" || "$(unit_prop ActiveState)" != "active" ]]; then
	clear_streak
	exit 0
fi
log "liveness probe failed $fails times in a row over ${span}s; restarting sandboxd.service"
clear_streak
systemctl --no-block restart "$UNIT"
log "sandboxd.service restart requested"
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

# gvisor_fetch_release downloads and verifies the gVisor release tarball ONCE
# per install, extracting it into a shared directory both installers read.
#
# Upstream changed its release layout: the bucket no longer publishes bare
# runsc / containerd-shim-runsc-v1 objects, only
#   releases/release/latest/<arch>/gvisor.tar.{bz2,zstd}(.sha512)
# so every `--with-gvisor` install failed at download with a plain 404:
#
#   curl: (22) The requested URL returned error: 404
#   --with-gvisor: failed to download runsc from .../latest/x86_64/runsc
#
# install.sh exits on that, so sandboxd was never installed at all on a
# gvisor node. It took out all four workers of an 8-node scenario while the
# servers — which do not set with_gvisor — came up fine, so the cluster
# reported "expected 8 members, never reached (last 4)" and looked like a
# membership bug.
GVISOR_RELEASE_DIR=""
GVISOR_TMP_DIRS=()
gvisor_cleanup_tmp() {
	local d
	for d in ${GVISOR_TMP_DIRS+"${GVISOR_TMP_DIRS[@]}"}; do
		[[ -n "$d" ]] && rm -rf "$d"
	done
	GVISOR_TMP_DIRS=()
}
trap gvisor_cleanup_tmp EXIT

gvisor_fetch_release() {
	if [[ -n "$GVISOR_RELEASE_DIR" && -x "${GVISOR_RELEASE_DIR}/runsc" ]]; then
		return 0
	fi
	local arch
	case "$(uname -m)" in
		x86_64|amd64)   arch="x86_64" ;;
		aarch64|arm64)  arch="aarch64" ;;
		*)
			echo "--with-gvisor: unsupported architecture $(uname -m) for gVisor" >&2
			exit 1
			;;
	esac

	local base="https://storage.googleapis.com/gvisor/releases/release/latest/${arch}"
	local tmp_dir
	tmp_dir="$(mktemp -d)"
	# Cleaned on exit rather than on RETURN: the extracted tree is shared by
	# install_runsc_binary and install_runsc_shim, so a RETURN trap would
	# delete it out from under the second caller. It is ~500MB extracted, on
	# a 20GB root volume, so leaving it behind is not an option either.
	GVISOR_TMP_DIRS+=("$tmp_dir")

	echo "Downloading gVisor release for ${arch} from ${base}"
	if ! curl_download "${base}/gvisor.tar.bz2" -o "${tmp_dir}/gvisor.tar.bz2"; then
		echo "--with-gvisor: failed to download gvisor.tar.bz2 from ${base}/gvisor.tar.bz2" >&2
		exit 1
	fi
	if ! curl_download "${base}/gvisor.tar.bz2.sha512" -o "${tmp_dir}/gvisor.tar.bz2.sha512"; then
		echo "--with-gvisor: failed to download gvisor.tar.bz2.sha512" >&2
		exit 1
	fi

	# The published checksum names the file as "gvisor.tar.bz2", which is what
	# we wrote, but rewrite it anyway so a future rename upstream cannot turn
	# verification into a silent no-op.
	(
		cd "$tmp_dir"
		awk '{print $1"  gvisor.tar.bz2"}' gvisor.tar.bz2.sha512 > gvisor.sha512.local
		if ! sha512sum -c gvisor.sha512.local; then
			echo "--with-gvisor: gvisor.tar.bz2 checksum verification failed" >&2
			exit 1
		fi
	)

	if ! tar xjf "${tmp_dir}/gvisor.tar.bz2" -C "$tmp_dir"; then
		echo "--with-gvisor: failed to extract gvisor.tar.bz2" >&2
		exit 1
	fi
	# runsc now ships with a gvisor-bin/ payload beside it (gvisor_sentry,
	# checkpointgofer, the metric server…). Installing the single binary and
	# dropping the rest would produce a runsc that fails at first container
	# start rather than at install time.
	if [[ ! -x "${tmp_dir}/runsc" ]]; then
		echo "--with-gvisor: gvisor.tar.bz2 did not contain runsc (upstream layout changed again?)" >&2
		exit 1
	fi
	GVISOR_RELEASE_DIR="$tmp_dir"
}

install_runsc_binary() {
	gvisor_fetch_release
	install -m 0755 "${GVISOR_RELEASE_DIR}/runsc" /usr/local/bin/runsc
	if [[ -d "${GVISOR_RELEASE_DIR}/gvisor-bin" ]]; then
		install -d -m 0755 /usr/local/bin/gvisor-bin
		find "${GVISOR_RELEASE_DIR}/gvisor-bin" -maxdepth 1 -type f -exec \
			install -m 0755 {} /usr/local/bin/gvisor-bin/ \;
		echo "Installed gVisor support binaries to /usr/local/bin/gvisor-bin"
	fi
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
	gvisor_fetch_release
	if [[ ! -x "${GVISOR_RELEASE_DIR}/containerd-shim-runsc-v1" ]]; then
		echo "--with-gvisor: gvisor.tar.bz2 did not contain containerd-shim-runsc-v1" >&2
		exit 1
	fi
	install -m 0755 "${GVISOR_RELEASE_DIR}/containerd-shim-runsc-v1" /usr/local/bin/containerd-shim-runsc-v1
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
SB_TOOLBOX_BINARY_PATH=$TOOLBOX_BINARY_PATH
SB_TOOLBOX_MOUNT_PATH=/usr/local/bin/toolboxd
SB_TOOLBOX_PORT=2280
SB_IDLE_TIMEOUT_MIN=$IDLE_TIMEOUT_MIN
SB_ENABLE_CADDY=false
# No per-sandbox firewall in local mode: a create or update that asks for
# network policy (block-all, address lists, hostname rules, byte caps) is
# refused with 501 network_policy_unenforced instead of being accepted and not
# enforced. SB_ALLOW_UNENFORCED_NETWORK_POLICY=true accepts it unenforced
# (development only); SB_ENABLE_NETWORK_RULES=true enforces it.
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

# write_egress_gateway_units installs the egress gateway (plans/
# egress-domain-filtering.md D9, CEO D22): a dedicated unprivileged user, a
# root-owned 0600 control socket created by systemd, and the hardened unit.
# The gateway's own env file holds only SB_EGRESS_* settings, never the
# daemon's secrets.
write_egress_gateway_units() {
	if ! id aerolvm-egress >/dev/null 2>&1; then
		useradd --system --no-create-home --shell /usr/sbin/nologin aerolvm-egress
	fi
	mkdir -p /etc/sandboxd
	if [[ ! -f /etc/sandboxd/egress-gateway.env ]]; then
		cat > /etc/sandboxd/egress-gateway.env <<EOF
# Egress gateway settings (setup/config-defaults.md). sandboxd reads the same
# SB_EGRESS_GATEWAY_SOCKET from its own env.
SB_EGRESS_GATEWAY_SOCKET=/run/aerolvm/egress-gateway.sock
SB_EGRESS_DNS_PORT=53054
SB_EGRESS_PROXY_PORT=15080
EOF
		chmod 0644 /etc/sandboxd/egress-gateway.env
	fi
	cat > /etc/systemd/system/aerolvm-egress-gateway.socket <<EOF
[Unit]
Description=AerolVM egress gateway control socket

[Socket]
ListenStream=/run/aerolvm/egress-gateway.sock
SocketUser=root
SocketGroup=root
SocketMode=0600
DirectoryMode=0755

[Install]
WantedBy=sockets.target
EOF
	cat > /etc/systemd/system/aerolvm-egress-gateway.service <<EOF
[Unit]
Description=AerolVM egress gateway (filtering DNS + SNI/Host proxy)
After=network-online.target containerd.service docker.service
Wants=network-online.target
Requires=aerolvm-egress-gateway.socket

[Service]
Type=simple
User=aerolvm-egress
Group=aerolvm-egress
EnvironmentFile=-/etc/sandboxd/egress-gateway.env
ExecStart=$INSTALL_PREFIX/sandboxd egress-gateway
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
StateDirectory=aerolvm-egress
StateDirectoryMode=0700
LimitCORE=0
LimitNOFILE=131072
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
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

# detect_darwin_docker_host prints the unix:// endpoint of the current user's
# Docker engine. launchd starts the agent with an empty environment, and
# OrbStack / Docker Desktop serve the engine from a socket under $HOME
# (~/.orbstack/run/docker.sock, ~/.docker/run/docker.sock);
# /var/run/docker.sock exists only when Docker Desktop's default-socket option
# is on. Order: DOCKER_HOST, the active docker context, /var/run/docker.sock.
detect_darwin_docker_host() {
	local host=""
	if [[ "${DOCKER_HOST:-}" == unix://* ]]; then
		host="$DOCKER_HOST"
	elif command -v docker >/dev/null 2>&1; then
		host="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
	fi
	if [[ "$host" != unix://* || ! -S "${host#unix://}" ]]; then
		host=""
		if [[ -S /var/run/docker.sock ]]; then
			host="unix:///var/run/docker.sock"
		fi
	fi
	[[ -n "$host" ]] || return 1
	echo "$host"
}

# reuse_darwin_pat_token keeps an existing install's token so re-running the
# installer (the upgrade path) does not lock out clients already holding it.
reuse_darwin_pat_token() {
	if [[ "$PAT_TOKEN_EXPLICIT" == "true" || ! -f "$DARWIN_LAUNCH_AGENT" ]]; then
		return
	fi
	local existing
	existing="$(plutil -extract EnvironmentVariables.SB_PAT_TOKEN raw -o - "$DARWIN_LAUNCH_AGENT" 2>/dev/null || true)"
	if [[ -n "$existing" ]]; then
		PAT_TOKEN="$existing"
	fi
}

# write_launch_agent_plist registers sandboxd as a per-user LaunchAgent: every
# path is under $DARWIN_HOME and every listener is bound to 127.0.0.1.
#   SB_DOCKER_TOOLBOX_LOOPBACK  each sandbox publishes only its toolbox port,
#                               on 127.0.0.1; macOS Local Network privacy
#                               blocks a user process from dialing the Docker
#                               VM's container IPs, but not loopback.
#   SB_SSH_LISTEN_ADDR          the SSH gateway otherwise binds 0.0.0.0:2220.
#   SB_RESOURCE_LIMITS_DISABLED every create carries a disk quota (StorageOpt
#                               size), which dockerd only honours on overlay
#                               over xfs+pquota; the OrbStack / Docker Desktop
#                               VMs reject it with a 500.
# The plist carries the PAT token, so it is created under umask 077.
write_launch_agent_plist() {
	local docker_host="$1"
	local state="$DARWIN_HOME/state"
	local run="$DARWIN_HOME/run"
	mkdir -p "$state" "$DARWIN_HOME/mounts" "$run" "$DARWIN_HOME/logs" "$(dirname "$DARWIN_LAUNCH_AGENT")"
	chmod 0700 "$state" "$DARWIN_HOME/mounts" "$run"
	local old_umask
	old_umask="$(umask)"
	umask 077
	cat > "$DARWIN_LAUNCH_AGENT" <<EOF
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
		<key>DOCKER_HOST</key>
		<string>$docker_host</string>
		<key>SB_PAT_TOKEN</key>
		<string>$PAT_TOKEN</string>
		<key>SB_NODE_NAME</key>
		<string>$NODE_NAME</string>
		<key>SB_API_HOST</key>
		<string>127.0.0.1</string>
		<key>SB_API_PORT</key>
		<string>21212</string>
		<key>SB_PUBLIC_HOST</key>
		<string>127.0.0.1</string>
		<key>SB_SSH_LISTEN_ADDR</key>
		<string>127.0.0.1:2220</string>
		<key>SB_DB_PATH</key>
		<string>$state/state.db</string>
		<key>SB_CREDENTIAL_ENCRYPTION_KEY_PATH</key>
		<string>$state/credential_encryption.key</string>
		<key>SB_SSH_HOST_KEY_PATH</key>
		<string>$state/ssh_host_ed25519_key</string>
		<key>SB_WASM_MODULES_DIR</key>
		<string>$state/wasm/modules</string>
		<key>SB_FIRECRACKER_TEMPLATES_DIR</key>
		<string>$state/firecracker/templates</string>
		<key>SB_PLATFORM_VOLUMES_RECLAIM_MOUNT_ROOT</key>
		<string>$state/volume-reclaim</string>
		<key>SB_DOCKER_NETWORK</key>
		<string>bridge</string>
		<key>SB_DOCKER_TOOLBOX_LOOPBACK</key>
		<string>true</string>
		<key>SB_TOOLBOX_BINARY_PATH</key>
		<string>$TOOLBOX_BINARY_PATH</string>
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
		<key>SB_RESOURCE_LIMITS_DISABLED</key>
		<string>true</string>
		<key>SB_MOUNTS_ROOT</key>
		<string>$DARWIN_HOME/mounts</string>
		<key>SB_MOUNTS_CRED_DIR</key>
		<string>$run</string>
		<key>SB_INTERNAL_L4_WAKE_DIR</key>
		<string>$run/l4wake</string>
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
	<string>$DARWIN_HOME/logs/sandboxd.log</string>
	<key>StandardErrorPath</key>
	<string>$DARWIN_HOME/logs/sandboxd.err</string>
</dict>
</plist>
EOF
	umask "$old_umask"
}

# install_darwin_local is --local on macOS: a per-user install, no root.
install_darwin_local() {
	if [[ $EUID -eq 0 ]]; then
		echo "On macOS, run install.sh --local without sudo: it installs into ~/.aerolvm for the current user." >&2
		exit 1
	fi
	local docker_host
	if ! docker_host="$(detect_darwin_docker_host)"; then
		echo "No running Docker engine socket found. Start OrbStack or Docker Desktop and re-run," >&2
		echo "or name it: DOCKER_HOST=unix:///path/to/docker.sock ./install.sh --local" >&2
		exit 1
	fi
	reuse_darwin_pat_token
	install_binaries
	write_launch_agent_plist "$docker_host"
	local domain
	domain="gui/$(id -u)"
	launchctl bootout "$domain/com.aerol.sandboxd" >/dev/null 2>&1 || true
	launchctl bootstrap "$domain" "$DARWIN_LAUNCH_AGENT"

	local healthy="false"
	local _
	for _ in $(seq 1 30); do
		if curl -fsS -o /dev/null http://127.0.0.1:21212/health 2>/dev/null; then
			healthy="true"
			break
		fi
		sleep 1
	done
	if [[ "$healthy" != "true" ]]; then
		echo "sandboxd did not become healthy within 30s; see $DARWIN_HOME/logs/sandboxd.err" >&2
		exit 1
	fi

	echo "AerolVM installed (local mode, current user)"
	echo "PAT token: $PAT_TOKEN"
	echo "Use header: Authorization: Bearer <PAT token>"
	echo "API URL: http://127.0.0.1:21212"
	echo "Health URL: http://127.0.0.1:21212/health"
	echo "Docker engine: $docker_host"
	echo "Service: LaunchAgent com.aerol.sandboxd (starts at login)"
	echo "Files: $DARWIN_HOME (logs in $DARWIN_HOME/logs)"
	echo "Stop: launchctl bootout $domain/com.aerol.sandboxd"
}

if [[ "$LOCAL_MODE" == "true" ]]; then
	if [[ -n "$DOMAIN" || -n "$DNS_PROVIDER" ]]; then
		echo "--local is incompatible with --domain and --dns-provider" >&2
		exit 1
	fi
	if [[ "$(uname -s)" == "Darwin" ]]; then
		install_darwin_local
		exit 0
	fi
	if [[ $EUID -ne 0 ]]; then
		echo "install.sh must run as root (use sudo)" >&2
		exit 1
	fi
	install_binaries
	record_sandboxd_state
	write_local_environment
	# This branch skips install_packages, so it installs the two parts of it
	# a local server still needs, in the same order: the mount tools (platform
	# volumes and external storage are mounted on the host), then Docker.
	install_mount_tools
	# The local unit hard-Requires docker.service; on Linux we must install
	# the engine here since this branch skips install_packages.
	ensure_docker
	write_local_systemd_unit
	write_egress_gateway_units
	write_healthcheck_script
	write_healthcheck_units
	systemctl daemon-reload
	systemctl enable --now aerolvm-egress-gateway.socket aerolvm-egress-gateway.service
	restart_sandboxd_if_reconfigured
	systemctl enable --now sandboxd sandboxd-healthcheck.timer
	echo "AerolVM installed (local mode)"
	echo "PAT token: $PAT_TOKEN"
	echo "Use header: Authorization: Bearer <PAT token>"
	echo "API URL: http://127.0.0.1:21212"
	echo "Health URL: http://127.0.0.1:21212/health"
	echo "systemd restart policy: always (5 second backoff, 10 restarts per 5 minutes)"
	echo "Health watchdog: sandboxd-healthcheck.timer probes the liveness socket every 30 seconds and restarts sandboxd only after 3 failed probes in a row over 90 seconds"
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
record_sandboxd_state
write_environment
prepare_key_custody
write_caddy_env
write_caddy_systemd_dropin
write_route_dns_resolver
write_caddyfile
write_systemd_unit
write_egress_gateway_units
write_healthcheck_script
write_healthcheck_units

systemctl daemon-reload
systemctl enable --now aerolvm-egress-gateway.socket aerolvm-egress-gateway.service
if [[ "$NO_START" == "true" ]]; then
	# A joiner: cluster-join.sh starts sandboxd once cluster.env and the
	# cluster's server key are in place (see --no-start).
	systemctl enable caddy sandboxd sandboxd-healthcheck.timer
	systemctl start caddy sandboxd-healthcheck.timer
else
	# Before Caddy: a re-run that changed sandboxd's settings restarts it and
	# waits for it, so Caddy starts in front of a sandboxd (and, under
	# --pat-scope host, a public socket) that is already there.
	restart_sandboxd_if_reconfigured
	systemctl enable --now caddy sandboxd sandboxd-healthcheck.timer
fi

echo "AerolVM installed"
if [[ "$NO_START" == "true" ]]; then
	echo "sandboxd: enabled, not started (--no-start); cluster-join.sh starts it"
fi
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
	if [[ -n "$LB_HEALTH_PORT" ]]; then
		echo "Load-balancer health check: http://<this node>:${LB_HEALTH_PORT}/health (open it to the balancer only)"
	fi
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
echo "Health watchdog: sandboxd-healthcheck.timer probes the liveness socket every 30 seconds and restarts sandboxd only after 3 failed probes in a row over 90 seconds"
