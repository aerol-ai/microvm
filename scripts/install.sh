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
CADDY_BUILD_URL_BASE="https://caddyserver.com/api/download"
WITH_GVISOR="false"
RUNSC_PATH=""
WITH_NVIDIA_GPU="false"
WITH_AMD_GPU="false"

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
  --install-prefix <dir>       Binary install directory (default: /usr/local/bin)
  --idle-timeout-min <minutes> Idle auto-stop timeout in minutes
  --build-from-source          Build binaries from the current checkout
  --dns-provider <name>        DNS provider for wildcard TLS (DNS-01 ACME).
                               Currently supported: cloudflare. Requires --domain
                               and --dns-api-token. Without this flag, Caddy
                               falls back to on-demand HTTP-01 issuance, which
                               does not scale past Let's Encrypt's 50-cert/week
                               rate limit per registered domain.
  --dns-api-token <token>      API token for the configured DNS provider.
                               For cloudflare: a scoped API token with
                               Zone:Read + DNS:Edit on the target zone.
  --with-gvisor                Install gVisor's runsc and register it as an
                               alternative OCI runtime in
                               /etc/docker/daemon.json so sandboxes can opt
                               into gVisor isolation via runtime: "runsc" on
                               create. Downloads runsc from the upstream
                               release bucket (verified by SHA-512) if it
                               isn't already on PATH. Restarts Docker if
                               daemon.json actually changed.
  --runsc-path <path>          Absolute path to a pre-installed runsc binary.
                               Skips the download step and registers this
                               binary instead. Only consulted with
                               --with-gvisor.
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
	if [[ "$os" != "linux" ]]; then
		echo "Only Linux hosts are supported by this installer" >&2
		exit 1
	fi

	case "$(uname -m)" in
		x86_64|amd64)
			arch="amd64"
			;;
		aarch64|arm64)
			arch="arm64"
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
	else
		SANDBOXD_URL="${SANDBOXD_URL:-${release_base}/download/${VERSION}/sandboxd_${platform}}"
		TOOLBOXD_URL="${TOOLBOXD_URL:-${release_base}/download/${VERSION}/toolboxd_${platform}}"
		CHECKSUMS_URL="${CHECKSUMS_URL:-${release_base}/download/${VERSION}/checksums.txt}"
	fi
}

download_asset() {
	local url="$1"
	local output="$2"

	curl -fL --retry 5 --retry-delay 2 --retry-connrefused "$url" -o "$output"
}

verify_downloads() {
	local tmp_dir="$1"
	local sandboxd_asset="$2"
	local toolboxd_asset="$3"

	if [[ -z "$CHECKSUMS_URL" ]]; then
		return 0
	fi

	if ! download_asset "$CHECKSUMS_URL" "$tmp_dir/checksums.txt"; then
		echo "Warning: failed to download checksums; skipping verification" >&2
		return 0
	fi

	(
		cd "$tmp_dir"
		grep -E "[[:space:]](${sandboxd_asset}|${toolboxd_asset})$" checksums.txt > selected-checksums.txt || true
		if [[ ! -s selected-checksums.txt ]]; then
			echo "Warning: no checksum entries found for downloaded assets; skipping verification" >&2
			exit 0
		fi
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
		--with-gvisor)
			WITH_GVISOR="true"
			shift
			;;
		--runsc-path)
			RUNSC_PATH="$2"
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

if [[ -z "$DOMAIN" && -z "$PUBLIC_HOST" ]]; then
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

if [[ $EUID -ne 0 ]]; then
	echo "install.sh must run as root" >&2
	exit 1
fi

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
				if curl -fsSL "https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch_suffix}/mount-s3.deb" -o "$tmp_deb"; then
					apt-get install -y "$tmp_deb" || \
						echo "Warning: mountpoint-s3 install failed; s3 mounts will be unavailable until installed manually" >&2
				else
					echo "Warning: failed to download mountpoint-s3; s3 mounts will be unavailable until installed manually" >&2
				fi
				rm -f "$tmp_deb"
			fi
		fi
		if ! command -v docker >/dev/null 2>&1; then
			apt-get install -y docker.io
			systemctl enable --now docker
		fi
		if ! command -v caddy >/dev/null 2>&1; then
			apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
			curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
			curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
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

install_caddy_dns_plugin() {
	# Replace the apt-installed Caddy binary with a custom build that includes
	# the chosen caddy-dns plugin. This is required for DNS-01 wildcard TLS.
	# Caddy's official build server returns a single static binary with the
	# requested modules baked in; no Go toolchain needed on the host.
	local provider="$1"
	local arch_tag

	case "$(uname -m)" in
		x86_64|amd64) arch_tag="amd64" ;;
		aarch64|arm64) arch_tag="arm64" ;;
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

	local download_url="${CADDY_BUILD_URL_BASE}?os=linux&arch=${arch_tag}&p=github.com/caddy-dns/${provider}"
	local tmp_binary
	tmp_binary="$(mktemp)"

	if ! curl -fL --retry 5 --retry-delay 2 --retry-connrefused "$download_url" -o "$tmp_binary"; then
		rm -f "$tmp_binary"
		echo "Failed to download Caddy with ${provider} DNS plugin from ${download_url}" >&2
		exit 1
	fi

	if [[ ! -s "$tmp_binary" ]]; then
		rm -f "$tmp_binary"
		echo "Caddy build server returned an empty binary" >&2
		exit 1
	fi

	if ! file "$tmp_binary" 2>/dev/null | grep -q ELF; then
		echo "Caddy build server did not return an ELF binary; first bytes:" >&2
		head -c 200 "$tmp_binary" >&2 || true
		echo "" >&2
		rm -f "$tmp_binary"
		exit 1
	fi

	chmod +x "$tmp_binary"

	# Verify the requested DNS plugin is actually compiled in. Without this
	# the Caddyfile we generate later would fail to provision at runtime
	# with a cryptic "loading module 'acme.dns.${provider}'" error.
	local module_name="dns.providers.${provider}"
	if ! "$tmp_binary" list-modules 2>/dev/null | grep -q "^${module_name}\$"; then
		echo "Downloaded Caddy does not include ${module_name}." >&2
		echo "Modules present matching 'dns':" >&2
		"$tmp_binary" list-modules 2>/dev/null | grep -i dns >&2 || true
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
EOF
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

	if [[ -n "$DNS_PROVIDER" ]]; then
		# DNS-01 wildcard issuance. Caddy issues exactly two certs that are
		# renewed automatically:
		#   - one for $DOMAIN
		#   - one for *.$DOMAIN  (covers every sandbox subdomain forever)
		# This sidesteps Let's Encrypt's per-registered-domain rate limits
		# (50 certs/week) regardless of how many sandboxes are created.
		# {env.SB_DNS_API_TOKEN} is read from /etc/default/caddy.
		cat > /etc/caddy/Caddyfile <<EOF
{
	admin localhost:2019
}

https://$DOMAIN {
	tls {
		dns $DNS_PROVIDER {env.SB_DNS_API_TOKEN}
	}
	@api path /health /v1 /v1/*
	handle @api {
		reverse_proxy 127.0.0.1:21212
	}
	handle {
		respond "Sandbox API not found" 404
	}
}

https://*.$DOMAIN {
	tls {
		dns $DNS_PROVIDER {env.SB_DNS_API_TOKEN}
	}
	respond "Sandbox not found" 404
}
EOF
		return
	fi

	# Fallback: HTTP-01 on-demand TLS. Each sandbox subdomain is issued its
	# own cert at first hit. Suitable for small deployments only — Let's
	# Encrypt rate limits will throttle creation past ~50 sandboxes/week.
	cat > /etc/caddy/Caddyfile <<EOF
{
	admin localhost:2019
	on_demand_tls {
		ask http://127.0.0.1:21212/v1/tls-check
	}
}

https://$DOMAIN {
	tls {
		on_demand
	}
	@api path /health /v1 /v1/*
	handle @api {
		reverse_proxy 127.0.0.1:21212
	}
	handle {
		respond "Sandbox API not found" 404
	}
}

https://*.$DOMAIN {
	tls {
		on_demand
	}
	respond "Sandbox not found" 404
}
EOF
}

write_caddy_env() {
	if [[ -z "$DNS_PROVIDER" ]]; then
		return
	fi
	# The stock Caddy debian unit from Cloudsmith does NOT load
	# /etc/default/caddy as an EnvironmentFile, so writing it alone is not
	# enough. write_caddy_systemd_dropin() installs a drop-in that wires it
	# in. 0600 root:root is fine — Caddy receives the value via process env.
	cat > /etc/default/caddy <<EOF
# Managed by AerolVM install.sh.
# Read by Caddy via {env.SB_DNS_API_TOKEN} substitution in /etc/caddy/Caddyfile.
SB_DNS_API_TOKEN=$DNS_API_TOKEN
EOF
	chmod 0600 /etc/default/caddy
	chown root:root /etc/default/caddy
}

write_caddy_systemd_dropin() {
	if [[ -z "$DNS_PROVIDER" ]]; then
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
		curl -fsSL "https://nvidia.github.io/libnvidia-container/gpgkey" \
			| gpg --dearmor -o "$keyring"
	fi

	# nvidia-container-toolkit.list uses plain https:// refs; rewrite to
	# include the signed-by pointer so apt can verify the packages.
	if [[ ! -f /etc/apt/sources.list.d/nvidia-container-toolkit.list ]]; then
		curl -fsSL "https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list" \
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
	if curl -fsSL \
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
		curl -fsSL "https://repo.radeon.com/rocm/rocm.gpg.key" | gpg --dearmor -o "$keyring"
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
	if ! curl -fL --retry 5 --retry-delay 2 "${base}/runsc" -o "${tmp_dir}/runsc"; then
		echo "--with-gvisor: failed to download runsc from ${base}/runsc" >&2
		exit 1
	fi
	if ! curl -fL --retry 5 --retry-delay 2 "${base}/runsc.sha512" -o "${tmp_dir}/runsc.sha512"; then
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

	mkdir -p /etc/docker
	local daemon_json="/etc/docker/daemon.json"
	local desired
	desired="$(printf '{"runtimes":{"runsc":{"path":"%s"}}}' "$runsc_bin")"

	# Merge our runtimes.runsc entry into any existing daemon.json instead of
	# replacing the file. jq does this cleanly when present; a Python fallback
	# covers minimal hosts that don't have jq.
	local merged
	if [[ -s "$daemon_json" ]]; then
		if command -v jq >/dev/null 2>&1; then
			merged="$(jq --arg path "$runsc_bin" '.runtimes = (.runtimes // {}) | .runtimes.runsc = {"path": $path}' "$daemon_json")"
		elif command -v python3 >/dev/null 2>&1; then
			merged="$(RUNSC_PATH="$runsc_bin" python3 - <<'PY'
import json, os, sys
path = "/etc/docker/daemon.json"
with open(path) as f:
    cfg = json.load(f)
cfg.setdefault("runtimes", {})
cfg["runtimes"]["runsc"] = {"path": os.environ["RUNSC_PATH"]}
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

install_packages
if [[ "$WITH_GVISOR" == "true" ]]; then
	register_gvisor_runtime
fi
if [[ "$WITH_NVIDIA_GPU" == "true" ]]; then
	install_nvidia_gpu
fi
if [[ "$WITH_AMD_GPU" == "true" ]]; then
	install_amd_gpu
fi
if [[ -n "$DNS_PROVIDER" ]]; then
	install_caddy_dns_plugin "$DNS_PROVIDER"
fi
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
	if [[ -n "$DNS_PROVIDER" ]]; then
		echo "TLS: wildcard DNS-01 via $DNS_PROVIDER (one cert covers all subdomains)"
	else
		echo "TLS: on-demand HTTP-01 (per-subdomain). Subject to Let's Encrypt rate limits."
		echo "  For production, re-run with --dns-provider cloudflare --dns-api-token <token>"
	fi
else
	echo "API URL: http://$PUBLIC_HOST:21212"
	echo "Health URL: http://$PUBLIC_HOST:21212/health"
	echo "Public sandbox URL pattern: http://$PUBLIC_HOST/<docker-short-id>/"
fi
echo "systemd restart policy: always (5 second backoff, 10 restarts per 5 minutes)"
echo "Health watchdog: sandboxd-healthcheck.timer probes /health every 30 seconds"