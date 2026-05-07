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
  --help                       Show this help

Examples:
	curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- --domain sandbox.example.com --pat-token my-pat-token
  ./scripts/install.sh --version v0.1.0 --public-host 203.0.113.42
	./scripts/install.sh --public-host 203.0.113.42 --pat-token dev-token --build-from-source
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
	mkdir -p /etc/sandboxd /var/lib/sandboxd
	cat > /etc/sandboxd/sandboxd.env <<EOF
SB_PAT_TOKEN=$PAT_TOKEN
SB_API_HOST=0.0.0.0
SB_API_PORT=8080
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
EOF
	chmod 0600 /etc/sandboxd/sandboxd.env
}

write_caddyfile() {
	mkdir -p /etc/caddy
	if [[ -n "$DOMAIN" ]]; then
		cat > /etc/caddy/Caddyfile <<EOF
{
	admin localhost:2019
	on_demand_tls {
		ask http://127.0.0.1:8080/v1/tls-check
	}
}

$DOMAIN {
	tls {
		on_demand
	}
	@api path /health /v1 /v1/*
	reverse_proxy @api 127.0.0.1:8080
	respond "Sandbox API not found" 404
}

*.$DOMAIN {
	tls {
		on_demand
	}
	respond "Sandbox not found" 404
}
EOF
	else
		cat > /etc/caddy/Caddyfile <<EOF
{
	admin localhost:2019
}

:80 {
	respond "Sandbox not found" 404
}
EOF
	fi
}

write_systemd_unit() {
	cat > /etc/systemd/system/sandboxd.service <<EOF
[Unit]
Description=sandbox-library daemon
After=docker.service caddy.service network-online.target
Wants=network-online.target
Requires=docker.service
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
EnvironmentFile=/etc/sandboxd/sandboxd.env
ExecStart=$INSTALL_PREFIX/sandboxd
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
HEALTH_PORT="${SB_API_PORT:-8080}"
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
Description=sandbox-library health watchdog
After=sandboxd.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_PREFIX/sandboxd-healthcheck
EOF

	cat > /etc/systemd/system/sandboxd-healthcheck.timer <<EOF
[Unit]
Description=Run sandbox-library health watchdog

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

install_packages
install_binaries
write_environment
write_caddyfile
write_systemd_unit
write_healthcheck_script
write_healthcheck_units

systemctl daemon-reload
systemctl enable --now caddy sandboxd sandboxd-healthcheck.timer

echo "sandbox-library installed"
echo "PAT token: $PAT_TOKEN"
echo "Use header: Authorization: Bearer <PAT token>"
if [[ -n "$DOMAIN" ]]; then
	echo "API URL: https://$DOMAIN"
	echo "Health URL: https://$DOMAIN/health"
	echo "Public sandbox URL pattern: https://<docker-short-id>.$DOMAIN"
else
	echo "API URL: http://$PUBLIC_HOST:8080"
	echo "Health URL: http://$PUBLIC_HOST:8080/health"
	echo "Public sandbox URL pattern: http://$PUBLIC_HOST/<docker-short-id>/"
fi
echo "systemd restart policy: always (5 second backoff, 10 restarts per 5 minutes)"
echo "Health watchdog: sandboxd-healthcheck.timer probes /health every 30 seconds"