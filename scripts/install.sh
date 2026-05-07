#!/usr/bin/env bash

set -euo pipefail

DOMAIN=""
PUBLIC_HOST=""
API_TOKEN=""
INSTALL_PREFIX="/usr/local/bin"
BUILD_FROM_SOURCE="auto"
SANDBOXD_URL=""
TOOLBOXD_URL=""
IDLE_TIMEOUT_MIN="0"

usage() {
	cat <<'EOF'
Usage: install.sh [options]

Options:
  --domain <domain>            Base domain for wildcard sandbox routes
  --public-host <host-or-ip>   Public host used for IP mode or local URLs
  --token <token>              API token for sandboxd
  --sandboxd-url <url>         Download URL for sandboxd binary
  --toolboxd-url <url>         Download URL for toolboxd binary
  --install-prefix <dir>       Binary install directory (default: /usr/local/bin)
  --idle-timeout-min <minutes> Idle auto-stop timeout in minutes
  --build-from-source          Build binaries from the current checkout
  --help                       Show this help

Examples:
  ./scripts/install.sh --domain sandbox.example.com --token dev-token
  ./scripts/install.sh --public-host 203.0.113.42 --token dev-token --build-from-source
EOF
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
		--token)
			API_TOKEN="$2"
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

if [[ -z "$API_TOKEN" ]]; then
	if command -v openssl >/dev/null 2>&1; then
		API_TOKEN="$(openssl rand -hex 24)"
	else
		echo "--token is required when openssl is unavailable" >&2
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
	if [[ -z "$SANDBOXD_URL" || -z "$TOOLBOXD_URL" ]]; then
		echo "download mode requires both --sandboxd-url and --toolboxd-url" >&2
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
		curl -fsSL "$SANDBOXD_URL" -o "$INSTALL_PREFIX/sandboxd"
		curl -fsSL "$TOOLBOXD_URL" -o "$INSTALL_PREFIX/toolboxd"
		chmod 0755 "$INSTALL_PREFIX/sandboxd" "$INSTALL_PREFIX/toolboxd"
	fi
}

write_environment() {
	mkdir -p /etc/sandboxd /var/lib/sandboxd
	cat > /etc/sandboxd/sandboxd.env <<EOF
SB_API_TOKEN=$API_TOKEN
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

$DOMAIN, *.$DOMAIN {
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

[Service]
Type=simple
EnvironmentFile=/etc/sandboxd/sandboxd.env
ExecStart=$INSTALL_PREFIX/sandboxd
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

install_packages
install_binaries
write_environment
write_caddyfile
write_systemd_unit

systemctl daemon-reload
systemctl enable --now caddy sandboxd

echo "sandbox-library installed"
echo "API token: $API_TOKEN"
if [[ -n "$DOMAIN" ]]; then
	echo "Public sandbox URL pattern: https://<sandbox-id>.$DOMAIN"
else
	echo "Public sandbox URL pattern: http://$PUBLIC_HOST/<sandbox-id>/"
fi