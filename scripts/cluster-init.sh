#!/usr/bin/env bash

# cluster-init.sh — start an AerolVM cluster on this node (the seed).
#
# A thin wrapper over `sudo sandboxd init` for one release
# (plans/kubectl-style-cluster-ops.md D2, §4.1): sandboxd makes the CA, the
# gossip key and the server key, signs this node's cert, writes
# /etc/sandboxd/cluster.env and the systemd drop-in, restarts sandboxd and
# prints a join command. Use `sandboxd init` directly; new nodes join with
# the line `aerolvm join-command` prints.
#
# For the old two-pass join (cluster-join.sh with bundles and a CSR signed
# by cluster-sign-node.sh), this wrapper still writes the two bundles it
# always wrote: ca.crt only, and the server key on its own.
#
# install.sh must already have run on this host.

set -euo pipefail

SANDBOXD_BIN="${SANDBOXD_BIN:-/usr/local/bin/sandboxd}"
ENV_FILE="${SB_ENV_FILE:-/etc/sandboxd/sandboxd.env}"
CLUSTER_ENV="${SB_CLUSTER_ENV_FILE:-/etc/sandboxd/cluster.env}"
TLS_BUNDLE_OUT=""
CRED_BUNDLE_OUT=""
INIT_ARGS=()

usage() {
	cat <<'EOF'
Usage: cluster-init.sh [options]

Starts a cluster on this node. A wrapper over `sudo sandboxd init`; run that
instead (see `sandboxd init --help`). Run install.sh first.

Options passed to sandboxd init:
  --node-id <id>                    default: the short host name
  --role <role>                     must include server, or be mixed (default)
  --api-advertise-url <url>
  --data-plane-advertise-host <host>
  --ingress-advertise-host <host>
  --gossip-key <base64>             default: a new random key
  --key-custody <file|wrapped>      default: file

Kept for the old two-pass join:
  --tls-bundle-out <path>           ca.crt only (default ./aerolvm-tls-bundle.tar.gz)
  --cred-bundle-out <path>          the server key (default ./aerolvm-cred-bundle.tar.gz)

The other old options have no sandboxd init equivalent; the script names
what to do instead.
EOF
}

# unsupported refuses an old option that sandboxd init has no place for.
unsupported() {
	echo "cluster-init.sh: $1 is no longer supported. $2" >&2
	exit 1
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--node-id | --role | --api-advertise-url | --data-plane-advertise-host | --ingress-advertise-host | --gossip-key | --key-custody)
			[[ $# -ge 2 ]] || { echo "cluster-init.sh: $1 needs a value" >&2; exit 1; }
			INIT_ARGS+=("$1" "$2")
			shift 2
			;;
		--tls-bundle-out) TLS_BUNDLE_OUT="$2"; shift 2 ;;
		--cred-bundle-out) CRED_BUNDLE_OUT="$2"; shift 2 ;;
		--raft-bind | --raft-advertise | --gossip-bind | --gossip-advertise | --internal-bind | --internal-advertise)
			unsupported "$1" "sandboxd init listens on 7000-7003 and advertises one address: run sudo sandboxd init --advertise <ip>."
			;;
		--tls-dir | --ca-dir | --credential-key-path | --wrapped-key-path)
			unsupported "$1" "Set the matching SB_* path in /etc/sandboxd/sandboxd.env (SB_CLUSTER_TLS_DIR, SB_CLUSTER_CA_DIR, SB_CREDENTIAL_ENCRYPTION_KEY_PATH, SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH), then run sudo sandboxd init."
			;;
		--node-cert-days)
			unsupported "$1" "Set SB_CLUSTER_NODE_CERT_TTL (for example 2160h) in /etc/sandboxd/sandboxd.env, then run sudo sandboxd init; certs now renew themselves."
			;;
		--max-auto-voters)
			unsupported "$1" "Run sudo sandboxd init, then set SB_CLUSTER_MAX_AUTO_VOTERS in /etc/sandboxd/cluster.env and restart sandboxd."
			;;
		--force)
			unsupported "$1" "Run sudo sandboxd reset --yes, then sudo sandboxd init."
			;;
		--help | -h) usage; exit 0 ;;
		*) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

if [[ $EUID -ne 0 && -z "${CLUSTER_INIT_ALLOW_NONROOT:-}" ]]; then
	echo "cluster-init.sh must run as root" >&2
	exit 1
fi
if [[ ! -x "$SANDBOXD_BIN" ]]; then
	echo "Missing $SANDBOXD_BIN — run install.sh first" >&2
	exit 1
fi

echo "[cluster-init] cluster-init.sh now runs: sandboxd init (use it directly next time)" >&2
"$SANDBOXD_BIN" init ${INIT_ARGS[@]+"${INIT_ARGS[@]}"}

env_value() {
	local key="$1" value=""
	for f in "$ENV_FILE" "$CLUSTER_ENV"; do
		[[ -r "$f" ]] || continue
		local v
		v="$(awk -F= -v key="$key" '$1 == key { value = substr($0, length($1) + 2) } END { print value }' "$f")"
		[[ -n "$v" ]] && value="$v"
	done
	echo "$value"
}

# The two bundles of the old two-pass join, from what sandboxd init wrote.
TLS_DIR="$(env_value SB_CLUSTER_TLS_DIR)"
TLS_DIR="${TLS_DIR:-/etc/sandboxd/tls}"
TLS_BUNDLE_OUT="${TLS_BUNDLE_OUT:-$(pwd)/aerolvm-tls-bundle.tar.gz}"
tar -C "$TLS_DIR" -czf "$TLS_BUNDLE_OUT" ca.crt
chmod 0644 "$TLS_BUNDLE_OUT"

CRED_BUNDLE_OUT="${CRED_BUNDLE_OUT:-$(pwd)/aerolvm-cred-bundle.tar.gz}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
if [[ "$(env_value SB_CREDENTIAL_KEY_CUSTODY)" == "wrapped" ]]; then
	WRAPPED="$(env_value SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH)"
	install -m 0600 "${WRAPPED:-/var/lib/sandboxd/credential_encryption.key.wrapped}" "$STAGE/credential_encryption.key.wrapped"
	tar -C "$STAGE" -czf "$CRED_BUNDLE_OUT" credential_encryption.key.wrapped
else
	KEY="$(env_value SB_CREDENTIAL_ENCRYPTION_KEY_PATH)"
	install -m 0600 "${KEY:-/var/lib/sandboxd/credential_encryption.key}" "$STAGE/credential_encryption.key"
	tar -C "$STAGE" -czf "$CRED_BUNDLE_OUT" credential_encryption.key
fi
chmod 0600 "$CRED_BUNDLE_OUT"

cat <<EOF

For the old two-pass join (cluster-join.sh, deprecated):
  TLS trust bundle (ca.crt only): $TLS_BUNDLE_OUT
  Credential bundle (server key): $CRED_BUNDLE_OUT
  Gossip key: SB_GOSSIP_SECRET_KEY in $CLUSTER_ENV
The one-line join above replaces all three.
EOF
