#!/usr/bin/env bash

# cluster-init.sh — bootstrap the FIRST node of an AerolVM cluster.
#
# Run this on exactly one node per cluster (the seed). It generates a gossip
# secret key, writes /etc/sandboxd/cluster.env with the cluster vars, installs
# a systemd drop-in that layers cluster.env on top of the base sandboxd.env
# from install.sh, then restarts sandboxd. Other nodes join via cluster-join.sh
# using the printed gossip key + this node's gossip address.
#
# install.sh must already have run successfully on this host. This script does
# NOT install binaries, Caddy, or Docker — it only flips the existing daemon
# into cluster mode.

set -euo pipefail

NODE_ID=""
API_ADVERTISE_URL=""
DATA_PLANE_ADVERTISE_HOST=""
RAFT_BIND_ADDR="0.0.0.0:7000"
RAFT_ADVERTISE_ADDR=""
GOSSIP_BIND_ADDR="0.0.0.0:7001"
GOSSIP_ADVERTISE_ADDR=""
GOSSIP_SECRET_KEY=""
RAFT_DATA_DIR="/var/lib/sandboxd/raft"
TLS_DIR="/etc/sandboxd/tls"
CA_DIR="/etc/sandboxd/cluster-ca"
NODE_CERT_DAYS="${CERT_DAYS:-90}"
INTERNAL_BIND_ADDR="0.0.0.0:7002"
INTERNAL_ADVERTISE_URL=""
TLS_BUNDLE_OUT=""
CRED_KEY_PATH=""
CRED_BUNDLE_OUT=""
FORCE="false"
MAX_AUTO_VOTERS="5"
NODE_ROLE=""
INGRESS_ADVERTISE_HOST=""

usage() {
	cat <<'EOF'
Usage: cluster-init.sh [options]

Bootstrap the first node of an AerolVM cluster. Run install.sh first.

Options:
  --node-id <id>                Stable node identity. Default: hostname.
  --api-advertise-url <url>     URL other nodes use to forward writes back to
                                this node. Default: http://<primary-ip>:21212
                                (port read from SB_API_PORT in sandboxd.env).
  --data-plane-advertise-host <host>
                                Host/IP other nodes use for sandbox ingress
                                (HTTP/SNI passthrough and raw TCP proxying).
                                Default: <primary-ip>. Set this separately
                                when API traffic uses a load balancer or
                                API-only DNS name.
  --raft-bind <host:port>       Raft listen address. Default: 0.0.0.0:7000
  --raft-advertise <host:port>  Raft address peers connect to. Default: derived
                                from --api-advertise-url host + raft-bind port.
  --gossip-bind <host:port>     Gossip listen address. Default: 0.0.0.0:7001
  --gossip-advertise <host:port> Gossip address peers connect to. Default:
                                derived like --raft-advertise.
  --gossip-key <base64>         Gossip secret key (base64-encoded 16/24/32
                                bytes). Default: auto-generated 32-byte key.
                                Save the printed value — every other node
                                needs the same key to join.
  --tls-dir <path>              Daemon TLS directory (CA trust + node cert/key).
                                Default: /etc/sandboxd/tls
  --ca-dir <path>               Seed-only CA signing directory. Default:
                                /etc/sandboxd/cluster-ca (never used by daemon)
  --node-cert-days <n>          Seed node certificate lifetime. Default:
                                CERT_DAYS or 90
  --internal-bind <host:port>   Cluster-internal mTLS listen address (used for
                                leader-forwarded raft applies). Default: 0.0.0.0:7002
  --internal-advertise <url>    HTTPS URL peers dial for the internal channel.
                                Default: derived from primary IP + internal-bind port.
  --tls-bundle-out <path>       Where to save the joiner TLS trust bundle
                                (tarball with ca.crt ONLY — never ca.key).
                                Joiners generate node.key locally and get
                                node.crt signed via cluster-sign-node.sh on
                                the seed. Default: ./aerolvm-tls-bundle.tar.gz
  --credential-key-path <path>  Path to the credential encryption key file.
                                Default: SB_CREDENTIAL_ENCRYPTION_KEY_PATH from
                                /etc/sandboxd/sandboxd.env, or
                                /var/lib/sandboxd/credential_encryption.key.
                                If the file is missing, a fresh 32-byte key is
                                generated and written here.
  --cred-bundle-out <path>      Standalone credential bundle (tarball with
                                credential_encryption.key). Kept separate from
                                the TLS trust bundle so ca.crt distribution
                                does not also ship SB_CREDENTIALS_KEY.
                                Default: ./aerolvm-cred-bundle.tar.gz
                                (always emitted; required by cluster-join.sh)
  --max-auto-voters <n>         Max Raft voters auto-promoted from gossip.
                                Additional nodes become non-voters. Default 5.
                                Set 0 for the old unlimited behavior.
  --role <role>                 SB_NODE_ROLE for this daemon. One of
                                server, worker, ingress, mixed — or a
                                comma-separated combination of server / worker
                                / ingress (e.g. "server,worker") for hybrid
                                nodes. Default mixed (every component on every
                                node — fine through 10 live nodes only).
                                Clusters above 10 live nodes must use
                                dedicated server, worker, and ingress roles;
                                mixed and hybrid-role members block placement.
                                "mixed" cannot be combined with other tokens.
                                The bootstrap node's role set must contain
                                "server" (or be "mixed"); pure worker /
                                ingress / worker,ingress refuse to bootstrap a
                                fresh cluster.
  --ingress-advertise-host <h>  SB_INGRESS_ADVERTISE_HOST — the public host
                                in SDK-returned sandbox URLs. Defaults to
                                empty (URLs use SB_PUBLIC_HOST or
                                SB_DOMAIN). Set this to your wildcard-DNS
                                ingress endpoint when running a dedicated
                                ingress tier.
  --force                       Allow re-init even if the raft data dir
                                already exists (DESTROYS existing raft state).
  --help                        Show this help.

Examples:
  sudo ./cluster-init.sh
  sudo ./cluster-init.sh --gossip-key "$(openssl rand -base64 32)" \
                         --api-advertise-url http://10.0.0.5:21212
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--node-id)            NODE_ID="$2"; shift 2 ;;
		--api-advertise-url)  API_ADVERTISE_URL="$2"; shift 2 ;;
		--data-plane-advertise-host) DATA_PLANE_ADVERTISE_HOST="$2"; shift 2 ;;
		--raft-bind)          RAFT_BIND_ADDR="$2"; shift 2 ;;
		--raft-advertise)     RAFT_ADVERTISE_ADDR="$2"; shift 2 ;;
		--gossip-bind)        GOSSIP_BIND_ADDR="$2"; shift 2 ;;
		--gossip-advertise)   GOSSIP_ADVERTISE_ADDR="$2"; shift 2 ;;
		--gossip-key)         GOSSIP_SECRET_KEY="$2"; shift 2 ;;
		--tls-dir)            TLS_DIR="$2"; shift 2 ;;
		--ca-dir)             CA_DIR="$2"; shift 2 ;;
		--node-cert-days)     NODE_CERT_DAYS="$2"; shift 2 ;;
		--internal-bind)      INTERNAL_BIND_ADDR="$2"; shift 2 ;;
		--internal-advertise) INTERNAL_ADVERTISE_URL="$2"; shift 2 ;;
		--tls-bundle-out)     TLS_BUNDLE_OUT="$2"; shift 2 ;;
		--credential-key-path) CRED_KEY_PATH="$2"; shift 2 ;;
		--cred-bundle-out)    CRED_BUNDLE_OUT="$2"; shift 2 ;;
		--max-auto-voters)    MAX_AUTO_VOTERS="$2"; shift 2 ;;
		--role)               NODE_ROLE="$2"; shift 2 ;;
		--ingress-advertise-host) INGRESS_ADVERTISE_HOST="$2"; shift 2 ;;
		--force)              FORCE="true"; shift ;;
		--help)               usage; exit 0 ;;
		*) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

if [[ $EUID -ne 0 ]]; then
	echo "cluster-init.sh must run as root" >&2
	exit 1
fi
if [[ ! "$NODE_CERT_DAYS" =~ ^[1-9][0-9]*$ ]]; then
	echo "--node-cert-days must be a positive integer" >&2
	exit 1
fi

# Validate --role early. cluster-init bootstraps raft, so the role set must
# include "server" (or be the "mixed" shorthand). Pure worker / ingress /
# worker,ingress nodes are joiners — they use cluster-join.sh, not this script.
# Accepts a comma-separated combination (e.g. "server,worker"); "mixed" cannot
# be combined with other tokens.
validate_node_role() {
	local raw="$1"
	if [[ -z "$raw" ]]; then return 0; fi
	local has_server="false" has_mixed="false" has_other="false" token_count=0
	local IFS=','
	# shellcheck disable=SC2206
	local parts=($raw)
	for raw_tok in "${parts[@]}"; do
		local tok
		tok="$(echo "$raw_tok" | tr '[:upper:]' '[:lower:]' | xargs)"
		if [[ -z "$tok" ]]; then
			echo "Invalid --role=$raw: empty token (check for stray or trailing commas)" >&2
			exit 1
		fi
		case "$tok" in
			server)  has_server="true" ;;
			mixed)   has_mixed="true" ;;
			worker|ingress) has_other="true" ;;
			*)
				echo "Unknown --role token '$tok' in '$raw' (allowed: server, worker, ingress, mixed)" >&2
				exit 1
				;;
		esac
		token_count=$((token_count + 1))
	done
	if [[ "$has_mixed" == "true" && "$token_count" -gt 1 ]]; then
		echo "Invalid --role=$raw: 'mixed' is shorthand for server,worker,ingress and cannot be combined with other tokens" >&2
		exit 1
	fi
	if [[ "$has_server" != "true" && "$has_mixed" != "true" ]]; then
		echo "cluster-init.sh cannot bootstrap with --role=$raw (use cluster-join.sh for pure worker/ingress nodes, or include 'server' here)" >&2
		exit 1
	fi
}
validate_node_role "$NODE_ROLE"

if [[ ! -f /etc/sandboxd/sandboxd.env ]]; then
	echo "Missing /etc/sandboxd/sandboxd.env — run install.sh first" >&2
	exit 1
fi
if [[ ! -f /etc/systemd/system/sandboxd.service ]]; then
	echo "Missing /etc/systemd/system/sandboxd.service — run install.sh first" >&2
	exit 1
fi

if ! [[ "$MAX_AUTO_VOTERS" =~ ^[0-9]+$ ]]; then
	echo "--max-auto-voters must be a non-negative integer" >&2
	exit 1
fi

read_sandboxd_env_value() {
	local key="$1"
	if [[ ! -f /etc/sandboxd/sandboxd.env ]]; then
		return 0
	fi
	awk -F= -v key="$key" '$1 == key { value = substr($0, length($1) + 2) } END { print value }' /etc/sandboxd/sandboxd.env
}

# Refuse to clobber an existing raft data dir unless --force. Re-running this
# script with stale on-disk state would silently fork the cluster.
if [[ -d "$RAFT_DATA_DIR" ]] && [[ -n "$(ls -A "$RAFT_DATA_DIR" 2>/dev/null || true)" ]]; then
	if [[ "$FORCE" != "true" ]]; then
		echo "Refusing to re-init: $RAFT_DATA_DIR is not empty." >&2
		echo "  This node has already been bootstrapped (or joined a cluster)." >&2
		echo "  Pass --force to wipe and re-bootstrap, or use cluster-join.sh" >&2
		echo "  to join an existing cluster." >&2
		exit 1
	fi
	echo "WARNING: --force given; wiping $RAFT_DATA_DIR"
	rm -rf "$RAFT_DATA_DIR"
fi

# Pull SB_API_PORT from the base env so the default API URL matches whatever
# install.sh wrote (defaults to 21212 but a custom install can change it).
SB_API_PORT_DEFAULT="$(read_sandboxd_env_value SB_API_PORT)"
SB_API_PORT_DEFAULT="${SB_API_PORT_DEFAULT:-21212}"

primary_ip() {
	# Grab the source IP of the route used to reach the default gateway. Avoids
	# picking a docker0 / loopback address. Falls back to hostname -I if `ip` is
	# missing for any reason.
	if command -v ip >/dev/null 2>&1; then
		local ip
		ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
		if [[ -n "$ip" ]]; then echo "$ip"; return; fi
	fi
	hostname -I 2>/dev/null | awk '{print $1}'
}

if [[ -z "$NODE_ID" ]]; then
	NODE_ID="$(hostname -s 2>/dev/null || hostname)"
fi
if [[ ! "$NODE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
	echo "--node-id must start with an alphanumeric and contain only alphanumerics, dot, underscore, or hyphen (max 128 characters)" >&2
	exit 1
fi

PRIMARY_IP="$(primary_ip)"
if [[ -z "$PRIMARY_IP" ]]; then
	PRIMARY_IP="127.0.0.1"
fi

if [[ -z "$API_ADVERTISE_URL" ]]; then
	API_ADVERTISE_URL="http://${PRIMARY_IP}:${SB_API_PORT_DEFAULT}"
fi
if [[ -z "$DATA_PLANE_ADVERTISE_HOST" ]]; then
	DATA_PLANE_ADVERTISE_HOST="$PRIMARY_IP"
fi

# Derive advertise addrs from the primary IP + each bind's port if the operator
# didn't override them. Binding 0.0.0.0 is fine; advertising 0.0.0.0 is not —
# peers can't dial it.
derive_advertise() {
	local bind="$1"
	local port="${bind##*:}"
	echo "${PRIMARY_IP}:${port}"
}
if [[ -z "$RAFT_ADVERTISE_ADDR" ]];   then RAFT_ADVERTISE_ADDR="$(derive_advertise "$RAFT_BIND_ADDR")"; fi
if [[ -z "$GOSSIP_ADVERTISE_ADDR" ]]; then GOSSIP_ADVERTISE_ADDR="$(derive_advertise "$GOSSIP_BIND_ADDR")"; fi

if [[ -z "$GOSSIP_SECRET_KEY" ]]; then
	if ! command -v openssl >/dev/null 2>&1; then
		echo "openssl not found — pass --gossip-key explicitly" >&2
		exit 1
	fi
	GOSSIP_SECRET_KEY="$(openssl rand -base64 32)"
	GENERATED_KEY="true"
else
	GENERATED_KEY="false"
fi

# Validate the key here too so a bad value fails before sandboxd restart, not
# after. Mirror the daemon's check: base64-decode, must be 16/24/32 bytes.
DECODED_LEN="$(printf '%s' "$GOSSIP_SECRET_KEY" | base64 -d 2>/dev/null | wc -c | tr -d ' ')"
case "$DECODED_LEN" in
	16|24|32) ;;
	*)
		echo "Invalid --gossip-key: base64 must decode to 16, 24, or 32 bytes (got $DECODED_LEN)" >&2
		exit 1
		;;
esac

# --- Credential encryption key --------------------------------------------
# Sealed registry passwords and per-mount credentials replicated via raft are
# decrypted with this key on the failover owner. Every node MUST share the
# same value or recovered sandboxes lose access to private registries and
# credentialed mounts. install.sh lazy-generates a per-node file by default;
# we capture the seed's key (or generate one) and ship it to every joiner via
# the bundle below.
if [[ -z "$CRED_KEY_PATH" ]]; then
	# Honor SB_CREDENTIAL_ENCRYPTION_KEY_PATH from sandboxd.env if the
	# operator customized it; otherwise the daemon default.
	CRED_KEY_PATH="$(read_sandboxd_env_value SB_CREDENTIAL_ENCRYPTION_KEY_PATH)"
	CRED_KEY_PATH="${CRED_KEY_PATH:-/var/lib/sandboxd/credential_encryption.key}"
fi

if [[ ! -f "$CRED_KEY_PATH" ]]; then
	mkdir -p "$(dirname "$CRED_KEY_PATH")"
	if ! command -v openssl >/dev/null 2>&1; then
		echo "openssl not found — required to generate the credential encryption key." >&2
		echo "Install openssl, or pre-create $CRED_KEY_PATH (base64-encoded 32 bytes)." >&2
		exit 1
	fi
	openssl rand -base64 32 > "$CRED_KEY_PATH"
	chmod 0600 "$CRED_KEY_PATH"
fi

CRED_KEY_VALUE="$(tr -d '\n' < "$CRED_KEY_PATH")"
CRED_DECODED_LEN="$(printf '%s' "$CRED_KEY_VALUE" | base64 -d 2>/dev/null | wc -c | tr -d ' ')"
if [[ "$CRED_DECODED_LEN" != "32" ]]; then
	echo "Invalid credential key at $CRED_KEY_PATH: base64 must decode to 32 bytes (got $CRED_DECODED_LEN)" >&2
	exit 1
fi

# --- Cluster TLS material (self-signed CA + per-node cert) -----------------
# Generated once on the seed. ca.key stays on the seed only — joiners receive
# ca.crt (trust anchor) and have their CSR signed via cluster-sign-node.sh.
# Daemon runtime needs ca.crt + node.{crt,key}; never ca.key.
CLUSTER_SAN="aerolvm-cluster-node"
	if ! command -v openssl >/dev/null 2>&1; then
		echo "openssl not found — required for cluster TLS." >&2
		echo "Install openssl before initializing the cluster." >&2
		exit 1
	fi

	mkdir -p "$TLS_DIR" "$CA_DIR"
	chmod 0700 "$TLS_DIR"
	chmod 0700 "$CA_DIR"

	if [[ -f "$TLS_DIR/ca.crt" ]] || [[ -f "$TLS_DIR/node.crt" ]] || [[ -f "$CA_DIR/ca.key" ]] || [[ -f "$CA_DIR/ca.crt" ]]; then
		if [[ "$FORCE" != "true" ]]; then
			echo "Refusing to overwrite existing TLS material in $TLS_DIR." >&2
			echo "  Pass --force to regenerate (will invalidate joined nodes' trust)." >&2
			exit 1
		fi
		echo "WARNING: --force given; regenerating TLS material in $TLS_DIR"
		rm -f "$TLS_DIR/ca.crt" "$TLS_DIR/ca.key" "$TLS_DIR/node.crt" "$TLS_DIR/node.key"
		rm -f "$CA_DIR/ca.crt" "$CA_DIR/ca.key" "$CA_DIR/ca.srl"
	fi

	# 1. CA. 10-year lifetime — operators rotate by re-running cluster-init
	#    with --force and re-distributing ca.crt. Long-lived intentionally
	#    because the CA only signs cluster-internal node certs (never anything
	#    user-visible). ca.key never leaves the controlled signer.
	openssl genrsa -out "$CA_DIR/ca.key" 4096 2>/dev/null
	openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" -sha256 -days 3650 \
		-subj "/CN=AerolVM Cluster CA" \
		-out "$CA_DIR/ca.crt" 2>/dev/null
	install -m 0644 "$CA_DIR/ca.crt" "$TLS_DIR/ca.crt"

	# 2. This node's keypair + cert. DNS:aerolvm-cluster-node satisfies the
	#    daemon's ServerName check; DNS:node:${NODE_ID} binds the cert to the
	#    gossip node id (fail-closed peer identity). No IP/hostname SANs —
	#    dial verification is name-based, not address-based.
	openssl genrsa -out "$TLS_DIR/node.key" 4096 2>/dev/null
	openssl req -new -key "$TLS_DIR/node.key" \
		-subj "/CN=$CLUSTER_SAN" \
		-out "$TLS_DIR/node.csr" 2>/dev/null

	cat > "$TLS_DIR/node.ext" <<EOF
subjectAltName = DNS:$CLUSTER_SAN,DNS:node:${NODE_ID}
extendedKeyUsage = serverAuth, clientAuth
EOF

	openssl x509 -req -in "$TLS_DIR/node.csr" \
		-CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
		-out "$TLS_DIR/node.crt" -days "$NODE_CERT_DAYS" -sha256 \
		-extfile "$TLS_DIR/node.ext" 2>/dev/null

	rm -f "$TLS_DIR/node.csr" "$TLS_DIR/node.ext" "$CA_DIR/ca.srl"
	chmod 0600 "$CA_DIR/ca.key" "$TLS_DIR/node.key"
	chmod 0644 "$CA_DIR/ca.crt"
	chmod 0644 "$TLS_DIR/ca.crt" "$TLS_DIR/node.crt"

	# Trust bundle for joiners: ca.crt ONLY. Signing stays on the seed via
	# cluster-sign-node.sh. Credential encryption key ships separately.
	if [[ -z "$TLS_BUNDLE_OUT" ]]; then
		TLS_BUNDLE_OUT="$(pwd)/aerolvm-tls-bundle.tar.gz"
	fi
	tar -C "$TLS_DIR" -czf "$TLS_BUNDLE_OUT" ca.crt
	chmod 0644 "$TLS_BUNDLE_OUT"

# Always emit a standalone credential bundle.
# Keeping SB_CREDENTIAL_ENCRYPTION_KEY out of the CA trust tarball limits
# blast radius if ca.crt is copied more broadly than the encryption key.
CRED_BUNDLE_GENERATED="false"
if [[ -z "$CRED_BUNDLE_OUT" ]]; then
	CRED_BUNDLE_OUT="$(pwd)/aerolvm-cred-bundle.tar.gz"
fi
CRED_STAGE_DIR="$(mktemp -d)"
install -m 0600 "$CRED_KEY_PATH" "$CRED_STAGE_DIR/credential_encryption.key"
tar -C "$CRED_STAGE_DIR" -czf "$CRED_BUNDLE_OUT" credential_encryption.key
chmod 0600 "$CRED_BUNDLE_OUT"
rm -rf "$CRED_STAGE_DIR"
CRED_BUNDLE_GENERATED="true"

# Derive internal advertise URL when operator didn't override.
if [[ -z "$INTERNAL_ADVERTISE_URL" ]]; then
	INTERNAL_PORT="${INTERNAL_BIND_ADDR##*:}"
	INTERNAL_ADVERTISE_URL="https://${PRIMARY_IP}:${INTERNAL_PORT}"
fi

mkdir -p /etc/sandboxd
{
	cat <<EOF
# Managed by cluster-init.sh. Layered on top of /etc/sandboxd/sandboxd.env
# via the systemd drop-in at /etc/systemd/system/sandboxd.service.d/cluster.conf.
SB_ENABLE_CLUSTER=true
SB_CLUSTER_BOOTSTRAP=true
SB_NODE_ID=$NODE_ID
SB_API_ADVERTISE_URL=$API_ADVERTISE_URL
SB_DATA_PLANE_ADVERTISE_HOST=$DATA_PLANE_ADVERTISE_HOST
SB_RAFT_BIND_ADDR=$RAFT_BIND_ADDR
SB_RAFT_ADVERTISE_ADDR=$RAFT_ADVERTISE_ADDR
SB_RAFT_DATA_DIR=$RAFT_DATA_DIR
SB_GOSSIP_BIND_ADDR=$GOSSIP_BIND_ADDR
SB_GOSSIP_ADVERTISE_ADDR=$GOSSIP_ADVERTISE_ADDR
SB_GOSSIP_SECRET_KEY=$GOSSIP_SECRET_KEY
SB_CREDENTIAL_ENCRYPTION_KEY=$CRED_KEY_VALUE
SB_CREDENTIAL_ENCRYPTION_KEY_PATH=$CRED_KEY_PATH
SB_CLUSTER_MAX_AUTO_VOTERS=$MAX_AUTO_VOTERS
EOF
	if [[ -n "$NODE_ROLE" ]]; then
		echo "SB_NODE_ROLE=$NODE_ROLE"
	fi
	if [[ -n "$INGRESS_ADVERTISE_HOST" ]]; then
		echo "SB_INGRESS_ADVERTISE_HOST=$INGRESS_ADVERTISE_HOST"
	fi
	cat <<EOF
SB_CLUSTER_TLS_DIR=$TLS_DIR
SB_CLUSTER_INTERNAL_LISTEN=$INTERNAL_BIND_ADDR
SB_CLUSTER_INTERNAL_ADVERTISE=$INTERNAL_ADVERTISE_URL
EOF
} > /etc/sandboxd/cluster.env
chmod 0600 /etc/sandboxd/cluster.env

mkdir -p /etc/systemd/system/sandboxd.service.d
cat > /etc/systemd/system/sandboxd.service.d/cluster.conf <<'EOF'
[Service]
EnvironmentFile=/etc/sandboxd/cluster.env
EOF

restart_sandboxd_with_diagnostics() {
	echo "[cluster-init] restarting sandboxd with cluster mode enabled"
	if ! systemctl restart sandboxd; then
		echo "[cluster-init] sandboxd restart failed; dumping status and recent journal" >&2
		systemctl status sandboxd --no-pager -n 80 >&2 || true
		journalctl -u sandboxd --no-pager -n 160 >&2 || true
		exit 1
	fi

	echo "[cluster-init] sandboxd restart succeeded"
	systemctl is-active sandboxd || true
	systemctl show sandboxd \
		-p ActiveState -p SubState -p MainPID -p NRestarts -p ExecMainStatus \
		--no-pager || true
	echo "[cluster-init] listeners on cluster ports"
	ss -ltnup 2>/dev/null | grep -E ':(7000|7001|7002|21212)\b' || echo "(nothing listening on cluster ports yet)"
	if command -v curl >/dev/null 2>&1; then
		echo "[cluster-init] local /health"
		curl -sS --max-time 5 "http://127.0.0.1:${SB_API_PORT_DEFAULT}/health" || true
		echo
		local pat
		pat="$(read_sandboxd_env_value SB_PAT_TOKEN)"
		if [[ -n "$pat" ]]; then
			echo "[cluster-init] local /v1/cluster/members"
			curl -sS --max-time 5 -H "Authorization: Bearer ${pat}" \
				"http://127.0.0.1:${SB_API_PORT_DEFAULT}/v1/cluster/members" || true
			echo
			echo "[cluster-init] local /v1/cluster/leader"
			curl -sS --max-time 5 -H "Authorization: Bearer ${pat}" \
				"http://127.0.0.1:${SB_API_PORT_DEFAULT}/v1/cluster/leader" || true
			echo
		fi
	fi
}

systemctl daemon-reload
restart_sandboxd_with_diagnostics

cat <<EOF

=========================================================================
Cluster bootstrapped on this node.

  Node ID:           $NODE_ID
  API advertise URL: $API_ADVERTISE_URL
  Data-plane host:   $DATA_PLANE_ADVERTISE_HOST
  Raft advertise:    $RAFT_ADVERTISE_ADDR
  Gossip advertise:  $GOSSIP_ADVERTISE_ADDR

=========================================================================
GOSSIP SECRET KEY (save this — every joining node needs the same value):

  $GOSSIP_SECRET_KEY

EOF

if [[ "$GENERATED_KEY" == "true" ]]; then
	echo "Key was auto-generated. Store it in your secrets manager now."
	echo
fi

cat <<EOF
=========================================================================
TLS TRUST BUNDLE (ca.crt only — ca.key stays outside the daemon directory):

  $TLS_BUNDLE_OUT

CREDENTIAL BUNDLE (sealed-secret encryption key — separate artefact):

  $CRED_BUNDLE_OUT

CA signer: $CA_DIR (move this directory to an offline signer/HSM after provisioning).
ca.key never leaves the signer. Joiners generate node.key + CSR locally;
sign on the seed with scripts/cluster-sign-node.sh (see setup/cluster.md).
=========================================================================

To add another node:

  # On joiner — unpack ca.crt, generate CSR, then pause for signing:
  scp this-host:$TLS_BUNDLE_OUT /tmp/aerolvm-tls-bundle.tar.gz
  scp this-host:$CRED_BUNDLE_OUT /tmp/aerolvm-cred-bundle.tar.gz
  sudo ./cluster-join.sh \\
      --gossip-key '$GOSSIP_SECRET_KEY' \\
      --peers $GOSSIP_ADVERTISE_ADDR \\
      --tls-bundle /tmp/aerolvm-tls-bundle.tar.gz \\
      --cred-bundle /tmp/aerolvm-cred-bundle.tar.gz

  # cluster-join.sh prints the CSR path; copy it here and sign:
  sudo ./cluster-sign-node.sh --csr /tmp/node.csr --node-id <joiner-id> --out /tmp/node.crt
  # Copy /tmp/node.crt back to the joiner's /etc/sandboxd/tls/node.crt, then
  # re-run cluster-join.sh (or restart sandboxd once the cert is in place).
EOF

cat <<EOF

Verify membership from this node:

  curl -H "Authorization: Bearer <PAT>" http://127.0.0.1:${SB_API_PORT_DEFAULT}/v1/cluster/members
EOF
