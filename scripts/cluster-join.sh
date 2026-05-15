#!/usr/bin/env bash

# cluster-join.sh — join an existing AerolVM cluster.
#
# Run this on every node EXCEPT the one that ran cluster-init.sh. The seed
# node's printed gossip key + gossip-advertise address are required. install.sh
# must already have run on this host.

set -euo pipefail

NODE_ID=""
API_ADVERTISE_URL=""
RAFT_BIND_ADDR="0.0.0.0:7000"
RAFT_ADVERTISE_ADDR=""
GOSSIP_BIND_ADDR="0.0.0.0:7001"
GOSSIP_ADVERTISE_ADDR=""
GOSSIP_SECRET_KEY=""
PEERS=""
RAFT_DATA_DIR="/var/lib/sandboxd/raft"
TLS_DIR="/etc/sandboxd/tls"
TLS_BUNDLE=""
CRED_BUNDLE=""
CRED_KEY_PATH=""
INTERNAL_BIND_ADDR="0.0.0.0:7002"
INTERNAL_ADVERTISE_URL=""
NO_TLS="false"
FORCE="false"
MAX_AUTO_VOTERS="5"

usage() {
	cat <<'EOF'
Usage: cluster-join.sh --gossip-key <base64> --peers <host:port,...> [options]

Required:
  --gossip-key <base64>         Same gossip secret key the seed node printed.
                                Without an exact match, joining fails silently
                                (the gossip handshake is rejected).
  --peers <host:port,...>       Comma-separated list of gossip-advertise
                                addresses for one or more existing cluster
                                members. One reachable peer is enough.

Optional:
  --node-id <id>                Stable node identity. Default: hostname.
  --api-advertise-url <url>     URL other nodes use to forward writes back
                                to this node. Default: http://<primary-ip>:<api-port>.
  --raft-bind <host:port>       Raft listen address. Default: 0.0.0.0:7000
  --raft-advertise <host:port>  Raft address peers connect to. Default: derived.
  --gossip-bind <host:port>     Gossip listen address. Default: 0.0.0.0:7001
  --gossip-advertise <host:port> Gossip address peers connect to. Default: derived.
  --tls-bundle <path>           Path to the TLS bundle (tarball with ca.crt +
                                ca.key + credential_encryption.key) emitted by
                                cluster-init.sh on the seed. A fresh node cert
                                is signed locally from the bundled CA, and the
                                credential encryption key is installed so this
                                node can decrypt sealed registry/mount creds
                                replicated via raft. Required unless --no-tls.
  --cred-bundle <path>          In --no-tls mode, path to the standalone
                                credential bundle (tarball with just
                                credential_encryption.key) emitted by
                                cluster-init.sh. Required when --no-tls is
                                set.
  --tls-dir <path>              Where to write the loaded TLS material.
                                Default: /etc/sandboxd/tls
  --credential-key-path <path>  Where to write the shared credential
                                encryption key.
                                Default: SB_CREDENTIAL_ENCRYPTION_KEY_PATH from
                                /etc/sandboxd/sandboxd.env, or
                                /var/lib/sandboxd/credential_encryption.key.
  --internal-bind <host:port>   Cluster-internal mTLS listen address.
                                Default: 0.0.0.0:7002
  --internal-advertise <url>    HTTPS URL peers dial for the internal channel.
                                Default: derived from primary IP + internal-bind port.
  --max-auto-voters <n>         Max Raft voters auto-promoted from gossip.
                                Additional nodes become non-voters. Default 5.
                                Set 0 for the old unlimited behavior.
  --no-tls                      Skip TLS. Cluster-internal channels ride over
                                the public API URL with PAT-only auth. ONLY
                                safe on a fully isolated network.
  --force                       Allow re-join even if the raft data dir
                                already exists (DESTROYS local raft state).
  --help                        Show this help.

Example:
  sudo ./cluster-join.sh \
      --gossip-key 'A1bC2dE3...==' \
      --peers 10.0.0.5:7001
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--node-id)            NODE_ID="$2"; shift 2 ;;
		--api-advertise-url)  API_ADVERTISE_URL="$2"; shift 2 ;;
		--raft-bind)          RAFT_BIND_ADDR="$2"; shift 2 ;;
		--raft-advertise)     RAFT_ADVERTISE_ADDR="$2"; shift 2 ;;
		--gossip-bind)        GOSSIP_BIND_ADDR="$2"; shift 2 ;;
		--gossip-advertise)   GOSSIP_ADVERTISE_ADDR="$2"; shift 2 ;;
		--gossip-key)         GOSSIP_SECRET_KEY="$2"; shift 2 ;;
		--peers)              PEERS="$2"; shift 2 ;;
		--tls-bundle)         TLS_BUNDLE="$2"; shift 2 ;;
		--cred-bundle)        CRED_BUNDLE="$2"; shift 2 ;;
		--tls-dir)            TLS_DIR="$2"; shift 2 ;;
		--credential-key-path) CRED_KEY_PATH="$2"; shift 2 ;;
		--internal-bind)      INTERNAL_BIND_ADDR="$2"; shift 2 ;;
		--internal-advertise) INTERNAL_ADVERTISE_URL="$2"; shift 2 ;;
		--max-auto-voters)    MAX_AUTO_VOTERS="$2"; shift 2 ;;
		--no-tls)             NO_TLS="true"; shift ;;
		--force)              FORCE="true"; shift ;;
		--help)               usage; exit 0 ;;
		*) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

if [[ $EUID -ne 0 ]]; then
	echo "cluster-join.sh must run as root" >&2
	exit 1
fi

if [[ -z "$GOSSIP_SECRET_KEY" || -z "$PEERS" ]]; then
	echo "--gossip-key and --peers are required" >&2
	usage
	exit 1
fi

if [[ "$NO_TLS" != "true" ]] && [[ -z "$TLS_BUNDLE" ]]; then
	echo "--tls-bundle is required (or pass --no-tls for plaintext private-network setups)." >&2
	echo "  The bundle is the tarball cluster-init.sh emits on the seed node." >&2
	exit 1
fi

if [[ "$NO_TLS" != "true" ]] && [[ ! -f "$TLS_BUNDLE" ]]; then
	echo "TLS bundle not found: $TLS_BUNDLE" >&2
	exit 1
fi

if [[ "$NO_TLS" == "true" ]] && [[ -z "$CRED_BUNDLE" ]]; then
	echo "--cred-bundle is required when --no-tls is set." >&2
	echo "  cluster-init.sh --no-tls emits aerolvm-cred-bundle.tar.gz on the seed;" >&2
	echo "  copy it here and pass --cred-bundle <path>." >&2
	echo "  Without it, this node cannot decrypt sealed registry/mount credentials" >&2
	echo "  replicated via raft, and recovered sandboxes will fail to pull images." >&2
	exit 1
fi

if [[ -n "$CRED_BUNDLE" ]] && [[ ! -f "$CRED_BUNDLE" ]]; then
	echo "Credential bundle not found: $CRED_BUNDLE" >&2
	exit 1
fi

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

if [[ -d "$RAFT_DATA_DIR" ]] && [[ -n "$(ls -A "$RAFT_DATA_DIR" 2>/dev/null || true)" ]]; then
	if [[ "$FORCE" != "true" ]]; then
		echo "Refusing to join: $RAFT_DATA_DIR is not empty." >&2
		echo "  This node already has raft state from a prior bootstrap or join." >&2
		echo "  Pass --force to wipe and re-join." >&2
		exit 1
	fi
	echo "WARNING: --force given; wiping $RAFT_DATA_DIR"
	rm -rf "$RAFT_DATA_DIR"
fi

DECODED_LEN="$(printf '%s' "$GOSSIP_SECRET_KEY" | base64 -d 2>/dev/null | wc -c | tr -d ' ')"
case "$DECODED_LEN" in
	16|24|32) ;;
	*)
		echo "Invalid --gossip-key: base64 must decode to 16, 24, or 32 bytes (got $DECODED_LEN)" >&2
		exit 1
		;;
esac

SB_API_PORT_DEFAULT="$(read_sandboxd_env_value SB_API_PORT)"
SB_API_PORT_DEFAULT="${SB_API_PORT_DEFAULT:-21212}"

primary_ip() {
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

PRIMARY_IP="$(primary_ip)"
if [[ -z "$PRIMARY_IP" ]]; then
	PRIMARY_IP="127.0.0.1"
fi

if [[ -z "$API_ADVERTISE_URL" ]]; then
	API_ADVERTISE_URL="http://${PRIMARY_IP}:${SB_API_PORT_DEFAULT}"
fi

derive_advertise() {
	local bind="$1"
	local port="${bind##*:}"
	echo "${PRIMARY_IP}:${port}"
}
if [[ -z "$RAFT_ADVERTISE_ADDR" ]];   then RAFT_ADVERTISE_ADDR="$(derive_advertise "$RAFT_BIND_ADDR")"; fi
if [[ -z "$GOSSIP_ADVERTISE_ADDR" ]]; then GOSSIP_ADVERTISE_ADDR="$(derive_advertise "$GOSSIP_BIND_ADDR")"; fi

# --- Cluster TLS material -------------------------------------------------
# Unpack the seed-emitted bundle (ca.crt + ca.key) and locally mint this
# node's keypair + signed cert. Only ca.crt + node.{crt,key} are needed at
# runtime; we keep ca.key on disk too (root-only) so future re-mints don't
# need a fresh bundle copy.
CLUSTER_SAN="aerolvm-cluster-node"
TLS_GENERATED="false"
if [[ "$NO_TLS" == "true" ]]; then
	echo "WARNING: --no-tls given; cluster-internal channels will use the public"
	echo "         API URL with PAT-only auth. Only safe on a fully isolated network."
else
	if ! command -v openssl >/dev/null 2>&1; then
		echo "openssl not found — required to mint a node cert from the TLS bundle." >&2
		exit 1
	fi

	mkdir -p "$TLS_DIR"
	chmod 0700 "$TLS_DIR"

	if [[ -f "$TLS_DIR/node.crt" ]]; then
		if [[ "$FORCE" != "true" ]]; then
			echo "Refusing to overwrite existing TLS material in $TLS_DIR." >&2
			echo "  Pass --force to regenerate." >&2
			exit 1
		fi
		echo "WARNING: --force given; regenerating TLS material in $TLS_DIR"
		rm -f "$TLS_DIR/ca.crt" "$TLS_DIR/ca.key" "$TLS_DIR/node.crt" "$TLS_DIR/node.key"
	fi

	# Extract bundle. tar will refuse path traversals; we restrict the file
	# list explicitly anyway.
	tar -C "$TLS_DIR" -xzf "$TLS_BUNDLE" ca.crt ca.key credential_encryption.key
	if [[ ! -f "$TLS_DIR/ca.crt" ]] || [[ ! -f "$TLS_DIR/ca.key" ]]; then
		echo "TLS bundle did not contain ca.crt + ca.key" >&2
		exit 1
	fi
	if [[ ! -f "$TLS_DIR/credential_encryption.key" ]]; then
		echo "TLS bundle did not contain credential_encryption.key" >&2
		echo "  Re-run cluster-init.sh on the seed with the updated script and copy" >&2
		echo "  the regenerated bundle. Without the shared key, this node cannot" >&2
		echo "  decrypt sealed registry/mount creds for failed-over sandboxes." >&2
		exit 1
	fi

	openssl genrsa -out "$TLS_DIR/node.key" 4096 2>/dev/null
	openssl req -new -key "$TLS_DIR/node.key" \
		-subj "/CN=$CLUSTER_SAN" \
		-out "$TLS_DIR/node.csr" 2>/dev/null

	cat > "$TLS_DIR/node.ext" <<EOF
subjectAltName = DNS:$CLUSTER_SAN
extendedKeyUsage = serverAuth, clientAuth
EOF

	openssl x509 -req -in "$TLS_DIR/node.csr" \
		-CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
		-out "$TLS_DIR/node.crt" -days 3650 -sha256 \
		-extfile "$TLS_DIR/node.ext" 2>/dev/null

	rm -f "$TLS_DIR/node.csr" "$TLS_DIR/node.ext" "$TLS_DIR/ca.srl"
	chmod 0600 "$TLS_DIR/ca.key" "$TLS_DIR/node.key"
	chmod 0644 "$TLS_DIR/ca.crt" "$TLS_DIR/node.crt"
	TLS_GENERATED="true"
fi

if [[ -z "$INTERNAL_ADVERTISE_URL" ]] && [[ "$NO_TLS" != "true" ]]; then
	INTERNAL_PORT="${INTERNAL_BIND_ADDR##*:}"
	INTERNAL_ADVERTISE_URL="https://${PRIMARY_IP}:${INTERNAL_PORT}"
fi

# --- Credential encryption key --------------------------------------------
# Sealed registry / mount creds replicated via raft are decrypted with this
# key on the failover owner. Every node must hold the seed-generated value.
# Source it from the TLS bundle (TLS path) or the standalone --cred-bundle
# (no-tls path), validate it, and install it at the daemon's configured key
# path so re-running install.sh later does not lazy-generate a divergent
# key file. We also write SB_CREDENTIAL_ENCRYPTION_KEY into cluster.env so
# the env var (highest precedence in pkg/secrets) carries the same value
# regardless of file state.
if [[ -z "$CRED_KEY_PATH" ]]; then
	CRED_KEY_PATH="$(read_sandboxd_env_value SB_CREDENTIAL_ENCRYPTION_KEY_PATH)"
	CRED_KEY_PATH="${CRED_KEY_PATH:-/var/lib/sandboxd/credential_encryption.key}"
fi

if [[ "$NO_TLS" == "true" ]]; then
	CRED_STAGE_DIR="$(mktemp -d)"
	tar -C "$CRED_STAGE_DIR" -xzf "$CRED_BUNDLE" credential_encryption.key
	if [[ ! -f "$CRED_STAGE_DIR/credential_encryption.key" ]]; then
		rm -rf "$CRED_STAGE_DIR"
		echo "Credential bundle did not contain credential_encryption.key" >&2
		exit 1
	fi
	CRED_KEY_SOURCE="$CRED_STAGE_DIR/credential_encryption.key"
else
	CRED_KEY_SOURCE="$TLS_DIR/credential_encryption.key"
fi

CRED_KEY_VALUE="$(tr -d '\n' < "$CRED_KEY_SOURCE")"
CRED_DECODED_LEN="$(printf '%s' "$CRED_KEY_VALUE" | base64 -d 2>/dev/null | wc -c | tr -d ' ')"
if [[ "$CRED_DECODED_LEN" != "32" ]]; then
	[[ "$NO_TLS" == "true" ]] && rm -rf "$CRED_STAGE_DIR"
	echo "Invalid credential key in bundle: base64 must decode to 32 bytes (got $CRED_DECODED_LEN)" >&2
	exit 1
fi

mkdir -p "$(dirname "$CRED_KEY_PATH")"
install -m 0600 "$CRED_KEY_SOURCE" "$CRED_KEY_PATH"

if [[ "$NO_TLS" == "true" ]]; then
	rm -rf "$CRED_STAGE_DIR"
fi

mkdir -p /etc/sandboxd
{
	cat <<EOF
# Managed by cluster-join.sh. Layered on top of /etc/sandboxd/sandboxd.env
# via the systemd drop-in at /etc/systemd/system/sandboxd.service.d/cluster.conf.
SB_ENABLE_CLUSTER=true
SB_CLUSTER_BOOTSTRAP=false
SB_NODE_ID=$NODE_ID
SB_API_ADVERTISE_URL=$API_ADVERTISE_URL
SB_RAFT_BIND_ADDR=$RAFT_BIND_ADDR
SB_RAFT_ADVERTISE_ADDR=$RAFT_ADVERTISE_ADDR
SB_RAFT_DATA_DIR=$RAFT_DATA_DIR
SB_GOSSIP_BIND_ADDR=$GOSSIP_BIND_ADDR
SB_GOSSIP_ADVERTISE_ADDR=$GOSSIP_ADVERTISE_ADDR
SB_GOSSIP_SECRET_KEY=$GOSSIP_SECRET_KEY
SB_BOOTSTRAP_PEERS=$PEERS
SB_CREDENTIAL_ENCRYPTION_KEY=$CRED_KEY_VALUE
SB_CREDENTIAL_ENCRYPTION_KEY_PATH=$CRED_KEY_PATH
SB_CLUSTER_MAX_AUTO_VOTERS=$MAX_AUTO_VOTERS
EOF
	if [[ "$TLS_GENERATED" == "true" ]]; then
		cat <<EOF
SB_CLUSTER_TLS_DIR=$TLS_DIR
SB_CLUSTER_INTERNAL_LISTEN=$INTERNAL_BIND_ADDR
SB_CLUSTER_INTERNAL_ADVERTISE=$INTERNAL_ADVERTISE_URL
EOF
	fi
} > /etc/sandboxd/cluster.env
chmod 0600 /etc/sandboxd/cluster.env

mkdir -p /etc/systemd/system/sandboxd.service.d
cat > /etc/systemd/system/sandboxd.service.d/cluster.conf <<'EOF'
[Service]
EnvironmentFile=/etc/sandboxd/cluster.env
EOF

systemctl daemon-reload
systemctl restart sandboxd

cat <<EOF

Joined cluster as node "$NODE_ID".

  API advertise URL: $API_ADVERTISE_URL
  Raft advertise:    $RAFT_ADVERTISE_ADDR
  Gossip advertise:  $GOSSIP_ADVERTISE_ADDR
  Bootstrap peers:   $PEERS

Verify on the seed node:

  curl -H "Authorization: Bearer <PAT>" http://<seed>:${SB_API_PORT_DEFAULT}/v1/cluster/members

The seed's leader will auto-promote this node to a raft voter once the gossip
join lands. If membership doesn't show up within ~30s, check:

  - SB_GOSSIP_SECRET_KEY matches the seed node exactly.
  - $GOSSIP_ADVERTISE_ADDR is reachable from the seed (firewall, security group).
  - $RAFT_ADVERTISE_ADDR is reachable from the seed (raft replication needs it).
  - sandboxd.service status: systemctl status sandboxd
EOF
