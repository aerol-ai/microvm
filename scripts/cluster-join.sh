#!/usr/bin/env bash

# cluster-join.sh — join an existing AerolVM cluster.
#
# Run this on every node EXCEPT the one that ran cluster-init.sh. The seed
# node's printed gossip key + gossip-advertise address are required. install.sh
# must already have run on this host.

set -euo pipefail

NODE_ID=""
API_ADVERTISE_URL=""
DATA_PLANE_ADVERTISE_HOST=""
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
SIGNED_CERT=""
INTERNAL_BIND_ADDR="0.0.0.0:7002"
INTERNAL_ADVERTISE_URL=""
FORCE="false"
MAX_AUTO_VOTERS="5"
NODE_ROLE=""
INGRESS_ADVERTISE_HOST=""

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
  --data-plane-advertise-host <host>
                                Host/IP other nodes use for sandbox ingress
                                (HTTP/SNI passthrough and raw TCP proxying).
                                Default: <primary-ip>. Set this separately
                                when API traffic uses a load balancer or
                                API-only DNS name.
  --raft-bind <host:port>       Raft listen address. Default: 0.0.0.0:7000
  --raft-advertise <host:port>  Raft address peers connect to. Default: derived.
  --gossip-bind <host:port>     Gossip listen address. Default: 0.0.0.0:7001
  --gossip-advertise <host:port> Gossip address peers connect to. Default: derived.
  --tls-bundle <path>           Path to the TLS trust bundle (tarball with
                                ca.crt ONLY) from cluster-init.sh. This node
                                generates node.key + CSR locally; the seed
                                signs via cluster-sign-node.sh (ca.key never
                                leaves the seed). Required.
  --cred-bundle <path>          Credential encryption key bundle (tarball
                                with credential_encryption.key). Required
                                always. Kept separate from
                                the CA trust bundle on purpose.
  --signed-cert <path>          Pre-signed node.crt from cluster-sign-node.sh.
                                When omitted, this script writes node.csr and
                                exits with instructions to sign on the seed.
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
  --role <role>                 SB_NODE_ROLE for this daemon. One of server,
                                worker, ingress, mixed — or a comma-separated
                                combination of server / worker / ingress (e.g.
                                "worker,ingress" for a data-plane edge node
                                that owns sandboxes AND fans out public
                                ingress without joining the raft quorum).
                                Default mixed, for clusters through 10 live
                                nodes only. Clusters above 10 live nodes must
                                use dedicated server, worker, and ingress
                                roles; mixed and hybrid-role members block
                                placement. A role set without "server" /
                                "mixed" never becomes a raft voter even after
                                gossip join. "mixed" cannot be combined with
                                other tokens.
  --ingress-advertise-host <h>  SB_INGRESS_ADVERTISE_HOST — the public host
                                in SDK-returned sandbox URLs. Defaults to
                                empty (URLs use SB_PUBLIC_HOST or SB_DOMAIN).
                                Required when running a dedicated ingress
                                tier so SDK URLs resolve there.
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
		--data-plane-advertise-host) DATA_PLANE_ADVERTISE_HOST="$2"; shift 2 ;;
		--raft-bind)          RAFT_BIND_ADDR="$2"; shift 2 ;;
		--raft-advertise)     RAFT_ADVERTISE_ADDR="$2"; shift 2 ;;
		--gossip-bind)        GOSSIP_BIND_ADDR="$2"; shift 2 ;;
		--gossip-advertise)   GOSSIP_ADVERTISE_ADDR="$2"; shift 2 ;;
		--gossip-key)         GOSSIP_SECRET_KEY="$2"; shift 2 ;;
		--peers)              PEERS="$2"; shift 2 ;;
		--tls-bundle)         TLS_BUNDLE="$2"; shift 2 ;;
		--cred-bundle)        CRED_BUNDLE="$2"; shift 2 ;;
		--signed-cert)        SIGNED_CERT="$2"; shift 2 ;;
		--tls-dir)            TLS_DIR="$2"; shift 2 ;;
		--credential-key-path) CRED_KEY_PATH="$2"; shift 2 ;;
		--internal-bind)      INTERNAL_BIND_ADDR="$2"; shift 2 ;;
		--internal-advertise) INTERNAL_ADVERTISE_URL="$2"; shift 2 ;;
		--max-auto-voters)    MAX_AUTO_VOTERS="$2"; shift 2 ;;
		--role)               NODE_ROLE="$2"; shift 2 ;;
		--ingress-advertise-host) INGRESS_ADVERTISE_HOST="$2"; shift 2 ;;
		--force)              FORCE="true"; shift ;;
		--help)               usage; exit 0 ;;
		*) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

if [[ $EUID -ne 0 ]]; then
	echo "cluster-join.sh must run as root" >&2
	exit 1
fi

# Accepts a single role or a comma-separated combination (e.g.
# "worker,ingress"). "mixed" cannot be combined with other tokens. Unlike
# cluster-init.sh there is no "must contain server" constraint — a joiner can
# be any combination, including pure worker / ingress / worker,ingress.
validate_node_role() {
	local raw="$1"
	if [[ -z "$raw" ]]; then return 0; fi
	local has_mixed="false" token_count=0
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
			server|worker|ingress) ;;
			mixed) has_mixed="true" ;;
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
}
validate_node_role "$NODE_ROLE"

if [[ -z "$GOSSIP_SECRET_KEY" || -z "$PEERS" ]]; then
	echo "--gossip-key and --peers are required" >&2
	usage
	exit 1
fi

if [[ -z "$TLS_BUNDLE" ]]; then
	echo "--tls-bundle is required." >&2
	echo "  The bundle is the tarball cluster-init.sh emits on the seed node." >&2
	exit 1
fi

if [[ ! -f "$TLS_BUNDLE" ]]; then
	echo "TLS bundle not found: $TLS_BUNDLE" >&2
	exit 1
fi

if [[ -z "$CRED_BUNDLE" ]]; then
	echo "--cred-bundle is required (credential encryption key ships separately from ca.crt)." >&2
	echo "  cluster-init.sh emits aerolvm-cred-bundle.tar.gz on the seed;" >&2
	echo "  copy it here and pass --cred-bundle <path>." >&2
	exit 1
fi

if [[ ! -f "$CRED_BUNDLE" ]]; then
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

derive_advertise() {
	local bind="$1"
	local port="${bind##*:}"
	echo "${PRIMARY_IP}:${port}"
}
if [[ -z "$RAFT_ADVERTISE_ADDR" ]];   then RAFT_ADVERTISE_ADDR="$(derive_advertise "$RAFT_BIND_ADDR")"; fi
if [[ -z "$GOSSIP_ADVERTISE_ADDR" ]]; then GOSSIP_ADVERTISE_ADDR="$(derive_advertise "$GOSSIP_BIND_ADDR")"; fi

# --- Cluster TLS material -------------------------------------------------
# Unpack ca.crt from the seed trust bundle, generate node.key + CSR locally.
# Signing uses ca.key only on the seed (cluster-sign-node.sh). Never require
# or unpack ca.key on joiners.
CLUSTER_SAN="aerolvm-cluster-node"
	if ! command -v openssl >/dev/null 2>&1; then
		echo "openssl not found — required to mint a node key/CSR." >&2
		exit 1
	fi

	mkdir -p "$TLS_DIR"
	chmod 0700 "$TLS_DIR"

	if [[ -f "$TLS_DIR/node.crt" && -z "$SIGNED_CERT" ]]; then
		if [[ "$FORCE" != "true" ]]; then
			echo "Refusing to overwrite existing TLS material in $TLS_DIR." >&2
			echo "  Pass --force to regenerate, or --signed-cert <path> to install a new cert." >&2
			exit 1
		fi
		echo "WARNING: --force given; regenerating TLS material in $TLS_DIR"
		rm -f "$TLS_DIR/ca.crt" "$TLS_DIR/ca.key" "$TLS_DIR/node.crt" "$TLS_DIR/node.key" "$TLS_DIR/node.csr"
	fi

	# Accept exactly the generated trust-bundle shape. A bundle carrying a CA
	# private key is a security incident, not something a worker should repair.
	BUNDLE_ENTRIES="$(tar -tzf "$TLS_BUNDLE" 2>/dev/null)" || {
		echo "TLS trust bundle is not a readable gzip tar archive" >&2
		exit 1
	}
	if [[ "$BUNDLE_ENTRIES" != "ca.crt" ]]; then
		echo "TLS trust bundle must contain exactly ca.crt" >&2
		exit 1
	fi
	tar -C "$TLS_DIR" -xzf "$TLS_BUNDLE" ca.crt

	if [[ -n "$SIGNED_CERT" ]]; then
		if [[ ! -f "$SIGNED_CERT" ]]; then
			echo "Signed cert not found: $SIGNED_CERT" >&2
			exit 1
		fi
		if [[ ! -f "$TLS_DIR/node.key" ]]; then
			echo "node.key missing under $TLS_DIR — generate CSR first (run without --signed-cert)." >&2
			exit 1
		fi
		install -m 0644 "$SIGNED_CERT" "$TLS_DIR/node.crt"
		chmod 0600 "$TLS_DIR/node.key"
		chmod 0644 "$TLS_DIR/ca.crt" "$TLS_DIR/node.crt"
		rm -f "$TLS_DIR/node.csr"
	else
		if [[ ! -f "$TLS_DIR/node.key" ]]; then
			openssl genrsa -out "$TLS_DIR/node.key" 4096 2>/dev/null
			chmod 0600 "$TLS_DIR/node.key"
		fi
		openssl req -new -key "$TLS_DIR/node.key" \
			-subj "/CN=$CLUSTER_SAN" \
			-out "$TLS_DIR/node.csr" 2>/dev/null
		chmod 0644 "$TLS_DIR/ca.crt" "$TLS_DIR/node.csr"
		cat <<EOF >&2
=========================================================================
CSR ready — ca.key is NOT on this host. Sign on the seed:

  scp $TLS_DIR/node.csr seed:/tmp/${NODE_ID}.csr
  # on seed:
  sudo ./cluster-sign-node.sh --csr /tmp/${NODE_ID}.csr --node-id ${NODE_ID} --out /tmp/${NODE_ID}.crt
  # back on this host:
  scp seed:/tmp/${NODE_ID}.crt /tmp/node.crt
  sudo ./cluster-join.sh ... --tls-bundle $TLS_BUNDLE --cred-bundle $CRED_BUNDLE --signed-cert /tmp/node.crt

Stopping before daemon restart (node.crt not installed yet).
=========================================================================
EOF
		exit 2
	fi

if [[ -z "$INTERNAL_ADVERTISE_URL" ]]; then
	INTERNAL_PORT="${INTERNAL_BIND_ADDR##*:}"
	INTERNAL_ADVERTISE_URL="https://${PRIMARY_IP}:${INTERNAL_PORT}"
fi

# --- Credential encryption key --------------------------------------------
# Always sourced from --cred-bundle (never from the ca.crt trust tarball).
if [[ -z "$CRED_KEY_PATH" ]]; then
	CRED_KEY_PATH="$(read_sandboxd_env_value SB_CREDENTIAL_ENCRYPTION_KEY_PATH)"
	CRED_KEY_PATH="${CRED_KEY_PATH:-/var/lib/sandboxd/credential_encryption.key}"
fi

CRED_STAGE_DIR="$(mktemp -d)"
tar -C "$CRED_STAGE_DIR" -xzf "$CRED_BUNDLE" credential_encryption.key
if [[ ! -f "$CRED_STAGE_DIR/credential_encryption.key" ]]; then
	rm -rf "$CRED_STAGE_DIR"
	echo "Credential bundle did not contain credential_encryption.key" >&2
	exit 1
fi
CRED_KEY_SOURCE="$CRED_STAGE_DIR/credential_encryption.key"

CRED_KEY_VALUE="$(tr -d '\n' < "$CRED_KEY_SOURCE")"
CRED_DECODED_LEN="$(printf '%s' "$CRED_KEY_VALUE" | base64 -d 2>/dev/null | wc -c | tr -d ' ')"
if [[ "$CRED_DECODED_LEN" != "32" ]]; then
	rm -rf "$CRED_STAGE_DIR"
	echo "Invalid credential key in bundle: base64 must decode to 32 bytes (got $CRED_DECODED_LEN)" >&2
	exit 1
fi

mkdir -p "$(dirname "$CRED_KEY_PATH")"
install -m 0600 "$CRED_KEY_SOURCE" "$CRED_KEY_PATH"
rm -rf "$CRED_STAGE_DIR"

mkdir -p /etc/sandboxd
{
	cat <<EOF
# Managed by cluster-join.sh. Layered on top of /etc/sandboxd/sandboxd.env
# via the systemd drop-in at /etc/systemd/system/sandboxd.service.d/cluster.conf.
SB_ENABLE_CLUSTER=true
SB_CLUSTER_BOOTSTRAP=false
SB_NODE_ID=$NODE_ID
SB_API_ADVERTISE_URL=$API_ADVERTISE_URL
SB_DATA_PLANE_ADVERTISE_HOST=$DATA_PLANE_ADVERTISE_HOST
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
	echo "[cluster-join] restarting sandboxd with cluster mode enabled"
	if ! systemctl restart sandboxd; then
		echo "[cluster-join] sandboxd restart failed; dumping status and recent journal" >&2
		systemctl status sandboxd --no-pager -n 80 >&2 || true
		journalctl -u sandboxd --no-pager -n 160 >&2 || true
		exit 1
	fi

	echo "[cluster-join] sandboxd restart succeeded"
	systemctl is-active sandboxd || true
	systemctl show sandboxd \
		-p ActiveState -p SubState -p MainPID -p NRestarts -p ExecMainStatus \
		--no-pager || true
	echo "[cluster-join] listeners on cluster ports"
	ss -ltnup 2>/dev/null | grep -E ':(7000|7001|7002|21212)\b' || echo "(nothing listening on cluster ports yet)"
	if command -v curl >/dev/null 2>&1; then
		echo "[cluster-join] local /health"
		curl -sS --max-time 5 "http://127.0.0.1:${SB_API_PORT_DEFAULT}/health" || true
		echo
		local pat
		pat="$(read_sandboxd_env_value SB_PAT_TOKEN)"
		if [[ -n "$pat" ]]; then
			echo "[cluster-join] local /v1/cluster/members"
			curl -sS --max-time 5 -H "Authorization: Bearer ${pat}" \
				"http://127.0.0.1:${SB_API_PORT_DEFAULT}/v1/cluster/members" || true
			echo
			echo "[cluster-join] local /v1/cluster/leader"
			curl -sS --max-time 5 -H "Authorization: Bearer ${pat}" \
				"http://127.0.0.1:${SB_API_PORT_DEFAULT}/v1/cluster/leader" || true
			echo
		fi
	fi
}

systemctl daemon-reload
restart_sandboxd_with_diagnostics

cat <<EOF

Joined cluster as node "$NODE_ID".

  API advertise URL: $API_ADVERTISE_URL
  Data-plane host:   $DATA_PLANE_ADVERTISE_HOST
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
