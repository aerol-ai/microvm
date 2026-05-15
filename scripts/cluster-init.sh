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
INTERNAL_BIND_ADDR="0.0.0.0:7002"
INTERNAL_ADVERTISE_URL=""
NO_TLS="false"
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
  --tls-dir <path>              Directory for cluster TLS material (CA + node
                                cert). Default: /etc/sandboxd/tls
  --internal-bind <host:port>   Cluster-internal mTLS listen address (used for
                                leader-forwarded raft applies). Default: 0.0.0.0:7002
  --internal-advertise <url>    HTTPS URL peers dial for the internal channel.
                                Default: derived from primary IP + internal-bind port.
  --tls-bundle-out <path>       Where to save the TLS bundle (tarball with CA +
                                CA key + credential encryption key) for
                                distribution to joining nodes.
                                Default: ./aerolvm-tls-bundle.tar.gz
  --credential-key-path <path>  Path to the credential encryption key file.
                                Default: SB_CREDENTIAL_ENCRYPTION_KEY_PATH from
                                /etc/sandboxd/sandboxd.env, or
                                /var/lib/sandboxd/credential_encryption.key.
                                If the file is missing, a fresh 32-byte key is
                                generated and written here.
  --cred-bundle-out <path>      In --no-tls mode, where to save the standalone
                                credential bundle (tarball with just the
                                credential encryption key) for distribution to
                                joining nodes.
                                Default: ./aerolvm-cred-bundle.tar.gz
  --max-auto-voters <n>         Max Raft voters auto-promoted from gossip.
                                Additional nodes become non-voters. Default 5.
                                Set 0 for the old unlimited behavior.
  --role <role>                 SB_NODE_ROLE for this daemon. One of
                                server, worker, ingress, mixed. Default mixed
                                (every component on every node — fine for
                                small clusters; use server/worker/ingress to
                                split components at 10+ nodes). The bootstrap
                                node must be server or mixed; worker/ingress
                                refuse to bootstrap a fresh cluster.
  --ingress-advertise-host <h>  SB_INGRESS_ADVERTISE_HOST — the public host
                                in SDK-returned sandbox URLs. Defaults to
                                empty (URLs use SB_PUBLIC_HOST or
                                SB_DOMAIN). Set this to your wildcard-DNS
                                ingress endpoint when running a dedicated
                                ingress tier.
  --no-tls                      Skip TLS generation. Cluster-internal channels
                                ride over the public API URL with PAT-only auth.
                                ONLY safe on a fully isolated private network.
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
		--internal-bind)      INTERNAL_BIND_ADDR="$2"; shift 2 ;;
		--internal-advertise) INTERNAL_ADVERTISE_URL="$2"; shift 2 ;;
		--tls-bundle-out)     TLS_BUNDLE_OUT="$2"; shift 2 ;;
		--credential-key-path) CRED_KEY_PATH="$2"; shift 2 ;;
		--cred-bundle-out)    CRED_BUNDLE_OUT="$2"; shift 2 ;;
		--max-auto-voters)    MAX_AUTO_VOTERS="$2"; shift 2 ;;
		--role)               NODE_ROLE="$2"; shift 2 ;;
		--ingress-advertise-host) INGRESS_ADVERTISE_HOST="$2"; shift 2 ;;
		--no-tls)             NO_TLS="true"; shift ;;
		--force)              FORCE="true"; shift ;;
		--help)               usage; exit 0 ;;
		*) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

if [[ $EUID -ne 0 ]]; then
	echo "cluster-init.sh must run as root" >&2
	exit 1
fi

# Validate --role early. cluster-init bootstraps raft, so the role must be one
# that participates in raft voting (server or mixed). Worker/ingress nodes are
# joiners — they use cluster-join.sh, not this script.
case "$NODE_ROLE" in
	""|server|mixed) ;;
	worker|ingress)
		echo "cluster-init.sh cannot bootstrap with --role=$NODE_ROLE (use cluster-join.sh on a worker/ingress node, or pick server/mixed here)" >&2
		exit 1
		;;
	*)
		echo "Unknown --role=$NODE_ROLE (allowed: server, worker, ingress, mixed)" >&2
		exit 1
		;;
esac

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
# Generated once on the seed; the CA + CA key go into a tarball that the
# operator copies to each joining node. The CA key is NOT required at daemon
# runtime — only at join-time so cluster-join.sh can mint a fresh node cert.
# We still keep ca.key under root-only perms to limit blast radius if a node
# is compromised: the attacker needs root + the file to mint joiner certs.
CLUSTER_SAN="aerolvm-cluster-node"
TLS_GENERATED="false"
if [[ "$NO_TLS" == "true" ]]; then
	echo "WARNING: --no-tls given; cluster-internal channels will ride over the public API"
	echo "         URL with PAT-only auth. Only safe on a fully isolated network."
else
	if ! command -v openssl >/dev/null 2>&1; then
		echo "openssl not found — required for cluster TLS." >&2
		echo "Install openssl, or pass --no-tls to skip (NOT recommended)." >&2
		exit 1
	fi

	mkdir -p "$TLS_DIR"
	chmod 0700 "$TLS_DIR"

	if [[ -f "$TLS_DIR/ca.crt" ]] || [[ -f "$TLS_DIR/node.crt" ]]; then
		if [[ "$FORCE" != "true" ]]; then
			echo "Refusing to overwrite existing TLS material in $TLS_DIR." >&2
			echo "  Pass --force to regenerate (will invalidate joined nodes' trust)." >&2
			exit 1
		fi
		echo "WARNING: --force given; regenerating TLS material in $TLS_DIR"
		rm -f "$TLS_DIR/ca.crt" "$TLS_DIR/ca.key" "$TLS_DIR/node.crt" "$TLS_DIR/node.key"
	fi

	# 1. CA. 10-year lifetime — operators rotate by re-running cluster-init
	#    with --force and re-distributing the bundle. Long-lived intentionally
	#    because the CA only signs cluster-internal node certs (never anything
	#    user-visible).
	openssl genrsa -out "$TLS_DIR/ca.key" 4096 2>/dev/null
	openssl req -x509 -new -nodes -key "$TLS_DIR/ca.key" -sha256 -days 3650 \
		-subj "/CN=AerolVM Cluster CA" \
		-out "$TLS_DIR/ca.crt" 2>/dev/null

	# 2. This node's keypair + cert. CN/SAN is fixed (clusterServerName in
	#    Go); SAN intentionally doesn't include IP/hostname because the daemon
	#    uses ServerName-based verification, not address-based.
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

	# Bundle CA + CA key + credential encryption key for joiners. Uses tar
	# so the operator can scp/curl a single artefact. This file MUST be
	# transferred over a secure channel — anyone with the bundle can mint
	# a node cert and join the cluster, AND can decrypt every sandbox's
	# sealed registry/mount credentials.
	if [[ -z "$TLS_BUNDLE_OUT" ]]; then
		TLS_BUNDLE_OUT="$(pwd)/aerolvm-tls-bundle.tar.gz"
	fi
	# Stage the credential key inside TLS_DIR (root-only) so all bundle
	# entries share one tar root. Copy rather than move — the original at
	# CRED_KEY_PATH must remain so the daemon can keep reading it.
	install -m 0600 "$CRED_KEY_PATH" "$TLS_DIR/credential_encryption.key"
	tar -C "$TLS_DIR" -czf "$TLS_BUNDLE_OUT" ca.crt ca.key credential_encryption.key
	chmod 0600 "$TLS_BUNDLE_OUT"
	TLS_GENERATED="true"
fi

# In --no-tls mode we still need to ship the credential key. Emit a tiny
# standalone bundle so the joiner has a uniform extraction path.
CRED_BUNDLE_GENERATED="false"
if [[ "$NO_TLS" == "true" ]]; then
	if [[ -z "$CRED_BUNDLE_OUT" ]]; then
		CRED_BUNDLE_OUT="$(pwd)/aerolvm-cred-bundle.tar.gz"
	fi
	CRED_STAGE_DIR="$(mktemp -d)"
	install -m 0600 "$CRED_KEY_PATH" "$CRED_STAGE_DIR/credential_encryption.key"
	tar -C "$CRED_STAGE_DIR" -czf "$CRED_BUNDLE_OUT" credential_encryption.key
	chmod 0600 "$CRED_BUNDLE_OUT"
	rm -rf "$CRED_STAGE_DIR"
	CRED_BUNDLE_GENERATED="true"
fi

# Derive internal advertise URL when operator didn't override.
if [[ -z "$INTERNAL_ADVERTISE_URL" ]] && [[ "$NO_TLS" != "true" ]]; then
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
	if [[ "$TLS_GENERATED" == "true" ]]; then
		cat <<EOF
SB_CLUSTER_TLS_DIR=$TLS_DIR
SB_CLUSTER_INTERNAL_LISTEN=$INTERNAL_BIND_ADDR
SB_CLUSTER_INTERNAL_ADVERTISE=$INTERNAL_ADVERTISE_URL
EOF
	else
		echo "SB_CLUSTER_INSECURE_GOSSIP=false  # TLS off — relying on private network"
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

if [[ "$TLS_GENERATED" == "true" ]]; then
	cat <<EOF
=========================================================================
TLS BUNDLE (CA cert + CA key + credential encryption key —
            required by every joining node):

  $TLS_BUNDLE_OUT

Copy this file to each joining node over a SECURE channel (scp, vault).
Anyone with the bundle can mint a node cert AND decrypt every sandbox's
sealed registry/mount credentials.
=========================================================================

To add another node, on that host:

  scp this-host:$TLS_BUNDLE_OUT /tmp/aerolvm-tls-bundle.tar.gz   # secure transfer
  sudo ./cluster-join.sh \\
      --gossip-key '$GOSSIP_SECRET_KEY' \\
      --peers $GOSSIP_ADVERTISE_ADDR \\
      --tls-bundle /tmp/aerolvm-tls-bundle.tar.gz
EOF
else
	cat <<EOF
=========================================================================
CREDENTIAL BUNDLE (sealed-secret encryption key —
                   required by every joining node):

  $CRED_BUNDLE_OUT

Copy this file to each joining node over a SECURE channel (scp, vault).
Anyone with the bundle can decrypt every sandbox's sealed registry/mount
credentials.
=========================================================================

To add another node (NO TLS — keep all traffic on a private network), run:

  scp this-host:$CRED_BUNDLE_OUT /tmp/aerolvm-cred-bundle.tar.gz   # secure transfer
  sudo ./cluster-join.sh \\
      --gossip-key '$GOSSIP_SECRET_KEY' \\
      --peers $GOSSIP_ADVERTISE_ADDR \\
      --cred-bundle /tmp/aerolvm-cred-bundle.tar.gz \\
      --no-tls
EOF
fi

cat <<EOF

Verify membership from this node:

  curl -H "Authorization: Bearer <PAT>" http://127.0.0.1:${SB_API_PORT_DEFAULT}/v1/cluster/members
EOF
