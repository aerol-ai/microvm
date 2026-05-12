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
RAFT_BIND_ADDR="0.0.0.0:7000"
RAFT_ADVERTISE_ADDR=""
GOSSIP_BIND_ADDR="0.0.0.0:7001"
GOSSIP_ADVERTISE_ADDR=""
GOSSIP_SECRET_KEY=""
RAFT_DATA_DIR="/var/lib/sandboxd/raft"
FORCE="false"

usage() {
	cat <<'EOF'
Usage: cluster-init.sh [options]

Bootstrap the first node of an AerolVM cluster. Run install.sh first.

Options:
  --node-id <id>                Stable node identity. Default: hostname.
  --api-advertise-url <url>     URL other nodes use to forward writes back to
                                this node. Default: http://<primary-ip>:21212
                                (port read from SB_API_PORT in sandboxd.env).
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
		--raft-bind)          RAFT_BIND_ADDR="$2"; shift 2 ;;
		--raft-advertise)     RAFT_ADVERTISE_ADDR="$2"; shift 2 ;;
		--gossip-bind)        GOSSIP_BIND_ADDR="$2"; shift 2 ;;
		--gossip-advertise)   GOSSIP_ADVERTISE_ADDR="$2"; shift 2 ;;
		--gossip-key)         GOSSIP_SECRET_KEY="$2"; shift 2 ;;
		--force)              FORCE="true"; shift ;;
		--help)               usage; exit 0 ;;
		*) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

if [[ $EUID -ne 0 ]]; then
	echo "cluster-init.sh must run as root" >&2
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
SB_API_PORT_DEFAULT="$(grep -E '^SB_API_PORT=' /etc/sandboxd/sandboxd.env | tail -n1 | cut -d= -f2-)"
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

mkdir -p /etc/sandboxd
cat > /etc/sandboxd/cluster.env <<EOF
# Managed by cluster-init.sh. Layered on top of /etc/sandboxd/sandboxd.env
# via the systemd drop-in at /etc/systemd/system/sandboxd.service.d/cluster.conf.
SB_ENABLE_CLUSTER=true
SB_CLUSTER_BOOTSTRAP=true
SB_NODE_ID=$NODE_ID
SB_API_ADVERTISE_URL=$API_ADVERTISE_URL
SB_RAFT_BIND_ADDR=$RAFT_BIND_ADDR
SB_RAFT_ADVERTISE_ADDR=$RAFT_ADVERTISE_ADDR
SB_RAFT_DATA_DIR=$RAFT_DATA_DIR
SB_GOSSIP_BIND_ADDR=$GOSSIP_BIND_ADDR
SB_GOSSIP_ADVERTISE_ADDR=$GOSSIP_ADVERTISE_ADDR
SB_GOSSIP_SECRET_KEY=$GOSSIP_SECRET_KEY
EOF
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
To add another node to this cluster, run on that host:

  sudo ./cluster-join.sh \\
      --gossip-key '$GOSSIP_SECRET_KEY' \\
      --peers $GOSSIP_ADVERTISE_ADDR

Verify membership from this node:

  curl -H "Authorization: Bearer <PAT>" http://127.0.0.1:${SB_API_PORT_DEFAULT}/v1/cluster/members
EOF
