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
FORCE="false"

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

if [[ ! -f /etc/sandboxd/sandboxd.env ]]; then
	echo "Missing /etc/sandboxd/sandboxd.env — run install.sh first" >&2
	exit 1
fi
if [[ ! -f /etc/systemd/system/sandboxd.service ]]; then
	echo "Missing /etc/systemd/system/sandboxd.service — run install.sh first" >&2
	exit 1
fi

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

SB_API_PORT_DEFAULT="$(grep -E '^SB_API_PORT=' /etc/sandboxd/sandboxd.env | tail -n1 | cut -d= -f2-)"
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

mkdir -p /etc/sandboxd
cat > /etc/sandboxd/cluster.env <<EOF
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
