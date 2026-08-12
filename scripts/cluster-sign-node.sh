#!/usr/bin/env bash

# cluster-sign-node.sh — sign a joining node's CSR with the seed CA private key.
#
# The CA private key (ca.key) MUST stay on the seed (or an offline HSM/vault).
# Joiners generate node.key + CSR locally and never receive ca.key.
#
# Usage (on the seed, after the joiner copies its CSR):
#   sudo ./cluster-sign-node.sh \
#       --csr /tmp/node.csr \
#       --node-id worker-2 \
#       --out /tmp/node.crt
#
# Then copy node.crt back to the joiner's /etc/sandboxd/tls/node.crt.

set -euo pipefail

CSR=""
NODE_ID=""
OUT=""
TLS_DIR="/etc/sandboxd/tls"
CLUSTER_SAN="aerolvm-cluster-node"
DAYS="${CERT_DAYS:-90}"

usage() {
	cat <<'EOF'
Usage: cluster-sign-node.sh --csr <path> --node-id <id> --out <path> [options]

Sign a joining node's certificate signing request with the seed's ca.key.
ca.key never leaves the seed.

Node certs are intentionally short-lived (default 90 days via CERT_DAYS /
--days). Rotate by re-running cluster-join / this script with a fresh CSR.
Revocation is pragmatic: remove the node from the cluster CA trust path
(reissue CA or stop distributing ca.crt that chains to the old leaf) and
reissue remaining nodes — there is no CRL/OCSP in the daemon.

Required:
  --csr <path>       Path to the joiner's CSR (PEM).
  --node-id <id>     Gossip node id; minted as DNS SAN node:<id>.
  --out <path>       Where to write the signed node.crt.

Optional:
  --tls-dir <path>   Directory with ca.crt + ca.key. Default: /etc/sandboxd/tls
  --days <n>         Certificate lifetime in days. Default: CERT_DAYS or 90
  --help             Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--csr)      CSR="$2"; shift 2 ;;
		--node-id)  NODE_ID="$2"; shift 2 ;;
		--out)      OUT="$2"; shift 2 ;;
		--tls-dir)  TLS_DIR="$2"; shift 2 ;;
		--days)     DAYS="$2"; shift 2 ;;
		--help|-h)  usage; exit 0 ;;
		*) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
	esac
done

if [[ -z "$CSR" || -z "$NODE_ID" || -z "$OUT" ]]; then
	echo "--csr, --node-id, and --out are required." >&2
	usage >&2
	exit 1
fi
if [[ ! -f "$CSR" ]]; then
	echo "CSR not found: $CSR" >&2
	exit 1
fi
if [[ ! -f "$TLS_DIR/ca.crt" || ! -f "$TLS_DIR/ca.key" ]]; then
	echo "Seed CA material missing under $TLS_DIR (need ca.crt + ca.key)." >&2
	exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
	echo "openssl is required." >&2
	exit 1
fi

EXT="$(mktemp)"
trap 'rm -f "$EXT"' EXIT
cat > "$EXT" <<EOF
subjectAltName = DNS:$CLUSTER_SAN,DNS:node:${NODE_ID}
extendedKeyUsage = serverAuth, clientAuth
EOF

openssl x509 -req -in "$CSR" \
	-CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
	-out "$OUT" -days "$DAYS" -sha256 \
	-extfile "$EXT" 2>/dev/null

chmod 0644 "$OUT"
rm -f "$TLS_DIR/ca.srl" 2>/dev/null || true
echo "Signed node cert for node:$NODE_ID -> $OUT"
