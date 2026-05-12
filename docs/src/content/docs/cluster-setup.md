---
title: Cluster Setup
---

A multi-node AerolVM cluster lets sandboxes be placed across many hosts while keeping the API surface single-node-identical: clients call any node, and forwarding happens transparently. Cluster mode is opt-in - existing single-node installs are unaffected.

## When to use cluster mode

Single-node installs ([Server Setup](/getting-started)) handle every workload that fits on one host. Move to a cluster when you need:

- More concurrent sandboxes than a single host can hold.
- Per-node failure isolation - the loss of one node only affects the sandboxes it owned, and survivors keep serving traffic.
- Geographic distribution across multiple data centers behind one logical API.

Cluster mode adds two new pieces on top of the single-node binaries: a Raft quorum (placement decisions) and a SWIM gossip ring (membership + capacity). See [Durability and Failover](/durability) for what survives node loss.

## Prerequisites

Before running any cluster script:

- Run [`install.sh`](/getting-started) on every node (single-node config first). The cluster scripts only flip an existing daemon into cluster mode - they do not install binaries, Caddy, or Docker.
- All nodes must share the **same `SB_PAT_TOKEN`**. Cluster-internal traffic (raft writes forwarded from followers to the leader) authenticates with this token. The simplest workflow is to run `install.sh --pat-token <shared-pat>` on every node with the same value.
- Open the cluster-internal ports on each node's firewall to **other cluster members only** - never to the public internet:
  - `7000/TCP` - Raft replication.
  - `7001/TCP+UDP` - SWIM gossip.
- A private network the operator controls (VPC peering, WireGuard mesh, dedicated subnet). Cluster traffic must not be reachable from outside the cluster.

## Bootstrap the seed node

Pick one host to bootstrap the cluster. On that host, run:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/cluster-init.sh \
  | sudo bash
```

The script:

1. Auto-generates a 32-byte gossip secret key (override with `--gossip-key`).
2. Auto-derives the node ID from the hostname and advertise addresses from the host's primary IP.
3. Writes `/etc/sandboxd/cluster.env` and a systemd drop-in at `/etc/systemd/system/sandboxd.service.d/cluster.conf` that layers cluster vars on top of the base `sandboxd.env` from `install.sh`.
4. Restarts `sandboxd` and prints the gossip key plus the exact `cluster-join.sh` command for other nodes.

**Save the printed gossip key** - every joining node needs the same value, and it is only printed once.

Common overrides:

```bash
sudo ./cluster-init.sh \
    --node-id seed-1 \
    --api-advertise-url http://10.0.0.5:21212 \
    --gossip-key "$(openssl rand -base64 32)"
```

The script refuses to re-run if `/var/lib/sandboxd/raft` is non-empty (avoids silently forking the cluster). Pass `--force` only if you intentionally want to wipe local raft state.

## Join additional nodes

On every other node, run:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/cluster-join.sh \
  | sudo bash -s -- \
    --gossip-key '<key-printed-by-cluster-init>' \
    --peers <seed-gossip-host>:7001
```

`--peers` accepts a comma-separated list - one reachable peer is enough; the new node discovers the rest through gossip. The seed's leader auto-promotes the new node to a Raft voter once the gossip join lands (typically within seconds).

`--force` is available for re-joining after a local raft state wipe; it deletes `/var/lib/sandboxd/raft` before starting.

## Verify

Tail the seed node's daemon log to confirm new joiners arrive and get auto-promoted to raft voters:

```bash
sudo journalctl -u sandboxd -f
```

Lines like `cluster: voter promoted node_id=...` and `cluster gossip joined peers ...` indicate a healthy join. Once the cluster is up, two HTTP endpoints expose membership for monitoring tools - they are operator-facing observability surfaces, not part of the SDK API:

- `GET /v1/cluster/members` - one entry per alive node with its capacity snapshot.
- `GET /v1/cluster/leader` - current Raft leader.

Both require the same `Authorization: Bearer $SB_PAT_TOKEN` header as the rest of the API. From the SDK perspective, sandbox creation is identical to single-node mode: a request to any node returns a sandbox owned by whichever node has the most headroom, and subsequent calls are transparently forwarded.

## What the cluster scripts write

Both scripts create the same two files (only the contents of `cluster.env` differ):

- `/etc/sandboxd/cluster.env` (mode 0600) - cluster env vars (`SB_ENABLE_CLUSTER`, `SB_NODE_ID`, raft + gossip addrs, `SB_GOSSIP_SECRET_KEY`, etc.).
- `/etc/systemd/system/sandboxd.service.d/cluster.conf` - systemd drop-in adding `EnvironmentFile=/etc/sandboxd/cluster.env`.

The base `/etc/sandboxd/sandboxd.env` from `install.sh` is never touched. Re-running `install.sh` later does not overwrite the cluster overlay.

To take a node out of cluster mode without uninstalling, stop the daemon, remove the drop-in and the cluster env file, then start the daemon:

```bash
sudo systemctl stop sandboxd
sudo rm /etc/sandboxd/cluster.env /etc/systemd/system/sandboxd.service.d/cluster.conf
sudo systemctl daemon-reload
sudo systemctl start sandboxd
```

The local SQLite store and any sandboxes the node owned remain - only the cluster-membership wiring is removed.

## Cluster-mode environment variables

These are written by `cluster-init.sh` / `cluster-join.sh`. Listed here for reference - operators who prefer to manage the env file themselves can set them directly in `/etc/sandboxd/cluster.env`.

| Variable | Required | Description |
|---|---|---|
| `SB_ENABLE_CLUSTER` | yes | Set to `true` to enable cluster mode. Default `false`. |
| `SB_NODE_ID` | yes | Stable identifier for this node. |
| `SB_API_ADVERTISE_URL` | yes | URL other nodes use to forward writes back to this node (e.g. `http://10.0.0.5:21212`). |
| `SB_RAFT_BIND_ADDR` | yes | Raft listen address. Default `0.0.0.0:7000`. |
| `SB_RAFT_ADVERTISE_ADDR` | yes | Raft address peers connect to. Cannot be `0.0.0.0`. |
| `SB_RAFT_DATA_DIR` | yes | On-disk raft state. Default `/var/lib/sandboxd/raft`. |
| `SB_GOSSIP_BIND_ADDR` | yes | Gossip listen address. Default `0.0.0.0:7001`. |
| `SB_GOSSIP_ADVERTISE_ADDR` | yes | Gossip address peers connect to. Cannot be `0.0.0.0`. |
| `SB_GOSSIP_SECRET_KEY` | yes | Base64-encoded 16, 24, or 32-byte AES key. Same value on every node. |
| `SB_BOOTSTRAP_PEERS` | join only | Comma-separated gossip-advertise addresses to join. Bootstrap node leaves this empty. |
| `SB_CLUSTER_BOOTSTRAP` | yes | `true` only on the seed; `false` on joiners. |

See [Durability and Failover](/durability) for what gets replicated, what survives node loss, and the cluster network security model.
