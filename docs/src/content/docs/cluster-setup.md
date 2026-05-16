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

`--peers` accepts a comma-separated list - one reachable peer is enough; the new node discovers the rest through gossip. The seed's leader auto-promotes new nodes to Raft voters until `SB_CLUSTER_MAX_AUTO_VOTERS` is reached; later nodes are added as Raft non-voters so they receive the placement log without increasing quorum.

`--force` is available for re-joining after a local raft state wipe; it deletes `/var/lib/sandboxd/raft` before starting.

## Verify

Tail the seed node's daemon log to confirm new joiners arrive and are added to the Raft configuration:

```bash
sudo journalctl -u sandboxd -f
```

Lines like `cluster: auto-promoted member to raft voter`, `cluster: added member as raft non-voter because voter cap is reached`, and `cluster gossip joined peers ...` indicate a healthy join. Once the cluster is up, two HTTP endpoints expose membership for monitoring tools - they are operator-facing observability surfaces, not part of the SDK API:

- `GET /v1/cluster/members` - one entry per alive node with its capacity snapshot.
- `GET /v1/cluster/leader` - current Raft leader.

Both require the same `Authorization: Bearer $SB_PAT_TOKEN` header as the rest of the API. From the SDK perspective, sandbox creation is identical to single-node mode: a request to any node returns a sandbox owned by whichever node has the most headroom, and subsequent calls are transparently forwarded.

## How sandbox create works in cluster mode

When a create lands on a node (call it `A`):

1. `A` runs placement scoring against the gossiped capacity snapshot, biased
   by any pending reservations it knows about, and picks a target `T`. If
   `A == T`, `A` runs the create locally and commits a placement to the raft
   log on success.
2. If `T` is a different node, `A` mints a sandbox ID, seals + redacts the
   request secrets, and writes a **reservation** for `T` to the raft log
   *before* forwarding. The reservation holds the requested capacity and the
   sandbox name on `T` for 120 seconds.
3. `A` forwards the request to `T` with `X-Cluster-Create-Target: T` (so the
   second hop never re-runs placement scoring) and `X-Cluster-Create-ID`
   (the reserved ID). `T` runs the local create against that ID, then
   promotes the reservation to a placement on success.
4. If `T` crashes mid-create or the local create fails, the leader's
   reservation-GC sweep cancels the row within ~125s and the headroom
   returns to the cluster.

The user-visible effect: two concurrent creates can never double-book the
same target (the second reservation lands strictly after the first in the
raft log and is rejected if `T` no longer fits), and a target that dies
between reservation and promote returns its capacity to the cluster
automatically. The added cost is one extra raft round-trip per cross-node
create — same-node creates collapse back to a single commit.

## Public ingress behavior

Cluster mode publishes sandbox traffic through owner-aware ingress. The public load balancer can send API, sandbox URL, exposed HTTP/TLS, or raw TCP traffic to any live node:

- API requests are forwarded by the Go control plane when the receiving node is not the owner.
- Domain-mode sandbox URLs and exposed HTTP/TLS port hosts are SNI-routed to the owner.
- IP/path-mode sandbox URLs are reverse-proxied to the owner's Caddy listener.
- Raw TCP exposures replicate their `hostPort`; every node binds that port and proxies to the owner.

The owner target for sandbox data-plane traffic comes from `SB_DATA_PLANE_ADVERTISE_HOST`, not `SB_API_ADVERTISE_URL`. This matters when the API advertise URL is an API-only hostname, a shared load-balancer hostname, or an address that would loop back through the public LB. Keep `SB_API_ADVERTISE_URL` for peer API forwarding and set `SB_DATA_PLANE_ADVERTISE_HOST` to the node address peers can dial on Caddy/L4 ports.

Route changes are reconciled from the Raft placement map every few seconds. Immediately after exposing a port or after owner failover, a non-owner backend can briefly return 404/502 until its ingress routes refresh. For a stable public surface, set `SB_DOMAIN` or `SB_PUBLIC_HOST` to the shared load-balancer hostname, not a per-node address.

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
| `SB_DATA_PLANE_ADVERTISE_HOST` | yes | Host/IP other nodes use to route sandbox data-plane traffic to this node's Caddy/L4 listeners. Defaults to the host in `SB_API_ADVERTISE_URL`; set explicitly when API traffic uses an API-only name or shared LB. |
| `SB_RAFT_BIND_ADDR` | yes | Raft listen address. Default `0.0.0.0:7000`. |
| `SB_RAFT_ADVERTISE_ADDR` | yes | Raft address peers connect to. Cannot be `0.0.0.0`. |
| `SB_RAFT_DATA_DIR` | yes | On-disk raft state. Default `/var/lib/sandboxd/raft`. |
| `SB_GOSSIP_BIND_ADDR` | yes | Gossip listen address. Default `0.0.0.0:7001`. |
| `SB_GOSSIP_ADVERTISE_ADDR` | yes | Gossip address peers connect to. Cannot be `0.0.0.0`. |
| `SB_GOSSIP_SECRET_KEY` | yes | Base64-encoded 16, 24, or 32-byte AES key. Same value on every node. |
| `SB_CLUSTER_INSECURE_GOSSIP` | no | Set to `true` to opt out of the gossip-key requirement. **Only safe on a fully isolated network.** Without it, any reachable peer can join the raft configuration via voter auto-promotion. Default `false`. |
| `SB_CREDENTIAL_ENCRYPTION_KEY` | yes | Base64-encoded 32-byte key used to seal/unseal sandbox registry passwords and per-mount credentials replicated via raft. Same value on every node. `cluster-init.sh` captures or generates this on the seed; `cluster-join.sh` extracts it from the bundle and writes it here. |
| `SB_CREDENTIAL_ENCRYPTION_KEY_PATH` | no | Path the daemon falls back to when `SB_CREDENTIAL_ENCRYPTION_KEY` is empty. Default `/var/lib/sandboxd/credential_encryption.key`. The cluster scripts install the shared key here as a backup so re-running `install.sh` doesn't lazy-generate a divergent key file. |
| `SB_CLUSTER_INSECURE_CREDENTIALS` | no | Set to `true` to opt out of the shared-credential-key requirement. **Recovered sandboxes lose access to private registries and credentialed mounts after failover** without it. Default `false`. |
| `SB_CLUSTER_TLS_DIR` | recommended | Directory holding the cluster CA + this node's keypair (`ca.crt`, `node.crt`, `node.key`). When set, raft replication and leader-forwarded applies require a peer cert chained to the cluster CA — possession of the PAT alone is no longer enough to forge an internal apply. `cluster-init.sh` / `cluster-join.sh` populate this automatically. |
| `SB_CLUSTER_INTERNAL_LISTEN` | no | Bind address for the cluster-internal mTLS listener (used for leader-forwarded raft applies). Default `0.0.0.0:7002`. Ignored when `SB_CLUSTER_TLS_DIR` is empty. |
| `SB_CLUSTER_INTERNAL_ADVERTISE` | no | HTTPS URL peers dial for the internal channel (e.g. `https://10.0.0.5:7002`). Auto-derived from primary IP + internal-listen port when empty. Must be HTTPS. |
| `SB_BOOTSTRAP_PEERS` | join only | Comma-separated gossip-advertise addresses to join. Bootstrap node leaves this empty. |
| `SB_CLUSTER_BOOTSTRAP` | yes | `true` only on the seed; `false` on joiners. |
| `SB_CLUSTER_MAX_AUTO_VOTERS` | no | Maximum gossip-discovered nodes auto-promoted as raft voters. Default `5`; additional nodes are added as raft non-voters so they receive the placement log without increasing quorum. Set `0` for the old unlimited behavior. |

### Cluster-internal TLS (recommended)

`cluster-init.sh` generates a self-signed CA + a per-node keypair under `SB_CLUSTER_TLS_DIR` (default `/etc/sandboxd/tls`) and emits a TLS bundle (tarball with `ca.crt` + `ca.key`) that you copy to each joining node. `cluster-join.sh --tls-bundle <path>` extracts the bundle, mints a fresh per-node keypair from the bundled CA, and writes the same env vars on the joiner. Once enabled:

- **Raft replication** rides over mTLS (`raft.NewNetworkTransportWithConfig` + a custom TLS `StreamLayer`). A peer that can't present a cert chained to the cluster CA fails handshake.
- **Leader-forwarded raft applies** ride over a separate HTTPS listener on `SB_CLUSTER_INTERNAL_LISTEN` (default port 7002), bypassing the public API URL entirely. Same CA-pinned mTLS rules apply.
- **Owner API forwarding** (cross-node sandbox API hops — `GET /v1/sandboxes/{id}`, mutating writes, port exposure, etc.) also rides the `:7002` mTLS listener: the listener serves the same `/v1/...` mux as the public port, so peers reverse-proxy owner traffic over the cert-pinned channel instead of the public `SB_API_ADVERTISE_URL`.
- **Falls back gracefully**: a node without `SB_CLUSTER_TLS_DIR` still works (the daemon advertises no `internal_url` via gossip, and peers fall back to the public API URL with PAT-only auth for both raft applies and owner forwarding). Use `--no-tls` on `cluster-init.sh` / `cluster-join.sh` for ephemeral test setups on a fully private network.

The CA bundle MUST be transferred over a secure channel (scp, vault) — anyone with the bundle can mint a node cert and join the cluster.

### Credential encryption key (required)

Sandbox registry passwords and per-mount credentials replicated via raft are stored as sealed blobs encrypted with `SB_CREDENTIAL_ENCRYPTION_KEY`. Every node must hold the same value, or sandboxes that fail over to a new owner cannot pull from their private registry or attach their credentialed mounts — the recovered owner decrypts with a different key and silently fails.

`cluster-init.sh` ships the key automatically:

- In TLS mode (default), the key is added to `aerolvm-tls-bundle.tar.gz` alongside `ca.crt` + `ca.key`.
- In `--no-tls` mode, the key is emitted as a standalone `aerolvm-cred-bundle.tar.gz` and `cluster-join.sh --cred-bundle <path>` is required.

Both bundles MUST be transferred over a secure channel — anyone with the bundle can decrypt every sandbox's sealed credentials.

The daemon refuses to boot in cluster mode unless `SB_CREDENTIAL_ENCRYPTION_KEY` is set or a key file already exists at `SB_CREDENTIAL_ENCRYPTION_KEY_PATH`. The `--no-tls` opt-out for gossip is independent; credential sharing is required regardless of TLS. Set `SB_CLUSTER_INSECURE_CREDENTIALS=true` to bypass the check, only for ephemeral test setups that don't use sealed registry/mount creds.

See [Durability and Failover](/durability) for what gets replicated, what survives node loss, and the cluster network security model.

## Quorum and node count

Raft requires a majority of voters to commit any write. With `N` voters, the cluster tolerates the loss of `(N-1)/2` nodes before it loses quorum and stops accepting writes (placements, reassignments, port intents).

| Voters | Failures tolerated | Notes |
|---|---|---|
| 1 | 0 | Single-node cluster. Any restart blocks writes briefly; any disk loss is total. |
| 2 | 0 | **Worst case.** Quorum is 2. Losing either node halts the cluster. Avoid. |
| 3 | 1 | Minimum recommended for any production deployment. |
| 5 | 2 | Recommended for clusters that span availability zones. |
| 7 | 3 | Diminishing returns; replication latency grows. |

**Rules of thumb:**

- Always run an **odd number** of voters (1, 3, 5, 7). Even counts only raise the quorum threshold without raising fault tolerance.
- Treat a 2-node cluster as a single point of failure with extra steps. If you only have two hosts, run single-node mode on the more-reliable one.
- `SB_CLUSTER_MAX_AUTO_VOTERS` defaults to `5`. After that cap, new runners join as raft non-voters: they can own sandboxes and forward writes, but they do not count toward quorum.
- `SB_NODE_ID` must be **stable** across restarts. A node that comes back with a new ID joins as a brand-new raft server while the old server sits in the configuration as dead — eventually evicted by the dead-owner reconciler, but until then it may inflate replication work or quorum if it was a voter.

## Lost-quorum recovery

If you lose more than `(N-1)/2` voters at once, the surviving nodes cannot elect a leader and the cluster stops accepting writes. Reads from already-replicated state still work; new placements do not.

**Before doing anything, confirm the diagnosis.** On a surviving node:

```bash
sudo journalctl -u sandboxd --since "10 minutes ago" | grep -i 'leader\|election'
curl -s -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/leader
```

A persistent empty `Leader` field with repeated election timeouts is the signature.

### Option A — wait for the lost nodes to come back

If the lost voters' raft state on disk is intact, restarting them rejoins the existing configuration. No special procedure required. **Try this first** — it does not destroy any state.

### Option B — manual quorum recovery (last resort)

If the lost voters are gone for good (disk loss, hardware destroyed) and waiting is not an option, you can rewrite the raft configuration on a surviving node so it bootstraps a fresh single-node cluster from its existing log. This is **destructive to durability guarantees** — any committed entry that the surviving node never replicated is lost.

1. Stop `sandboxd` on every surviving node.
2. On the node with the most-recent raft log (highest `LastIndex` from `journalctl`), edit `/var/lib/sandboxd/raft/peers.json` to list only itself as a voter:

   ```json
   [
     { "id": "this-node-id", "address": "10.0.0.5:7000", "non_voter": false, "suffrage": "Voter" }
   ]
   ```

3. Start `sandboxd` on that node only. It will detect `peers.json` and rewrite the raft configuration to itself.
4. Once it elects itself leader, re-add the other surviving nodes by joining them fresh:
   ```bash
   sudo rm -rf /var/lib/sandboxd/raft   # on each rejoining node
   sudo ./cluster-join.sh --gossip-key '<key>' --peers <recovered-node>:7001 --force
   ```
5. Inspect placements via `GET /v1/cluster/members` and reconcile any sandboxes that were owned by permanently-lost nodes — under the current non-HA policy the dead-owner reconciler orphans them on the next tick (clients then see `410 Gone` and should issue a fresh `Create`).

Document this procedure in your runbook before you need it. Do not improvise during an outage.

## Backup and restore

The raft log under `SB_RAFT_DATA_DIR` (default `/var/lib/sandboxd/raft`) is the cluster's source of truth for **placement state only** — sandbox IDs, owner nodes, replicated specs, sealed credentials, and exposed-port intents. Per-node local state (the `state.db` SQLite file, Docker containers, Caddy config) is **not** in the backup.

### What lives where

| Path | Contents | Per-node or cluster-wide |
|---|---|---|
| `$SB_RAFT_DATA_DIR/raft-log.bolt` | Raft log (every committed `opPlace` / `opReserve` / etc.) | Cluster-wide; same content on every voter |
| `$SB_RAFT_DATA_DIR/raft-stable.bolt` | Raft term + voted-for state | Per-node |
| `$SB_RAFT_DATA_DIR/snapshots/` | Periodic FSM snapshots | Per-node, fungible with peers |
| `$SB_DB_PATH` (default `/var/lib/sandboxd/state.db`) | Local sandbox rows, host-port allocations, snapshots ledger | Per-node only |
| Docker volumes + images | Sandbox filesystems | Per-node only |

A backup of the raft directory on one voter is sufficient to reconstruct the cluster's placement view; it is **not** sufficient to recover the actual sandbox containers, which only exist on the node that originally hosted them.

### Take a backup

The backup is a hot copy of the raft directory on any voter (leader or follower — every voter holds the full log). Quiesce raft writes for the duration of the copy if you want a transactionally clean snapshot; the BoltDB files survive `cp -a` while sandboxd is running but you may capture a partial entry that raft will replay on next boot.

```bash
# On any voter. Stop sandboxd for the cleanest copy:
sudo systemctl stop sandboxd
sudo tar -C /var/lib/sandboxd -czf /var/backups/sandboxd-raft-$(date +%F).tar.gz raft
sudo systemctl start sandboxd

# Or, hot copy (acceptable; raft replay reconciles a torn entry):
sudo cp -a /var/lib/sandboxd/raft /var/backups/sandboxd-raft-$(date +%F)
```

Run this on at least one node per scheduled interval. The backup is small (KB–MB scale even on large fleets) so daily retention with weekly/monthly rollups is reasonable.

### What gets lost vs preserved on restore

A raft-only restore brings back **cluster intent** (which sandbox should be where, with which spec, and which ports). It does **not** bring back:

- Local sandbox containers — Docker state on each node is independent. After a restore, the owner watcher on each node will try to re-materialize sandboxes whose placement points at it via the recreate hook (this requires the image still being pullable and the replicated spec being intact).
- Local `state.db` rows — host-port allocations, snapshot ledger, per-sandbox network counters. These are rebuilt opportunistically as the recreate path runs.
- **In-flight reservations** with `expires_unix` in the past at restore time — the leader's GC sweep will cancel them on the first tick. Reservations whose TTL hasn't elapsed yet are honored.

If the original cluster had sandboxes whose owners are permanently gone (disk loss), the dead-owner reconciler orphans those placements on the next tick (~15s after grace expires) and clients see `410 Gone` on next access — same shape as the lost-quorum recovery flow.

### Restore procedure

1. Provision a fresh node (or wipe an existing one). Match the `SB_NODE_ID` of the node whose backup you're restoring.
2. Stop sandboxd:
   ```bash
   sudo systemctl stop sandboxd
   sudo rm -rf /var/lib/sandboxd/raft
   ```
3. Extract the backup:
   ```bash
   sudo tar -C /var/lib/sandboxd -xzf /var/backups/sandboxd-raft-YYYY-MM-DD.tar.gz
   sudo chown -R sandboxd:sandboxd /var/lib/sandboxd/raft
   ```
4. If this is the only surviving voter, follow the **manual quorum recovery** steps above to seed `peers.json` so it bootstraps a single-node cluster from the restored log. Otherwise, restarting `sandboxd` will rejoin the existing cluster as a follower and the log will sync from peers.
5. Verify with `GET /v1/cluster/leader` and `GET /v1/cluster/members`. The placement count should match what was in the backup; counts that don't match indicate a stale snapshot or a backup taken mid-replication.

The restore does not reach into Docker or `state.db` — sandboxes that pre-dated the backup will only come back up if their original images and (where applicable) sealed credentials are still valid. Treat the backup as a recovery aid for accidental placement-state loss, not as a substitute for per-node disaster recovery.

## Verifying cluster health

A healthy cluster reports:

- A non-empty `Leader` from `GET /v1/cluster/leader`.
- All expected node IDs in `GET /v1/cluster/members` with `alive: true`.
- No repeated `cluster: AssertOwnership skipped, no leader yet` warnings in `journalctl -u sandboxd`.
- `cluster: auto-promoted member to raft voter` or `cluster: added member as raft non-voter because voter cap is reached` log lines when joiners come online - silence here means the raft membership loop is not seeing the joiner.

Set up monitoring on `GET /v1/cluster/leader` returning empty for more than 30 seconds: that's the earliest signal of a brewing quorum problem.
