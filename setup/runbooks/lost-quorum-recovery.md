# Runbook: Lost-Quorum Recovery

Use this only when Raft has no leader because too many voter nodes are gone and
you cannot bring a majority back. This is a last-resort procedure.

## Severity

Lost quorum in production is **SEV-1**. New sandbox creates, placement writes,
exposure changes, and recovery writes cannot commit until quorum returns.

## Safety Rules

- Try to bring the original voter nodes back first.
- Stop sandboxd on every surviving server-role node before writing
  `peers.json`.
- Pick exactly one survivor as the recovery source.
- Prefer the survivor with the highest Raft log index.
- Do not delete old Raft data from other survivors until the recovered leader
  is healthy and backed up.

This recovery may implicitly commit entries that were present on the chosen
survivor but not previously committed by a quorum. That is safer than inventing
new log state, but it is still a durability compromise.

## Confirm Lost Quorum

Run on at least two surviving nodes:

```bash
export SB_PAT_TOKEN=<redacted>
curl -s -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/leader | jq .
sudo journalctl -u sandboxd --since "15 minutes ago" --no-pager \
  | grep -iE 'leader|election|failed to make requestVote|heartbeat timeout'
```

Lost quorum signature:

- `Leader` is empty or unstable for more than 30 seconds.
- Repeated election or heartbeat timeout logs.
- A majority of configured voters is unavailable.

If a majority can be restarted with intact disks, do that instead and stop this
runbook.

## Pick the Recovery Node

On each surviving server node:

```bash
sudo journalctl -u sandboxd --since "24 hours ago" --no-pager \
  | grep -iE 'last.index|last-index|raft.*index|snapshot' | tail -50
sudo ls -lah /var/lib/sandboxd/raft
sudo find /var/lib/sandboxd/raft -maxdepth 2 -type f -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' \
  | sort | tail -20
```

Choose the node with the most recent Raft state. Record why it was chosen in
the incident log.

## Recovery Procedure

1. Stop sandboxd on every surviving server node:

   ```bash
   sudo systemctl stop sandboxd
   ```

2. On the chosen node, back it up, write `peers.json` and start sandboxd on
   this node only:

   ```bash
   sudo sandboxd recover-quorum --start
   ```

   It takes the node ID (`SB_NODE_ID`), the Raft address
   (`SB_RAFT_ADVERTISE_ADDR`) and the Raft directory from the node's env
   files; pass `--node-id`, `--raft-address` or `--raft-dir` to override
   them. Before it changes anything it backs the node up to
   `/var/lib/sandboxd/backups/pre-recover-quorum-<host>-<time>.tar.gz`
   (`--backup-output` picks another path). It refuses while sandboxd runs on
   this node, on a worker or ingress node, with another node's ID, with a
   bind address such as `0.0.0.0:7000`, and on a directory with no Raft
   data. With `--start` it waits until sandboxd has applied the file.
   Without it, start sandboxd yourself and watch `journalctl -u sandboxd -f`.
   The older `raft-lost-quorum-recover.sh` now only calls this command.

3. Check the recovery applied. The recovery file is renamed:

   ```bash
   sudo ls -l /var/lib/sandboxd/raft/peers.json*
   ```

Expected: `peers.json.applied.<unix>` exists and plain `peers.json` is gone.

## Verification Before Rejoining Nodes

```bash
export SB_PAT_TOKEN=<redacted>
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/leader | jq .
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/members | jq .
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/metrics \
  | grep -E 'aerolvm_raft_apply_errors_total|aerolvm_raft_apply_inflight'
```

Expected:

- The chosen node is leader.
- Raft apply errors are not increasing.
- `aerolvm_raft_apply_inflight` is 0.
- The cluster accepts a harmless read and can list members.

## Rejoin Other Nodes

For every other surviving server node, do not reuse stale Raft state. Started
with its old Raft log, a server still counts the lost servers as voters and
can elect a second leader with another old server.

```bash
sudo systemctl stop sandboxd
sudo sandboxd recover-quorum --rejoin --start
```

`--rejoin` moves `/var/lib/sandboxd/raft` aside as
`raft.pre-rejoin.<unix>` (keep it until the cluster is healthy and backed up)
and starts sandboxd; the node finds the cluster through gossip and the leader
adds it as a voter. It refuses on a node with `SB_CLUSTER_BOOTSTRAP=true` (the
seed): with an empty Raft log that node would start a new cluster of its own.
Set `SB_CLUSTER_BOOTSTRAP=false` in its `cluster.env` first.

If the node also lost its cluster settings or certificates, join it again
instead. From your laptop, delete the old member and make a server token:

```bash
aerolvm delete node <node-id> --force
aerolvm join-command --role server
```

Then on the node:

```bash
sudo sandboxd reset --yes      # removes the old cluster files and Raft data
# run the printed join line here, with --node-id <node-id> at the end
```

Rejoin one server at a time. Wait for membership and health before the next.

## Raft-WAL log store (one-way per node)

As of the warm-create-latency Tier 1 Phase 3 rollout, new nodes open the Raft
**log** store as `hashicorp/raft-wal` under `$DataDir/raft-wal/` when
`raft-log.bolt` is absent. Existing nodes that still have `raft-log.bolt` keep
Bolt until they are drained and rejoined with a fresh DataDir.

**This is NOT in-place revertable.** Once a node has written WAL state, a
boltdb-only build cannot read it. To revert a WAL node to Bolt:

1. `aerolvm drain <node-id>` — never drop below quorum.
2. `aerolvm delete node <node-id>`.
3. Stop sandboxd, move aside the DataDir Raft tree (`mv …/raft …/raft.pre-revert.$(date +%s)`).
4. Deploy the desired build against a **fresh** DataDir (current builds recreate
   WAL when `raft-log.bolt` is absent; pin an older build only if you must stay
   on Bolt).
5. `sudo sandboxd reset --yes`, then rejoin with a fresh `aerolvm join-command --role server` line.

Rollout is one node at a time via the standard **drain → delete node →
rejoin** cycle. Mixed-format clusters (some Bolt, some WAL) are safe: the log
store is node-local; Raft replicates log entries over the transport, not store
files. Re-verify this lost-quorum recovery runbook on a WAL node after the
fleet is all-WAL.

## Post-Recovery Cleanup

1. Take a fresh backup from the new leader.
2. Confirm expected voter count.
3. Confirm no worker lease or create backlog alerts are firing.
4. Inspect orphaned placements and decide whether to reclaim or force-delete.
5. Open a postmortem with:
   - failed voter list
   - chosen survivor and why
   - data-loss risk assessment
   - exact recovery timestamps

## Rollback

There is no clean in-place rollback once `RecoverCluster` has rewritten Raft
state. Rollback means stopping the recovered cluster and restoring the
pre-recovery archive from the chosen node. Escalate before doing this in
production.

## Lost-Quorum Drill

Perform as a tabletop unless you are in a disposable staging cluster.

| Field | Value |
|---|---|
| Date | |
| Commander | |
| Simulated failed voters | |
| Recovery node selected | |
| Evidence used for selection | |
| `peers.json` command reviewed | yes/no |
| Rejoin order reviewed | yes/no |
| Gaps found | |
