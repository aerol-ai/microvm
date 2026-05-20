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

2. Back up the chosen survivor before mutation:

   ```bash
   sudo /usr/local/sbin/sandboxd-backup.sh \
     --output /root/pre-quorum-recovery-$(hostname)-$(date +%F-%H%M%S).tar.gz
   ```

3. On the chosen node, write `peers.json`:

   ```bash
   sudo /usr/local/sbin/raft-lost-quorum-recover.sh \
     --raft-dir /var/lib/sandboxd/raft \
     --node-id <chosen-node-id> \
     --raft-address <chosen-private-ip>:7000
   ```

4. Start sandboxd on the chosen node only:

   ```bash
   sudo systemctl start sandboxd
   sudo journalctl -u sandboxd -f
   ```

5. Wait for recovery to apply. The recovery file should be renamed:

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

For every other surviving server node, do not reuse stale Raft state:

```bash
sudo systemctl stop sandboxd
sudo mv /var/lib/sandboxd/raft /var/lib/sandboxd/raft.pre-rejoin.$(date +%s)
sudo /usr/local/sbin/cluster-join.sh \
  --gossip-key '<key>' \
  --peers <recovered-node-private-ip>:7001 \
  --tls-bundle /path/to/aerolvm-tls-bundle.tar.gz \
  --force
```

Rejoin one server at a time. Wait for membership and health before the next.

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
