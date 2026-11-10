# Cluster upgrades: rollouts, finalize and rollback

This runbook covers the `sandboxd.rollouts` alerts and the rollout the
cluster runs for `aerolvm upgrade apply`
(`plans/kubectl-style-cluster-ops.md` §6). The Raft leader drives the
rollout from a record in Raft, so a laptop or CI job that started it can
exit. Every command below is safe to repeat.

Read the rollout first, every time:

```bash
aerolvm upgrade status            # GET /v1/cluster/upgrade
```

It shows the rollout state, each node's state (`pending`, `staged`,
`upgrading`, `done`, `failed`, `manual`, `skipped`), each node's error,
and the command to run on a `manual` node. The D5 dashboard has a
"Rollouts" row with the same numbers.

## Rollout failed

`SandboxdRolloutFailed`. The rollout stopped at its first failure and
starts no new node. Nodes that finished stay on the new version; the
failed node's own upgrader put its previous files back, so it runs the old
version.

1. Read the failed node's error in `aerolvm upgrade status`. Common ones:
   - `failed to stage: not enough free space ...`: free disk on that node.
     No node restarted.
   - `systemd-run not found`: the node is not a systemd host.
   - `did not come back healthy on <version> within 10m0s`: look at
     `journalctl -u sandboxd` and `journalctl -u aerolvm-upgrade-<op>` on
     the node. `--node-timeout` raises the limit.
   - `the node's upgrader failed and put the previous files back`: the new
     build did not start; the upgrader's journal names why.
   - `restarting it would leave no Raft majority`: a server is down. Bring
     it back first; with three servers and one down, no server restarts.
2. Then either:
   - fix the cause and run `aerolvm upgrade apply <same version>`: the
     rollout goes back to staging, and nodes already on the target are
     skipped; or
   - run `aerolvm upgrade rollback` to put every node back on the previous
     version (§6.8).

## Rollout stuck

`SandboxdRolloutStuck`: one state for over an hour.

- `paused`: the `--pause-after` canary is done. Check the canary nodes,
  then `aerolvm upgrade resume` (or `aerolvm upgrade rollback`).
- `stopped`: someone ran `aerolvm upgrade stop`. `aerolvm upgrade apply`
  with the same version continues; `rollback` undoes it.
- `staging`: a node does not answer its stage call. A node that never
  answers fails after one `--node-timeout`; check that servers can reach
  it on TCP 7002.
- `running`: a node is `upgrading`. Its sandboxes are not failed over while
  it is upgrading, until its deadline. Check `systemctl status
  aerolvm-upgrade-<op>` on it.
- `finalizing`: a node has not run its one-way migrations: it is down, or
  its migration failed (its error is in status; it stays cordoned). Bring
  it back; the leader retries.
- `rolling-back`: as for `running`, in reverse order.

## Node stuck manual or skipped

`SandboxdRolloutNodeWaiting`.

- `manual`: the node runs with `SB_REMOTE_UPGRADE=false` (the default in
  enterprise mode). Run the command `aerolvm upgrade status` prints for it,
  on that node: `sudo sandboxd upgrade node <version> --sha256 ...`. The
  rollout marks it done once it reports the version.
- `skipped`: the node was down when its turn came. It stays cordoned; when
  it comes back the leader stages and upgrades it first, then uncordons it.
  A node that is gone for good: `aerolvm delete node <id>`.

Finalize waits for every skipped node to be upgraded or deleted.

## Member below the active version

`SandboxdMemberBelowActiveVersion`. A member was down while the cluster
finalized a newer version (or while every live member moved to a newer
build). It gets no new sandboxes, and if it is a server it is kept out of
Raft so it never replays an op it cannot apply. Upgrade it with
`sudo sandboxd upgrade node <version>` (or `install.sh`), or delete it.
It joins Raft and placement again by itself once it runs the active
version.

## Join failing

`SandboxdClusterJoinsFailing`. See
[secrets-and-audit.md](secrets-and-audit.md) for the join alerts. During a
rollout a new node may join only on the rollout's target or previous
version; any other build is refused with `version` as the reason. Install
the version `GET /v1/join/cluster-info` names.

## Cert renewal failing

`SandboxdClusterCertRenewalFailing`. See
[secrets-and-audit.md](secrets-and-audit.md).

## Finalize and rollback in short

- `aerolvm upgrade finalize` commits the new active cluster version
  (`finalizing`), then every node runs its one-way schema migrations, then
  the rollout is `finalized`. After that there is no rollback.
- Without `--hold` the leader finalizes by itself once every node is done.
- `aerolvm upgrade rollback` works from `done`, `failed`, `stopped` and
  `paused`: workers first, then ingress nodes, then servers, with the
  leader last. Nodes put their `*.prev` files back; the database stays as
  it is (only `n1_safe` migrations ran before finalize).
