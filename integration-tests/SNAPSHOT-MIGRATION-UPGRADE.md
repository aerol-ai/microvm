# Release gate: per-owner snapshot-namespace migration (warm upgrade)

**When to run:** before cutting the first release that contains the per-owner
snapshot namespace (`sandbox_snapshots` PK → `(owner_ref, name)`,
`snapshot_aliases.owner_ref` + composite FK, `migrateSnapshotOwnerPK`). That
change is destructive and runs **only on a database that already has the old
name-PK schema** — a fresh-provisioned node creates the new schema directly, so
the suite's normal runs never exercise the rebuild. This runbook upgrades a node
that already holds snapshots and proves the rebuild preserves them.

Pair it with **UC-58d** (`TestSnapshotBackedFailover`, in
`suite/z_disruptive_cluster_test.go`), which exercises the rebuilt tables on the
cluster *recreate-via-failover* path. UC-58d runs automatically in
`make integration-cluster-hetero`; this upgrade check is manual because the
harness has no in-place upgrade mode (follow-up: a `run.sh --upgrade-from <tag>`
phase).

Facts used below:
- binary `/usr/local/bin/sandboxd`, service `sandboxd.service`
- state DB `/var/lib/sandboxd/state.db` (+ `-wal`, `-shm`), raft `/var/lib/sandboxd/raft`
- backup/restore: `scripts/sandboxd-backup.sh` / `scripts/sandboxd-restore.sh`
- SSH key: `~/.ssh/suman-saurabh-aws.pem` (see `reference_itest_live_gotchas`)

---

## A. Single-node (minimum gate)

### 1. Provision on the last released version (old schema)

```bash
cd integration-tests
./run.sh single-node --released --keep          # or: --version v0.6.7
```

`--keep` leaves the node up. Note the node's public IP from the run output
(`AEROL_INTEGRATION_TARGETS` / the tfvars) and export `BASE`/`TOKEN` for the API
(the operator PAT the harness installed is in the node's `/etc/sandboxd/*.env`).

### 2. Confirm the DB is on the OLD schema

```bash
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP \
  "sudo sqlite3 /var/lib/sandboxd/state.db 'PRAGMA table_info(sandbox_snapshots);'"
# EXPECT: pk flag on `name` only; NO owner_ref column.
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP \
  "sudo sqlite3 /var/lib/sandboxd/state.db 'PRAGMA table_info(snapshot_aliases);'"
# EXPECT: NO owner_ref column.
```

### 3. Seed snapshots + aliases (operator namespace, owner_ref = "")

Use the Go SDK or the API. Create a mix so the rebuild has rows to carry:
- 2–3 image-registered snapshots (`RegisterSnapshot{Name, Image: "alpine:3.20"}`)
- 1–2 committed snapshots (`CreateSnapshot(sandboxID, name)` on a running sandbox)
- at least one alias (register a snapshot under a second name, if the API path
  you use creates an alias row)

Record the exact names, then snapshot the pre-upgrade row counts:

```bash
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP \
  "sudo sqlite3 /var/lib/sandboxd/state.db \
   'SELECT count(*) FROM sandbox_snapshots; SELECT count(*) FROM snapshot_aliases;'"
```

### 4. Back up, then upgrade the binary in place

```bash
# pre-upgrade backup (rollback floor — the migration is one-way)
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP \
  "sudo bash -s" < ../scripts/sandboxd-backup.sh --out /tmp/pre-upgrade.tar.gz

# build the new sandboxd from the release candidate (this branch's main) and copy it
make build                                      # -> bin/sandboxd
scp -i ~/.ssh/suman-saurabh-aws.pem bin/sandboxd ubuntu@$IP:/tmp/sandboxd.new
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP '
  sudo systemctl stop sandboxd &&
  sudo install -m0755 /tmp/sandboxd.new /usr/local/bin/sandboxd &&
  sudo systemctl start sandboxd &&
  sleep 3 && sudo systemctl is-active sandboxd'
```

> Match the binary's GOARCH to the node (amd64 vs arm64). For arm64 metal use the
> cross-compile recipe in `project_containerd_engine_shipped` / `lib/build.sh`.

### 5. Verify the rebuild preserved everything

```bash
# clean boot — no migration/store errors (migrateSnapshotOwnerPK is silent on
# success and only surfaces on error, so the authoritative proof is the schema
# check below, not a log line).
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP \
  "sudo journalctl -u sandboxd --since '2 min ago' | grep -iE 'error|panic|migrat|snapshot' || echo 'clean'"
# migration ran, schema is NEW
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP \
  "sudo sqlite3 /var/lib/sandboxd/state.db 'PRAGMA table_info(sandbox_snapshots);'"
# EXPECT: composite PK over (owner_ref, name); owner_ref present.
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP \
  "sudo sqlite3 /var/lib/sandboxd/state.db 'PRAGMA table_info(snapshot_aliases);'"
# EXPECT: owner_ref present.

# row counts unchanged (no data loss); every seeded snapshot backfilled owner_ref=''
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP \
  "sudo sqlite3 /var/lib/sandboxd/state.db \
   'SELECT count(*) FROM sandbox_snapshots; SELECT count(*) FROM snapshot_aliases; \
    SELECT count(*) FROM sandbox_snapshots WHERE owner_ref IS NULL;'"
# EXPECT: counts match step 3; the NULL-owner count is 0.
```

Then prove behaviour end to end against the API:
- `GET /v1/snapshots/{name}` for each seeded name → 200
- `GET /v1/snapshots` lists all of them
- create a sandbox `{"image": "<seeded snapshot name>"}` → reaches running
- `DELETE /v1/snapshots/{name}` → 204, then `GET` → 404

### 6. Idempotency

Restart `sandboxd` once more and confirm the boot is clean and the schema/counts
are unchanged — `migrateSnapshotOwnerPK` must be a no-op on an already-migrated DB.

### 7. Rollback (if the gate fails)

```bash
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP '
  sudo systemctl stop sandboxd'
ssh -i ~/.ssh/suman-saurabh-aws.pem ubuntu@$IP \
  "sudo bash -s" < ../scripts/sandboxd-restore.sh --input /tmp/pre-upgrade.tar.gz --force
# reinstall the old binary (re-run run.sh ... --released, or keep a copy), start.
```

### 8. Tear down

```bash
./run.sh single-node --destroy-only
```

---

## B. Cluster (full gate)

Repeat A on a `cluster-hetero` (or `cluster-3-mixed`) deployment, upgrading the
nodes **one at a time** (owners before/after workers both exercised), then:

1. Confirm each node migrated and kept its snapshot rows (step 5 per node).
2. Confirm cross-node snapshot routing still works after the upgrade
   (B6: `GET`/`DELETE` a snapshot from a non-owner node — UC-247..251).
3. Run the failover gate on the upgraded cluster:
   ```bash
   go test -tags integration -run TestSnapshotBackedFailover ./integration-tests/suite/...
   ```
   (or let `make integration-cluster-hetero` run the whole disruptive set).
   EXPECT: the snapshot-backed sandbox recreates on a peer and the snapshot stays
   resolvable after the owner is killed.

Pass criteria for the release: no snapshot rows lost on any node, every seeded
snapshot resolvable + create-from-snapshot works post-upgrade, cross-node routing
intact, and UC-58d green.
