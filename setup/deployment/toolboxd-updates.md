# Updating toolboxd across the cluster

`toolboxd` is the in-container agent that handles file I/O, exec, and session
proxying for every sandbox. It is **not** a host daemon - sandboxd
bind-mounts the host binary read-only into each container at create time
(see `pkg/docker/client.go`), so updating it has different semantics from
updating sandboxd:

- There is no systemd service to restart.
- The host's `/health` endpoint reflects sandboxd, not toolboxd.
- Sandboxes running **before** the swap keep the old binary loaded in RAM
  forever. Only sandboxes created **after** the swap pick up the new code.

This guide is the routine "I pushed new toolboxd code, now what" runbook.

## The rule

**`toolboxd` ships with `sandboxd`, and they upgrade together.** Every
release carries `sandboxd`, `toolboxd` and `caddy` for each CPU type, and
`aerolvm upgrade apply` replaces all three on every node in one step. There
is no separate toolboxd rollout. The old Ansible playbook
(`update-toolboxd.yml`) is gone, and Terraform never touches the binary.

On each node the upgrader (`sandboxd upgrade node`) checks every file
against its SHA-256 before anything changes, keeps the old files as
`*.prev`, and swaps `toolboxd` first, then `caddy`, then `sandboxd`. Each
swap is a rename, so a sandbox starting mid-upgrade sees either the old or
the new file, never a half-written one.

Don't `scp` a binary onto a node by hand.

## Path A - a release

```bash
aerolvm upgrade plan v0.7.0
aerolvm upgrade apply v0.7.0 --wait
```

`plan` changes nothing. It shows each node's version, the order the nodes
go in, and what restarts. `apply` hands the rollout to the cluster's
leader: servers one at a time (the leader last), then ingress nodes, then
workers in batches. Each node is checked healthy before the next one
starts. See [`../runbooks/cluster-upgrades.md`](../runbooks/cluster-upgrades.md)
for `status`, `stop`, `resume`, `rollback` and what to do when a node fails.

## Path B - a build of your own (development)

Build the Linux files into one folder with a `checksums.txt` that lists
them (the integration harness's `make itest-build` makes exactly that
folder, under `integration-tests/.build/<id>/`):

```
dist/
  checksums.txt
  sandboxd_linux_amd64
  toolboxd_linux_amd64
```

Then push it to every node:

```bash
aerolvm upgrade apply <version-the-build-reports> --from ./dist --allow-unversioned --wait
```

`--from` uploads the files to the cluster, which hands them to the nodes;
the nodes need no internet access. `--allow-unversioned` lets a build whose
version is not a release tag through. To try it on one canary worker
first, add `--pause-after 1`; `aerolvm upgrade resume` goes on.

## Existing sandboxes do not pick up the change

The Linux kernel keeps the original inode alive as long as something holds
it open - and every running sandbox holds toolboxd open as PID 1 of its
container. Rolling the host binary updates the directory entry, not the
inode in use.

To force-pick-up on a running workload, recreate the sandbox. For an
SDK-driven flow:

```typescript
await daytona.delete(sandbox)
const next = await daytona.create({ image, language, ... })
```

For a sweep of many sandboxes, drive the recreate from your own
orchestration - there is no host-level toolboxd restart that flushes them,
and there shouldn't be (it would kill every running session at once).

If a user reports "I updated toolboxd but my fix doesn't show up", this is
almost always the explanation. Confirm by checking
`/proc/<sandbox-pid>/exe` on the host - it will be a symlink ending
`(deleted)` once the host binary has been replaced and the sandbox is still
running the old inode.

## Verifying the rollout

1. `aerolvm upgrade status` shows every node `done`, and
   `aerolvm get nodes` shows the new version on every node.
2. On a node, `timeout 5s /usr/local/bin/toolboxd --version` prints the new
   version.
3. Create a new sandbox and exercise the changed endpoint.

If all three pass, the rollout is complete. Existing long-lived sandboxes
that need the fix will pick it up on their next recreate cycle.

## When to use Terraform instead

Never, for toolboxd. The binary version is ephemeral cluster ops, exactly
like sandboxd's version. Terraform owns provisioning, role, and DNS - see
[`role-changes.md`](./role-changes.md) for the broader rule.
