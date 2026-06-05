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

**Ansible is the sole writer of `/usr/local/bin/toolboxd`. Terraform never
touches it.** Use `Ansible/playbooks/update-toolboxd.yml` - the playbook
already handles atomic file swap, per-host serialization, and version
reporting.

There are exactly two valid sources for the new binary:

1. A locally built `bin/toolboxd` (the common case during development).
2. A GitHub release asset attached by `.github/workflows/release.yml` when
   a tag is published (the common case after a release is cut).

Don't `scp` a binary onto a node by hand. The playbook's atomic `mv`
guarantees a sandbox starting mid-rollout sees either the old or the new
inode, never a half-written file.

## Path A - push a locally built binary (most common while developing)

Use this whenever you've merged or cherry-picked changes that aren't in a
released artifact yet.

```bash
# 1. Pull the latest code and cross-compile for Linux nodes.
cd <repo-root>
git pull origin main
GOOS=linux GOARCH=amd64 make build-toolboxd
# → produces bin/toolboxd

# 2. Roll it out across the fleet (run from Ansible/).
cd Ansible
ansible-playbook -i inventory/aws_ec2.yml playbooks/update-toolboxd.yml \
  -e toolboxd_local_binary=../bin/toolboxd
```

The path is resolved relative to the `Ansible/` directory, so `../bin/toolboxd`
works regardless of where ansible-playbook switches cwd to internally.

For ARM64 nodes (e.g. Graviton), build with `GOARCH=arm64` and roll out the
same way.

## Path B - fetch a GitHub release asset

Only valid if you've tagged a release and `release.yml` has finished
building. Release assets follow `toolboxd_<goos>_<goarch>` - matching the
sandboxd asset naming convention.

```bash
cd Ansible
ansible-playbook -i inventory/aws_ec2.yml playbooks/update-toolboxd.yml \
  -e toolboxd_remote_url=https://github.com/aerol-ai/microvm/releases/latest/download/toolboxd_linux_amd64
```

To pin to a specific version instead of `latest`:

```bash
-e toolboxd_remote_url=https://github.com/aerol-ai/microvm/releases/download/v0.2.2/toolboxd_linux_amd64
```

## Test on one node before the full rollout

The playbook uses `serial: 1` and `any_errors_fatal: true`, so a failure on
node 1 stops the rollout before it touches the rest of the cluster. Even so,
prefer to verify the binary on a single host first:

```bash
ansible-playbook -i inventory/aws_ec2.yml playbooks/update-toolboxd.yml \
  -e toolboxd_local_binary=../bin/toolboxd \
  --limit aerolvm-srv1
```

Then create a fresh sandbox against that host and exercise the changed code
path. Once it works, drop `--limit` and run the full sweep.

## What the playbook actually does

Per node, in order:

1. Validates exactly one of `toolboxd_local_binary` or `toolboxd_remote_url`
   was passed.
2. Stages the new binary at `/tmp/toolboxd.new` (upload or `get_url`),
   mode `0755`, root-owned.
3. Atomically `mv -f /tmp/toolboxd.new /usr/local/bin/toolboxd`. `mv`
   within a filesystem is a directory-entry swap - sandboxes that already
   bind-mounted the old inode keep it; new sandboxes see the new file.
4. Runs `timeout 5s /usr/local/bin/toolboxd --version` and prints the
   reported version. The `timeout` wrapper is intentional: toolboxd builds
   older than the `--version` flag (added 2026-05-23) interpret any argv as
   a user entrypoint and block on `ListenAndServe`. The timeout bounds that
   worst case.
5. Prints a reminder that **existing sandboxes still run the old in-RAM
   binary**.

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

After the playbook reports success, the recommended sanity check is:

1. Confirm the host file is the expected version on a sample of nodes:

   ```bash
   ansible all -i inventory/aws_ec2.yml -a \
     'timeout 5s /usr/local/bin/toolboxd --version'
   ```

2. Create a new sandbox and exercise the changed endpoint (e.g. for the
   2026-05-23 interactive-input fix, run a session command that uses
   `read`, send input via `sendSessionCommandInput`, and verify the
   response is no longer `501 interactive command input is not implemented`).

If both checks pass, the rollout is complete. Existing long-lived sandboxes
that need the fix will pick it up on their next recreate cycle.

## When to use Terraform instead

Never, for toolboxd. The binary version is ephemeral cluster ops, exactly
like sandboxd's version. Terraform owns provisioning, role, and DNS - see
[`role-changes.md`](./role-changes.md) for the broader rule.
