# Isolate runtime: workerd binary upgrade runbook

The V8-isolate runtime (plans/isolate-runtime.md) wraps Cloudflare's `workerd`
as an external process — the same posture as `firecracker`. The binary is
**version-pinned and SHA-256 verified** by `scripts/install.sh --with-isolate`;
there is no "latest" channel on purpose: a workerd upgrade changes V8, and V8
changes JS behavior. Sandboxes pin a `compatibility_date`, but the engine
binary is still a fleet-wide artifact that upgrades deliberately, not
implicitly.

## Where the pin lives

`scripts/install.sh`, top of file:

```bash
WORKERD_VERSION="v1.20260717.1"
WORKERD_SHA256_LINUX_64="7ff61e05…"
WORKERD_SHA256_LINUX_ARM64="3ef71b4a…"
```

The three values move together. The hashes are the release assets'
(`workerd-linux-64.gz` / `workerd-linux-arm64.gz`) SHA-256 — upstream ships no
checksum sidecar, so the pin in the script is the trust anchor.

## Upgrade procedure

1. Pick the target release at
   <https://github.com/cloudflare/workerd/releases>. Read the release notes
   for compatibility-date and V8 changes.
2. Fetch the per-asset SHA-256 from the GitHub API
   (`/repos/cloudflare/workerd/releases/tags/<tag>` — each asset carries a
   `digest`), or download the assets and hash them locally from two
   independent networks.
3. Update `WORKERD_VERSION` + both `WORKERD_SHA256_LINUX_*` values in
   `scripts/install.sh` in one commit.
4. Roll node-by-node, worker nodes first, one at a time:
   - drain the node (`Ansible/playbooks/` drain flow),
   - re-run the workerd install step (or `install.sh --with-isolate` on a
     fresh node),
   - restart `sandboxd`, confirm `GET /v1/health` reports the isolate runtime
     healthy (Ping stats the binary),
   - undrain.
5. Isolate group processes do NOT hot-swap the binary: resident groups keep
   the old workerd until their idle-TTL reap or a restart. A drain/undrain
   cycle is what actually moves tenants onto the new engine.

## Rollback

Same procedure with the previous version/hashes — the pin is in git history.
Because `ephemeral` isolate sandboxes rebuild from content-addressed bundles,
rollback has no artifact-migration step.

## Verification

```bash
/usr/local/bin/workerd --version
sha256sum /usr/local/bin/workerd   # compare against your own record, not upstream
curl -s localhost:21212/v1/health | jq .   # isolate runtime should be ok
```
