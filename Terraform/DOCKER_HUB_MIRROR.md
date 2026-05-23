# Docker Hub mirror via AOCR — day-0 setup

This document explains why Docker Hub pulls bypass the AOCR mirror by
default, what Terraform now does about it automatically, and how to
retrofit existing hosts that were provisioned before this change.

## Why Docker Hub is the odd one out

Sandboxd ships a client-side rewriter (`pkg/docker/mirror_rewrite.go`)
that turns refs like `ghcr.io/aerol-ai/sandbox:v1` into
`<mirror_host>/aocr/ghcr/aerol-ai/sandbox:v1` before handing them to
the Docker daemon. That works for any registry whose name appears in
`SB_MIRROR_UPSTREAMS` — `ghcr.io`, `gcr.io`, `quay.io`,
`registry.k8s.io` — because rewriting the URL is enough to redirect
the pull.

Docker Hub is intentionally **not** in that list. The reason is a
quirk in dockerd itself: Hub-style short refs (`alpine`,
`library/redis`) are resolved by the daemon's built-in Hub client, and
the daemon will only consult a mirror for that client if you set
`registry-mirrors` in `/etc/docker/daemon.json`. URL rewriting from
userspace doesn't intercept it.

**Net effect of doing nothing**: Hub pulls go straight to
`registry-1.docker.io`, skipping the AOCR cache and any rate-limit
protection it would have provided.

## What Terraform now does (day-0)

When `var.aocr.enabled = true` **and** `var.aocr.mirror_host != ""`,
`templates/bootstrap.sh.tftpl` writes `/etc/docker/daemon.json` before
`install.sh` runs:

```json
{
  "registry-mirrors": ["https://<mirror_host>"],
  "live-restore": true
}
```

Two things to know:

1. **`registry-mirrors`** routes Hub pulls through AOCR. The mirror
   recognises Hub paths (`/v2/library/alpine/...`,
   `/v2/<org>/<repo>/...`) and proxies them.
2. **`live-restore: true`** lets the daemon restart in the future
   (cert rotation, package upgrades) without killing running
   sandboxes. The first apply doesn't need the flag yet — no
   containers exist at provision time — but turning it on now means
   you don't have to remember later.

If a pre-baked AMI already contains `/etc/docker/daemon.json` with
other keys, the bootstrap merges (`jq '. + {...}'`) instead of
clobbering.

No additional Terraform variables. Reusing the existing
`var.aocr.mirror_host`.

## Retrofitting existing hosts

For a fleet provisioned **before** this change, run the one-shot
script below on each host. It's idempotent and safe to re-run.

```bash
#!/usr/bin/env bash
# Usage: sudo MIRROR_HOST=mirror.aocr.aerol.ai ./enable-aocr-hub-mirror.sh
set -euo pipefail

: "${MIRROR_HOST:?MIRROR_HOST is required, e.g. mirror.aocr.aerol.ai}"

command -v jq >/dev/null || { apt-get update -y && apt-get install -y jq; }

install -d -m 0755 /etc/docker
if [ -s /etc/docker/daemon.json ]; then
  jq --arg mirror "https://${MIRROR_HOST}" \
     '. + {"registry-mirrors": [$mirror], "live-restore": true}' \
     /etc/docker/daemon.json > /etc/docker/daemon.json.new
else
  jq -n --arg mirror "https://${MIRROR_HOST}" \
     '{"registry-mirrors": [$mirror], "live-restore": true}' \
     > /etc/docker/daemon.json.new
fi
mv /etc/docker/daemon.json.new /etc/docker/daemon.json
chmod 0644 /etc/docker/daemon.json

systemctl restart docker
echo "[ok] daemon.json updated; mirror=${MIRROR_HOST}"
```

> **Caveat on running hosts**: `systemctl restart docker` will kill
> running containers on a daemon that doesn't already have
> `live-restore: true` set *and active*. The first run on a legacy
> host writes the flag but the restart still happens without it
> (kernel state). Plan to drain the node first, or accept the
> sandbox eviction. Subsequent restarts will be transparent.

## Verification

After provisioning or retrofit, on the host:

```bash
# 1. Mirror is registered.
docker info 2>/dev/null | grep -A2 'Registry Mirrors'
# Expect: https://<mirror_host>/

# 2. live-restore is on.
docker info 2>/dev/null | grep -i 'Live Restore'
# Expect: Live Restore Enabled: true

# 3. Pull through the mirror.
docker pull alpine:3.20
# Check the mirror access log — you should see a /v2/library/alpine/...
# request from this host's IP. Hub itself should NOT see a hit.
```

## Why not Ansible?

This is a one-time, deterministic day-0 setting that piggybacks on
existing user_data. Ansible would add an extra moving part for what
amounts to "write one JSON file before dockerd starts." If you later
need fleet-wide rotation (changing `mirror_host`), the right move is
to roll the launch template and replace nodes — same operational
profile as any other AMI/user-data change.

## Sources

- Docker daemon mirror behavior:
  <https://docs.docker.com/engine/registry/recipes/mirror/> —
  "registry-mirrors" only applies to Docker Hub.
- `live-restore`: <https://docs.docker.com/config/containers/live-restore/>
- Sandboxd rewriter (non-Hub registries):
  `pkg/docker/mirror_rewrite.go`
- AOCR mirror router (Hub path handling): `aocr.sh/mirror/router.go`
