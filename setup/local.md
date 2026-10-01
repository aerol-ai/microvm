# Local Setup

Run AerolVM directly on your Mac or Linux laptop for SDK development, demos, or
quick experiments. No domain, no TLS, no Caddy - the daemon listens on
`http://localhost:21212` and your SDK connects there directly.

This setup is **not for production**. For a single production server see
[`single-node.md`](./single-node.md). For a multi-node failover-tolerant
deployment see [`cluster.md`](./cluster.md).

---

## Prerequisites

| Requirement | Notes |
|---|---|
| macOS or Linux | Other OSes are not supported. |
| Docker running | OrbStack or Docker Desktop on macOS, Docker Engine on Linux. `docker ps` must succeed. |
| `sudo` access | **Linux only** (systemd unit). On macOS the install is per-user and needs no admin rights — run it without `sudo`. |
| `curl` and `bash` | Available out of the box on both OSes. |

No port-forwarding, DNS, or firewall changes are needed - the API binds to
`127.0.0.1` only. On macOS every listener (API, SSH gateway) is bound to
`127.0.0.1`, and each sandbox publishes only its toolbox port, also on
`127.0.0.1`.

---

## Install

macOS (as yourself, **no** `sudo`):

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh \
  | bash -s -- \
      --local \
      --pat-token your-secret-pat
```

Linux:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh \
  | sudo bash -s -- \
      --local \
      --pat-token your-secret-pat
```

From a source checkout, `./scripts/install.sh --local` builds the binaries
instead of downloading them.

If you omit `--pat-token`, the installer generates a random token and prints
it once at the end. Save it - see "Re-read PAT" below. Re-running the macOS
installer keeps the existing token.

What the installer does on **macOS** (nothing outside `$HOME`):

1. Installs `sandboxd` (macOS build) to `~/.aerolvm/bin` and `toolboxd`
   (Linux build — it runs inside the sandbox containers) to
   `~/.aerolvm/toolbox`. `~/.aerolvm` sits under `/Users`, which the
   OrbStack / Docker Desktop VM shares, so `toolboxd` bind-mounts from there.
2. Writes the LaunchAgent `~/Library/LaunchAgents/com.aerol.sandboxd.plist`
   (mode `0600`, it carries the PAT) with state, keys, mounts and logs under
   `~/.aerolvm`, the Docker socket of your active `docker context`, and:
   - `SB_DOCKER_TOOLBOX_LOOPBACK=true` — macOS Local Network privacy blocks a
     user process from dialing the Docker VM's container IPs, so `sandboxd`
     reaches each sandbox's `toolboxd` on a `127.0.0.1` port instead.
   - `SB_SSH_LISTEN_ADDR=127.0.0.1:2220` — the SSH gateway default is
     `0.0.0.0:2220`.
   - `SB_RESOURCE_LIMITS_DISABLED=true` — the OrbStack / Docker Desktop VMs
     cannot enforce Docker disk quotas (`--storage-opt size`), so every create
     would fail with limits on.
3. Loads the LaunchAgent (it starts at login) and waits for
   `localhost:21212/health`.

What the installer does on **Linux**:

1. Downloads `sandboxd` and `toolboxd` to `/usr/local/bin`.
2. Writes `/etc/sandboxd/sandboxd.env` with `SB_API_HOST=127.0.0.1`,
   `SB_ENABLE_CADDY=false`, and `SB_ENABLE_NETWORK_RULES=false`.
3. Registers the systemd unit `sandboxd.service` (no Caddy dependency).
4. Starts the daemon. The API is immediately reachable on `localhost:21212`.

Verify:

```bash
curl http://localhost:21212/health
```

A `200 OK` with a JSON body means you're done.

---

## Connect from an SDK

Point the SDK at the local server and pass your PAT:

```ts
import { Sandbox } from "@aerol-ai/sdk";

const sb = new Sandbox({
  baseURL: "http://localhost:21212",
  apiKey: process.env.SB_PAT_TOKEN,
});
```

See [SDK Setup](https://microvm.aerol.ai/sdk-setup) for examples in all five
SDK languages.

---

## Day-to-day operations

| Task | macOS | Linux |
|---|---|---|
| View logs | `tail -f ~/.aerolvm/logs/sandboxd.log` | `journalctl -u sandboxd -f` |
| Restart | `launchctl kickstart -k gui/$(id -u)/com.aerol.sandboxd` | `sudo systemctl restart sandboxd` |
| Stop | `launchctl bootout gui/$(id -u)/com.aerol.sandboxd` | `sudo systemctl stop sandboxd` |
| Re-read PAT | `plutil -extract EnvironmentVariables.SB_PAT_TOKEN raw ~/Library/LaunchAgents/com.aerol.sandboxd.plist` | `grep SB_PAT_TOKEN /etc/sandboxd/sandboxd.env` |

Sandbox state lives in `state.db` (SQLite): `~/.aerolvm/state/` on macOS,
`/var/lib/sandboxd/` on Linux. Mounts and runtime files live under
`~/.aerolvm/{mounts,run}/` on macOS, `/var/lib/sandboxd/mounts/` and
`/run/sandboxd/` on Linux.

---

## Uninstall

macOS (`uninstall.sh` is Linux-only):

```bash
launchctl bootout gui/$(id -u)/com.aerol.sandboxd
rm -rf ~/.aerolvm ~/Library/LaunchAgents/com.aerol.sandboxd.plist
docker ps -a --filter 'label=aerolvm.managed=true' -q | xargs docker rm -f
```

Linux:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/uninstall.sh \
  | sudo bash
```

Removes the daemon registration, binaries, and `/etc/sandboxd/`. **Does not**
remove Docker, sandbox state DB, or running sandbox containers - clean those
up manually if you want a fresh slate:

```bash
sudo rm -rf /var/lib/sandboxd /var/log/sandboxd /run/sandboxd
docker ps -a --filter 'label=aerolvm.managed=true' -q | xargs -r docker rm -f
```

---

## What you do NOT get with --local

- **No public URLs.** Sandboxes are reachable from the host only.
- **No TLS.** Traffic is plaintext on loopback.
- **No multi-tenant isolation hardening.** `SB_ENABLE_NETWORK_RULES=false`.
- **No automatic restarts on host reboot if you uninstall Docker.** The
  daemon depends on Docker running first.

If any of those matter, move to [`single-node.md`](./single-node.md).
