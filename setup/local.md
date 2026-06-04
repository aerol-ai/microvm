# Local Setup

Run AerolVM directly on your Mac or Linux laptop for SDK development, demos, or
quick experiments. No domain, no TLS, no Caddy — the daemon listens on
`http://localhost:21212` and your SDK connects there directly.

This setup is **not for production**. For a single production server see
[`single-node.md`](./single-node.md). For a multi-node failover-tolerant
deployment see [`cluster.md`](./cluster.md).

---

## Prerequisites

| Requirement | Notes |
|---|---|
| macOS or Linux | Other OSes are not supported. |
| Docker running | Docker Desktop on macOS, Docker Engine on Linux. `docker ps` must succeed. |
| `sudo` access | The installer registers a launchd / systemd daemon. |
| `curl` and `bash` | Available out of the box on both OSes. |

No port-forwarding, DNS, or firewall changes are needed — the API binds to
`127.0.0.1` only.

---

## Install

One command:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh \
  | sudo bash -s -- \
      --local \
      --pat-token your-secret-pat
```

If you omit `--pat-token`, the installer generates a random token and prints
it once at the end. Save it — you can also re-read it from
`/etc/sandboxd/sandboxd.env` later.

What the installer does:

1. Downloads `sandboxd` and `toolboxd` to `/usr/local/bin`.
2. Writes `/etc/sandboxd/sandboxd.env` with `SB_API_HOST=127.0.0.1`,
   `SB_ENABLE_CADDY=false`, and `SB_ENABLE_NETWORK_RULES=false`.
3. Registers a daemon:
   - **macOS**: launchd plist `/Library/LaunchDaemons/com.aerol.sandboxd.plist`.
   - **Linux**: systemd unit `sandboxd.service` (no Caddy dependency).
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
| View logs | `tail -f /var/log/sandboxd/sandboxd.log` | `journalctl -u sandboxd -f` |
| Restart | `sudo launchctl kickstart -k system/com.aerol.sandboxd` | `sudo systemctl restart sandboxd` |
| Stop | `sudo launchctl unload /Library/LaunchDaemons/com.aerol.sandboxd.plist` | `sudo systemctl stop sandboxd` |
| Re-read PAT | `grep SB_PAT_TOKEN /etc/sandboxd/sandboxd.env` | same |

Sandbox state lives in `/var/lib/sandboxd/state.db` (SQLite). Mounts and
runtime files live under `/var/lib/sandboxd/mounts/` and `/run/sandboxd/`.

---

## Uninstall

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/uninstall.sh \
  | sudo bash
```

Removes the daemon registration, binaries, and `/etc/sandboxd/`. **Does not**
remove Docker, sandbox state DB, or running sandbox containers — clean those
up manually if you want a fresh slate:

```bash
sudo rm -rf /var/lib/sandboxd /var/log/sandboxd /run/sandboxd
docker ps -a --filter 'label=aerol.sandbox' -q | xargs -r docker rm -f
```

---

## What you do NOT get with --local

- **No public URLs.** Sandboxes are reachable from the host only.
- **No TLS.** Traffic is plaintext on loopback.
- **No multi-tenant isolation hardening.** `SB_ENABLE_NETWORK_RULES=false`.
- **No automatic restarts on host reboot if you uninstall Docker.** The
  daemon depends on Docker running first.

If any of those matter, move to [`single-node.md`](./single-node.md).
