---
title: Local Setup
description: Run AerolVM directly on your Mac or Linux machine with a localhost API endpoint.
---

Local setup is the fastest way to get started with AerolVM. It runs the server directly on your Mac or Linux machine, skips domain and TLS configuration, and exposes the API on `http://localhost:21212` for local SDK use.

## Prerequisites

- **macOS:** OrbStack or Docker Desktop must already be running. No admin rights are needed.
- **Linux:** `sudo` access. The installer installs Docker Engine if it is missing.

## Install on macOS

Run the installer as yourself, **without** `sudo`:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | bash -s -- \
    --local \
    --pat-token your-secret-pat
```

## Install on Linux

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- \
    --local \
    --pat-token your-secret-pat
```

If you omit `--pat-token`, the installer generates a random token and prints it once. Re-running the installer on macOS keeps the existing token.

## What The Installer Configures

**macOS** — a per-user install; nothing is written outside your home directory:

- Installs `sandboxd` to `~/.aerolvm/bin` and the in-sandbox agent `toolboxd` to `~/.aerolvm/toolbox`.
- Keeps state, keys and logs under `~/.aerolvm`.
- Registers a LaunchAgent, `com.aerol.sandboxd`, that starts at login.
- Binds every listener to `127.0.0.1`. Each sandbox publishes only its toolbox port, also on `127.0.0.1`, which is how `sandboxd` reaches it (`SB_DOCKER_TOOLBOX_LOOPBACK=true`).
- Turns off sandbox resource limits: the Linux VMs behind OrbStack and Docker Desktop cannot enforce Docker disk quotas.

**Linux:**

- Installs the `sandboxd` and `toolboxd` binaries to `/usr/local/bin`.
- Writes config to `/etc/sandboxd/sandboxd.env` with `SB_ENABLE_CADDY=false`.
- Registers a systemd service named `sandboxd`.

## Connection Details

| | |
|---|---|
| API URL | `http://localhost:21212` |
| PAT token (macOS) | Printed during install, or `plutil -extract EnvironmentVariables.SB_PAT_TOKEN raw ~/Library/LaunchAgents/com.aerol.sandboxd.plist` |
| PAT token (Linux) | Printed during install, or available in `/etc/sandboxd/sandboxd.env` |
| Logs on macOS | `~/.aerolvm/logs/sandboxd.log` |
| Logs on Linux | `journalctl -u sandboxd -f` |

Point your SDK at the local server with `baseURL: "http://localhost:21212"` and `apiKey: "<your-pat>"`. See [SDK Setup](/sdk-setup) for language-specific examples.

## Stop The Service

- macOS: `launchctl bootout gui/$(id -u)/com.aerol.sandboxd`
- Linux: `sudo systemctl stop sandboxd`

## Next Steps

- [SDK Setup](/sdk-setup) to connect your client.
- [Sandboxes](/sandboxes) to create your first sandbox.
- [Single-Node Setup](/getting-started/single-node-setup) if you want to move from local development to a public host.
