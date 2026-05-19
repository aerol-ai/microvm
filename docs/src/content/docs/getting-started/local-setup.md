---
title: Local Setup
description: Run AerolVM directly on your Mac or Linux machine with a localhost API endpoint.
---

Local setup is the fastest way to get started with AerolVM. It runs the server directly on your Mac or Linux machine, skips domain and TLS configuration, and exposes the API on `http://localhost:21212` for local SDK use.

## Prerequisites

Docker Desktop on macOS, or Docker Engine on Linux, must already be running.

## Install on Mac or Linux

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- \
    --local \
    --pat-token your-secret-pat
```

If you omit `--pat-token`, the installer generates a random token and prints it once.

## What The Installer Configures

- Downloads and installs the `sandboxd` and `toolboxd` binaries to `/usr/local/bin`.
- Writes config to `/etc/sandboxd/sandboxd.env` with `SB_ENABLE_CADDY=false`.
- On macOS, registers a launchd daemon named `com.aerol.sandboxd`.
- On Linux, registers a systemd service named `sandboxd`.

## Connection Details

| | |
|---|---|
| API URL | `http://localhost:21212` |
| PAT token | Printed during install, or available in `/etc/sandboxd/sandboxd.env` |
| Logs on macOS | `/var/log/sandboxd/sandboxd.log` |
| Logs on Linux | `journalctl -u sandboxd -f` |

Point your SDK at the local server with `baseURL: "http://localhost:21212"` and `apiKey: "<your-pat>"`. See [SDK Setup](/sdk-setup) for language-specific examples.

## Stop The Service

- macOS: `sudo launchctl unload /Library/LaunchDaemons/com.aerol.sandboxd.plist`
- Linux: `sudo systemctl stop sandboxd`

## Next Steps

- [SDK Setup](/sdk-setup) to connect your client.
- [Sandboxes](/sandboxes) to create your first sandbox.
- [Single-Node Setup](/getting-started/single-node-setup) if you want to move from local development to a public host.