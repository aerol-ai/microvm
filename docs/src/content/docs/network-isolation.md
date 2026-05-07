---
title: Network Isolation
description: Drop outbound traffic for individual sandboxes by installing host firewall rules in DOCKER-USER.
---

# Network isolation

When a sandbox is created with `network_block_all: true`, `sandboxd` installs a firewall rule on the host that drops every packet originating from that container's IP. The container can still receive incoming requests on its exposed ports, but it cannot make outbound network calls.

## How it works

The rule lives in the iptables `filter` table, in the `DOCKER-USER` chain:

```text
iptables -I DOCKER-USER 1 -s <containerIP> -j DROP
```

It is inserted at position `1` so it runs before other operator-defined rules in `DOCKER-USER`. The rule is removed when the sandbox is destroyed.

## Why DOCKER-USER matters

On newer Docker versions, a rule appended directly to `FORWARD` can miss traffic because Docker's own accept rules run first. `DOCKER-USER` is the operator-reserved chain that executes before Docker's routing logic, so the drop rule reliably matches there.

## Verifying the rule works

Create a sandbox with `networkBlockAll: true`, then inspect the chain on the host:

```bash
sudo iptables -L DOCKER-USER -n -v --line-numbers
```

You should see a line like:

```text
1   0     0   DROP   all  --  *  *  172.17.0.2  0.0.0.0/0
```

If you trigger outbound traffic from inside the container, the counters should increment.

## Limitations

- No DNS-only or host allowlist mode yet.
- IPv4 only today.
- The chain is global, so each blocked sandbox adds another rule.
- iptables rules do not survive a host reboot by default.

## File map

| File | Role |
| --- | --- |
| `pkg/docker/netrules/manager.go` | Rule creation and cleanup |
| `pkg/docker/client.go` | Calls `BlockAllEgress` after container start |
| `internal/config/config.go` | `SB_ENABLE_NETWORK_RULES` flag |