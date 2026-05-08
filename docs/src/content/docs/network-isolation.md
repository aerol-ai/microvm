---
title: Network Isolation
---

# Network Isolation

When a sandbox is created with `network_block_all: true`, the platform installs a firewall rule on the host that drops every outbound packet from that sandbox. The sandbox can still receive incoming requests on its exposed ports, but cannot make any outbound network calls.

## How it works

The rule is installed in the iptables `DOCKER-USER` chain:

```text
iptables -I DOCKER-USER 1 -s <containerIP> -j DROP
```

It is inserted at position `1` so it runs before other rules. The rule is removed when the sandbox is destroyed.

## Why DOCKER-USER

On newer Docker versions, a rule appended directly to `FORWARD` can miss traffic because Docker's own accept rules run first. `DOCKER-USER` is the operator-reserved chain that executes before Docker's routing logic, so the drop rule reliably matches there.

## Verifying the rule

Create a sandbox with `networkBlockAll: true`, then inspect the chain on the host:

```bash
sudo iptables -L DOCKER-USER -n -v --line-numbers
```

You should see a line like:

```text
1   0     0   DROP   all  --  *  *  172.17.0.2  0.0.0.0/0
```

If you trigger outbound traffic from inside the sandbox, the counters should increment.

## Limitations

- No DNS-only or host allowlist mode yet.
- IPv4 only today.
- The chain is global, so each blocked sandbox adds another rule.
- iptables rules do not survive a host reboot by default.
