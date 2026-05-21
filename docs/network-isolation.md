# Network isolation

When a sandbox is created with `network_block_all: true`, `sandboxd` installs
a firewall rule on the host that drops every packet originating from that
container's IP. The container can still receive incoming requests on its
exposed ports, but it cannot make any outbound network calls - useful when
running untrusted code, model agents you don't want phoning home, or
anything that should be airgapped from the network.

## How it works

The rule lives in the iptables `filter` table, in the `DOCKER-USER` chain:

```
iptables -I DOCKER-USER 1 -s <containerIP> -j DROP
```

Specifically: insert at position 1, so the rule fires before any other
operator-defined rules in `DOCKER-USER`. The rule is removed when the
sandbox is destroyed.

### Why DOCKER-USER and not FORWARD

Docker structures its firewall rules across several chains. On Docker 28+
(and on your typical EC2 Ubuntu install), the chain hierarchy looks like:

```
FORWARD (policy DROP)
  ├── jump DOCKER-USER          ← (1) operator rules go here
  └── jump DOCKER-FORWARD
        ├── jump DOCKER-CT      (established connections)
        ├── jump DOCKER-INTERNAL
        ├── jump DOCKER-BRIDGE
        └── iifname "docker0" accept   ← (2) blanket allow for outbound
```

A rule appended directly to `FORWARD` lands *after* the jump to
`DOCKER-FORWARD` - so by the time our rule would have run, line (2) has
already accepted the packet and exited the chain. The rule is installed
but never matches, with `0 packets, 0 bytes` in `iptables -L FORWARD -v`.

`DOCKER-USER` is the chain Docker explicitly reserves for operator
firewall rules. Docker guarantees it is jumped *before* its own logic,
which is why our rule needs to live there.

### iptables-legacy vs nftables

On Docker 28+ Ubuntu, `iptables` is actually `iptables-nft` - a shim that
translates the iptables CLI / library API into native nftables rules.
Writing to `DOCKER-USER` via the [`coreos/go-iptables`][go-ipt] library
goes through this shim, so the same code works on:

- Older systems running `iptables-legacy` directly.
- Modern systems where Docker's chains live in nftables.

[go-ipt]: https://github.com/coreos/go-iptables

No nftables-native backend is needed. If you're on a platform where the
`iptables` binary is missing entirely (e.g. some minimal CoreOS images),
this code will fail with "create iptables client" at startup - set
`SB_ENABLE_NETWORK_RULES=false` to disable network blocking on that host.

## Verifying the rule works

Create a sandbox with `networkBlockAll: true`:

```ts
const sandbox = await client.create({
  image: "ubuntu:22.04",
  networkBlockAll: true,
});
```

On the host running `sandboxd`:

```
sudo iptables -L DOCKER-USER -n -v --line-numbers
```

You should see a line like:

```
1   0     0   DROP   all  --  *  *  172.17.0.2  0.0.0.0/0
```

After making any outbound attempt from inside the container (e.g.
`docker exec <id> curl https://example.com`), the packet/byte counters
should increment, confirming the rule is matching.

If the counters stay at `0` while the container makes outbound requests,
the rule isn't firing. Common causes:

- **`SB_ENABLE_NETWORK_RULES=false`** - sandboxd skipped installation.
  Look for `m.Enabled()` in [`netrules/manager.go`](../pkg/docker/netrules/manager.go).
- **Wrong chain** - pre-fix versions of `sandboxd` (before this change)
  installed the rule in `FORWARD`, where it never matched on Docker 28+.
  Upgrade and recreate the sandbox.
- **Custom DOCKER-USER rules** - if an operator added their own
  `ACCEPT` rule earlier in `DOCKER-USER`, it would short-circuit our
  `DROP`. We `Insert` at position 1, but a manually-added rule at
  position 1 with `--insert` after ours could displace it. Audit
  `iptables -L DOCKER-USER --line-numbers`.

## Limitations

- **No DNS-only blocking** - current rule blocks all egress (TCP, UDP,
  ICMP, IPv4). There's no allowlist for "DNS allowed but nothing else."
- **IPv4 only** - the rule is in the `filter` table for IPv4. If your
  sandbox network has IPv6 routes, those are not blocked. Most Docker
  default-bridge setups are IPv4-only, but if you've enabled
  `--ipv6` on the daemon, add a parallel `ip6tables` rule.
- **Per-sandbox only** - there's no allowlist of permitted hosts. If
  you need "egress allowed to S3 but nothing else," extend the manager
  to install a sequence of `ACCEPT` rules followed by a final `DROP`.
- **Host shares the rule table** - `DOCKER-USER` is a global chain. If
  many sandboxes are running with `networkBlockAll`, the chain accrues
  one rule per sandbox. iptables handles thousands of rules fine, but
  it's a linear scan on the hot path. nftables sets would be faster at
  scale; not worth the complexity until you're at >1000 concurrent
  blocked sandboxes.

## Reconcile and reboot recovery

`networkBlockAll` is stored on the sandbox row and reconciled from Docker's
current runtime view. On every boot reconcile and periodic reconcile pass,
`sandboxd`:

1. Lists the managed containers Docker currently has.
2. Refreshes each sandbox row with the container's current ID and IP.
3. Re-applies `BlockAllEgress(<current container IP>)` for every running
   sandbox with `networkBlockAll=true`.

This means host reboot, Docker chain rebuild, `iptables` flush, or a missed
create/start rule install is healed by the next reconcile pass. The reapply is
idempotent: the netrules manager checks for an existing `DOCKER-USER` rule
before inserting, so running reconcile repeatedly does not create duplicate
rules.

You can force the same repair immediately:

```bash
curl -fsS -X POST -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/admin/reconcile
```

## Cleanup

`ClearBlockAllEgress` is called when the sandbox is destroyed or when the
runtime reports a stop/die/destroy event for that container IP. The stop path
clears the per-IP rule because Docker may later assign that IP to an unrelated
container. A later `Start` or reconcile pass re-applies the rule if the sandbox
is still configured with `networkBlockAll=true`.

## File map

| File | Role |
| --- | --- |
| `pkg/docker/netrules/manager.go` | `Manager`, `BlockAllEgress`, `ClearBlockAllEgress` |
| `pkg/docker/client.go` | calls `BlockAllEgress` after container start when `req.NetworkBlockAll` is set |
| `internal/service/service.go` | re-applies `networkBlockAll` during start and reconcile using Docker's current container IP |
| `internal/config/config.go` | `EnableNetworkRules` (env: `SB_ENABLE_NETWORK_RULES`, default `true`) |
