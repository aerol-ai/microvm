# Runbook: Egress gateway (hostname egress filtering)

Use this when a `SandboxdEgress*` alert fires, when hostname-filtered creates
answer `503 egress_gateway_unavailable`, or when a sandbox reports
`egress_status: held` or `unavailable`.

Sandboxes whose `network_allow_out` names a hostname (`pypi.org`,
`*.github.com`, `api.example.com:8443`) run in gateway mode. Their DNS and
their port 80/443 traffic go through the `aerolvm-egress-gateway` systemd
unit, which owns the `inet aerolvm_egress` nft table, a filtering DNS
resolver and an SNI/Host proxy. sandboxd drives it over a root-only UDS
(`/run/aerolvm/egress-gateway.sock`). Design:
`plans/egress-domain-filtering.md`.

**Everything here fails closed.** When the gateway is away, gateway-mode
sandboxes are held with no egress at all; they never fall back to
unfiltered egress. CIDR-only policies, block-all and sandboxes without lists
do not use the gateway and are unaffected by every alert below.

## Alerts

| Alert | Meaning |
|---|---|
| `SandboxdEgressGatewayDown` | No live gateway for 1 minute on a node with gateway-mode sandboxes. |
| `SandboxdEgressTableLost` | The gateway found its nft table missing and rebuilt it. |
| `SandboxdEgressAttachFailures` | sandboxd failed to attach more than 2 sandboxes in 10 minutes. |
| `SandboxdEgressSandboxesHeld` | Sandboxes have been held without egress for 10 minutes. |
| `SandboxdEgressAuditDropped` | The gateway's audit ring overflowed; audit records are missing. |
| `SandboxdEgressOperatorConfigDrift` | Nodes run different operator files. |
| `SandboxdEgressOperatorConfigReloadFailed` | An operator file edit did not validate. |
| `SandboxdEgressSelfTestFailing` | Probe traffic sent through the redirect never reached the gateway; the node refuses hostname-filtered creates. |

## Severity

| Severity | Criteria |
|---|---|
| SEV-2 | Gateway down on several nodes, or a cluster with no ready gateway (every hostname-filtered create is refused). |
| SEV-3 | One node's gateway is down or flapping; other nodes take new creates. |
| SEV-4 | Audit drops only; enforcement is unaffected. |

## Metrics

Read them from `GET /v1/metrics` on the node (see the README's standard
evidence commands) or the "Egress gateway" row of the D7 Ingress &
Networking dashboard (`setup/grafana/d7-ingress-networking.json`).

| Metric | Meaning |
|---|---|
| `aerolvm_egress_gateway_up` | 1 while sandboxd has a live, synced gateway connection. |
| `aerolvm_egress_gateway_heartbeat_age_seconds` | Time since the last gateway heartbeat (every 5s when healthy). |
| `aerolvm_egress_gateway_sync_age_seconds` | Time since sandboxd last replaced the gateway's whole state; `-1` = never. |
| `aerolvm_egress_fqdn_sandboxes` | Gateway-mode sandboxes the gateway is filtering. |
| `aerolvm_egress_held_sandboxes` | Gateway-mode sandboxes held without egress. |
| `aerolvm_egress_denied_total{key=<reason>}` | Denials by reason. Exact even when audit events drop. |
| `aerolvm_egress_attach_failed_total` | Failed attaches (each one a 503 create or a held sandbox). |
| `aerolvm_egress_layout_lost_total` | Table rebuilds after the nft table vanished. |
| `aerolvm_egress_audit_dropped_total` | Audit events lost to ring overflow. |
| `aerolvm_egress_dns_queries_total` | Queries reaching the filtering resolver; `rate()` is the DNS QPS. |
| `aerolvm_egress_proxy_connections` | Connections the proxy holds open now. |
| `aerolvm_egress_selftest_ok` | 0 while some sandbox bridge fails its self-test. |
| `aerolvm_egress_selftest_failures_total` | Failed self-test runs. |
| `aerolvm_egress_proxy_connections_cap` | The node-wide proxy connection cap (`SB_EGRESS_PROXY_MAX_CONNS`). |

The capacity heartbeat (`GET /v1/capacity`) also carries
`egress_gateway_ready`. In a cluster, placement sends hostname-filtered
creates only to nodes where it is true.

## GatewayDown

1. Is the unit running?

   ```bash
   sudo systemctl status aerolvm-egress-gateway.service aerolvm-egress-gateway.socket
   sudo journalctl -u aerolvm-egress-gateway --since "30 minutes ago" --no-pager
   ```

2. Common causes in the gateway log:
   - `operator file` errors: `SB_EGRESS_OPERATOR_FILE` failed validation at
     startup. Fix the file (the error names the field) and restart the unit.
   - `bind` / `address already in use`: something else holds the DNS or
     proxy port (`SB_EGRESS_DNS_PORT`, default 53054;
     `SB_EGRESS_PROXY_PORT`, default 15080).
   - `nft` permission errors: the unit lost `CAP_NET_ADMIN`. Compare the
     unit file with `packaging/aerolvm-egress-gateway.service`.
3. Is sandboxd allowed on the socket? The gateway accepts only root peers in
   the `sandboxd.service` cgroup. sandboxd logs
   `egress gateway not ready` with the reason; a `peer` error there means
   sandboxd runs under a different unit name (set `SB_EGRESS_PEER_CGROUP`).
4. Restart the gateway. Its restart is a short fail-closed pause for
   gateway-mode sandboxes; sandboxd re-syncs within 5 seconds of it coming
   back and releases the holds:

   ```bash
   sudo systemctl restart aerolvm-egress-gateway.service
   ```

5. Verify: `aerolvm_egress_gateway_up` is 1, `aerolvm_egress_held_sandboxes`
   returns to 0, and sandboxd logs `egress gateway ready`.

## TableLost

The gateway checks its table every heartbeat. When it is gone, the gateway
rebuilds it in one batch and re-applies its state, and sandboxd holds every
gateway-mode sandbox until a full re-sync confirms them. The exposure is one
heartbeat interval, and it is a fail-closed exposure: without the table the
sandbox's traffic hits the host firewall's hold rule, not the internet.

Find what flushed nftables:

```bash
sudo journalctl --since "1 hour ago" --no-pager | grep -iE 'nft|firewalld|ufw|iptables'
sudo nft list tables
```

Firewall managers (firewalld, ufw, a config-management run that does
`nft flush ruleset`) are the usual cause. Exclude the `inet aerolvm_egress`
table from them.

## AttachFailures

sandboxd logs each failure with the sandbox id. Group them:

```bash
sudo journalctl -u sandboxd --since "30 minutes ago" --no-pager | grep -E 'egress'
```

- `egress gateway unavailable` or `version mismatch`: see GatewayDown. A
  version mismatch means sandboxd and the gateway are two protocol versions
  apart; upgrade the gateway unit to the sandboxd build.
- `learned_cap`: a sandbox reached its learned-destination cap. Check the
  policy for very broad wildcards.
- Anything else from `nft`: capture `sudo nft list table inet aerolvm_egress`
  and the gateway log, then restart the gateway.

## SandboxesHeld

A held sandbox has no egress. `GET /v1/sandboxes/{id}` shows
`egress_status: held` (attach failed, or the policy is invalid) or
`unavailable` (the gateway was down or its table was lost). Holds lift on
the next successful attach: when the gateway recovers, on sandbox start, or
on the reconcile pass. A hold that does not lift while
`aerolvm_egress_gateway_up` is 1 points at that sandbox's policy; the
sandboxd log names the reason.

## AuditDropped

The gateway buffers audit events in a ring (`SB_EGRESS_AUDIT_BUFFER`) and
drops the oldest when sandboxd does not drain it in time, typically while
sandboxd restarts or during a denial storm from one sandbox. Enforcement is
unaffected and `aerolvm_egress_denied_total` stays exact. Raise
`SB_EGRESS_AUDIT_BUFFER` if drops recur outside sandboxd restarts, and look
at `aerolvm_egress_denied_total` by reason for a sandbox retrying a denied
host in a tight loop.

## SelfTestFailing

At gateway startup, after every gateway restart, and when a bridge first
appears, sandboxd checks each sandbox bridge. It builds a throwaway netns
(`aerolvm-egprobe<N>`) joined to the bridge by a veth, with the reserved
address `169.254.250.<N+1>`, sends one DNS query and one TCP connect to port
443 through the redirect, and asks the gateway whether both arrived. The
sandboxd log line `egress gateway self-test failed` names the bridge and the
cause:

- `redirected traffic did not reach the gateway`: the host's input path
  drops it. ufw, firewalld or a hardened AMI with an INPUT policy of DROP
  are the usual causes. Allow TCP and UDP to `SB_EGRESS_DNS_PORT` (default
  53054) and TCP to `SB_EGRESS_PROXY_PORT` (default 15080) arriving on the
  sandbox bridges (`docker0`, `aerolvm0`).
- `bridge-nf-call-iptables is not 1`: load `br_netfilter` and set the
  sysctl; sandboxd sets it at startup, so something reset it.
- `carries IPv6`: the gateway redirects IPv4 only, so a bridge with a global
  IPv6 address cannot be filtered. Disable IPv6 on the sandbox bridge.

A bridge that does not exist yet (containerd's `aerolvm0` before the first
sandbox) is not a failure; it is tested once it appears. Failed bridges are
retried with backoff up to every 5 minutes, and immediately on the next
sandboxd or gateway restart.

## OperatorFile

Private-cloud deployments set `SB_EGRESS_OPERATOR_FILE` (normally
`/etc/sandboxd/egress-policy.yaml`) for the default policy, the ceiling, the
deny floor, the internal zone and the upstream proxy. sandboxd reads it for
the default policy and the ceiling; the gateway reads it for the internal
zone, the floor and the proxy.

- **Edits.** sandboxd picks up a change within 10 seconds, or at once on
  `systemctl kill -s HUP sandboxd`. An edit that does not validate is
  ignored: the last good file stays live, sandboxd logs
  `egress operator file invalid` with the field, and
  `SandboxdEgressOperatorConfigReloadFailed` fires. The gateway reads the
  file at start; restart `aerolvm-egress-gateway` after changing the
  internal zone, floor or proxy.
- **Invalid at boot.** A sandboxd that starts with a file present but invalid
  refuses every create with `503 egress_operator_config_invalid`, because
  the default policy is unknown. Fix the file; the next poll picks it up and
  creates resume.
- **Drift.** Every node exports `aerolvm_egress_operator_config_info` with
  the file's hash as its label. `SandboxdEgressOperatorConfigDrift` fires
  when nodes disagree for 10 minutes; ship the same file everywhere
  (`config/cluster.yml` drives install, Terraform and Ansible).
- **Running sandboxes.** The default policy is written into each sandbox's
  spec at create, so editing the file never changes a running sandbox, and a
  failover recreate keeps what the sandbox was created with.

## Tracing and logs

With `SB_OTEL_TRACES_ENABLED` (or an OTLP traces endpoint) set in the
gateway's env file, `/etc/sandboxd/egress-gateway.env`, gateway spans
(`egress.gateway.<op>`) join sandboxd's `egress.attach` and `egress.sync`
traces. Every allow and deny decision is logged at debug level with
`sandbox_id`, `reason`, `rule` and `mode`.

## Turning it off

Set `SB_EGRESS_FQDN_ENABLED=false` for sandboxd and restart it. Hostname
policies are then refused with 501 at create; CIDR policies keep working on
the host firewall. Sandboxes already in gateway mode stay held until
deleted, because there is no unfiltered fallback by design.
