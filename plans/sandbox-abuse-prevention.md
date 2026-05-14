# Sandbox Abuse Prevention (Anti-DDoS, Anti-Scanning, Anti-Spam)

## Context

A sandbox-as-a-service is, by construction, a "give me arbitrary code
execution on the internet" product. The same primitive that makes it useful
for AI agents and code interpreters makes it perfect for:

- Outbound DDoS (volumetric or packet-rate)
- Reflection / amplification attacks (DNS, NTP, memcached, SSDP)
- Port scanning and vulnerability scanning
- Brute-force attacks against third-party auth endpoints
- Spam relay (outbound SMTP)
- Crypto mining
- Open proxy / Tor exit abuse
- C2 traffic for unrelated malware

AerolVM today has **one** anti-abuse primitive: `NetworkBlockAll` — a binary
DROP rule on `DOCKER-USER` keyed by container source IP
(`pkg/docker/netrules/manager.go`). That's all-or-nothing and not enabled by
default. There is no rate limiting, no destination filtering beyond
`networkAllowList` (≤10 CIDRs, off by default), no behavioral detection, and
no kill-switch. The platform's reputation is currently one bad customer away
from getting host IPs onto Spamhaus / AbuseIPDB.

This plan adds a **layered defense** rather than a single mechanism. Each
layer catches what the previous layer misses; cheap layers go first; the
expensive layer (eBPF) only ships once we have data to tune it.

A companion plan, [`network-usage-tracking.md`](./network-usage-tracking.md),
covers per-sandbox byte metering and quotas. That plan is the **billing /
volume backstop** layer of this one — necessary but not sufficient. The two
plans share the `pkg/docker/netrules/` and `internal/service/` integration
surface and should be reviewed together.

## Why bytes-quota alone is insufficient

DDoS is a **rate** problem, not a volume problem. A SYN flood at 100k pps
can take down a target in 30 seconds while moving only ~6 MB total — far
under any sane byte cap. Reflection attacks send tiny request packets and
the *victim* eats the amplified response. Port scans use minuscule
half-open connections. Reasoning purely in bytes/day misses every
fast-and-small attack class.

The metering plan's veth byte counter is the right tool for "did this
sandbox use 10 GB this month." It is the wrong tool for "is this sandbox
SYN-flooding a victim right now."

## Threat model

| Attack | Shape | Detection signal | Enforcement lever |
|---|---|---|---|
| Volumetric flood (UDP/TCP bandwidth) | Sustained high Mbps to one dst | Bandwidth meter trips per-sandbox cap | `tc` TBF rate cap on veth |
| SYN flood / packet flood | Tiny packets, very high pps | nftables pps counter trips | nftables `limit rate over` drop |
| Reflection / amplification (DNS, NTP, memcached, SSDP) | Spoofed-source UDP to amplifier ports | Anti-spoof + dst-port match | rp_filter + static dst port denylist |
| L7 flood (HTTP GET, slowloris) | Many "normal" HTTP/HTTPS requests | Egress proxy request rate per tenant | Caddy/Envoy rate limit |
| Port scanning / vuln scanning | High distinct-dst-IP count per second | eBPF fanout counter | Behavioral kill-switch |
| Brute-force | High cps to one dst:port | nftables per-(src,dst:port) cps | nftables connlimit / hashlimit |
| Spam relay | Outbound to SMTP ports | Static dst-port denylist | nftables drop |
| Crypto mining | Sustained outbound to known pool IPs | Threat-intel ipset match | nftables drop |
| Tor exit / open proxy | Wide fanout, mixed dst, sustained | Behavioral fanout + threat intel | Kill-switch |
| C2 traffic | DNS query to DGA domains, low-rate beacon | DNS filter logs | RPZ sinkhole |

## Layered defense architecture

Seven layers, ordered cheapest-first. The first four are required (table
stakes for a public sandbox service). Layers 5–7 are opt-in or paid-tier.

### Layer 0 — Kernel hygiene

**Cost:** hours. **What it stops:** spoofing-based reflection attacks,
conntrack table exhaustion DoS against the host itself.

- `sysctl net.ipv4.conf.all.rp_filter = 1` (strict reverse-path filter —
  drop packets whose source IP doesn't match the route back). Stops a
  sandbox from spoofing its source IP for reflection attacks.
- `sysctl net.ipv4.conf.all.send_redirects = 0`,
  `net.ipv4.conf.all.accept_redirects = 0`.
- Per-cgroup conntrack limits via `nft ct count` so one sandbox can't
  exhaust the host's `nf_conntrack` table.
- Disable IPv6 forwarding in the sandbox network namespace if unused —
  halves the attack surface.

These are sandboxd startup operations. Document the sysctl assumptions in
the install docs; refuse to start (or warn loudly) if `rp_filter != 1`.

### Layer 1 — Static destination/port denylist

**Cost:** ~1 day. **What it stops:** spam, amplification, lateral movement
to internal services, traffic to known-bad IPs.

Extend `pkg/docker/netrules/` with a denylist applied to every sandbox
unconditionally:

**Destination ports always blocked:**
- 25, 465, 587 (SMTP — spam relay)
- 23 (telnet)
- 19 (chargen), 17 (qotd) — legacy amplifiers
- 1900 (SSDP), 11211 (memcached), 161 (SNMP) — modern amplifiers
- 53 (DNS) — *unless* destined for the sandbox's configured resolver (Layer 6)
- 123 (NTP) — *unless* destined for an allowed time source

**Destination CIDRs always blocked:**
- RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Link-local (`169.254.0.0/16`)
- Carrier-grade NAT (`100.64.0.0/10`)
- Multicast (`224.0.0.0/4`)
- The host's own management subnet (operator-configured)
- Localhost (`127.0.0.0/8`) and the host's primary IPs

**Threat-intel denylists** (refreshed hourly via cron):
- Spamhaus DROP and EDROP
- FireHOL Level 1
- Known Tor exit nodes (optional, configurable)
- Known mining-pool IPs (optional, configurable)

Implementation: maintain these as `ipset` (or nftables sets) and have
`netrules` reference them. One DROP rule per set. Refresh job is a
goroutine in sandboxd.

A per-sandbox `networkAllowListOverride: ["smtp"]` escape hatch lets
specific tenants opt out of specific denylist categories — required for
legitimate use cases (e.g. a customer building a transactional-email
service). Off by default; surface as an admin-only field.

### Layer 2 — Per-sandbox rate limits (the primary lever)

**Cost:** ~1 week. **What it stops:** the bulk of practical DDoS, scanning,
and brute-force activity.

nftables, with one rule per sandbox container IP:

```nft
add rule ip filter DOCKER-USER \
  ip saddr <containerIP> ct state new \
  limit rate over 50/second drop comment "cps cap"

add rule ip filter DOCKER-USER \
  ip saddr <containerIP> \
  limit rate over 10000/second drop comment "pps cap"

add rule ip filter DOCKER-USER \
  ip saddr <containerIP> ct count over 1000 drop comment "concurrent cap"
```

**Default tier limits (tunable per sandbox via SDK):**

| Knob | Default | Rationale |
|---|---|---|
| New connections / sec | 50 | Normal app: ~5 cps. Scanner: 100s cps. |
| Packets / sec | 10,000 | Normal HTTP API: ~500 pps. Flood: 50k+ pps. |
| Concurrent connections | 1,000 | E2B caps at 2,500; we start stricter. |
| Outbound bandwidth (tc TBF) | 100 Mbit/s | Stops volumetric floods; doesn't slow normal app. |
| DNS queries / sec | 30 | Normal: <5/sec. DGA / amplification: 100s/sec. |

These numbers are starting points. They become per-tier defaults once we
have production telemetry. Trip-action is `drop` (silent), not `reject` —
attackers shouldn't get useful timing signal back.

Per-sandbox overrides shipped as new fields on `CreateSandboxRequest`
(admin-only or paid-tier; not exposed to free-tier users to override
upward).

### Layer 3 — Behavioral / fanout detection

**Cost:** 1–2 weeks once we have baseline data. **What it stops:** the
patient and the clever — slow scanners, low-rate floods, tool-assisted
reconnaissance that stays under static thresholds.

Static rate limits catch obvious abuse but not "5 cps to a victim for an
hour" or "1 connection to each of 10,000 IPs." What gives those away is
**pattern**:

- **Fanout**: distinct destination IPs per source per minute. >N → port
  scan or worm.
- **Concentration**: >P% of all connections in a window go to a single
  destination → flood.
- **Failed-connection ratio**: high SYN-without-SYNACK ratio → scanner.
- **DNS query rate spike or DGA pattern**: query rate or NXDOMAIN ratio
  above baseline → DGA / C2.

Right tool: **eBPF at `cgroup_skb`**, keying a hashmap on cgroup ID. This
is the use case where eBPF earns its complexity vs. sysfs polling — `cat
/sys/class/net/.../statistics/rx_bytes` cannot tell you "to how many
distinct destinations." Standard library: `cilium/ebpf` (Go).

A separate goroutine in sandboxd reads BPF maps every 1–5 seconds, runs
heuristics, and on trip:

1. Calls `netrules.BlockAllEgress(sandboxID)`.
2. Sets `abuse_suspected = true`, `abuse_reason = "fanout > 200/min"`,
   `abuse_detected_at = now` on the sandbox row.
3. Emits an `abuse_events` row with the sample window snapshot.
4. Sends an alert (webhook configurable; default off).

No automatic unfreeze. Operator review required to clear `abuse_suspected`
— for AI-agent workloads, "scanned 1000 IPs" is almost never a
false-positive.

**Why not ship Layer 3 first:** false-positive rate is impossible to tune
without production traffic baselines. Shipping it before Layers 0–2 means
either too-loose thresholds (no protection) or too-tight (legitimate users
freezing). Layers 0–2 buy us the time to collect that baseline.

### Layer 4 — Volume quota (the metering plan)

**Cost:** covered by [`network-usage-tracking.md`](./network-usage-tracking.md).

Last-line backstop for slow exfiltration that evades rate-domain detection.
Also serves the billing use case. No additional work in this plan; it's
called out here so reviewers see how the layers compose.

### Layer 5 — Egress proxy (paid tier / strict mode)

**Cost:** 1–2 weeks if we extend the existing Caddy; longer if we
introduce Envoy.

For tenants who want defense in depth, force outbound HTTP/HTTPS through a
proxy. Buys:

- Domain-level allowlist / denylist (much more useful than IP-level)
- L7 request-rate limits
- Full request log per tenant
- TLS interception (off by default; opt-in for tenants who consent)

Caddy is already in the stack as the L7 ingress proxy; reusing it as an
**egress** proxy means a small new admin module, not a new dependency.
For non-HTTP TCP, fall back to Layer 2. Surface as a `egressProxy: true`
field on `CreateSandboxRequest`.

### Layer 6 — DNS filtering

**Cost:** ~1 week.

Force all DNS through a controlled resolver (CoreDNS with the `rpz` plugin
or Unbound with RPZ). Layer 1 already blocks dst port 53 except to the
configured resolver, so this layer just chooses the resolver's behavior:

- Sinkhole malicious domains via Spamhaus/Quad9/SURBL feeds
- Block DGA-pattern queries (high-entropy subdomains, NXDOMAIN floods)
- Per-source rate limit (default: 30 q/s, same as Layer 2 knob)
- Full query log per tenant (rotated)

Most C2 traffic and many attacks need DNS. Controlling DNS controls a lot
for very little code.

### Layer 7 — Kill-switch & abuse review pipeline

**Cost:** ~3 days of glue work; reuses Layers 1–3 enforcement primitives.

When *any* layer trips, the action path is the same:

1. `netrules.BlockAllEgress(sandboxID)` — instant, idempotent.
2. Persist `abuse_suspected, abuse_reason, abuse_detected_at` on
   `sandboxes` row.
3. Append to `abuse_events` table (one row per detection).
4. Emit webhook to the operator's configured endpoint (Slack, PagerDuty,
   their billing/CRM system).
5. Sandbox status remains `running` (the user's code keeps running, it
   just can't reach the network). Operator decides whether to suspend the
   tenant entirely.

**No automatic unfreeze.** Manual operator action via a new admin
endpoint: `POST /v1/admin/sandboxes/{id}/clear-abuse-flag` with a `reason`
field for the audit log.

## Data model

### Store changes — `internal/store/store.go`

Three new columns on `sandboxes`:

```sql
ALTER TABLE sandboxes ADD COLUMN abuse_suspected     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sandboxes ADD COLUMN abuse_reason        TEXT NOT NULL DEFAULT '';
ALTER TABLE sandboxes ADD COLUMN abuse_detected_at   INTEGER NOT NULL DEFAULT 0;
```

Per-sandbox rate-limit overrides (paid-tier; nullable means "use
host default"):

```sql
ALTER TABLE sandboxes ADD COLUMN rate_cps_limit       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sandboxes ADD COLUMN rate_pps_limit       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sandboxes ADD COLUMN rate_concurrent_limit INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sandboxes ADD COLUMN rate_bw_mbps_limit    INTEGER NOT NULL DEFAULT 0;
```

`0` = use host default. The host defaults live in sandboxd config
(`SB_RATE_*` env vars).

New table for the audit log:

```sql
CREATE TABLE abuse_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  sandbox_id  TEXT NOT NULL,
  detected_at INTEGER NOT NULL,
  layer       TEXT NOT NULL,        -- 'static_denylist' | 'rate_limit' | 'behavioral' | 'manual'
  reason      TEXT NOT NULL,
  sample_json TEXT NOT NULL,        -- snapshot of metrics at detection
  cleared_at  INTEGER,
  cleared_by  TEXT,
  cleared_reason TEXT
);
CREATE INDEX abuse_events_sandbox_idx ON abuse_events(sandbox_id, detected_at DESC);
```

### Models — `pkg/models/types.go`

```go
type CreateSandboxRequest struct {
    // ... existing fields ...
    RateLimits *RateLimits `json:"rate_limits,omitempty"`
}

type RateLimits struct {
    NewConnectionsPerSecond int `json:"new_connections_per_second,omitempty"`
    PacketsPerSecond        int `json:"packets_per_second,omitempty"`
    ConcurrentConnections   int `json:"concurrent_connections,omitempty"`
    BandwidthMbps           int `json:"bandwidth_mbps,omitempty"`
}

type AbuseStatus struct {
    Suspected   bool       `json:"suspected"`
    Reason      string     `json:"reason,omitempty"`
    DetectedAt  *time.Time `json:"detected_at,omitempty"`
    Layer       string     `json:"layer,omitempty"`
    RecentEvents []AbuseEvent `json:"recent_events,omitempty"`
}
```

`Sandbox` gets a top-level `AbuseSuspected bool` for visibility in list
responses.

## Implementation surfaces

### `pkg/docker/netrules/` — extend, don't replace

The existing `Manager` is iptables-only and binary
(`BlockAllEgress`/`ClearBlockAllEgress`). Refactor:

- Migrate from `iptables` to `nft` for the new chains (the existing
  `DOCKER-USER` rule stays iptables for compatibility — you can mix in
  modern kernels).
- New methods: `ApplyStaticDenylists`, `ApplyRateLimits(sandboxID, RateLimits)`,
  `ApplyBandwidthCap(sandboxID, mbps)`, `ApplyIngressBlock`,
  `RefreshThreatIntel`.
- All idempotent — re-applying an existing rule is a no-op (use named
  chains and `nft -- atomic` reload).

### `pkg/docker/netstats/` — already proposed in the metering plan

Extended here with **rate-domain metrics** read from BPF maps (Layer 3),
not just sysfs counters (Layer 4). The package owns both polling cadences:
- 10s cadence: sysfs byte counters → store deltas (metering plan)
- 1s cadence: BPF map reads → in-memory rate samples → behavioral
  heuristics

### `internal/service/service.go`

New methods (version-agnostic):

- `SetRateLimits(ctx, id, RateLimits) (Sandbox, error)` — paid-tier;
  validate against host max ceilings.
- `GetAbuseStatus(ctx, id) (AbuseStatus, error)`
- `ClearAbuseFlag(ctx, id, reason string) (Sandbox, error)` — admin only.
- `EnsureAbuseDefenseReady()` — lazy bootstrap (canonical latch +
  single-flight pattern from `EnsureLayer4Ready`). Loads denylists,
  attaches BPF programs, starts refresh and detection goroutines.

The `CreateSandbox` path applies Layers 0–2 unconditionally as part of
container post-start (after the IP is known, before returning). Layer 3
attaches the BPF program at the same point.

### API surface — `/v1` additive only

```
GET    /v1/sandboxes/{id}/abuse-status
POST   /v1/admin/sandboxes/{id}/clear-abuse-flag       { reason }
PATCH  /v1/sandboxes/{id}/rate-limits                  RateLimits → Sandbox
```

Plus `POST /v1/sandboxes` accepts the new optional `rate_limits` field.
No behavioral changes to existing v1 routes.

### Facade behavior

- **Daytona** — no analog; new fields not surfaced.
- **E2B** — has the concept of rate limits (E2B's published limits are
  org-level, not per-sandbox). Surface AerolVM's per-sandbox limits via
  the existing E2B headers if there's a clean mapping; otherwise leave
  the facade silent. Defer to the E2B compat owner.

## SDK lockstep changes

Per `/add-sdk-method`, all five SDKs:

```ts
const status = await sandbox.getAbuseStatus();
// { suspected, reason, detectedAt, layer, recentEvents }

await sandbox.setRateLimits({
  newConnectionsPerSecond: 100,
  packetsPerSecond: 20000,
  concurrentConnections: 2000,
  bandwidthMbps: 200,
});
```

New typed error `AbuseDetectedError` returned when an SDK call against a
flagged sandbox would be misleading (e.g. reading network usage). `clear`
is admin-only; not exposed in the public SDKs by default.

## Documentation

Per the docs hard rules, two new `.mdx` pages:

- `docs/src/content/docs/abuse-prevention.mdx` — operator-facing.
  Explains the seven layers, what each catches, defaults, tuning knobs,
  and how to respond to abuse events. No SDK code samples (this is an
  operator concern).
- `docs/src/content/docs/rate-limits.mdx` — developer-facing. Five-tab
  examples for `setRateLimits` and `getAbuseStatus`. Documents the
  default tier, what tripping looks like, and how to request a tier
  upgrade.

Register both in `docs/src/content.config.ts`.

## Phasing

Three ships, ordered by "stops the most abuse per week of work."

### Phase 1 — Hygiene + static denylist (1 week, REQUIRED)

Layers 0 and 1. Plus the kill-switch wiring (Layer 7, partial — manual
trip from operator only).

- Kernel sysctls + install-time check
- Static dst-port and CIDR denylists
- Threat-intel ipset refresh job (Spamhaus DROP/EDROP)
- `abuse_suspected` column + admin clear endpoint
- `abuse_events` table

This alone cuts off spam relay, the major amplification vectors, lateral
movement to internal services, and traffic to known-bad IPs. It is the
table-stakes "don't get our IPs blocklisted" layer.

### Phase 2 — Per-sandbox rate limits (1–2 weeks)

Layer 2 in full + Layer 7 trip from rate-limit violations.

- nftables per-sandbox rate / pps / concurrent / bandwidth rules
- `RateLimits` model + store columns
- `SetRateLimits` service method + API + SDK lockstep
- Default tier in sandboxd config; per-sandbox overrides

After Phase 2 the platform is hardened against the bulk of practical
abuse. Phase 3 is for the patient/clever attackers.

### Phase 3 — Behavioral detection (2–4 weeks, after baseline data)

Layer 3 in full.

- `pkg/docker/netstats/` BPF programs (cilium/ebpf)
- 1s detection loop with fanout / concentration / DNS-rate heuristics
- Webhook alert configuration
- `recent_events` in `AbuseStatus`

Do NOT ship Phase 3 before collecting at least a month of Phase 1+2
production traffic. The heuristic thresholds are unknowable before that.

### Future phases (uncommitted)

- Layer 5: egress proxy (paid-tier feature).
- Layer 6: DNS filtering.
- ML-based detection (only after rule-based is well-tuned).

## What's explicitly out of scope

- **Inbound DDoS protection of the AerolVM control plane itself.** That's
  a different problem (front your own host with Cloudflare / AWS Shield).
  This plan is about preventing *outbound* abuse from sandboxes.
- **Tenant-level rate limits / quotas.** Per-tenant aggregation across
  many sandboxes is a different aggregation level; this plan is
  per-sandbox. A future plan can stack tenant limits on top.
- **Anti-fraud / payment abuse.** Out of network scope.
- **In-sandbox software inventory / antivirus.** We don't inspect the
  user's code; we govern its network behavior.
- **TLS interception / DPI by default.** Layer 5 mentions opt-in TLS
  interception but only as an explicit tenant choice with consent.

## Risks and PR-description call-outs

Per `pr-review.md`:

1. **Boot-path latency.** Layers 0 and 1 are sandboxd-startup work, not
   per-sandbox. Layer 2 adds 3 nftables rules per sandbox at create-time
   (~5 ms via netlink); call out in the PR. Layer 3 BPF attach is
   ~10–50 ms per sandbox; called out and benchmarked.
2. **Idempotency.** Every nftables rule is keyed by sandbox ID with
   named chains; re-apply is a no-op (`nft -- atomic` replace).
   Threat-intel refresh swaps the set atomically.
3. **Failure-path consistency.** If nftables apply fails during create,
   the sandbox start is **rolled back** (DELETE container, store row to
   `failed`). Document this explicitly — better to refuse to create than
   to start an unprotected sandbox.
4. **`/v1` freeze.** Only additive — new optional `rate_limits` field
   (default null), new sub-routes. No change to existing wire bodies.
5. **TCP host-port pool & L4 bootstrap.** Not touched.
6. **Lazy bootstrap pattern.** `EnsureAbuseDefenseReady` follows the
   `EnsureLayer4Ready` latch + single-flight template.
7. **iptables ↔ nftables coexistence.** We mix iptables (existing
   `DOCKER-USER` rule) with new nftables chains. Document the
   compatibility constraint (kernel ≥ 4.18, both binaries present) in
   install docs. Refuse to start if either is missing.
8. **False-positive blast radius.** Phase 3 freezes a sandbox on
   detection. Document the operator-clear path in the on-call runbook
   before shipping Phase 3.

## Open questions for the user

1. **Default-on or opt-in for Layers 0–2?** Recommendation: default-on,
   non-overridable for Layer 0, denylist-categories overridable for
   Layer 1, rate limits set to permissive defaults that real apps won't
   notice.
2. **Webhook destination format.** Slack-style incoming webhook,
   PagerDuty Events API, or generic JSON POST? Recommendation: generic
   JSON POST; let operators adapt.
3. **What action on abuse: network-block (current proposal) or
   container-stop?** Recommendation: network-block. Stopping the
   container loses customer state; blocking network preserves the
   blast-radius "the user's code is still running, it just can't reach
   out" model that matches billing-cap semantics in the metering plan.
4. **Tier surfacing.** Should `RateLimits` defaults be hardcoded or
   driven by a `tier` field on the sandbox? Recommendation: start
   hardcoded via env (`SB_RATE_*`); add a tier abstraction in a later
   plan when there's a real billing model to attach it to.
5. **Threat-intel feeds** — Spamhaus + FireHOL is the obvious start.
   Add Tor exit list and mining-pool list as opt-in operator config?
   Recommendation: yes, opt-in and configurable.
