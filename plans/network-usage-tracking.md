# Per-sandbox Network Usage Tracking & Limits

## Context

AerolVM today has **zero** network metering. The only network primitive on
sandboxes is `NetworkBlockAll` — a binary DROP rule on `DOCKER-USER` keyed by
container source IP (`pkg/docker/netrules/manager.go`). No bytes are counted,
no quotas exist, no limits can be expressed in `CreateSandboxRequest`, and no
SDK method asks "how much has this sandbox transferred?".

This plan adds:

1. **Metering** — cumulative ingress/egress byte counters per sandbox,
   persisted across container restarts and sandboxd restarts, queryable via
   the SDK.
2. **Limits** — optional caps (`net_bytes_in_limit`, `net_bytes_out_limit`)
   that, when exceeded, freeze the sandbox's network (block all egress,
   surface a typed error). Settable at create-time and via an update RPC.

The user-facing shape mirrors the existing `cpu` / `memory_mb` / `disk_gb`
quota fields: limits are advisory metadata held on the sandbox row, enforced
by a background reconcile, and exposed through the same five SDKs.

## Prior art — what the competitive bar actually looks like

I checked what each major sandbox/microVM platform exposes today:

| Platform | Per-sandbox bytes meter? | Per-sandbox bandwidth limit? | How |
|---|---|---|---|
| **E2B** | No | No | Limits are *concurrent egress connections* (2,500/sandbox) and request rates. Pricing is per-second compute only. |
| **Daytona** | No | No | "Network limits" = firewall allow/block list (≤10 CIDRs), not bytes. |
| **Modal** | No | No | Egress not on price list; no SDK call for bytes. |
| **Fly.io Machines** | Yes (Prometheus) | No (billed, not capped) | $0.02–0.12/GB egress, exposed via managed Prometheus at `api.fly.io/prometheus/<org>`. |
| **AWS Lambda / Fargate** | Customer-instrumented only | No | Official guidance is in-guest `/proc/net/dev` snapshots emitted as EMF. |
| **CF Workers / DO** | No | No | Egress fees eliminated; no per-DO byte counter. |

**Takeaway:** none of the direct competitors (E2B, Daytona, Modal, CF) expose
per-sandbox bandwidth metering or quota. Only Fly meters, and only as a
billing-driven Prometheus surface. Shipping `sandbox.getNetworkUsage()` and
`networkBytesOutLimit` on `CreateSandboxRequest` is genuinely differentiated
SDK surface, not catch-up.

## Implementation menu — metering

| Technique | Granularity | Overhead | Why we did/didn't pick it |
|---|---|---|---|
| **veth `/sys/class/net/<iface>/statistics/{rx,tx}_bytes`** | per-sandbox | ~zero (kernel already counts) | **Picked for v1.** Every container has a host-side veth; counter is free; pure read-side; no rules to install. |
| **iptables/nftables byte counters** per per-source-IP chain | per-sandbox + per-rule | low | Composes with the existing `DOCKER-USER` chain, but at hundreds of sandboxes the rule list scales poorly and we'd be inventing chain naming + lifecycle. v2 if we want per-destination breakdown. |
| **cgroup-bpf (cgroup v2, ≥4.10)** | per-cgroup, in+out | low; eBPF only on cgroup processes | Best for per-destination attribution; needs eBPF toolchain + cgroup-id → sandbox-id map. v2 path. |
| **`/proc/net/dev` polled by toolboxd** | per-sandbox | trivial | Tenant has root; can tamper. Reject. |
| **Caddy `/metrics`** | per-route (HTTP only) | already deployed | Misses raw TCP through L4, misses direct egress that doesn't go via Caddy. Only useful as a cross-check. |

**Decision: veth statistics polling, host-side, from sandboxd.** Lowest risk,
no new kernel features required, works with the existing single-bridge Docker
network setup. The rx/tx semantics from the *host* side of the veth are
inverted relative to the container (host-side `rx_bytes` = container egress),
which we'll abstract behind a single helper.

## Implementation menu — limits

| Technique | What it does | Why we did/didn't pick it |
|---|---|---|
| **Hard cap → block egress on exceed** (DROP rule via existing netrules) | When `bytes_out > limit_out`, install the same DROP rule `BlockAllEgress` already installs | **Picked for v1.** Reuses an audited primitive. Coarse but matches "quota" semantics — the same shape as a cloud-billing cutoff. |
| **tc TBF on veth** | Rate-shape (Mbps cap), not a quota | Different feature ("max 10 Mbps") vs. ("max 10 GB total"). Out of scope here; track separately if requested. |
| **eBPF EDT + FQ** | Nanosecond pacing, scales past tc | Overkill for current scale. v3+. |
| **App-layer throttle in Caddy** | HTTP-only | Misses raw TCP. Reject. |

**Decision: hard quota cap.** The SDK feature the user asked for is
"limited with the number of ingress or egress usage" — that maps to a
total-bytes cap, not a rate cap. Rate-limiting is a separate plan.

## What "ingress" enforcement actually means

Egress enforcement is straightforward — drop forwarded packets in
`DOCKER-USER` keyed on source IP, exactly like `NetworkBlockAll` already does.

Ingress enforcement is harder: by the time inbound bytes have hit the host's
NIC and been counted by the veth, we've already paid for them. Three honest
options:

1. **Count ingress, don't enforce it.** Limit applies to egress only. Ingress
   shows as a stat. Most customers care about egress (it's what gets billed
   upstream).
2. **Enforce ingress by also dropping `-d <containerIP>` in `DOCKER-USER`.**
   Wastes the bytes that already hit our NIC, but stops *application*-visible
   ingress. Honest about its limits.
3. **Enforce at the L7/L4 proxy (Caddy)** by tearing down published routes.
   Only catches published-port ingress, not direct container-IP traffic
   (which the bridge network blocks at the host firewall already, but that's
   a different rabbit hole).

**Decision: option 2.** When `bytes_in > limit_in`, install both
`-s <ip> -j DROP` and `-d <ip> -j DROP`. Document the "we already paid for the
bytes you see in the meter" caveat. Egress-only limits are the recommended
default in docs.

## Data model

### Store changes — `internal/store/store.go`

Four new columns on `sandboxes`. All `INTEGER NOT NULL DEFAULT 0`. None are
indexed.

```sql
ALTER TABLE sandboxes ADD COLUMN net_bytes_in        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sandboxes ADD COLUMN net_bytes_out       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sandboxes ADD COLUMN net_bytes_in_limit  INTEGER NOT NULL DEFAULT 0; -- 0 = unlimited
ALTER TABLE sandboxes ADD COLUMN net_bytes_out_limit INTEGER NOT NULL DEFAULT 0; -- 0 = unlimited
```

`net_bytes_*` are **cumulative across container restarts** — the lifetime
total for a sandbox. `0` for limits means unlimited (matching how
`memory_mb=0` would be treated, except we always require memory).

A new dedicated method `UpdateSandboxNetCounters(id, deltaIn, deltaOut)`
writes the deltas atomically. Limits are updated through the existing patch
path used by `Resize`. Per `/touch-tcp-pool`-style discipline, store changes
ship with a regression test in `internal/store/store_test.go`.

### Models — `pkg/models/types.go`

```go
type CreateSandboxRequest struct {
    // ... existing fields ...
    NetworkBytesInLimit  int64 `json:"network_bytes_in_limit,omitempty"`
    NetworkBytesOutLimit int64 `json:"network_bytes_out_limit,omitempty"`
}

type Sandbox struct {
    // ... existing fields ...
    NetworkBytesInLimit  int64 `json:"network_bytes_in_limit"`
    NetworkBytesOutLimit int64 `json:"network_bytes_out_limit"`
}

type NetworkUsage struct {
    SandboxID            string `json:"sandbox_id"`
    BytesIn              int64  `json:"bytes_in"`
    BytesOut             int64  `json:"bytes_out"`
    BytesInLimit         int64  `json:"bytes_in_limit"`           // 0 = unlimited
    BytesOutLimit        int64  `json:"bytes_out_limit"`          // 0 = unlimited
    QuotaExceededAt      *time.Time `json:"quota_exceeded_at,omitempty"`
    LastSampledAt        time.Time  `json:"last_sampled_at"`
}
```

Validation: limit ≥ 0; reject negative. Units are bytes, not GB — match the
disk_gb convention by *not* hiding the unit (`*_bytes` is in the field name).

## Counter pipeline

### New package `pkg/docker/netstats/`

Three responsibilities:

1. **Discover the host-side veth name** for a container. Docker doesn't
   expose this directly. Standard trick:
   - `docker.ContainerInspect` → `state.Pid`
   - `/proc/<pid>/ns/net` → enter or read `/sys/class/net/eth0/iflink` from
     the container ns to get the host ifindex
   - Walk `/sys/class/net/*/ifindex` on the host to find the matching veth
   - Cache the mapping `containerID → vethName` for the container lifetime

2. **Sample** `/sys/class/net/<veth>/statistics/{rx_bytes,tx_bytes}` and
   compute deltas against an in-memory baseline. From the host side: `rx` is
   container-egress, `tx` is container-ingress (we'll abstract this).

3. **Background poller** — one goroutine in `Service`, ticking every
   `NETSTATS_POLL_INTERVAL` (default 10s). For each running sandbox: sample,
   compute delta vs. last sample, persist via `UpdateSandboxNetCounters`,
   then check limits.

### Service hooks — `internal/service/service.go`

Following the canonical lazy-bootstrap pattern documented in `CLAUDE.md`
(`EnsureLayer4Ready` example), a netstats poller is **not** on the
`CreateSandbox` hot path. It starts on first running sandbox via the
`atomic.Bool` + `sync.Mutex` single-flight pattern, then runs forever.

New service methods (version-agnostic, called from v1 handlers + facades):

- `GetNetworkUsage(ctx, id) (NetworkUsage, error)`
- `SetNetworkLimits(ctx, id, in, out int64) (Sandbox, error)`
- `EnsureNetstatsReady()` — lazy bootstrap, latch + mutex

The reconcile loop at `internal/service/service.go:~1160` already re-heals
`NetworkBlockAll`; a cheap `bytes_*_limit > 0 && bytes_* >= limit` check is
added there as the limit-enforcement trigger. Enforcement uses the existing
`netrules.BlockAllEgress` (and a new `BlockAllIngress` mirror) so we are not
inventing a second iptables-touching primitive.

### Restart safety

Two failure modes to handle:

1. **Container restart.** Veth interface goes away; new one comes up with a
   fresh counter at 0. Solution: when the `containerID → vethName` cache
   miss occurs (or the iface disappears), reset the in-memory baseline to 0
   for the next sample. Cumulative store value is preserved.
2. **Sandboxd restart.** Process loses the in-memory baseline. On startup,
   the first poll for each sandbox snapshots the *current* veth counter as
   the baseline and records no delta. Worst case: the bytes transferred
   during the restart window are missed. Acceptable for a 10-second poll.

Document both in code comments — these are exactly the WHY-not-WHAT comments
the codebase prefers.

## API surface

### `/v1` additions (additive sub-routes only)

`/v1` is soft-frozen against *behavioral changes to existing routes*. Adding
new sub-paths is allowed and is the established pattern (compare
`/v1/sandboxes/{id}/expose-port`).

```
GET   /v1/sandboxes/{id}/network/usage   → NetworkUsage
PATCH /v1/sandboxes/{id}/network/limits  → { network_bytes_in_limit, network_bytes_out_limit } → Sandbox
```

Plus the existing `POST /v1/sandboxes` accepts the two new optional fields
on `CreateSandboxRequest`. New sandbox responses include the two new fields
(zero by default — backwards-compatible).

### Facade behavior

- **Daytona** — Daytona has no equivalent concept; the new fields are simply
  not surfaced by `/daytona/...` responses. No change.
- **E2B** — Same. The existing `TrafficAccessToken` field
  (`pkg/api/e2b/dto.go:53`) is unrelated and stays untouched.

## SDK lockstep changes

Per `/add-sdk-method`, all five SDKs ship together. Two new methods on the
sandbox object:

```ts
// TypeScript example, repeated structure across all 5 SDKs.
const usage = await sandbox.getNetworkUsage();
// { bytesIn, bytesOut, bytesInLimit, bytesOutLimit, quotaExceededAt, lastSampledAt }

await sandbox.setNetworkLimits({
  bytesIn:  10 * 1024 * 1024 * 1024,  // 10 GB
  bytesOut: 1  * 1024 * 1024 * 1024,  // 1  GB
});
```

Plus two new optional fields on the create-sandbox call:
`networkBytesInLimit`, `networkBytesOutLimit`.

A new typed error `QuotaExceededError` (mirroring how `models.ErrNotFound` is
mapped through `apihttp.WriteStoreAwareError`) is returned by any SDK call
that hits a quota-frozen sandbox in a way that requires network (today: none
do directly — it's the *user's* code inside the sandbox that fails). The
sandbox's `status` does **not** change; we add a new boolean
`network_quota_exceeded` on the response and a `quota_exceeded_at` timestamp.

## Documentation

Per the docs hard rules: a new top-level feature gets a new `.mdx` page, not
a subsection. Add `docs/src/content/docs/network-usage.mdx` registered in
`docs/src/content.config.ts`. Five-tab `<Tabs syncKey="lang">` with TS,
Python, Go, Rust, Java examples for `getNetworkUsage()`, `setNetworkLimits()`,
and the create-time fields. No raw `curl`.

## Phasing

Two ships, not three. Phase 1 is read-only and provides immediate value
(observability) without the riskier enforcement path.

### Phase 1 — Metering (read-only)

- `pkg/docker/netstats/` package (veth discovery + poller).
- Store columns `net_bytes_in`, `net_bytes_out` only.
- Service: `GetNetworkUsage`, `EnsureNetstatsReady` lazy bootstrap.
- API: `GET /v1/sandboxes/{id}/network/usage`.
- SDKs: `getNetworkUsage()` across all 5.
- Docs: new `network-usage.mdx`, metering section only.
- Tests: store regression test for new columns; service test for poller
  delta math; netstats unit test that mocks `/sys/class/net/...`.

### Phase 2 — Limits (enforcement)

- Store columns `net_bytes_in_limit`, `net_bytes_out_limit`.
- Models: extend `CreateSandboxRequest`, `Sandbox`.
- `pkg/docker/netrules/`: add `BlockAllIngress` mirror.
- Service: `SetNetworkLimits`; reconcile-loop hook to enforce on exceed;
  `network_quota_exceeded` flag.
- API: `POST /v1/sandboxes` accepts new fields; `PATCH /v1/sandboxes/{id}/network/limits`.
- SDKs: create-time fields + `setNetworkLimits()`.
- Docs: extend `network-usage.mdx` with limits section.
- Tests: service test that exceeding limit installs DROP rule; reconcile
  test that re-heals enforcement after sandboxd restart.

## What's explicitly out of scope

- **Rate shaping** (Mbps caps). Different feature; if requested, ships as a
  separate plan using tc TBF on veth.
- **Per-destination attribution** ("how many bytes did this sandbox send to
  github.com?"). Requires cgroup-bpf or nftables sets. Track for v3.
- **Billing integration.** This plan exposes the meter; converting bytes to
  invoices is a separate system.
- **Resetting the cumulative counter.** Counters are lifetime-of-sandbox.
  No reset RPC. (Delete the sandbox to reset.)
- **Daytona/E2B facade exposure.** Those facades don't model this; we don't
  invent fields for them.

## Risks and call-outs (PR-description bait)

Per `pr-review.md`, these get explicit call-outs in the PR description:

1. **Boot-path latency.** None. The poller is lazy-started on first running
   sandbox via the canonical latch pattern; `CreateSandbox` is unchanged.
2. **Idempotency.** `SetNetworkLimits` is idempotent (PATCH semantics).
   `GetNetworkUsage` is read-only. Limit enforcement is idempotent
   (re-installing an existing DROP rule is a no-op via the existing
   `netrules` checks).
3. **Failure-path consistency.** Counter writes are best-effort; a write
   failure logs and retries on the next tick. Limit-enforcement DROP rule
   install is the same primitive as `NetworkBlockAll` and inherits its
   rollback story.
4. **`/v1` freeze.** Only additive — new optional fields on the create body
   (default zero, backwards-compatible) and new sub-routes. No change to
   existing wire bodies, status codes, or paths.
5. **TCP host-port pool & L4 bootstrap.** Not touched.
6. **Veth discovery is privileged.** Reading
   `/proc/<pid>/ns/net` requires sandboxd to have `CAP_SYS_ADMIN` or root,
   which it already has for iptables. Document the requirement.

## Open questions for the user

1. **Default limit?** Ship as `0 = unlimited` (recommended) or pick a
   sensible default (e.g. 100 GB lifetime egress) so the feature is "on" by
   default? My recommendation is unlimited — opt-in matches the rest of the
   quota fields.
2. **Action on quota exceeded:** drop network only (recommended), or also
   stop the container? Dropping network only matches the "the sandbox is
   still running, the user's code just can't reach the network" model that
   feels closest to a billing cap.
3. **Poll interval:** 10s default OK, or do we want it configurable per
   sandbox? Recommend a single `NETSTATS_POLL_INTERVAL` env on sandboxd
   (default 10s), no per-sandbox override.
