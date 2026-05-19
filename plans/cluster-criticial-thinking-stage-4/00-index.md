# Cluster Critical Thinking - Stage 4

This stage reviews PR #79 (`distributed-orchestrator-2`, 170 files, ~34.5K
insertions) against a sharper, product-bounded bar than the abstract
"10,000-node / 100,000-sandbox" target Stage 3 used.

The Stage 4 product bar is:

- up to **500 nodes** total (3-5 Raft servers + ~500 workers + a small ingress
  tier);
- up to **100,000 concurrent sandboxes**;
- **highly available** for: control plane, sandbox *creation*, and node
  membership;
- **explicitly not highly available** for: an individual sandbox after its
  owner dies — a crashed/deleted sandbox is allowed to disappear (410 Gone);
- snapshotting is **out of scope** for this review — local-only snapshot
  storage is acceptable;
- the cluster work **must not regress** the existing public API or SDK
  surfaces:
  - MicroVM SDKs (TypeScript, Python, Go, Rust, Java);
  - Daytona facade (`/daytona/...`);
  - E2B facade (`/e2b/...`);
- the **TCP/TLS L4 routing** built into this codebase must keep working when
  the multi-node orchestration layer is active.

Stages 1, 2, and 3 are at:

- [`plans/cluster-criticial-thinking/`](../cluster-criticial-thinking/)
- [`plans/cluster-criticial-thinking-stage-2/`](../cluster-criticial-thinking-stage-2/)
- [`plans/cluster-criticial-thinking-stage-3/`](../cluster-criticial-thinking-stage-3/)

## Stage 4 Verdict (TL;DR)

PR #79 is a meaningful, structural rewrite of the cluster plane and it
**clears the Stage 4 product bar** with the following qualifications:

- it is now a **k3s-shaped** architecture: a small server quorum runs
  Raft/FSM, every other node is a lightweight agent that gossips capacity and
  does control-plane RPC over mTLS;
- the **reservation-first create flow is shared across v1, Daytona, and E2B**
  via `pkg/api/clustercreate`, so all three product surfaces use the same
  placement, name-uniqueness, idempotency, and owner-forwarding contract;
- the **cluster layer sits below the public API surface**: the MicroVM SDKs,
  Daytona, and E2B routes are unchanged at the URL/JSON wire level (the
  diff against `sdk/*` is purely additive — `list({tags})` and similar
  conveniences);
- the **TCP/TLS L4 path is preserved** end-to-end: per-sandbox host ports are
  unique cluster-wide (FSM `hostPortIndex` + partial unique index on
  `exposed_ports.host_port`), non-owner ingress nodes use
  `UpsertTCPProxyRoute` to forward to the owner's host port,
  `UpsertSNIPassthroughRoute` does SNI passthrough for TLS, and the
  `EnsureLayer4Ready` single-flight latch still bootstraps caddy-l4 lazily;
- **sandbox-level HA is explicitly disabled** (`clusterRecreateOnFailoverEnabled
  = false`) and the orphan/410-Gone semantics match the user's stated policy;
- **node and control-plane HA are real**: workers do not touch Raft membership,
  agents reach any server-role peer through a fallback loop on `ErrNotLeader`,
  dead-owner eviction is a single Raft command per dead owner, and false-
  positive eviction is recoverable via `POST /v1/cluster/orphans/{id}/reclaim-
  local`.

What is **not yet proven** by this PR:

- there is no multi-process 500-node integration test; the scale gates exist
  but exercise single-process FSM behavior at 100k rows, not real boot-up of
  500 distinct daemons;
- Daytona / E2B mutating handlers (resize, lifecycle, autostop, etc.)
  **bypass** the FSM spec write-through that v1 uses (see issues file);
- the PR description itself is the unfilled `pull_request_template.md` —
  every required section per `pr-review.md` is blank (boot impact, idempotency,
  failure-path rollback, L4 / host-port-pool changes, test plan);
- snapshot/image distribution is locally pinned for `local_only` images, but
  there is no proven cluster-wide image cache or registry-pull throttling at
  100k concurrent creates.

## Reading order

| File | Purpose |
|---|---|
| [`01-features-enhanced.md`](./01-features-enhanced.md) | Concrete features the PR adds or rewrites since stage-3, mapped to file paths. |
| [`02-positive-outcomes.md`](./02-positive-outcomes.md) | What the PR materially achieves against the 500-node / 100k-sandbox / HA-control-plane / no-API-regression / TCP-TLS-preserved bar. |
| [`03-limitations.md`](./03-limitations.md) | Where the architecture still falls short of the Stage 4 bar — and where it falls short of the harsher Stage 3 bar that's been deferred. |
| [`04-issues.md`](./04-issues.md) | Concrete running issues in this branch right now — bugs, gaps, and footguns that should be fixed before merge or filed as follow-ups. |
| [`05-pr-review.md`](./05-pr-review.md) | The line-by-line PR review against the user's question: clean k3s-like architecture? scales to 500/100k? control plane + creation HA? no API/SDK/Daytona/E2B/TCP-TLS regression? |
