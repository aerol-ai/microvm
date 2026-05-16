# Multi-Tenancy via a Control Plane in Front of AerolVM

## Context

AerolVM today is a **single-tenant** sandbox runtime. The whole daemon
authenticates every request against one shared bearer token
(`pkg/api/server.go:32` → `patToken`, checked in
`pkg/api/middleware.go:45`). The same token is forwarded between nodes for
cross-owner API calls (`pkg/api/v1/cluster_handler.go:261-274`). There is
no concept of users, projects, organizations, quotas-per-user, billing, or
per-user rate limits anywhere in the codebase.

That is the right shape for the runtime. It is the wrong shape for a public
SaaS where thousands of independent customers create sandboxes.

This document captures the architectural decision: **don't bolt
multi-tenancy onto AerolVM itself.** Instead, run a separate control plane
in front of it that owns user identity, billing, and quotas. AerolVM stays
a single-tenant runtime; the control plane is the multi-tenant SaaS.

This split is what every comparable product converged on (E2B, Modal, Fly
Machines, Daytona, RunPod, fly.io, EKS over Kubernetes, Vercel over their
build runners, AWS console over EC2). The reason is not aesthetic — it's
that identity, billing, and pricing churn 10x faster than the runtime, and
coupling them means every pricing change becomes a daemon release.

## The two-layer model

```
              ┌─────────────────────────────────────┐
              │  Customers (1000s of users)         │
              │  Browser, CLI, SDK                  │
              └──────────────┬──────────────────────┘
                             │  user JWT
                             │  (Clerk / Auth0 / own login)
                             ▼
   ┌─────────────────────────────────────────────────┐
   │  CONTROL PLANE  (separate service — new)        │
   │  - users / api_keys / billing tables            │
   │  - per-user quotas and rate limits              │
   │  - sandbox_id → user_id index                   │
   │  - holds ONE secret: the AerolVM PAT            │
   └──────────────┬──────────────────────────────────┘
                  │  AerolVM PAT (one shared secret)
                  │  body: { ..., tags: { user_id: "X" } }
                  ▼
   ┌─────────────────────────────────────────────────┐
   │  AEROLVM CLUSTER  (this repo)                   │
   │  - daemons, raft, placement, Caddy              │
   │  - knows: "sandbox S has tags {user_id: X}"     │
   │  - has NO concept of users                      │
   └─────────────────────────────────────────────────┘
```

End-to-end flow for one customer creating a sandbox:

1. Alice signs in to the SaaS dashboard. The control plane authenticates
   her (Clerk/Auth0/own login) and returns a JWT.
2. Alice's SDK calls `POST https://api.yourcompany.com/sandboxes` with her
   JWT.
3. The control plane:
   - verifies the JWT → resolves `user_id = alice`;
   - checks Alice's quota in its own DB (e.g. "3/10 sandboxes used");
   - calls `POST aerolvm-cluster.internal/v1/sandboxes` with the
     **single** AerolVM PAT, body
     `{image: "python:3.11", tags: {user_id: "alice", project_id: "p1"}}`.
4. AerolVM creates the sandbox, persists `tags`, replicates the placement
   (the spec — including tags — already replicates via
   `Placement.Spec`), and returns the sandbox.
5. The control plane records `sandbox_id → user_id` in its own DB and
   returns the sandbox URL to Alice.

When Alice calls `GET /sandboxes` later, the control plane asks AerolVM
for sandboxes tagged with her user_id only — see "What's missing" below.

## Where the data model already supports this

The metadata bag already exists. It is called `Tags` and is plumbed
end-to-end:

- **Wire**: `models.CreateSandboxRequest.Tags map[string]string`
  (`pkg/models/types.go:255-258`) and `models.Sandbox.Tags`
  (`pkg/models/types.go:313-317`).
- **Persisted**: `sandboxes.tags_json TEXT` column in the SQLite store
  (`internal/store/store.go:77`), written on create
  (`store.go:310`), upserted (`store.go:397`), and scanned back on every
  read (`store.go:1547`).
- **Replicated**: tags are part of `CreateSandboxRequest`, which is the
  `Placement.Spec` payload — so they live in the FSM and survive failover
  unchanged.
- **Mutable post-create**: `Store.UpdateTags` (`store.go:630-641`) lets
  the control plane patch tags without a re-create.

This means **no schema change is needed** for the control-plane pattern.
The control plane stamps `tags = {user_id, project_id, org_id, ...}` on
create; AerolVM stores and returns them; AerolVM never interprets them.

The only piece missing for option-1 to actually work end-to-end is
**filtering `GET /v1/sandboxes` by tags**.

## What's missing: tag-filtered list

Today `GET /v1/sandboxes` returns every sandbox on the cluster.
`Service.ListSandboxes(ctx)` takes no filter, and the v1 handler
(`pkg/api/v1/handlers.go:48-56`) doesn't parse any query parameters.

For multi-tenancy, the control plane must be able to ask "give me the
sandboxes belonging to user X" without retrieving every sandbox in the
cluster and filtering client-side. The minimal change:

- Query syntax: `GET /v1/sandboxes?tag.user_id=alice&tag.project_id=p1`
  (multiple `tag.*` params AND together).
- `Service.ListSandboxes(ctx, filter map[string]string)` filters in
  memory after the store read. (Push down to SQL `json_extract` only
  when the row count makes the difference; not premature.)
- `clusterListWrap` (`pkg/api/v1/cluster_handler.go:209-260`) forwards
  the query string to each peer in the fanout so each node filters
  locally and only matching rows traverse the network.

Tag values are caller-supplied strings — never interpolated into SQL even
if/when we push the filter down (use `json_extract(tags_json, '$.<key>')
= ?` with parameterized values).

That is the entire AerolVM-side change. It is small, additive, and
backward compatible (no `tag.*` param → behavior unchanged).

## What stays out of AerolVM

Explicitly, these belong in the control plane and not in this repo:

- `users`, `api_keys`, `organizations`, `projects` tables.
- Per-user / per-org quotas (the host-level `capacity.Admitter` is the
  hard floor; per-user accounting is a layer above and belongs in the
  control plane's DB).
- Per-user rate limits.
- Billing hooks, invoicing, Stripe, usage metering.
- Audit log of "who did what to what sandbox".
- GDPR delete flows.
- RBAC / fine-grained scopes.

Every one of those churns much faster than the runtime, and bolting them
into the daemon means a `sandboxd` release for every pricing or auth
provider change. Keeping them outside means the control plane ships
independently — typically a small stateless service in front of a
Postgres, deployed wherever your dashboard lives.

## Relation to B3 (node-to-node forwarding)

This split makes B3 (`02-release-blockers-in-current-pr.md`) cleaner, not
harder. B3 is about **node-to-node** trust — the fact that cross-node
forwards inside the cluster currently ride `OwnerInfo.APIURL` with the
shared PAT instead of the mTLS `:7002` channel the docs imply.

Once the SaaS is in front, the PAT becomes an internal infrastructure
secret used only between control plane and AerolVM, never between AerolVM
and end-users. Cross-node forwards no longer need to smuggle a
user-facing token. The clean answer becomes: cross-node hops use the
already-existing mTLS internal URL (cert-pinned node identity, no PAT);
the public API ingress stays on `APIURL` with the PAT, but only the
control plane ever holds that PAT.

In other words: option-1 splits user identity out of the data flow, and
B3 then becomes a straightforward "use the internal mTLS URL for cross-
node forwards" change with no token-propagation gymnastics.

## Concrete delta on this branch

In this repo, scope of this plan:

1. **Add tag-filtered list** — described above. Service signature change,
   v1 query parsing, cluster fanout passthrough, one regression test.

That's the whole AerolVM-side change. Everything else (the control plane,
the `users` table, the JWT verification, the quota engine) lives in a
separate service and is out of scope for this repo.

## Why not multi-tenant inside AerolVM

For completeness, the rejected alternative is: add `users`, `api_keys`,
sandbox ownership FKs, per-user quotas, RBAC, audit, billing hooks
**inside this daemon**.

The reasons not to:

- AerolVM is a runtime. A runtime that authenticates end-users has to
  defend the entire customer-identity surface (login flows, password
  resets, OAuth providers, MFA, account lockout, GDPR). That is a SaaS
  product, not a runtime.
- The daemon would need a relational store beyond SQLite for any
  serious multi-tenant scale (Postgres for users/billing) — pulling in
  a second database for the daemon contradicts the single-writer SQLite
  invariant (`internal/store/store.go`, `MaxOpenConns=1`).
- Every pricing change, auth provider swap, or quota tweak becomes a
  daemon release. The runtime stops shipping at runtime speed.
- The isolation story gets noisier: noisy-neighbor mitigation,
  fork-bombs, encryption-at-rest per tenant, registry-cred separation
  per tenant. Each one is solvable, but each one moves the daemon away
  from being a substrate and toward being a SaaS.

If a customer ever wants to self-host multi-tenant AerolVM, the right
answer is "self-host the control plane too" — not "make the runtime
multi-tenant."
