# 04 - API, Facades, And Idempotency

## P0. Daytona And E2B Bypass Cluster Placement

**Where:**

- `pkg/api/daytona/routes.go:56-74`
- `pkg/api/daytona/handlers.go:61`
- `pkg/api/e2b/routes.go:24-32`
- `pkg/api/e2b/handlers.go:103`

The v1 API is cluster-aware. Daytona and E2B are not.

Daytona and E2B create sandboxes by calling `Service.CreateSandbox` directly.
That means:

- no `SelectPlacement`;
- no `ReserveOnTarget`;
- no `RecordPlacement`;
- no cluster-wide name reservation;
- no owner-aware forwarding for follow-up calls;
- no cluster-wide list;
- no cluster-wide idempotency;
- no spec replication unless a later v1 mutation or boot replay happens.

This is not an edge case. Daytona and E2B facades are major product surfaces.
At scale, an API load balancer will send facade requests to arbitrary nodes,
and those nodes will behave as isolated single-node runners.

**Required fix:**

Cluster routing must move below the facade layer or be applied consistently to
every facade:

- create placement should be a service-level operation, not a v1 wrapper only;
- per-sandbox facade routes should use owner lookup and forwarding;
- name lookup should be cluster-wide;
- facade metadata should either live in the owner store and forward correctly,
  or move to shared control-plane state;
- all facade create idempotency must be cluster-wide.

## P0. E2B Idempotency Is Local

**Where:**

- `pkg/api/e2b/handlers.go:56-119`
- `internal/store/store.go` request_idempotency table

E2B create uses a local SQLite idempotency table. In a cluster behind a load
balancer, retry 1 can hit node A and retry 2 can hit node B. Both can acquire
the same fingerprint locally and create separate sandboxes.

This breaks exactly the retry behavior idempotency is supposed to protect.

**Required fix:**

Idempotency must be keyed in the control plane:

```text
scope + fingerprint -> target sandbox ID + owner + request hash + state
```

It must be compare-and-swap, replayable from any API node, and tied to the same
reservation state as create.

## P0. Cluster List Fans Out To Every Peer

**Where:**

- `pkg/api/v1/cluster_handler.go:350-459`

`GET /v1/sandboxes`:

- calls local list;
- creates one goroutine per peer;
- makes one HTTP request per peer;
- decodes each peer's full sandbox list;
- merges all rows in memory;
- returns a single unpaginated JSON response.

At 10,000 nodes this means 9,999 goroutines and 9,999 outbound HTTP requests
per list call. At 100,000 sandboxes it returns a huge response in one shot.
Multiple clients listing concurrently can become a cluster-wide self-DOS.

The 5-second per-peer timeout does not bound total work. It bounds latency while
still launching the fanout.

**Required redesign:**

- make list a control-plane indexed query;
- require pagination;
- require filters to be indexed;
- limit fanout concurrency if any fanout remains;
- return partial-result metadata explicitly;
- expose a cursor or revision;
- do not make every list call reach every worker.

## P0. Compatibility Facade List/Get/Delete Are Local

Daytona and E2B list, get, delete, connect, pause, timeout, preview, and
snapshot routes operate against the local service/store. They do not call
`clusterForwardWrap`.

At scale:

- `GET /e2b/sandboxes/{id}` can return 404 on the wrong API node;
- `DELETE /daytona/sandbox/{id}` can fail on the wrong API node;
- `connect` can start/update lifecycle only if it happens to hit the owner;
- facade lists are partial local views;
- name-based Daytona lookup is local.

The product cannot say "any node accepts any request" until every public API
surface shares the same owner-routing contract.

## P1. SSH Gateway Is Local-Only

**Where:**

- `pkg/sshgateway/gateway.go`
- `cmd/sandboxd/main.go:224-239`

The SSH gateway uses `Service.GetSandbox` against the local store. It has no
owner lookup or forwarding path.

If public SSH traffic lands on a non-owner node, auth fails because the sandbox
row is not local. If SSH is enabled on pure server or ingress nodes, those nodes
will accept connections but cannot serve the sandbox.

**Required fix:**

Pick one:

- route SSH by owner at the load balancer;
- make SSH gateway owner-aware and proxy to the owner;
- return node-specific SSH endpoints;
- disable SSH on non-worker/non-owner nodes and document the limitation.

## P1. Service-Layer Mutations Are Inconsistently Replicated

Some v1 handlers write through to the FSM after service mutations, but facades
call service methods directly:

- Daytona resize calls `Service.ResizeSandbox`;
- Daytona preview calls `Service.ExposePort`;
- Daytona lifecycle calls `Service.UpdateLifecycle`;
- E2B connect/timeout calls `Service.UpdateLifecycle`.

`Service.ExposePort` partly records cluster exposed ports itself, but
`Service.UpdateLifecycle`, `Service.ResizeSandbox`, and `Service.UnexposePort`
do not fully own cluster write-through semantics. The replication contract is
split between service and v1 handlers.

At high scale and with multiple facades, this causes stale replicated specs and
routes.

**Required fix:**

Move cluster write-through into the service layer or create a facade-agnostic
cluster mutation wrapper. API handlers should not be the only place where the
cluster state stays current.

## P1. Request Body Size Is Not Bounded For Create

**Where:**

- `pkg/api/v1/cluster_handler.go:117-133`

The v1 create wrapper reads the whole body into memory before placement. The
same create spec is then potentially sealed, redacted, serialized into Raft,
stored in snapshots, and replicated to all Raft participants.

At 100,000 concurrent creates, even moderately large request bodies can exhaust
memory or create enormous Raft logs.

**Required fix:**

- enforce a small max create-spec size;
- reject oversized env/tags/mount specs;
- keep large artifacts out of Raft;
- use object storage for large build/mount/material inputs.

## P1. Owner Forwarding Needs Better Stale-Read Semantics

`OwnerOf` reads the local FSM. If a follower is behind, it can forward to an
old owner. The loop detector returns 421 when forwarding loops, but clients and
SDKs are not guaranteed to retry correctly across all methods.

At 100,000 sandboxes and high churn, stale owner reads will happen.

**Required fix:**

- expose owner lookup with revision;
- require mutating operations to use a minimum applied revision or leader read;
- return structured retryable errors;
- add SDK retry behavior for 421/503/410;
- measure stale-owner forwards.

