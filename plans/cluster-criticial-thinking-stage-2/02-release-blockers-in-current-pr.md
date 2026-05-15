# 02 - Release Blockers In Current PR

This page is intentionally concrete. It compares the stage-1 plan to the code
in PR #58 and lists issues that should block a "cluster mode is production
ready" release. Some items now have first-slice fixes in this branch; those are
called out explicitly instead of being treated as still absent.

## B1. Forwarded create requests can reschedule and fail

**Where:**

- `pkg/api/v1/cluster_handler.go:81-122`
- `internal/cluster/forward.go:75-96`

**Current branch status:** first-slice fixed with target-locked create
forwarding.

`clusterCreateWrap` chooses a target and forwards the original request when the
target is not self. The receiver then runs `clusterCreateWrap` again and calls
`SelectPlacement` again. There is no target lock, no "create locally" header,
and no internal create endpoint.

Because `ForwardHTTP` adds `X-Cluster-Forwarded: 1`, any second forward returns
421 Misdirected Request.

At 200 nodes, this makes cross-node creates probabilistic. The first selected
target will rarely choose itself on the second placement pass.

**Required fix:**

Use one of these patterns:

- **target-locked create:** A sends `X-Cluster-Create-Target: <node-id>` and T
  creates locally only if the header matches self; otherwise it returns 409/421;
- **internal create endpoint:** A calls T's private
  `/internal/sandboxes:create-local` endpoint after placement;
- **reservation-first create:** leader writes a placement/reservation with the
  intended owner, then the selected owner consumes it.

The reservation-first path is the best long-term fix. The target-locked path is
the smallest hotfix and is what this branch now implements.

## B2. Create documentation disagrees with implementation

**Where:**

- `setup/cluster.md:68-90`
- `pkg/api/v1/cluster_handler.go:124-170`

The setup doc says create does `opPlace via raft` before docker run and then
forwards/create. The code does local create first, then seals secrets, then
records placement in Raft.

That difference matters:

- doc order gives the cluster a known intent before local side effects;
- code order creates a local sandbox first and tries to rollback if Raft commit
  fails.

The code order can be acceptable for boot-path latency, but it is not the
control-plane model described in the docs and it is weaker than a
Kubernetes-style desired-state model.

**Required fix:**

Either update docs to match the current code and document rollback risk, or
change implementation to reservation/placement-before-create.

For the requested robustness bar, use reservation-before-create.

## B3. API forwarding is documented as mTLS, but owner forwarding uses APIURL

**Where:**

- `setup/cluster.md:424-429`
- `internal/cluster/forward.go:75-96`
- `internal/cluster/internal_server.go:15-59`

The docs say API traffic reverse-proxies internally via mTLS on `:7002`.
The code uses `OwnerInfo.APIURL` and `ForwardHTTP`, which reverse-proxies to
the peer API URL. The mTLS `:7002` server only handles leader-forwarded Raft
applies.

This is not necessarily wrong, but it is a security and operability mismatch.
Operators reading the docs will assume hot-path API traffic is on the cert-pinned
internal channel when it is not.

**Required fix:**

Make one of these true:

- owner API forwarding uses internal mTLS URLs; or
- docs explicitly say only Raft applies use `:7002`, while owner API forwarding
  uses the advertised API URL and PAT auth.

For release-grade cluster mode, prefer an internal owner-forward URL distinct
from the public API URL.

## B4. Every joiner becomes a voter

**Where:**

- `internal/cluster/voter_autojoin.go:49-75`
- `internal/cluster/voter_autojoin.go:131-142`

This is already covered by stage 1, but it remains a release blocker. A
200-runner cluster must not have 200 Raft voters.

**Required fix:**

Minimum viable release change:

- add `SB_NODE_ROLE=server|worker|mixed`;
- only `server` nodes run Raft and vote;
- workers register capacity and own sandboxes without joining Raft.

Short-term safety patch if roles cannot land immediately:

- add a max voter cap;
- disable auto-promotion by default;
- make voter promotion explicit.

Do not ship "add every runner as voter" as the default cluster story.

## B5. Public sandbox URLs need owner-aware ingress

**Where:**

- `internal/service/service.go`
- `pkg/caddy/client.go`
- `internal/cluster/fsm.go`
- `setup/cluster.md`

**Current branch status:** first-slice fixed for functional routing.

The original PR gap was severe: only the owner had the Caddy route for
`<id>.sandbox.example.com`, so a round-robin LB had no owner mapping.

At 200 runners, a random backend hits the owner roughly 0.5% of the time.

This branch now adds an ingress reconciler on every node. Non-owners install
routes from the replicated placement map:

- domain-mode HTTP and TLS/SNI use caddy-l4 SNI pass-through to the owner;
- IP/path-mode HTTP reverse-proxies to the owner's Caddy listener;
- expected remote routes are added to zombie-GC's keep set.

That removes the 1/N hit-rate blocker for normal operation.

**Remaining release work:**

- replace polling with a watch/revision model or prove the polling interval is
  acceptable at 200 x 50;
- add metrics for route lag, Caddy admin latency, and route misses;
- test Caddy route churn and config size at 10K sandboxes;
- define explicit failover responses during the convergence window.

## B6. Raw TCP needs a stable cluster route map

**Where:**

- `pkg/models/types.go:435-445`
- `internal/service/service.go:960-1073`
- `internal/service/service.go:1113-1152`
- `internal/cluster/fsm.go`
- `pkg/caddy/client.go`

**Current branch status:** first-slice fixed with replicated TCP host-port
routes.

Raw TCP exposures return an owner-local `Host` and `HostPort`. This is reliable
only when the client dials the exact owner endpoint returned by the API. It is
not stable behind a shared cluster load balancer.

HTTP/TLS can route by hostname/SNI. Raw TCP cannot.

This branch implements the cluster-stable path:

- the placement FSM records TCP `HostPort`;
- the FSM rejects duplicate TCP host-port usage across placements;
- non-owner nodes bind the same host port and proxy to the owner host port;
- failover replay attempts to preserve the same host port on the new owner.

**Remaining release work:**

- prove there are no local port conflicts on large mixed clusters;
- decide whether failed preferred-host-port replay should park the exposure or
  allocate a replacement endpoint;
- expose clear status when the TCP ingress route has not converged;
- add scale tests for high-port listener count and Caddy admin latency.

## B7. UDP is not supported

**Where:**

- `pkg/models/types.go:471-485`

`ValidExposedPortProtocol` accepts only `http`, `tcp`, and `tls`.

The first-stage plan mentions UDP as future work, but the product narrative
should not imply Kubernetes-like Service protocol coverage. If UDP matters, it
is a separate design.

## B8. FSM snapshots shallow-copy mutable placement values

**Where:**

- `internal/cluster/fsm.go:241-254`
- `internal/cluster/fsm.go:178-213`

`placementFSM.snapshot()` copies the map, but the `Placement` values include
mutable reference fields: `Spec` pointer and `ExposedPorts` map. `opAddExposedPort`
and `opRemoveExposedPort` mutate the `ExposedPorts` map on the FSM path.

That means snapshot persistence can encode a map that aliases live FSM state
while future applies mutate it. At minimum this needs a deep-copy audit before
we rely on snapshots under churn.

**Required fix:**

Deep-copy `Placement.Spec`, `Placement.SealedSecrets`, and `Placement.ExposedPorts`
when taking FSM snapshots and when returning placement snapshots to watchers.

**Current branch status:** first-slice fixed, including
`ExposedPortRoutes`.

## B9. FSM version is not a durable watch revision

**Where:**

- `internal/cluster/fsm.go:69-72`
- `internal/cluster/fsm.go:252-273`

The stage-1 plan proposes worker/ingress watches using placement versions.
Current `placementFSM.version` is not persisted in snapshots, and restore does
not restore it. It is fine as an in-memory debugging counter, not as a durable
watch revision.

**Required fix:**

Use Raft log index as the watch revision or persist FSM version in snapshots.
Ingress and worker watches need monotonic, durable revisions.

## B10. Cluster-wide name uniqueness is not enforced

**Where:**

- `pkg/models/types.go:249-258`
- `internal/store/store.go:175-180`

Sandbox `Name` is unique only inside one node's SQLite store. In cluster mode,
two concurrent creates can place same-name sandboxes on different owners because
the Raft FSM does not maintain a cluster-wide name index.

If any API facade resolves sandboxes by name, this is a correctness bug.

**Required fix:**

Move name reservation into the cluster control plane:

- `name -> sandbox_id` index in Raft/etcd;
- reservation before create;
- idempotent retry semantics for duplicate create requests.

## B11. Placement ignores disk and GPU

**Where:**

- `pkg/models/types.go:229-241`
- `pkg/models/types.go:265-268`
- `internal/cluster/placement.go:21-59`

The scheduler considers CPU and memory. It does not consider disk or GPU, even
though both are in the create request model.

If the public API accepts these fields in cluster mode, placement is not
"completely proper" until these resource dimensions are modeled.

**Required fix:**

Add node resource inventory and scheduler filters for:

- disk budget and disk pressure;
- GPU inventory, type, count, and runtime compatibility;
- runtime support labels (`docker`, `gvisor`, future `kata`).

## B12. `cluster-init.sh` credential-key ordering is suspicious

**Where:**

- `scripts/cluster-init.sh:265-278`
- `scripts/cluster-init.sh:303-333`

The TLS bundle tries to copy `$CRED_KEY_PATH` before the script derives,
creates, and validates the credential key path. With `set -u` and the default
empty `CRED_KEY_PATH`, this path is at risk of failing unless the operator
passes `--credential-key-path`.

**Required fix:**

Move credential key derivation/generation before TLS bundle creation.

This belongs in the release blocker list because the setup scripts are the
first user experience of cluster mode.

## B13. Docs reference a node-removal endpoint that is not registered

**Where:**

- `setup/cluster.md:919-931`
- `pkg/api/v1/routes.go`

The docs show `DELETE /v1/cluster/members/<node-id>`, but the route table only
registers:

- `GET /v1/cluster/members`
- `GET /v1/cluster/leader`
- `GET /v1/cluster/placements/{id}`
- `POST /v1/cluster/internal/apply`

**Required fix:**

Implement the endpoint or remove it from the docs. For Kubernetes-grade
operability, an explicit remove/drain/promote API is useful, but it must exist
before it is documented.
