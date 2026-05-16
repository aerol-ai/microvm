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

**Current branch status:** **Resolved.** Owner API forwarding now rides the
cluster-internal mTLS channel when both peers have TLS material; the public
APIURL+PAT path remains as a mixed-rollout fallback.

- `OwnerInfo` / `PlacementTarget` carry an `InternalURL` populated from
  gossip's `peerInternalURL` (`internal/cluster/cluster.go`,
  `internal/cluster/client.go`, `internal/cluster/placement.go`).
- `ForwardHTTP(target Endpoint, ...)` (was `ForwardHTTP(string, ...)`) picks
  the channel: `mtlsProxies` keyed on `InternalURL` when this node has TLS
  AND the peer advertised one; else `publicProxies` keyed on `APIURL`. Hard
  network/TLS failures on the internal channel surface as 502 instead of
  silently downgrading, so the cert-pinned promise holds
  (`internal/cluster/forward.go`).
- The mTLS listener now serves the public v1 mux on every non-`/internal/apply`
  path via a lock-free `atomic.Pointer[http.Handler]` delegate. The handler
  is attached from `cmd/sandboxd/main.go` after `api.NewServer` returns; until
  then the listener 503s non-apply paths and peers fall back to the public
  path (`internal/cluster/internal_server.go`,
  `internal/cluster/client.go::AttachInternalHandler`, `cmd/sandboxd/main.go`).
- Regression coverage: `TestForwardHTTPPrefersInternalURLWhenAvailable`,
  `TestForwardHTTPFallsBackToAPIURLWithoutTLS`,
  `TestForwardHTTPFallsBackToAPIURLWhenInternalEmpty`,
  `TestForwardHTTPRejectsLoop`, `TestForwardHTTP503WhenNoUsableEndpoint`
  (`internal/cluster/forward_test.go`).
- **Known limitation:** `clusterListWrap`'s peer fan-out still constructs
  manual `peer.APIURL`-based requests because the existing code parses the
  JSON response (it's a fan-and-merge, not a reverse-proxy). Moving that
  read path to mTLS is a separate, smaller piece of follow-up work; the
  primary B3 concern (owner-scoped mutating forwards) is now cert-pinned.

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

**Current branch status:** **Resolved.** Both the role split and the
voter cap landed.

- `SB_NODE_ROLE=server|worker|ingress|mixed` is wired in
  `internal/config/config.go` (validated, defaults to `mixed`,
  rejects `worker`/`ingress` outside cluster mode, blocks
  `SB_CLUSTER_BOOTSTRAP` on non-server roles).
- The role is gossiped on `nodeMeta.Role`
  (`internal/cluster/gossip.go`) so the leader sees it without an
  extra round-trip.
- `voter_autojoin.go` forces `worker` and `ingress` peers to raft
  non-voters unconditionally (`peerForcedNonVoter` /
  `isForcedNonVoterRole`). Empty/unknown roles fall through to the
  legacy path so rolling upgrades don't strand pre-existing voters.
- `SB_CLUSTER_MAX_AUTO_VOTERS` (default `5`) caps gossip-driven
  voter promotion for `server`/`mixed` peers; everything beyond the
  cap is added as a non-voter so the FSM still replicates without
  growing quorum.
- `voterCapReached` is fail-safe: if the raft configuration read
  errors, we treat the cap as reached rather than promote blindly.

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

- ~~replace polling with a watch/revision model or prove the polling interval is
  acceptable at 200 x 50~~ — **Resolved on this branch.** The 500ms FSM-version
  poll is gone; `Cluster.SubscribePlacement` returns a buffered cap=1 channel
  and `placementFSM.Apply` wakes subscribers on every committed mutation. Noop
  returns nil so single-node mode select{}s harmlessly. See
  `internal/cluster/fsm.go` (`subscribers`, `notifySubscribers`),
  `internal/cluster/client.go` (`SubscribePlacement`), and
  `internal/service/ingress_wake_test.go`.
- ~~add metrics for route lag, Caddy admin latency, and route misses~~ —
  **Resolved on this branch.** Exposed at `/debug/vars`:
  - `aerolvm_ingress_route_lag_versions` — gauge updated on every reconcile as
    `max(0, FSM.PlacementVersion - last-reconciled-version)`. Computed in
    `service.SetIngressRouteLag` and called after every
    `ReconcileClusterIngress` tick regardless of pass outcome
    (`internal/service/ingress_metrics.go`, `internal/service/service.go`).
  - `aerolvm_caddy_admin_calls_total` / `aerolvm_caddy_admin_errors_total` /
    `aerolvm_caddy_admin_last_nanos` — transport-level wrapper on
    `caddy.Client.httpClient.Transport` so every admin call is metric'd
    uniformly without per-call-site drift; errors here are *transport*
    failures (connection refused, DNS, timeout) so the counter is the
    Caddy-down canary (HTTP 4xx/5xx come back via resp.StatusCode and the
    caller classifies). `pkg/caddy/metrics.go`.
  - `aerolvm_ingress_route_misses_total` — incremented from
    `clusterForwardWrap` when placement says someone else owns the sandbox
    but gossip hasn't surfaced any forwarding URL (mid-rollover or
    misconfigured advertise URLs). Distinct from `reconcile_errors_total`
    which tracks Caddy admin failures. `pkg/api/v1/cluster_handler.go`,
    `internal/service/ingress_metrics.go`.
  - Regression coverage: `TestSetIngressRouteLagZeroWhenInstalledAhead`,
    `TestSetIngressRouteLagComputesDelta`,
    `TestSetIngressRouteLagZeroWhenFSMVersionUnknown`,
    `TestRecordRouteMissIncrements` in
    `internal/service/ingress_metrics_b5_test.go`;
    `TestInstrumentingTransportCountsCalls`,
    `TestInstrumentingTransportCountsErrors`,
    `TestInstrumentingTransportIgnoresHTTPErrorCodes` in
    `pkg/caddy/metrics_test.go`.
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

**Current branch status:** **Resolved by explicit disclaim** (the
cheap half of the original "design or disclaim" fork).

- `pkg/models/types.go` (`ValidExposedPortProtocol`) rejects any
  protocol outside `http`/`tcp`/`tls` and surfaces the allowed list
  verbatim in the error, so an SDK user asking for `udp` gets a
  clear `400` with the right hint instead of a silent fallback.
- `docs/src/content/docs/cluster-ingress.mdx:132` calls UDP out by
  name: *"UDP is not supported. caddy-l4 can carry TCP and TLS/SNI;
  UDP exposure needs a separate design."* This is the narrative
  carve-out the blocker required.
- The only other repo mention of UDP is the SWIM gossip port
  (`cluster-setup.md:25` — `7001/TCP+UDP`), which is internal
  control-plane traffic, not user-exposed sandbox ports. No
  ambiguity there.

A real UDP exposure design (connection-less host-port pool,
caddy-l4 UDP module, source-IP preservation, no SNI) is a separate
feature, not a release blocker.

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

**Current branch status:** **Resolved.** The deep-copy plumbing was
in place in the first slice; the audit pinned what was missing —
regression coverage proving snapshots are isolated from later Applies.

- `clonePlacement` (`internal/cluster/fsm.go`) deep-copies `Spec`
  (via `cloneCreateSandboxRequest` — Env, Tags, ContainerCommand,
  Mounts.Options/Credentials, Registry, Lifecycle, GPUs.DeviceIDs),
  `SealedSecrets`, `ExposedPorts`, and `ExposedPortRoutes`. Every
  external read path (`f.get`, `f.snapshot`, `c.SpecOf`,
  `c.ExposedPortsOf`, `c.SealedSecretsOf`, `c.Placements`) flows
  through it. `Snapshot()` calls `f.snapshot()` so the
  `*fsmSnapshot` raft holds across the deferred `Persist()` is
  independent of subsequent Applies.
- `opAddExposedPort` and `opRemoveExposedPort` still mutate the
  `ExposedPorts` / `ExposedPortRoutes` maps in place — that's the
  steady-state hot path. Because `Snapshot()` deep-clones every
  placement up front, the in-place mutation only affects the live
  FSM and is invisible to the persisted snapshot.
- New regression coverage: `TestFSMSnapshotIsolatedFromLaterApplies`
  (verifies a post-snapshot `opUpsertSpec` does not leak Spec /
  SealedSecrets into the persisted bytes) and
  `TestFSMSnapshotIsolatedFromExposedPortMutations` (verifies
  post-snapshot `opAddExposedPort` / `opRemoveExposedPort` do not
  leak through the ExposedPorts maps). Both restore into a fresh
  FSM and assert pre-snapshot state — proving raft log truncation
  is safe even if Persist runs arbitrarily long after Snapshot.

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

**Current branch status:** **Resolved.** Did both halves the plan asked
for:

- `placementFSM.apply` now sets `f.version = log.Index`
  (`internal/cluster/fsm.go`). Raft guarantees the index is strictly
  monotonic and globally ordered, so it doubles as a durable watch
  revision — leader and followers see the same number for the same
  state, and it can never regress across restarts.
- `Snapshot`/`Persist` encode an `fsmSnapshotPayload{Version,
  Placements}` envelope instead of a bare map. `Restore` decodes the
  envelope and falls back to the legacy bare-map shape (deriving the
  version from the highest `Placement.Version`) so a snapshot taken
  pre-fix still loads without regressing the revision.
- Regression coverage: `TestFSMVersionTracksLogIndex`,
  `TestFSMSnapshotPreservesVersion`,
  `TestFSMRestoreLegacySnapshotRecoversVersion` in
  `internal/cluster/fsm_test.go`.

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

**Current branch status:** **Resolved.** `placementFSM` now maintains a
`nameIndex` (`name -> sandbox_id`); `opPlace` and `opUpsertSpec` validate
uniqueness before mutating state and return `ErrNameConflict` on collision
(idempotent for the same sandbox_id). `Restore` rebuilds the index from
placements. The cluster-create path in `pkg/api/v1/cluster_handler.go` maps
`ErrNameConflict` to `409 Conflict` and rolls back the local create.

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

**Current branch status:** **Resolved (placement filter).**
`capacity.{Snapshot,Request,HostInfo,Limits}` extended with disk
(GB-granular, operator-declared `SB_HOST_DISK_GB` +
`SB_DISK_RESERVATION_RATIO`), GPU inventory (`SB_HOST_GPU_COUNT` /
`SB_HOST_GPU_VENDOR`), and `SB_HOST_RUNTIMES`. `placement.nodeFits`
filters on disk budget, GPU count + vendor, and runtime support;
`headroomScore` includes disk when reported. The local `Admitter`
charges and rejects on the same axes so a forwarded create can't pass
placement and then 503 on the receiving node. `capacityRequestFromSpec`
and `capacityRequestFromCreate` populate the new fields from
`models.CreateSandboxRequest` so failover-recreate inherits the same
constraints. Auto-detection of disk and GPU inventory is deliberately
out of scope (operator-declared) — overlay2/devicemapper/btrfs report
disk differently and GPU enumeration is vendor-specific.

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

**Current branch status:** **Resolved.** The credential-key block
(`scripts/cluster-init.sh:264-294`: derive `CRED_KEY_PATH` from
sandboxd.env or default, generate if missing, validate the base64
length) now runs before the TLS material section (line 296 onwards)
and before the bundle stages it via `install -m 0600 "$CRED_KEY_PATH"
"$TLS_DIR/credential_encryption.key"` at line 369. Running with the
default empty `CRED_KEY_PATH` no longer trips `set -u`.

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

**Current branch status:** **Resolved by removing the false claim.**
A grep across `docs/src/content/docs/` for `DELETE.*cluster/members`
turns up nothing — the live `cluster-setup.md` only references `GET
/v1/cluster/members` (lines 82, 228, 237), which is what
`pkg/api/v1/routes.go:105` actually registers. The original
`setup/cluster.md:919-931` block no longer exists; the docs and the
route table now agree. A proper drain/remove/promote API is still
useful for operability but is feature work, not a release blocker.
