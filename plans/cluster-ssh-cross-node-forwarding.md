# Cluster SSH Cross-Node Forwarding — Plan

Status: **IMPLEMENTED** (branch `feat/cluster-ssh-cross-node-forwarding`).
See "§8. As-built" at the bottom for how the shipped code differs from the
original B2 proposal below. Fixes the cluster-mode half of UC-43:
SSH only works today when the client happens to land on the node that owns the
sandbox. This plan teaches the SSH gateway to authenticate and run the session
against the **owner node** regardless of which node the connection terminates on,
using the **B2 design** (authenticate at the edge with the sandbox's *public*
key, then forward the session to the owner over the existing cluster mTLS data
path).

## 0. Background — why this is needed

In cluster mode, sandboxes are owner-sharded: sandbox X lives on exactly one
node, and its SSH key + running container exist only there. The SSH gateway runs
on every worker (`pkg/daemon/daemon.go` — `cfg.EnableSSHGateway && cfg.IsWorker()`)
and resolves sandboxes via `g.svc.GetSandbox` → `store.Get`, which reads the
**local** SQLite only (`internal/service/owner_scope.go:scopedGet`). The leased
domain load-balances across nodes, so a client frequently lands on a node that
isn't the owner → the local lookup misses → `permission denied`.

HTTP already solves this: toolbox/session/port-forward calls are reverse-proxied
to the owner via `cluster.ForwardHTTP` (`internal/cluster/forward.go`). SSH never
got that hand-off. The routing key (sandbox ID) travels **inside** the encrypted
SSH channel as the username, so a raw-TCP proxy can't peek it before the
handshake — the entry node must participate in SSH, which is why this is a
"forward the authenticated session" problem, not a "look it up" problem.

**Why B2 over B1 (bastion / re-originate):** B2 never distributes a fleet-wide
secret SSH *host* key, only ever moves *public* keys, rides the already-mutually-
authenticated cluster mTLS channel, and is a smaller change in the high-risk
`internal/cluster` area. See the design discussion in §3.

---

## 1. Use cases this solves (≥20)

Grouped for readability. Each is a behaviour that is broken or impossible today
and must hold after this lands.

### Core routing
1. **Remote-owned SSH succeeds** — client SSHes to the leased domain, lands on
   node A, sandbox is owned by node B → session works (the UC-43 cluster fix).
2. **Self-owned fast path** — client lands on the node that owns the sandbox →
   handled locally with no extra hop (no latency regression).
3. **Single-node unchanged** — with `EnableCluster=false` the `cluster.Noop`
   reports `IsSelf=true`, so the gateway always takes the local path; byte-for-
   byte identical to today.
4. **Load-balanced ingress** — SSH to the same sandbox succeeds regardless of
   which of the 3 ingress nodes DNS hands the client.

### Session shapes
5. **Default interactive shell** (`ssh <id>`) routes to the owner's container.
6. **Named session** (`ssh <id>+<name>`) attaches to the correct named session
   on the owner.
7. **Legacy one-shot exec** (`ssh <id>+exec`) forwards the exec to the owner.
8. **Non-interactive command** (`ssh <id> -- echo hi`) returns the owner's
   stdout and the correct **exit code**.
9. **PTY semantics** — `pty-req`, `window-change`, and TTY mode are honored
   end-to-end across the forward.
10. **Large / streaming output** — long-running or high-volume output streams
    without truncation and with backpressure.
11. **Concurrent sessions** — multiple clients SSHing to the same remote-owned
    sandbox are routed independently.

### Authentication & authorization correctness (must NOT regress)
12. **Forged/wrong key → denied** for a remote-owned sandbox; auth is enforced
    using the owner's authoritative key, not a guess.
13. **Unknown sandbox ID → denied** with the existing "constant-time-ish"
    behaviour (failure doesn't leak which step failed) preserved across the hop.
14. **Stopped sandbox → denied** — status is checked against the owner's truth.
15. **Key rotation/revocation honored immediately** — a key rotated on the owner
    must not be accepted at the edge (no stale cache lets a revoked client in).
16. **mTLS-gated forwarding** — only authenticated cluster member nodes can drive
    the owner's SSH-forward endpoint; an outside/non-member node cannot.

### Cluster lifecycle correctness
17. **Owner change after failover/recreate** — when a sandbox is recreated on a
    new node, subsequent SSH routes to the **new** owner.
18. **Orphaned sandbox** (owner dead, not yet reclaimed) → clean
    `permission denied` / retryable error, never a panic or hang.
19. **Owner unreachable** (transient network blip) → bounded-timeout error to the
    client, no indefinite hang.
20. **Graceful drain** — SSH during an owner's drain either routes to the new
    owner or fails cleanly (no half-open session).

### Data-plane fidelity & ops
21. **Per-sandbox egress/network rules still apply** — because exec runs on the
    owner where the container and its `netrules` live (not at the edge).
22. **Host identity is stable** across nodes so clients don't get
    host-key-changed warnings as DNS rotates (shared host key, or documented
    guidance).
23. **Correlated observability** — edge and owner emit log lines that can be
    joined for one forwarded SSH session (a forward/session correlation id).
24. **Metrics** — cross-node SSH forwards are counted/measured alongside the
    existing owner-forward metrics (`beginOwnerForward` family).
25. **Integration coverage** — UC-43 flips from skip→pass in the cluster
    scenarios, and a new negative UC proves cross-node auth rejection.

---

## 2. Non-goals

- **No SSH bastion (B1)** and **no shared SSH *private* host key requirement**
  for correctness (shared host key is an optional UX nicety, see UC-22).
- **No new public API surface.** All new endpoints are cluster-internal
  (`/v1/cluster/internal/ssh/...`), mTLS-gated like the existing placement RPCs.
- **No change to single-node behaviour.** `cluster.Noop` keeps the local path.
- **No replication of secret material.** Only the SSH *public* key is read
  cross-node (and per-connection, not cached durably).

---

## 3. Design (B2)

Entry node = the worker the client's SSH connection terminates on. Owner =
the node that owns the sandbox (`cluster.OwnerOf(id)` →
`OwnerInfo{NodeID, InternalURL, IsSelf}`, already available; placement state is
replicated to every node via Raft).

`publicKeyCallback` (`pkg/sshgateway/gateway.go`) gains an owner branch:

```
sandboxID := parseSSHUser(conn.User())
owner := cluster.OwnerOf(sandboxID)
if owner.IsSelf {            // existing local path, unchanged
    authorize against local store; serve via local docker / container WS
} else {                     // NEW remote path
    // A. authenticate at the edge
    authz := clusterClient.SSHAuthz(owner, sandboxID)   // mTLS GET to owner
    //   authz = { authorizedKey, status, hasContainer } (public key only)
    verify client signature against authz.authorizedKey, check status/container
    // B. run the session on the owner
    //   on session/exec open, stream the SSH channel to the owner's internal
    //   SSH-forward endpoint over mTLS; the owner executes locally and pipes
    //   stdio/exit-code back.
}
```

**Sub-problem A — authenticate (UC-12..16).** The edge fetches the sandbox's
authorized **public** key + status + container presence from the owner via a new
mTLS-only endpoint `GET /v1/cluster/internal/ssh/authz/<id>`. The edge verifies
the client's signature locally (it is the SSH server the client actually talks
to, so this is cryptographically sound — no vouching). Fetch is **per
connection** (no durable cache) so revocation is honored immediately (UC-15).
Any failure collapses to `permission denied` to preserve the constant-time-ish
property (UC-13).

**Sub-problem B — execute on the owner (UC-5..11, 21).** The session can't run
at the edge (the container is on the owner). The edge opens a stream to a new
mTLS endpoint `/v1/cluster/internal/ssh/session/<id>` on the owner; the owner-
side handler does exactly what the local gateway does today (`attachToSession`
WebSocket to the container, or `ExecCreate`/`ExecStart`) and bridges bytes back
over the mTLS connection. This reuses the cluster's existing cert-pinned data
path (`mtlsProxies` in `internal/cluster/agent.go`) rather than inventing new
transport.

**Owner lookup freshness (UC-17..20).** `OwnerOf` reads replicated placement
state; orphaned/owner-changed/draining states surface as typed errors
(`ErrOrphaned`, etc.) that map to a clean denial or bounded retry, never a hang.

---

## 4. Implementation plan — files

### New files

| File | Purpose |
|---|---|
| `plans/cluster-ssh-cross-node-forwarding.md` | This plan. |
| `internal/cluster/ssh_forward.go` | Owner-side: register `/v1/cluster/internal/ssh/authz/<id>` and `/v1/cluster/internal/ssh/session/<id>` (mTLS-gated); edge-side client methods `SSHAuthz(owner, id)` and `OpenSSHSession(owner, id, …)` over `mtlsProxies`. Defines the `SSHAuthzResponse` DTO (public key + status + hasContainer). |
| `internal/cluster/ssh_forward_test.go` | Cluster-correctness regression test: self vs remote routing, owner-change after recreate, orphaned owner, mTLS rejection of non-members, and the single-node `Noop` no-op. |
| `pkg/sshgateway/forward.go` | Edge-side remote path: given an `OwnerInfo`, authenticate via the cluster client's `SSHAuthz`, then bridge the SSH channel to the owner's session endpoint. Keeps the local path in `gateway.go` untouched. |
| `pkg/sshgateway/forward_test.go` | Unit tests for the remote branch: signature verify against fetched key, denial paths, exit-code propagation, timeout/owner-unreachable handling (with a fake cluster client). |

### Modified files

| File | Change |
|---|---|
| `pkg/sshgateway/gateway.go` | Add an owner-lookup dependency to the gateway; branch `publicKeyCallback` on `OwnerOf` (self → today; remote → `forward.go`). Extend the `SandboxLookup`/constructor to receive the cluster client. |
| `pkg/sshgateway/session_attach.go` | Factor the local container-WS attach so the owner-side handler can reuse it; route to owner when the permission marks the sandbox remote. |
| `pkg/sshgateway/config.go` | Add forward timeout(s) and the owner-dial config (mTLS client handle, bounded dial/handshake timeouts). |
| `internal/cluster/cluster.go` | Extend the `Cluster` interface with `SSHAuthz` + `OpenSSHSession` (and add no-op implementations to `Noop` so single-node stays a no-op; `OwnerOf` already exists). |
| `internal/cluster/agent.go` | Implement the new interface methods on `Agent` using the existing mTLS transport / `doControlPlaneJSON` pattern; add the new `/ssh/...` path constants next to the placement constants. |
| `internal/cluster/forward.go` | Add a bidirectional stream proxy helper (raw byte bridge) for the SSH session, alongside `ForwardHTTP`; reuse `beginOwnerForward`/metrics. |
| `pkg/api/server.go` (or the internal-route registration site) | Register the two new mTLS-gated internal SSH endpoints behind the same auth as the other `/v1/cluster/internal/*` routes. |
| `internal/service/service.go` | Add a thin `SandboxSSHAuthz(ctx, id)` returning `(authorizedKey, status, hasContainer)` from the **local** store, used by the owner-side handler; expose `OwnerOf` passthrough if the gateway needs it via the service. |
| `pkg/daemon/daemon.go` | Pass the cluster client (and its mTLS material) into `sshgateway.New(...)`; the gateway can now route cross-node. |
| `internal/config/config.go` | Add `SB_SSH_FORWARD_TIMEOUT` (bounded owner dial) and a documented `SB_SSH_HOST_KEY_SHARED`/path note for stable host identity (optional). |
| `integration-tests/suite/harness/usecases.go` | Drop the cluster gating on UC-43 (it works cross-node now); add a new negative UC (cross-node forged-key → denied). |
| `integration-tests/suite/ssh_test.go` | Add a cluster assertion that SSH succeeds for a sandbox forced onto a non-entry node; keep single-node path. |
| `integration-tests/suite/cluster_test.go` | If a placement-pinning helper is needed to force the sandbox onto a specific (non-entry) node for a deterministic cross-node test. |
| `Ansible/playbooks/` (+ inventory) | Optional: distribute a shared SSH host key so clients see a stable host identity across nodes (UC-22). |
| `Terraform/templates/bootstrap.sh.tftpl` | Optional: emit the shared host-key path / `SB_SSH_FORWARD_TIMEOUT` env if introduced. |
| `docs/src/content/docs/ssh.mdx` (or the cluster doc) | Document cross-node SSH behaviour, host-identity guidance, and the per-connection auth/revocation semantics (no curl; SDK tabs where examples are needed). |

---

## 5. Security considerations

- **Edge is in the auth TCB by necessity** (it terminates the client's SSH).
  Mitigations: fetch the authorized key **per connection** (no durable cache) so
  revocation is immediate (UC-15); collapse all failures to `permission denied`
  (UC-13).
- **Only public keys cross the wire.** No secret host key or private material is
  replicated (the core reason B2 beats B1).
- **mTLS-gated owner endpoints.** The `/ssh/authz` and `/ssh/session` endpoints
  require cluster-member mTLS, identical to the placement RPCs — a non-member
  cannot fetch keys or open sessions (UC-16).
- **Bounded timeouts** on every cross-node hop so an unreachable owner fails
  fast instead of pinning gateway goroutines (UC-19).

---

## 6. Testing & rollout

- **Unit:** `pkg/sshgateway/forward_test.go` (remote-branch auth + bridge),
  `internal/cluster/ssh_forward_test.go` (routing, owner-change, orphan, mTLS,
  Noop no-op) — these are the mandated regression tests for the high-risk
  `internal/cluster` change.
- **Integration:** UC-43 un-gated in cluster scenarios + the new negative UC;
  the cross-node case forced via placement pinning so it's deterministic.
- **Single-node guard:** an explicit test asserting the `Noop` path is byte-for-
  byte the existing local flow.
- **Rollout:** ship behind the existing `EnableCluster`/`Noop` seam so single-
  node is untouched; cluster nodes pick up forwarding on upgrade. PR must carry
  the cluster-correctness call-out (split-brain/leader-change/single-node-noop)
  per the repo rules.

## 7. Open questions

- **Shared host key vs per-node:** ship per-node first (clients use the leased
  domain; document the host-key behaviour) or distribute a shared host key in
  the same PR? (Affects UC-22 only, not correctness.)
- **Authz transport:** per-connection `SSHAuthz` fetch (tightest revocation) vs
  replicating the SSH *public* key into the placement spec (one fewer hop, but
  revocation must propagate through the FSM). Plan defaults to per-connection
  fetch.

---

## 8. As-built (what actually shipped)

The shipped implementation keeps the B2 **security model** (authenticate at the
edge with the sandbox's *public* key; run the session on the owner; only public
keys + session bytes cross nodes) but **reuses the existing cluster HTTP
owner-forward data path** instead of building bespoke mTLS SSH endpoints. This
removed the entire planned `internal/cluster` surface change — a deliberate
risk reduction in the repo's most fragile package.

**Key realization:** every per-sandbox v1 route is already wrapped with
`clusterForwardWrap`, which reverse-proxies the request — **WebSocket upgrades
included** (`pkg/api/v1/proxy.go`, `internal/cluster/forward.go`) — to the owner
over the cert-pinned mTLS internal channel. So the edge SSH gateway never needs
to know the owner or hold mTLS material: it talks to **its own node's v1 API
over loopback** and the existing forward path does the cross-node hop.

How each B2 sub-problem maps:

- **Auth (A):** when a sandbox is not in the local store, the gateway GETs
  `/v1/sandboxes/<id>` on loopback → forwarded to the owner → returns the
  authoritative `ssh_public_key` + status. The offered key is verified against
  it. Fetch is per-connection (no cache) so revocation is immediate. Any failure
  collapses to `permission denied`.
- **Execute on owner (B):** the session is bridged to
  `/v1/sandboxes/<id>/sessions[...]` (and the `/attach` WebSocket) on loopback →
  forwarded to the owner → owner's `sessionsProxy` reaches its local toolboxd and
  injects the real toolbox token. The toolbox token never crosses nodes.

**Single-node guarantee:** `RemoteAPIBaseURL` is set only when
`cfg.EnableCluster`. Empty → the remote branch is never taken and the local
docker/container path is byte-for-byte unchanged (covered by
`TestPublicKeyCallback_SingleNodeNeverRemote`).

### Files actually changed

New:
- `pkg/sshgateway/forward.go` — edge remote auth (`authorizeRemoteSSH`,
  `fetchRemoteSandbox`) + remote session bridge (`handleRemoteSession`,
  `remoteSessionEndpoint`, `httpToWS`).
- `pkg/sshgateway/forward_test.go` — remote auth success, forged-key/unknown/
  stopped denials, single-node-never-remote guard, local-wins, `httpToWS`.

Modified:
- `pkg/sshgateway/gateway.go` — `Config.RemoteAPIBaseURL`/`RemoteAPIToken`;
  gateway fields; `publicKeyCallback` local-then-remote resolution; extracted
  `authorizeLocalSSH`/`authorizeKey`; `handleSession` gains a `remoteOwned`
  branch; `sessionState.execCommand`.
- `pkg/sshgateway/session_attach.go` — `attachToSession`/`findOrCreateSession`
  parameterized by `sessionEndpoint` (local container vs owner-forwarded v1);
  one-shot exec injection for the remote path.
- `pkg/daemon/daemon.go` — pass loopback v1 base URL + PAT to the gateway in
  cluster mode (`loopbackAPIBaseURL`).

### Follow-up batch (completed after the initial commit)

- **UC-7 / UC-8 — exact remote exec/exit codes.** A cross-node one-shot exec now
  runs as its own short-lived toolbox session via `CreateSessionRequest.Command`
  (`sh -c <cmd>`); the session's exit status is reported back over the attach WS
  `exit` frame, so exit codes are exact (no more stdin `cmd\nexit` injection).
- **UC-9 — mid-session resize on the remote path.** `handleRemoteSession` now
  runs the attach concurrently with the request loop and forwards
  `window-change` events as toolbox `resize` control messages
  (`attachToSession` gained a resize channel). (The *local* session path still
  only applies the initial size — a pre-existing, unchanged limitation.)
- **UC-22 — shared SSH host key.** Optional shared host key distributed by
  Terraform (`ssh_host_key_pem`) and Ansible (`ssh.host_key` /
  `sandboxd_ssh_host_key_src`) to every ingress node; documented in
  `docs/.../ssh-access.mdx`. Default stays per-node.
- **UC-23 — correlated observability.** A `forward_id` is generated per
  forwarded session, stamped on the `X-Aerol-Ssh-Forward-Id` header of the
  cross-node calls and logged on both the edge (gateway) and owner
  (`ServeToolboxReverseProxy`) sides.
- **UC-24 — metrics.** Cross-node SSH rides `ForwardHTTP`, so it is already
  counted by the existing `beginOwnerForward` metric family (no new code).
- **UC-25 — negative integration test.** Added `UC-67` (`Cross-node SSH rejects
  a forged key`) to the registry + `TestSSHCrossNodeForgedKeyRejected`.

### Still not done

- No new `internal/cluster` endpoints, no `Client` interface change, no Noop
  change (the reuse made them unnecessary).
- **Live multi-node validation** — the implementation is unit-tested in
  isolation but has NOT been run against a real cluster. UC-43 + UC-67 in the
  integration harness need an actual cluster deploy to confirm end-to-end.
- Local (single-node) session-attach mid-session resize remains unaddressed
  (pre-existing; out of scope for the cross-node fix).
