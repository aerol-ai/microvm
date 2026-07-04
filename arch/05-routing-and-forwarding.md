# Routing and forwarding — reaching the owner

Placement answers **who** owns a sandbox. This document covers **how** traffic gets there after that decision — API control plane and public data plane.

## Two traffic planes

```mermaid
flowchart TB
    CLIENT["Client"]

    subgraph api_plane["Control plane (API)"]
        ANY["Any node :21212 /v1/..."]
        LOOKUP["OwnerOf(sandbox_id)<br/>local FSM or Agent cache"]
        FWD_API["ForwardHTTP → owner API"]
    end

    subgraph data_plane["Data plane (sandbox URLs)"]
        EDGE["Any node :443 / :80 / host ports"]
        CADDY["Caddy + caddy-l4 routes<br/>from FSM snapshot"]
        FWD_DP["Proxy / SNI pass-through<br/>to owner data plane"]
    end

    CLIENT -->|SDK exec, files, create| ANY
    CLIENT -->|https://id.domain| EDGE

    ANY --> LOOKUP
    LOOKUP -->|not self| FWD_API
    LOOKUP -->|self| LOCAL["Local service + SQLite"]

    EDGE --> CADDY
    CADDY -->|not owner| FWD_DP
    CADDY -->|owner| LOCAL_DP["Local container / VM"]
```

| Plane | Uses Raft on hot path? | Resolution source |
|-------|------------------------|-------------------|
| API | No | FSM placement map + gossip URLs |
| Sandbox HTTP/TLS URLs | No | Ingress reconciler from FSM |
| Raw TCP host ports | No | Same — bind on every node, proxy to owner |

## API forwarding (`forward.go`)

Every sandbox-scoped handler resolves ownership first:

```mermaid
sequenceDiagram
    participant C as Client
    participant N as Node N (non-owner)
    participant O as Owner node

    C->>N: GET /v1/sandboxes/{id}/exec
    N->>N: OwnerOf(id) → owner=O
    alt is self
        N->>N: handle locally
    else remote owner
        N->>O: ForwardHTTP (mTLS or PAT)
        Note over N,O: Header X-Cluster-Forwarded: 1
        O->>O: execute toolbox path
        O-->>N: response stream
        N-->>C: proxied response
    end
```

### Transport selection

1. **Preferred:** cluster mTLS on `:7002` when both sides have `SB_CLUSTER_TLS_DIR`
2. **Fallback:** public `SB_API_ADVERTISE_URL` with `Authorization: Bearer PAT`

Separate reverse-proxy caches per transport — TLS state and keepalives are not shared.

### Loop prevention

If a node receives a request that already has `X-Cluster-Forwarded: 1` and would forward again → **421 Misdirected Request**. Caller should re-resolve owner (stale FSM view).

### Error contract (routing)

| HTTP | Meaning | Client action |
|------|---------|---------------|
| 503 | Owner URL unknown / no leader / placement resolving | Retry with backoff |
| 410 Gone | Placement orphaned (owner dead, default policy) | New create |
| 421 Misdirected | Forward loop / wrong target | Re-resolve owner |

## Create forwarding (special case)

Creates are different from exec/file paths:

1. **Receiving** node runs `SelectPlacement` + `opReserve` (not the owner).
2. Request is forwarded with pinned headers so only the chosen owner executes `CreateSandboxWithID`.
3. Owner commits `opPlace`.

This guarantees placement is chosen **once** cluster-wide, not independently on each hop.

## Ingress reconciliation

Non-owner nodes still install routes so a dumb load balancer can send `*.domain` to any backend.

```mermaid
flowchart LR
    FSM["FSM apply<br/>placement version++"] --> SUB["SubscribePlacement<br/>buffered signal"]
    SUB --> REC["Ingress reconciler loop"]
    REC --> CADDY["Update Caddy L7 routes"]
    REC --> L4["Update caddy-l4 TCP/SNI routes"]

    REC --> METRICS["expvar: route lag,<br/>misses, errors"]
```

**Event-driven:** each FSM mutation wakes the reconciler; a 5s tick is a safety net.

**Convergence:** `placement_version` vs `node_installed_version` on `GET /v1/cluster/placements/:id`. Brief window where HTTP returns 503 `Retry-After: 2` (“placement in flux”).

### Data-plane target address

Peers forward to `OwnerDataPlaneHost` (`SB_DATA_PLANE_ADVERTISE_HOST`), not necessarily the API URL. Set explicitly when API traffic uses a shared LB hostname that would loop back.

Forwarding modes (from `setup/cluster.md`):

| Exposure type | Non-owner behavior |
|---------------|-------------------|
| Domain HTTP (`id.domain`) | SNI pass-through to owner |
| IP/path HTTP | Reverse-proxy to owner :80 |
| Raw TCP `host_port` | Bind same port locally, proxy to owner |
| TLS-SNI port routes | Pass-through to owner :443 |

## Worker / Agent nodes

Agents do not run the full FSM. For `OwnerOf`:

- Point read via control-plane RPC, or
- Cached placement shard/page (for list operations)

Forwarding behavior is identical — once owner is known, `ForwardHTTP` applies.

## Single-node mode

`Noop` reports every sandbox as owned locally. No forwarding, no ingress fan-out to remote owners. Caddy routes still reconcile from local SQLite + placement noop.

## End-to-end diagram (steady state)

```mermaid
graph TB
    subgraph client["Client"]
        SDK["SDK baseURL = LB"]
    end

    subgraph lb["Load balancer"]
        LB443[":443 TLS pass-through"]
    end

    subgraph node_a["node-A"]
        API_A["API"]
        ING_A["Ingress routes"]
    end

    subgraph node_b["node-B (owner of sandbox X)"]
        API_B["API"]
        RT_B["Runtime X"]
        SQL_B[("SQLite")]
        API_B --> RT_B
        API_B --> SQL_B
    end

    SDK --> LB443
    LB443 --> API_A
    SDK --> LB443
    LB443 --> ING_A

    API_A -->|"OwnerOf(X)=B"| API_B
    ING_A -->|"route for X → B data plane"| RT_B
```

**Takeaway:** Clients stay ignorant of placement. The cluster presents one API URL; ingress makes sandbox URLs work no matter which node receives the TCP connection.
