# Architecture at a glance

One-page map of **sandbox placement** in AerolVM cluster mode. Details live in the numbered docs.

## System context

```mermaid
C4Context
    title AerolVM cluster — placement context

    Person(client, "Client", "SDK / HTTP")
    System_Boundary(aerolvm, "AerolVM cluster") {
        System(api, "sandboxd API", "Any node :21212")
        System(raft, "Raft quorum", "Placement FSM")
        System(gossip, "SWIM gossip", "Membership")
        System(cap, "Capacity leases", "Pull /v1/capacity")
        System(owner, "Owner node", "Runtime + SQLite")
    }
    System_Ext(lb, "Load balancer", "TLS pass-through")
    System_Ext(caddy, "Caddy ingress", "Per-node routes")

    client --> lb
    lb --> api
    api --> raft
    api --> gossip
    api --> cap
    api --> owner
    raft --> owner
    lb --> caddy
    caddy --> owner
```

## Placement decision — condensed

```mermaid
flowchart TB
    subgraph input["Inputs to SelectPlacement"]
        G["Gossip: alive, role, API URLs"]
        C["Capacity lease: CPU/mem/disk/GPU/runtime/template"]
        P["FSM: pending reservations, drain marks"]
        R["Request: cpu, memory, disk, runtime, …"]
    end

    subgraph algo["Algorithm (placement.go)"]
        F["Filter candidates"]
        T["pickTwo random"]
        H["headroomScore — higher wins"]
        S["Self wins ties"]
    end

    subgraph output["Output"]
        O["PlacementTarget<br/>node_id + URLs + IsSelf"]
    end

    G --> F
    C --> F
    P --> F
    R --> F
    F --> T --> H --> S --> O
```

## Create path — condensed

```mermaid
flowchart LR
    A["Client POST create"] --> B["Any API node"]
    B --> C["SelectPlacement"]
    C --> D["opReserve → Raft"]
    D --> E{"Owner = self?"}
    E -->|no| F["ForwardHTTP to owner"]
    E -->|yes| G["CreateSandboxWithID"]
    F --> G
    G --> H["Runtime boot"]
    H --> I["opPlace → Raft"]
    I --> J["201 + sandbox id"]
```

## Consistency boundaries

```mermaid
quadrantChart
    title Where strong consistency is required
    x-axis Low coordination cost --> High coordination cost
    y-axis Best-effort OK --> Must not diverge
    quadrant-1 Use Raft
    quadrant-2 Avoid — too expensive
    quadrant-3 Gossip / local
    quadrant-4 Pull + TTL

    Name uniqueness: [0.85, 0.92]
    Capacity reservation: [0.80, 0.88]
    Custom hostname bind: [0.82, 0.90]
    Pick worker node: [0.25, 0.35]
    Membership liveness: [0.20, 0.25]
    Capacity snapshot: [0.30, 0.30]
    Exec/file hot path: [0.15, 0.20]
```

## Document map

```mermaid
flowchart LR
    README["README"] --> O["01 Overview"]
    O --> T["02 Topology"]
    T --> W["03 Workflow"]
    W --> F["04 FSM"]
    F --> R["05 Routing"]
    R --> FO["06 Failover"]

    style W fill:#e8f4fc,stroke:#333
    style F fill:#e8f4fc,stroke:#333
```

**Start here for a design review:** [03-placement-workflow.md](./03-placement-workflow.md) + [04-placement-fsm.md](./04-placement-fsm.md)

**Start here for ops / failure modes:** [06-failover-and-recovery.md](./06-failover-and-recovery.md) + [`setup/cluster.md`](../setup/cluster.md)
