# 03 - Placement, Admission, And Create

## P0. Placement Is O(nodes + placements), Not O(1)

**Where:**

- `internal/cluster/placement.go:57-89`
- `internal/cluster/fsm.go:539-558`

`SelectPlacement` reads every member, copies drained-node state, and scans
every placement to aggregate pending reservations. The final power-of-two
choice is O(1), but the preparation is not.

At 10,000 nodes and 100,000 sandboxes, one create can scan:

- 10,000 members;
- up to 100,000 placement rows for reservations;
- all drained nodes;
- capacity metadata for every member.

Now multiply that by a 100,000-create burst. The leader and routers spend a lot
of CPU deciding where to send work before the system has applied backpressure.

**Required redesign:**

- keep pending reservations indexed by node in the FSM;
- expose an incremental scheduler cache instead of scanning placements;
- keep ready worker sets pre-filtered by role, health, capacity, runtime, and
  drain state;
- batch placement decisions;
- add a queue and admission budget before requests reach Docker.

## P0. Roles Are Not A Scheduling Constraint

**Where:**

- `internal/cluster/placement.go:73-89`
- `cmd/sandboxd/main.go:132-159`

The scheduler does not filter candidates by `worker` role. A pure `server` or
pure `ingress` node can still be selected if it is alive and has an API URL.
The process also still constructs Docker, store, mounts, Caddy, and service
objects before role-specific loops are gated.

This defeats the operational model. A node role must be a hard capability
constraint, not just a background-loop toggle.

**Required redesign:**

- only worker-capable nodes should advertise schedulable capacity;
- `SelectPlacement` must exclude nodes that do not include `worker`;
- worker-only handlers must return clear 503/409 on non-worker roles;
- pure server/ingress nodes should not require Docker or mount dependencies;
- SSH gateway should be disabled or owner-aware on non-workers.

## P0. Local Admission Does Not Count Disk, GPU, Or Runtime

**Where:**

- `internal/service/service.go:386-390`
- `internal/service/service.go:1645-1648`
- `internal/service/events.go:237-240`

Placement and reservations talk about disk, GPU, and runtime. But the actual
local `Admit` calls during create, replay, and out-of-band start reserve only
CPU and memory.

Consequences:

- `ReservedDiskGB` in capacity snapshots never reflects placed sandboxes;
- `totalGPUs` never reflects placed GPU sandboxes;
- disk placement can look safe until the node fills;
- multiple GPU sandboxes can be admitted onto the same single GPU;
- a future failover/restart can replay CPU/memory but not disk/GPU pressure;
- placement's resource model and the target's actual admission model diverge.

This is a direct scalability bug. At 100,000 sandboxes, disk and GPU are not
edge constraints. They are primary constraints.

**Required fix:**

All admission/reserve paths must use the full request:

```text
CPU, memory, disk, GPUs, GPU vendor, runtime
```

and tests must assert that snapshots change after real creates, starts,
replays, and event-driven starts.

## P0. Reservation TTL Can Expire During A Slow Create

**Where:**

- `pkg/api/v1/cluster_handler.go:24-29`
- `pkg/api/v1/cluster_handler.go:189-217`
- `pkg/api/v1/cluster_handler.go:231-331`
- `internal/cluster/dead_owner.go:219-254`

Cross-node create reserves the placement for 120 seconds. The target then runs
Docker create, image pull, mount setup, Caddy route installation, store writes,
and finally `RecordPlacement`.

If the local create takes longer than the TTL:

1. reservation GC cancels the row;
2. the target later calls `RecordPlacement(resp.Sandbox.ID, nil, nil)`;
3. `opPlace` can create a placed row without the original spec, sealed secrets,
   or name;
4. cluster-wide name uniqueness can be lost;
5. failover reconstruction data is gone.

Slow image pulls, GPU images, registry throttling, large mount setup, or a
busy Docker daemon can all exceed 120 seconds in a large fleet.

**Required redesign:**

- reservation TTL must be extended by the target while create is in progress;
- the target must promote with the original spec if the reservation is missing;
- the FSM should reject nil-spec promotion for a previously reserved cross-node
  create unless the target supplies a verified fallback;
- create should have explicit states: reserved, creating, ready, failed;
- reservation GC should be per-state and owner-heartbeat aware.

## P0. Create Has No Cluster Backpressure

The create path immediately performs expensive work:

- reads the whole request body into memory;
- seals/redacts secrets;
- does one or two Raft writes;
- forwards over HTTP;
- runs Docker create/pull;
- mounts external storage;
- writes Caddy config;
- writes SQLite.

There is no global queue, no per-node create concurrency cap, no image-pull
budget, no mount budget, and no admission preflight for Docker daemon health.

At 100,000 concurrent creates, this can overwhelm:

- the Raft leader;
- API goroutines and request memory;
- Docker pull/create concurrency;
- registry rate limits;
- mount adapters;
- Caddy admin;
- SQLite single writer on the target node.

**Required redesign:**

- introduce per-node create workers with configurable concurrency;
- return 429/503 with retry-after when queues are full;
- reserve in control plane, enqueue on target, then complete asynchronously or
  block only within a bounded wait;
- deduplicate image pulls per node;
- expose queue depth, age, and reject counts.

## P0. Spec Replication Uses The Unnormalized Request

The v1 create wrapper replicates the original request, not the final normalized
runtime spec produced by `service.createSandbox`.

Examples:

- empty runtime can recreate under the new owner's default runtime, not the
  original owner's actual runtime;
- default CPU/memory/disk are inferred later rather than stored explicitly;
- OS user and env defaulting happen locally;
- future defaults can change the meaning of old replicated specs.

At small scale this is a correctness footgun. At large scale and during
rolling upgrades it becomes dangerous.

**Required fix:**

Persist the normalized, resolved, immutable sandbox spec that was actually
used to create the container.

## P1. Resize Spec Replication Can Clobber Existing Values

**Where:**

- `pkg/api/v1/handlers.go:126-142`

The resize handler patches the replicated spec by assigning all three fields:

```go
s.CPU = req.CPU
s.MemoryMB = req.MemoryMB
s.DiskGB = req.DiskGB
```

If the caller only changes memory and leaves CPU/DiskGB zero, the replicated
spec now records zero for CPU/DiskGB. Later recreation or placement scoring
falls back to defaults rather than the sandbox's actual current values.

**Required fix:**

Patch only fields explicitly set by the request, or rebuild the replicated spec
from the post-resize persisted sandbox row.

## P1. Placement Ignores Product Constraints

Even after disk/GPU/runtime are fixed, real 100,000-sandbox placement needs
more dimensions:

- max sandboxes per worker;
- image cache locality;
- registry pull pressure;
- mount backend locality and credentials;
- data locality;
- region/zone/rack awareness;
- tenant quotas and noisy-neighbor isolation;
- network bandwidth and conntrack pressure;
- cgroup/pid/file-descriptor pressure;
- Docker daemon health;
- Caddy health;
- node version/capability compatibility;
- maintenance and drain state.

The current scheduler has no reason codes and no way to answer "why was this
node selected or rejected?" That makes large-scale operations hard to debug.

## P1. Self-Win Create Still Does Side Effects Before Cluster Reservation

When placement selects self, the code skips `opReserve` and does local create
before `RecordPlacement`. That saves one Raft round trip, but it preserves the
old failure mode for self-owned creates:

- local Docker/Caddy/store side effects can happen before cluster ownership is
  known;
- cluster-wide name conflict is detected after the expensive local create;
- rollback failure leaves local state without a placement;
- create behavior differs between self-selected and peer-selected targets.

For a small cluster this may be acceptable. For high concurrency, the invariant
should be simpler:

```text
all creates reserve in the control plane before side effects
```

