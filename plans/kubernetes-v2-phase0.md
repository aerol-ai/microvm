# Phase 0 goal: prove the worker pod on EKS

**Status:** started 2026-11-11. Owner: the Kubernetes v2 effort.
**Source:** `plans/kubernetes-v2-architecture.md` §18, the Phase 0 row and N1.
**Spend:** live EKS runs approved by the owner on 2026-11-11.

## The goal

Run Phase 0's spikes (S1 to S9) and the side-by-side benchmark (N1) on real
EKS clusters, and write every result into `plans/kubernetes-v2-architecture.md`.

**Done** means each spike has a recorded result in the plan: pass or fail, its
numbers, and what it changes. That is enough to judge the first two conditions
of the N1–N8 gate (§18). If S1 or S2 fails, stop and rethink K2 and K3 before
anything else, as the plan's Phase 0 exit gate says.

## Rules for every run

1. **One spike at a time.** A run that fails is understood before the next
   one starts.
2. **Every AWS resource is tagged** `aerol:purpose=k8s-phase0`,
   `aerol:owner=itest` and `aerol:ttl=<RFC 3339 time>`. A run destroys what it
   made when it ends, pass or fail. An EKS reaper next to
   `scripts/integration-reap.sh` removes anything past its TTL: clusters, node
   groups, load balancers and the VPC.
3. **No large uploads from this laptop.** `sandboxd` goes through S3
   (`integration-tests/lib/build.sh publish`), content-addressed and checked by
   SHA-256. containerd, runc and gVisor come from their upstream release URLs,
   downloaded inside AWS and checked against their published checksums. No
   container image is built or pushed from this machine.
4. **`make test` stays offline.** Spike code lives in `integration-tests/k8s/`
   and runs only through its own `make` targets.
5. **Each run reports its cost** (machine hours times the price, plus the EKS
   control plane), and the result goes into the plan in the same PR as the
   spike's code.
6. **AKS waits.** The plan's AKS parts (S1's AKS images, S7 on AKS) need Azure
   access, which this effort does not have yet. They are recorded as "not run"
   until it does.

## The order

| Step | What | Why this order | Machines |
|---|---|---|---|
| H0 | The harness: Terraform for a throwaway EKS 1.36 cluster (its own VPC, two zones, public subnets so no NAT gateway), one small untainted system node and one tainted worker node; the EKS reaper; a worker pod that fetches its binaries and runs containerd, runsc and a single-node `sandboxd`. Smoke test: create one gVisor sandbox and run a command in it. | Every spike needs it | t3.medium + m7i.xlarge |
| S1 | Where a sandbox lands: its cgroup (inside the pod's or at the machine's top level), its network namespace and the bridge (inside the pod's network). Expected today: outside the pod's cgroup, because `sandboxd` sets no cgroup path (plan §8.3). If so, a prototype of C7's cgroup placement behind a setting, with tests, is part of S1. | The plan's first bet | m7i.xlarge, AL2023, then Bottlerocket |
| S2 | Split the pod into `runtime` and `agent` containers, change the `agent` image in place, and check that no sandbox restarts and that I/O on an external mount keeps going. | The plan's second bet; S1 and S2 decide K2 and K3 | m7i.xlarge |
| S9 | The same pod with `hostUsers: false` (Kubernetes user namespaces). | If it passes, it replaces S7's answer, so it runs first | m7i.xlarge |
| S7 | The same pod with a named list of rights instead of `privileged: true`. | Only needed where S9 fails | m7i.xlarge |
| S3 | Memory pressure: does the kubelet ever evict the worker pod? Kubelet and cAdvisor cost at 100, 500 and 1,000 sandboxes. | Needs a bigger machine | m7i.4xlarge |
| S8 | Per-sandbox disk limits with XFS project quotas on local NVMe. | Needs a machine with local NVMe | an NVMe ("d") type |
| S6 | `/dev/kvm` and Firecracker speed on a nested-virtualization machine. | Decides N7 | m8i.xlarge with nested virtualization |
| S5 | Karpenter with `do-not-disrupt`, a cordon-triggered decommission, and a managed node group upgrade inside its 15-minute limit. | Needs the operator's drain logic to be mocked first | small |
| S4 | The cell ceiling: Raft writes per second, apply latency, snapshot and restore at 100k, 250k and 1M placements. | Not Kubernetes-specific; runs on the existing EC2 harness | existing harness |
| N1 | agent-sandbox with gVisor next to AerolVM's worker pod, on one cluster and machine type: cold and warm starts, a burst larger than the pool, several templates, one command's round trip, sandboxes per machine, etcd writes. | Needs H0 to S2 working | m7i.xlarge × 2 |

## Progress

| Step | State | Where the result is |
|---|---|---|
| H0 | **Done, 2026-11-10.** Pass after eight runs on one cluster; six findings for Phase 1 (F1 to F6) | v2 plan §18, "Phase 0 results" |
| S1 | **Done, 2026-11-10. Pass** on AL2023 and Bottlerocket with the C7 prototype (`SB_CONTAINERD_CGROUP_PARENT`), loading `br_netfilter` (F2) and, on Bottlerocket, raising `user.max_user_namespaces` (F7) | Same |
| S2 | **Done, 2026-11-10. Pass:** only the agent restarted; the sandbox kept running with the same processes. Finding F8 (namespace mounts leak onto the machine). The external-mount part (OV-E2) is still to do | v2 plan §18, "Phase 0 results" |
| S9 | **Done, 2026-11-10. Fails on per-sandbox limits:** a user-namespaced pod cannot make cgroups (read-only, not delegated). Networking and gVisor work. Images keep S7's answer | v2 plan §18, "Phase 0 results" |
| S7 | **Done for the one-container worker on AL2023, 2026-11-10. Pass** with 14 named rights, seccomp and AppArmor unconfined, and two stand-ins (cgroup and `/proc/sys` remounted read-write). The split pod needs F8's fix first (Bidirectional propagation needs privileged). Bottlerocket not run | v2 plan §18, "Phase 0 results" |
| S3 | **Done, 2026-11-11.** 1,000 gVisor sandboxes in one pod; findings F9 (57 cAdvisor series per sandbox) and F10 (one pod-level OOM kills the whole worker, machinery included). No eviction: the pod's own limit is the danger. **F10 fixed in the seventh run:** a cap on `sandboxes/`, containerd and its shims inside it, `memory.min` on `sandboxd`'s group; the pod's limit was never hit, only whole sandboxes died, `sandboxd` answered and created. New finding F12: `sandboxd` did not notice the killed sandboxes | v2 plan §18, "Phase 0 results" |
| S4 | **Offline half done, 2026-11-11.** FSM apply about 8 µs at 100k to 1M placements; commits about 2,000 a second with 64 in flight (6.5 ms modelled sync); at 1M a snapshot holds up Apply for 1.1 s and the FSM needs 2.4 GiB (finding F11, for Phase 3). Live half (three EC2 server nodes) still to run | v2 plan §18, "Phase 0 results" |
| S8 | **Done, 2026-11-11. Pass** on AL2023 (m6id.xlarge NVMe as XFS with project quotas): a gVisor sandbox with a 100 MB quota stopped at 99.0 MB, the other wrote 300 MB; gVisor keeps its root overlay in a disk file in the writable layer. Bottlerocket not run | v2 plan §18, "Phase 0 results" |
| S6 | **Done, 2026-11-11. Pass:** m8i.xlarge with nested virtualization has `/dev/kvm`; Firecracker v1.18.0 cold-booted a guest 5 of 5 times in 817 to 862 ms. Not compared with metal; warm pool and snapshot restore not measured under nested virtualization (needed for N7) | v2 plan §18, "Phase 0 results" |
| N1 | **First run done, 2026-11-11.** Same machine type, same gVisor sandbox: cold p50 1.16 s (agent-sandbox) against 239 ms (AerolVM); warm 290 ms against 19 ms; a burst of 20 on a pool of 5 in about 5 s against 1.2 s; 231 Kubernetes API writes for 10 sandboxes against 0. Agent-sandbox times include about 0.2 s of `kubectl`. Still to measure: p99, several templates, a command's round trip, machine-full density | v2 plan §18, "Phase 0 results" |
| S5 | **Done, 2026-11-11. Pass:** Karpenter 1.15.1 left a drifted machine alone for 3 minutes while the worker had `do-not-disrupt`, then replaced it within 2 minutes of the operator stand-in letting go; a managed node group AMI upgrade cordoned first, the stand-in let the worker go 37 s later, and the upgrade succeeded in 450 s. On Karpenter pools the signal is NodeClaim `Drifted`, not a cordon | v2 plan §18, "Phase 0 results" |

## Cost, before it is spent

Prices are us-east-1 on-demand. A normal run is 1 to 2 hours:

| Item | Per hour |
|---|---|
| EKS control plane | $0.10 |
| t3.medium (system node) | about $0.04 |
| m7i.xlarge (worker) | about $0.20 |
| m7i.4xlarge (S3 only) | about $0.81 |

So most runs cost $1 to $3, and S3 about $5. Phase 0 should stay under $150
if every run is torn down. Each run's real cost is written next to its result.

## What is not in this goal

- The question to the bank (Q6). The owner sends it, with the evidence pack
  draft.
- Phase 1 code. It starts only after S1 and S2 pass, except the C7 prototype
  that S1 may need.
- N2 to N8. They wait for the gate in §18.
