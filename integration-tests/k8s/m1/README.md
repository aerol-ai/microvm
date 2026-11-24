# The M1 drill on EKS

This drill proves, on real AWS machines, that worker pods can run in
privilege mode `split` (the agent has no root rights) and keep doing
everything they did in `single`. It is the live proof the plan asks for
before the chart's default changes (`plans/security-gaps-m1-m4.md` §3.6,
eng review D10).

**It spends real AWS money. The owner must say yes before each run.**

It has two parts:

- **Part A** (`m1-eks.sh`): one small EKS cluster in us-east-1. Two system
  machines (m7i.large), three worker machines (m7i.xlarge, Amazon Linux
  2023), cluster mode, two zones. The workers start in `single` and are
  switched to `split` one at a time.
- **Part B** (`vm-n1.sh`): one EC2 machine (m7i.xlarge, Ubuntu 24.04). It
  times WASM and V8 creates in `single` and in `split` on the same machine.
  The chart does not run WASM or V8 in a split worker pod yet, so EKS
  cannot answer this.

## What it proves

Every check writes one line, `PASS`, `FAIL`, `SKIP` or `INFO`, to
`integration-tests/k8s/.state/<name>/m1.txt`. Evidence goes to
`.state/<name>/evidence/`. The last column is what the second run (m1d-2,
2026-11-24) got.

| Check (result line) | What passes | m1d-2 |
|---|---|---|
| `kernel` | every worker machine runs Linux 6.12 or later | PASS (6.18) |
| `verify-single`, `verify-mixed1`, `verify-mixed2`, `verify-all-split`, `verify-final` | `aerolvm k8s verify` passes with all single, a mixed pool, all split, and at the end | PASS |
| `switch1`, `switch2`, `switch3` | each worker machine is switched: the old worker is decommissioned, a new one comes back in split | PASS (switch2 and switch3 needed the B1 workaround below) |
| `s1-recreate`, `s2-recreate`, `s3-recreate` | a runc sandbox with `failover: recreate` moves off the old worker and answers | s2 and s3 PASS; s1 failed on a test bug, which is fixed |
| `shape-*` (7 checks) | the split agent: uid 65531, no capabilities, not privileged, no containerd, reaches the helper, no two-way mount, runs the signed helper | PASS |
| `image-user-6.12` | three images run as the same user in split as in single | PASS |
| `n1` | create time, split against single: the median difference is inside the budget (+3 ms cold, +1 ms warm) | PASS (numbers below) |
| `moves-split-split` | a gVisor sandbox moves from one split worker to another and keeps its memory | PASS |
| `switch1-gvisor-move`, `single-single-gvisor-move` | the same, between two single workers | not proven: test bugs (a placement label that never matches; a test sandbox from the warm pool, which moves by recreate only). Both are fixed |
| `cross-mode-refusal` | a gVisor move from single to split is refused before anything is saved, and the sandbox keeps running | PASS |
| `s2`, `s2-helper-swap` | a version rollout swaps every agent in place, every sandbox keeps running, and the newer signed helper takes over | PASS |
| `ov-e2-reach`, `ov-e2-swap`, `ov-e2-helper-restart` | an rclone mount reaches the sandbox and keeps writing across the rollout and a helper restart | PASS |
| `helper-restart` | a killed helper is started again; its cgroup holds only the new helper and has `cgroup.kill` | PASS |
| `helper-otherkey`, `helper-older`, `helper-unsigned` | a helper signed by another key, an older one and an unsigned one are refused; the running helper stays | PASS. The run graded `helper-unsigned` FAIL because it read the wrong log; read by hand, it passed. The test is fixed |
| `f10` | memory pressure stops whole sandboxes only, never the worker's own processes | PASS, done by hand. The run's own fill was too small (64 MB); the test is fixed |
| `f8` | deleting a split worker pod with sandboxes running leaves nothing on the machine | PASS |

N1 in m1d-2 (time the worker reports for each create, 95% range from a
bootstrap):

- Cold: split p50 143.3 ms, single 152.0 ms. Median difference -0.15 ms
  (95% range -36.00 to +20.70). Budget +3 ms.
- Warm: split p50 18.0 ms, single 16.7 ms. Median difference +0.80 ms
  (95% range +0.40 to +1.60). Budget +1 ms. The median is inside the
  budget; the top of the range is above it.

Part B, first run (m1d-1-vm): WASM warm +0.05 ms, WASM busy mix +0.15 ms,
V8 warm -0.10 ms. Budget +1 ms. All three meet it.

## What it costs

| Part | Usual cost | Seen |
|---|---|---|
| A, the EKS cluster (about 3 h) | about $2 to $3.50 | $2.11 in m1d-2 (2.20 cluster hours at $0.959 an hour) |
| B, the VM (under 1.5 h) | well under $1 | about $0.07 in m1d-1-vm (0.35 h). That whole first day, with a cluster stopped early, cost $0.77 |

The cost guards:

- **A spend limit.** `up` prints the plan and the worst case (`cost.py`) and
  refuses when the worst case passes `M1_CEILING` ($8). After every step
  the run writes what it spent so far, and what the rest will cost, to
  `.state/<name>/cost.log`. When that passes `M1_COST_LIMIT` ($6.15), the
  run stops and tears itself down.
- **Teardown by name.** `down` removes the chart and its volumes, then runs
  `cluster.sh down <name>`, which works from the run's own Terraform state.
- **A timer in AWS.** `cluster.sh up --teardown` has AWS end the machines at
  the TTL (`M1_TTL_HOURS`, 5 h) and the cluster soon after, even if this
  computer is gone. The VM powers itself off after 170 minutes, and
  `vm-n1.sh` ends it on any exit.
- **A leak check.** `leak-check.sh` lists anything of the run still in AWS
  (cluster, machines, disks, network parts, load balancers, ECR, IAM, the
  timer). It only reads. `down` runs it at the end.
- **One account, one cluster.** Every step after `up` talks only to the
  kubeconfig `cluster.sh` wrote for this run, only if it names this EKS
  cluster, and only with this account's credentials. A refused step changes
  nothing and never tears anything down.

## How to run it

You need: AWS credentials for the test account, the artifact bucket
(`make itest-artifacts-init`), `aws`, `kubectl`, Helm 3.8 or newer (`HELM=`),
`terraform`, `jq`, `go`, `git` and `python3`. Run it from a checkout of the
commit under test. The images, the chart and `aerolvm k8s verify` are built
from that commit (`AEROL_BUILD_REF`, default `HEAD`), not from your working
tree. Use a new name for every run.

```bash
cd integration-tests/k8s/m1

# Free: the cost table, and every call printed without making anything.
./m1-eks.sh m1d-3 estimate
DRY_RUN=1 ./m1-eks.sh m1d-3 all
DRY_RUN=1 ./vm-n1.sh m1d-3-vm

# The run (after the owner says yes). Part B can run at the same time,
# in a second terminal.
HELM=<helm 3.8+> ./m1-eks.sh m1d-3 all      # tears down at the end
./vm-n1.sh m1d-3-vm                         # ends its VM at the end

# Part A alone: tell the cost check no VM runs.
M1_VM_HOURS=0 HELM=<helm 3.8+> ./m1-eks.sh m1d-3 all
```

Read the results:

```bash
cat ../.state/m1d-3/m1.txt               # one line per check
cat ../.state/m1d-3/cost.log             # spend after each step
cat ../.state/m1d-3-vm/vm-verdict.txt    # Part B
```

Each step can also run alone, for example `./m1-eks.sh m1d-3 s2 f8`. The
order and what each step does are at the top of `m1-eks.sh`.

## How to stop it and tear it down

- **Stop:** press Ctrl-C. A run started with `all` then tears itself down
  (`M1_KEEP=1` keeps it up). A run of single steps does not; run `down`.
- **Tear down by name:** `./m1-eks.sh m1d-3 down`. If that fails, run
  `../cluster.sh down m1d-3` again. After the TTL, `../reap.sh` finds what
  is left by its tags (`DRY_RUN=1 ../reap.sh` first).
- **The VM:** Ctrl-C on `vm-n1.sh` ends it. If that machine is gone too, the
  VM powers itself off, and `make integration-reap` ends it after 3 hours.
- **Leak check:** `./leak-check.sh m1d-3 m1d-3-vm`. It must end with
  "nothing of m1d-3 or m1d-3-vm is left". The source copies in the artifact
  bucket are kept on purpose and not counted.

Keep `integration-tests/k8s/.state/<name>/` until `down` has finished: it
holds the Terraform state `down` needs.

## Known problems

Two product bugs the second run found. Fixes are in progress.

- **B1: a switch can stall past its deadline.** When a worker holds a
  sandbox that counts as movable but can never move (a gVisor sandbox from
  the warm pool, or one in single when only split workers are left), its
  decommission does not end at the deadline. `switch3` hits this on
  purpose. Workaround: delete the stuck test sandbox from that step.
- **B2: a sandbox on a removed worker cannot be deleted.** After the
  workaround above, the operator may remove the node while the sandbox is
  still being deleted. Later deletes of that sandbox fail. It goes away
  with the cluster.

## Not in this drill

- Firecracker. The chart does not run it in a split pod yet.
- The bank preset (`values-bank-eks.yaml`) live. It renders in split with
  `helm template`; a live run needs the bank cell (`../eks-bank.sh`).
- A real S3 bucket for the mount. An in-cluster MinIO stands in.
- The release signing key. The drill signs with throwaway keys made and
  deleted inside the build pod.

## Files

| File | What |
|---|---|
| `m1-eks.sh` | Part A: every step, the dry run, the cost and account gates, results, teardown |
| `m1-lib.sh` | its helpers (the API through one port-forward, worker and helper reads, `aerolvm k8s verify`) |
| `values.yaml` | the chart values (cluster mode, 2 zones, gVisor moves on, containerd warm pool) |
| `build-job.yaml` | the in-cluster image build, with throwaway signing keys and the refused helper variants |
| `n1-bench.sh` | N1 inside the cluster: paired creates, timed from `Server-Timing` |
| `n1-stats.py` | the N1 verdict: p50, p90, p99, the median difference and its 95% range |
| `vm-n1.sh`, `vm-userdata.sh`, `vm-bench.py` | Part B on the VM |
| `leak-check.sh` | lists what is left in AWS; read only |
| `cost.py` | the cost table and the running cost check |

It reuses `../cluster.sh` (and its Terraform), `../lib.sh` (`source_tree`),
`../minio-store.sh`, `../cell/node-setup.yaml` and `../reap.sh`.
