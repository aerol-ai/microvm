# Integration Test Harness

Stands up **real** AerolVM deployments from the released install artifacts and
drives the live `/v1` API + Go SDK against them, producing a use-case coverage
matrix. Full design + decisions: [`../plans/integration-tests.md`](../plans/integration-tests.md).

> ⚠️ **These tests provision real AWS EC2 and cost money.** They use the
> production Terraform module but against **isolated state** (`integration/<scenario>`
> key + separate `TF_DATA_DIR`) so production state is never touched. Spot
> instances + auto-teardown + `make integration-reap` keep cost down.

## Status

Live scenarios cover single-node (docker / containerd / fc / wasm / isolate),
3× mixed clusters (docker, containerd, gvisor, wasm, fc), hetero, local-mode,
and arm64. Reports and the coverage matrix live in `reports/`. Isolate is
exercised by `make integration-single-isolate` (UC-103/104/105) and
`make integration-benchmark-isolate` (UC-94).

## Prerequisites

- `terraform`, `go`, `awscli`, `jq`, `yq`, `curl`, `openssl`, `ssh`
- `zig` (`brew install zig`) — the cross-compiling C toolchain the local
  artifact build needs; `sandboxd` links CGO sqlite, so a pure-Go cross-compile
  is not an option. `xcaddy` only for `--with-caddy`.
- AWS credentials with permission to create EC2/VPC/etc.
- `config/secrets.yml` populated (PAT, Cloudflare token) — see `config/secrets.example.yml`
- `integration-tests/scenarios/domains.yml` — copy from `domains.example.yml`, fill in
  **real test FQDNs you control** (distinct from your prod domain)

## Run

```bash
make integration-single                 # single-node scenario
make integration-single-isolate         # single-node + V8-isolate (workerd); UC-103/104/105
make integration-local                  # local-mode (--local install on a throwaway box)
integration-tests/run.sh single-node --keep        # leave infra up for debugging
integration-tests/run.sh single-node --prod-tls    # use real Let's Encrypt instead of staging
make integration-cluster-hetero           # 8-node heterogeneous cluster (x86 fc)
make integration-cluster-mixed-fc         # 3× mixed cluster, FC on seed c5.metal
make integration-cluster-mixed-gvisor       # 3× mixed cluster, gVisor on every node
make integration-cluster-mixed-wasm         # 3× mixed cluster, WASM workers
make integration-single-fc                # single-node-fc (x86 firecracker, c5.metal)
make integration-arm64                    # arm64 firecracker single + cluster scenarios
make integration-arm64-single             # single-node-fc-arm64 (Graviton metal)
make integration-arm64-cluster            # cluster-arm64 (homogeneous arm64)
make integration-reap                   # terminate any leaked itest instances past ttl
```

Reports land in `integration-tests/reports/` (`<scenario>.md`, `<scenario>.json`,
`index.md` matrix). Legend: ✅ pass · ❌ fail · ⚪ skip(n/a) · 🟡 pending · 🟤 inconclusive.

## Agent eval

`agenteval/` checks that Claude can use the `aerolvm mcp` tools, against a
local sandboxd and the Anthropic API rather than AWS. Run it before changing
tool names, descriptions or notices; see [`agenteval/README.md`](agenteval/README.md).

## Where the binaries come from

**Scenarios build the daemon locally by default.** Every run cross-compiles the
current working tree, uploads it to a per-account artifacts bucket, and hands
the nodes presigned URLs. This is what lets the harness test an **unmerged
branch** — before this, a scenario could only provision from `releases/latest`,
so a branch was testable only after it merged and released.

One-time per operator/account:

```bash
make itest-artifacts-init     # creates s3://aerol-itest-artifacts-<account>
```

Then the default path needs nothing extra:

```bash
make integration-single                      # builds HEAD, publishes, provisions from it
make integration-single released             # old behaviour: releases/latest
make integration-single no-build             # reuse the last published build (fast re-provision)
make integration-single FLAGS=--version=v0.7.21   # pin a released tag (A/B vs known-good)
```

The build id is **content-addressed** —
`AEROL_BUILD_ID = <short-sha>[-dirty-<tree-hash>]` — so an unchanged tree skips
both the compile and the upload. That is what makes iterating against a
`--keep` cluster free. A tree with uncommitted or untracked changes gets a
`-dirty-` id, and the report says so: those numbers are not reproducible from
git.

Working on the build itself:

```bash
make itest-build                             # build only
make itest-build BUILD_FLAGS="--ref main"    # build another commit (detached worktree)
make itest-publish                           # upload + print presigned tfvars on stdout
```

Artifacts expire from the bucket after 7 days; presigned URLs default to 12h,
which covers a slow `*.metal` provision. `reports/<scenario>.json` carries a
`build` block naming the tree that produced its numbers.

### When GitHub's downloads fail

GitHub's release downloads once answered 504 for hours while its status page
stayed green, and every run failed. The harness and `install.sh` now fall back
to the public download mirror (`s3://aerolvm-downloads`, filled by
`scripts/mirror-sync.sh`), which holds each release at `aerolvm/<tag>/<file>`
and each pinned third-party file at `deps/<project>/<version>/<file>`.

| Variable | Default | What it does |
|---|---|---|
| `AEROL_RELEASE_BASE` | `https://github.com/aerol-ai/microvm/releases` | The releases URL `--version` pins and the released Caddy are taken from. |
| `AEROL_DOWNLOAD_MIRROR` | `https://aerolvm-downloads.s3.us-east-1.amazonaws.com` | The mirror. `""` or `off` turns it off. |
| `AEROL_RELEASE_API` | GitHub's releases API for `aerol-ai/microvm` | Where `build.sh` asks which release carries the custom Caddy. For tests. |

- **`--version <tag>`** probes the release's `checksums.txt` on GitHub, then on
  the mirror, and pins every file to whichever answered.
- **The released Caddy** (local builds without `--with-caddy`) is probed the
  same way. When GitHub's API does not answer either, the mirror's
  `aerolvm/latest.txt` names the release.
- **The nodes' own downloads** go through `install.sh`'s fallback, which uses
  the public mirror by default. To change that, set `AEROL_DOWNLOAD_MIRROR`
  when you run the harness: in local-build mode `build.sh` then hands the nodes
  a copy of the build's `install.sh` with that value as its default
  (`install.mirror-<hash>.sh` beside it). The bootstrap runs `install.sh` under
  `sudo`, so no variable would reach it, and the bootstrap template is not
  touched. Unset, the nodes get the build's `install.sh` unchanged. A
  `--version` or `--released` run uses that release's own `install.sh`.
- **Not covered:** the Terraform bootstrap's own CNI and BuildKit steps
  (containerd nodes, the default) and its Firecracker download still fetch
  from GitHub. Those live in `bootstrap.sh.tftpl`, and changing it replaces
  every node of a running cluster.

## Container engine

**containerd is the default engine for every scenario.** `run.sh` writes
`SB_CONTAINER_ENGINE=containerd` into the config overlay unless a scenario
advertises the `docker-engine` capability, in which case it uses dockerd. Only
two scenarios opt out:

- `local-mode` — the local dev install always uses docker.
- `cluster-3-mixed-docker` — the docker A/B benchmark baseline, kept on docker so
  its `cluster-3-mixed-docker-*` artifacts stay a valid comparison against the
  containerd engine measured by `cluster-3-mixed-containerd`.

This encodes the target end-state of the docker→containerd migration: *the local
installation uses docker; every real deployment (single-node, mixed cluster,
hetero cluster) uses containerd.* The `containerd-engine` capability no longer
selects the engine — it opts a scenario into the containerd-specific soak UCs
(UC-99..102) and the distinctly-labeled `containerd` benchmark row.

Because containerd's CNI container networking is still ship-dark
(`SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED`, `plans/containerd-engine.md` §8), the
containerd path has been live-validated on t3 topologies (`cluster-3-mixed-containerd`);
the metal (`*-fc`) and arm64 scenarios request containerd on hardware where the
containerd bootstrap has not yet been live-proven — validate those on a `--keep`
run before relying on them.

## Release gate: snapshot-namespace migration

The per-owner snapshot namespace (`sandbox_snapshots` PK → `(owner_ref, name)`)
ships a destructive one-time migration that only runs on a pre-existing old-schema
DB, so a fresh-provisioned run never exercises it. Before the first release that
carries it, run the warm-upgrade gate and the failover exercise `UC-58d`
(`TestSnapshotBackedFailover`, part of `make integration-cluster-hetero`).

The warm-upgrade gate is automated — it provisions the old release, seeds
snapshots, upgrades every node in place to the local build, and verifies the
migration lost no rows:

```bash
integration-tests/run.sh single-node --upgrade-from v0.6.7     # minimum gate
integration-tests/run.sh cluster-hetero --upgrade-from v0.6.7  # full gate
```

[`SNAPSHOT-MIGRATION-UPGRADE.md`](./SNAPSHOT-MIGRATION-UPGRADE.md) is the manual
runbook the automation mirrors (use it to debug a failed gate).

## Key custody scenarios

Customer key custody (`plans/customer-key-custody.md` Phase 6) has five
scenarios. Each costs what any scenario of its size costs; none adds an AWS
service except the KMS key of the last three.

| Scenario | Make target | Key store |
|---|---|---|
| `cluster-3-mixed-secrets-vault` | `make integration-key-custody-vault` | OpenBao 2.1.1 dev server (TLS) on the seed, OpenBao Proxy on every node |
| `cluster-3-mixed-secrets-pkcs11` | `make integration-key-custody-pkcs11` | SoftHSM2 on every node, the same keys imported into each token |
| `cluster-3-mixed-wrapped-kms` | `make integration-key-custody-kms` | A real AWS KMS key, with Terraform `key_custody = "wrapped"`; UC-311 disables and re-enables it |
| `cluster-3-mixed-kms-switch` | `make integration-key-custody-kms-switch` | A real AWS KMS key with custody `file`; UC-312 runs the two-step switch from local to it |
| `single-node-wrapped-kms` | `make integration-key-custody-single` | A real AWS KMS key, one node with `install.sh --key-custody wrapped`; UC-316 replaces its root disk and restores a backup onto the fresh install |

The vault and pkcs11 scenarios boot a plain local cluster. The cases
(`suite/z_keycustody_*_test.go`, helpers in
`suite/keycustody_support_test.go`) install the key store over SSH, switch
to it the two-step way and wrap the server key, which is the migration a
customer runs. Each step leaves a marker in `/var/lib/itest-keycustody` on
the node, so a case run alone (`-run`) brings the cluster to the state it
needs first. Settings go into `/etc/sandboxd/itest-keycustody.env` under a
drop-in that sorts before the suite's transient override, so a boot-gate
case can still override them for one restart.

Fixture notes:

- The OpenBao dev store is in memory: it lives as long as the
  `itest-openbao` unit on the seed. The Transit key is exportable with
  plaintext backup allowed, only so UC-300 can restore it after deleting it.
- `softhsm2-util --import` skips whitespace bytes in a key file, so the
  fixture's AES keys are 32 alphanumeric bytes.
- UC-313's private registry (`registry:2.8.3` in Docker on the seed, TLS from
  a per-cluster CA, htpasswd auth) and SSHFS share (user `itestshare`, key
  login, `restrict`) live on the seed; the vault scenario opens ports 5000
  and 22 between nodes for them. Every node trusts the registry's CA and
  restarts once, because sandboxd reads the system roots once per process.
- UC-311 disables the scenario's own KMS key with the AWS CLI from the
  machine running the suite, and re-enables it in cleanup; teardown
  schedules the key for deletion either way.
- SoftHSM2 keeps keys on the node's disk: the pkcs11 scenario proves the
  code path, not a network HSM. The one AWS CloudHSM run is operator-gated
  and not a scenario here (CloudHSM bills hourly per HSM).

## Ingress load balancer (UC-356)

`cluster-3-mixed-lb` (`make integration-cluster-mixed-lb`) is cluster-3-mixed
with a health-checked AWS Network Load Balancer in front of the ingress
nodes. Its `api-load-balancer` capability is the switch: run.sh applies and
destroys with `api_load_balancer = "nlb"` for it and `"none"` for every other
scenario, whatever `config/terraform.tfvars` says. The domain then resolves to
the balancer's Elastic IP, and raw TCP ports to `tcp.<domain>` (one record
per node), so the whole suite also runs through the balancer.

UC-356 (`suite/api_lb_test.go`) checks the domain resolves to the balancer
only, stops sandboxd on one non-seed node, and reads the balancer's own view
(`aws elbv2 describe-target-health` on the 443 target group): the node must
leave rotation within `AEROL_LB_OUT_OF_ROTATION_MAX` (default 20s), 60
fresh-connection calls through the domain must then all succeed, and after
the daemon restarts the node must be healthy again within
`AEROL_LB_BACK_IN_ROTATION_MAX` (default 90s). Each call opens its own TCP
and TLS connection on a transport of its own, so neither keep-alive nor the
suite's shared client can hide a 502. The numbers land in
`<reports>/cluster-3-mixed-lb-bank.json` under
`api_load_balancer_daemon_outage`.

The scenario needs the default local build, or a release that has
`install.sh --lb-health-port` and `SB_L4_PUBLIC_HOST`. The reaper
(`scripts/integration-reap.sh`) terminates instances only, so a scenario
whose teardown failed keeps its balancer and Elastic IP until
`integration-tests/run.sh cluster-3-mixed-lb --destroy-only`.

## Routing gate from inside the VPC (UC-171 / UC-357) and the A/B

The gate for turning `SB_INGRESS_PROXY_ROUTING` on by default
(`plans/cluster-phase-2.md` §4.2) runs on `cluster-hetero-lite-routing`
(8 × t3.medium) with the test binary on one of its server nodes, not on a
laptop. A laptop adds its Wi-Fi and ISP to every latency number, and an SSH
or DNS blip there fails a case that has nothing to do with the code. A
server node is a Raft voter that serves no sandbox and is not behind the
domain, so the load generator neither competes with what it measures nor
skips the public path: it reaches the domain through the Internet gateway,
like a customer's servers in the region.

UC-171 also records latency: expose to first 200 on the public URL, and
p50/p99 of the successful fresh-connection HTTP and raw-TCP probes during
churn. The numbers are in the test log, in the report row's Detail column,
and in `<scenario>-bank.json` under `ingress_routing_churn_gate`. Its pass
rule is still 0 failed connections.

**Run tests from a node.** `scripts/run-on-node.sh` builds
`go test -c -tags integration ./integration-tests/suite/` for the node's
architecture, copies it with the harness's SSH key, hands it the same
`AEROL_*` environment `run.sh` gives the suite (other exported `AEROL_*`
knobs pass through), starts it detached so an SSH drop here does not kill
it, and copies back `test.json`, `test.log`, the bank JSON and a report to
`reports/run-on-node/<scenario>/<stamp>[-<label>]/`. The default node is a
server-only node (a non-seed one first); `--node <name>` picks another.
The node has no SSH key, AWS credentials or checkout, so cases that need
those, and every disruptive case (`AEROL_ALLOW_DISRUPTIVE=0`), belong on
the laptop. `--dry-run` prints the node and test flags and touches nothing.

**Flip the flag on every node.** `scripts/routing-ab.sh <scenario> off`
sets `SB_INGRESS_PROXY_ROUTING=false` in a drop-in
(`/etc/systemd/system/sandboxd.service.d/zz-ab-routing.conf`) and restarts
sandboxd one node at a time, seed first. Each routing node rolls back to
per-sandbox Caddy routes in one Caddy load, through its
`ingress_proxy_routing_last_enabled` marker. `on` removes the drop-in and
restarts the same way. After each restart it waits for `/health` and for
the node's own member list to be whole, then checks the flip took (marker
and Caddy's static `sandbox-ingress-proxy` route), so a node that refused
to engage fails there and not as an odd A/B number. A node already flipped
is skipped, so re-running a command that stopped half way finishes it.
`status` prints each node's state.

The gate, then the A/B (flag on, flag off, and the pair once more, because
t3 CPU credits add noise):

```bash
S=cluster-hetero-lite-routing
GATE='^(TestIngressRoutingChurnGate|TestIngressChurnNewConnectionsAndExecStreams)$'
# Bring the stack up and keep it (this also runs UC-171 once from the laptop).
AEROL_TEST_RUN='^TestIngressRoutingChurnGate$' integration-tests/run.sh $S --keep

# Churn gate: 0 failed connections in each case.
integration-tests/scripts/run-on-node.sh $S --label gate -run "$GATE"

# A/B: flag-on p50/p99 must be no worse than flag-off beyond the spread of
# the repeated pair. The off runs are expected to fail UC-171 (connections
# drop on Caddy reloads); their numbers are still written.
for pass in 1 2; do
  integration-tests/scripts/run-on-node.sh $S --label on-$pass -run '^TestIngressRoutingChurnGate$'
  integration-tests/scripts/routing-ab.sh $S off
  integration-tests/scripts/run-on-node.sh $S --label off-$pass -run '^TestIngressRoutingChurnGate$'
  integration-tests/scripts/routing-ab.sh $S on
done
grep -h ucdetail= integration-tests/reports/run-on-node/$S/*/test.log

integration-tests/run.sh $S --destroy-only
```

Both scripts read the stack from this worktree's `.tf/<scenario>`; export
`AEROL_INTEGRATION_TARGETS` (the Terraform `integration_targets` JSON) to
point them at a stack kept from another worktree.

## Overload is shed, not restarted (UC-361)

UC-361 (`suite/overload_shed_test.go`) runs on any scenario with `cluster`,
`domain` and `disruptive: true`. It drives `AEROL_OVERLOAD_CONCURRENCY`
clients (default 1024, the step that broke the bank flagship) at
`GET /v1/sandboxes` through the domain for `AEROL_OVERLOAD_SECONDS` (default
60) with a client that never retries. Every answer must be 200 or a refusal
with `Retry-After` (503 or 429); a 502, any other 5xx, a refused or reset
connection, or a request hung past 30 s fails it. Over SSH it then checks
that no sandboxd restarted on any node: the unit's `InvocationID` and
`NRestarts` are unchanged (a watchdog restart does not raise `NRestarts`),
and neither `journalctl -u sandboxd` nor `journalctl -t sandboxd-healthcheck`
shows a start or a restart since the load began. Last, the list must be back
to its baseline latency (the median of 5 in a row within 2x the idle p50, or
the p50 plus 250 ms) within 60 s of the load stopping. The numbers, and each
node's `aerolvm_api_list_shed_total`, land in `<reports>/<scenario>-bank.json`
under `overload_shed_v1_sandboxes`; a run that shed nothing says so in the
test log, since it never reached the shedding point.

## One tenant's list storm does not degrade another (UC-362)

UC-362 (`suite/list_fairness_test.go`) runs on a scenario with `cluster`,
`domain`, `identity`, `docker`, `api-list-fairness` and `disruptive: true`:
today `cluster-3-mixed-lb`, whose tfvars run the list gate at 8 slots with 2
per tenant (`SB_API_LIST_MAX_INFLIGHT`, `SB_API_LIST_MAX_INFLIGHT_PER_TENANT`).
That is on purpose: a healthy list holds its slot for milliseconds, so with
the default 16 slots and 4 per tenant the suite's client may never fill a
tenant's share, and the case is about what happens when it is full.

It mints runner tokens for two teams (`payments`, noisy; `checkout`, quiet),
gives each `AEROL_FAIRNESS_SANDBOXES` sandboxes (default 3) so every list
fans out to owner nodes, then lists as both at once for
`AEROL_FAIRNESS_SECONDS` (default 60): `AEROL_FAIRNESS_NOISY` clients
(default 1024) and `AEROL_FAIRNESS_QUIET` (default 4), each pinned to one
ingress node round-robin on its own tenant's connection, so every node serves
both. It first reads each node's gate size from `/v1/metrics` and refuses to
run when the quiet tenant's clients would not fit inside its own share on a
node. It passes when the quiet team's lists succeed at least 99% of the time
with a p99 within `AEROL_FAIRNESS_QUIET_P99_MS` (default 2000), the noisy
team got at least one `429` with code `rate_limited` and `Retry-After` and no
`502`, other 5xx, refusal without `Retry-After`, transport error or request
over 30 s, and no sandboxd restarted (UC-361's checks). The numbers land in
`<reports>/<scenario>-bank.json` under `list_fairness_v1_sandboxes`, with
each node's `429`/`503` counts. A run whose noisy team never got a `429`
fails and says to raise `AEROL_FAIRNESS_NOISY`.

## Cluster correctness under faults (UC-470..UC-482)

`cluster-chaos` (`make integration-cluster-chaos`) is the live layer of
`plans/cluster-correctness-and-create-latency.md` §3.2. Each case injects one
fault and asserts the plan's §1 invariants (I1 one executor, I3 no
resurrection, I4 capacity, I6 convergence, I7 routing safety, I8 a failed
create leaves nothing), not just "no error". Several fail on `main` until the
plan's fixes C2..C7 land; each test's doc comment in
`suite/z_cluster_chaos_test.go` names the fix it guards.

| UC | Fault | Invariants | Guards |
|----|-------|------------|--------|
| UC-470 | Owner worker + ingress cut off from the servers for 120 s | I1, I7, I6 | C4 |
| UC-471 | Worker cut off, its sandbox reassigned and deleted, worker heals and restarts | I3, I6 | C2 |
| UC-472 | Owner killed (sandboxd, containers, engine); DELETE right after the reassign | I3 | C3 |
| UC-473 | Raft leader killed during 200 concurrent creates | I8, I6, I4 | C5, C1 |
| UC-474 | Leader and a second voter stopped while creates are between reserve and promote | I8 | C5 |
| UC-475 | Concurrent create, destroy, stop, start on the same names | I3 | C2, C3 |
| UC-476 | 5% loss and 200 ms delay between every pair of nodes, under creates | I1, I4, I8 | C4, C6, C7 |
| UC-477 | Every server restarted in turn, leader last | I6 | C1 |
| UC-478 | Loaded worker killed when the survivors have less room | I4, I6 | C7 |
| UC-479 | Owner killed for real; the old node returns | I1, I6 | C4, C2 |
| UC-480 | Worker's sandboxd SIGKILLed while a failpoint parks a create between the runtime start and the store write | I8, I6 | release gate |
| UC-481 | sandboxd SIGKILLed on every server at once (or the leader); control-plane recovery time measured | I6, I8, I4 | release gate |
| UC-482 | Soak: closed-loop create, probe, delete for 15 min, every node sampled | I6 | release gate |
| UC-484 | Owner worker cut off from the servers only; its paused sandbox's toolbox URL, HTTP port and raw TCP port probed on the worker | I7 | C4 (#1050) |

UC-480..482 are the release-gate tools of `plans/cluster-phase-2.md` §5,
run as short smoke runs in this scenario:

- **UC-480 needs a failpoint build.** run.sh compiles this scenario's local
  sandboxd with `-tags itest_failpoints` (the caps file's `go_tags`, passed
  to `lib/build.sh` as `AEROL_GO_TAGS`; the build id ends
  `-tags-itest_failpoints`). The case arms
  `/run/sandboxd/failpoints/create-before-persist` on every worker for one
  sandbox name, waits for the `.hit` marker, and SIGKILLs sandboxd on that
  node. On `--released` / `--version`, whose binaries have no failpoints, it
  skips. Every other scenario builds without tags, and
  `safety/go_tags_test.go` keeps any `go_tags` entry `itest_*`.
- **UC-481** probes once a second through the API domain: the leader, a
  placement read for a sandbox made before the kill, and a create. Each
  signal recovers at its first success after its last failure; the recovery
  time is the latest of the three, logged as `rto ... recovery_seconds=` and
  written into the I6 detail of `reports/cluster-chaos.json`.
- **UC-482** writes one JSON line per sample to `AEROL_SOAK_OUT`. The pass
  rule is `harness.SoakVerdict`: counts back at baseline after the drain
  plus one reconcile interval; for goroutines (`aerolvm_go_goroutines`),
  RSS, fds, WAL and Raft size, the last third's median within the larger of
  20% and a floor of the first third's; no sandboxd restart. The 72-hour run
  is the same case with a longer `AEROL_SOAK_MINUTES` and
  `AEROL_SUITE_TIMEOUT`.

- **Topology.** 3 servers, 3 workers, 1 ingress, all t3.medium on-demand
  (`scenarios/cluster-chaos.tfvars` says why each). About $0.29/h; bring-up
  ~20 min, the ten fault cases ~80 min plus ~35 min for UC-480..482 (the
  soak is 15 of it), teardown ~5 min, so ~$0.60-0.80 a run.
  The scenario sets `SB_RECONCILE_INTERVAL=60s`; the cases read it off a node
  and wait two intervals plus a minute before calling a state converged.
- **Focused.** The caps file's `focus` block makes run.sh pass
  `-run '^TestClusterChaos'` and tells the report generator to mark every
  other use case skip (not in this focused scenario) instead of missing, so
  the gate is red only for a chaos case that failed or never reported.
  `safety/focus_filter_test.go` keeps the regex matching exactly the tests
  that claim a `cluster-chaos` use case.
- **Invariant verdicts in the report.** Each case calls
  `harness.TrackInvariants` and logs one `invariant=I<n> <held|violated|not-exercised>`
  line per invariant; `report/gen.go` puts them on the row
  (`reports/cluster-chaos.json` `invariants`, and the Detail column), pass
  rows included, so a green row also says what it held over.
- **How faults are injected.** Partitions are iptables DROP rules both ways
  on the cut-off nodes, as UC-291, with a dead-man heal armed by
  `systemd-run` first. Packet loss and delay are a netem qdisc on a filtered
  prio band, so only traffic to the other nodes is impaired; SSH and the
  internet are not. A "real" owner kill stops sandboxd, SIGKILLs every
  sandbox container and stops the engine; the restore starts them and waits
  for the rejoin. "Two copies" is read from every worker's engine over SSH
  (`harness.RuntimeCensusScript`), and a census that failed is never read
  as "no copy".

| Env var | Default | Purpose |
|---------|---------|---------|
| `AEROL_CHAOS_PARTITION_SECONDS` | `120` | UC-470's partition |
| `AEROL_CHAOS_CREATES` / `AEROL_CHAOS_KILL_AFTER_MS` | `200` / `1500` | UC-473's burst and when the leader dies |
| `AEROL_CHAOS_SANDBOX_CPU` / `AEROL_CHAOS_SANDBOX_MEMORY_MB` | `0.25` / `128` | size of the bulk cases' sandboxes |
| `AEROL_CHAOS_PROMOTE_CREATES` / `_WINDOW_SECONDS` / `_STOP_AFTER_MS` / `_IMAGE` | `12` / `30` / `2500` / `python:3.12-slim` | UC-474 |
| `AEROL_CHAOS_LIFECYCLE_NAMES` / `_ROUNDS` | `6` / `8` | UC-475 |
| `AEROL_CHAOS_NETEM_DELAY` / `_LOSS` / `_SECONDS` / `_CREATES` | `200ms` / `5%` / `180` / `30` | UC-476 |
| `AEROL_CHAOS_RESTART_SANDBOXES` | `6` | UC-477 |
| `AEROL_CHAOS_MASS_SANDBOXES` / `_CPU` / `_MEMORY_MB` / `_SURVIVOR_FREE_CPU` | `12` / `1.0` / `256` / `4` | UC-478 |
| `AEROL_CHAOS_FAILOVER_BOUND_SECONDS` | `300` | how long a reassign, and a reassigned sandbox's start, may take |
| `AEROL_CHAOS_CONVERGE_SECONDS` | 2 x reconcile + 60 | override the convergence bound T |
| `AEROL_CHAOS_RTO_MODE` | `all` | UC-481: `all` SIGKILLs every server at once, `leader` only the Raft leader |
| `AEROL_CHAOS_RTO_BUDGET_SECONDS` | `55` | UC-481's recovery-time budget: about 1.5 times the first measured run (34.5 s, 2026-11-08) |
| `AEROL_CHAOS_RTO_SANDBOXES` / `_MAX_CREATES` | `3` / `120` | UC-481: sandboxes whose placements must survive, and a cap on the prober's creates |
| `AEROL_SOAK_MINUTES` | `15` | UC-482's load duration |
| `AEROL_SOAK_WORKERS` | `4` | UC-482's closed-loop workers |
| `AEROL_SOAK_SAMPLE_SECONDS` | `60` | UC-482's sampling interval |
| `AEROL_SOAK_OUT` | `<reports>/<scenario>-soak.jsonl` | UC-482's samples, one JSON line each |
| `AEROL_GO_TAGS` | caps `go_tags` | test-only Go build tags for the local sandboxd build (overrides the caps file) |

## Enterprise scenarios and the audit witness

Enterprise mode (`SB_ENTERPRISE_MODE=true`) refuses to boot without an
external witness for the audit chain. Every scenario that advertises the
`audit-witness` capability — `single-node-secrets-enterprise`,
`cluster-3-mixed-secrets-enterprise` and the five `cluster-hetero-*` security
scenarios — gets one the way an operator would: Terraform creates an S3 Object
Lock bucket (`audit_witness_enabled = true`) and the **stock** daemon writes
its chain heads there. No scenario uses a test build of `sandboxd`.

- **Lock:** `GOVERNANCE` for 1 day, with `SB_SECRET_AUDIT_RETENTION_DAYS=1`,
  because the daemon refuses a lock shorter than retention. A `COMPLIANCE` or
  longer lock would leave a bucket nobody can delete until it expires.
  `make test` (`safety/`) refuses a scenario that drifts from this.
- **Suite:** `run.sh` exports `AEROL_AUDIT_WITNESS_BUCKET` and
  `AEROL_AUDIT_WITNESS_PREFIX` (from the scenario's `terraform output`) and
  `AEROL_AUDIT_WITNESS_REGION`, and sets `AWS_PROFILE` to `aws_profile` from
  `config/terraform.tfvars` when that is set. UC-143 reads heads, UC-144
  plants a disagreeing head and buries it again, and UC-263 checks each
  node's boot canary, all directly in the bucket with your credentials.
  UC-264 and UC-265 edit, then delete, the same victim's local audit log,
  require a refused boot, and put the log back.
- **Teardown:** the bucket has no `force_destroy`. Before `terraform destroy`,
  teardown (and `--destroy-only`) deletes every version and delete marker with
  `--bypass-governance-retention`, and empties it again if the destroy fails,
  since the nodes keep shipping heads until they are terminated. Your AWS
  identity needs `s3:ListBucketVersions`, `s3:DeleteObjectVersion` and
  `s3:BypassGovernanceRetention`. If emptying fails, teardown says so and
  destroys everything else; fix the credentials and run
  `integration-tests/run.sh <scenario> --destroy-only`. `make integration-reap`
  terminates instances only and never empties a bucket.
- **Single server:** `make integration-secrets-enterprise-single` runs
  `single-node-secrets-enterprise`, which is also the scenario the release
  smoke (T24 in `plans/open-audit-witness.md`) runs on a published tag. Note
  that `--version`/`--released` provision no audit-receiver binary (releases
  do not ship the fixture), so until T24 wires one in, the export cases fail
  there while the witness cases still run.

## Persistent cert store (avoid Let's Encrypt re-issuance)

Every domain scenario provisions a fresh box whose Caddy issues a `*.<domain>`
wildcard via DNS-01. Because the box is thrown away each run, that cert used to
be re-issued **every run** — the managed cert bucket is created and destroyed
with each cluster, and single-node disabled sharing entirely. Against
`--prod-tls` (or if staging limits bite) that burns the issuance budget.

Run this **once per operator/account** to back the harness with a persistent,
cross-run cert store:

```bash
make integration-cert-store-init
```

It idempotently creates a long-lived S3 bucket (`aerol-itest-caddy-certs-<acct>`,
versioning + AES256 + public-access-block) that lives **outside** all scenario
Terraform state — so per-scenario `terraform destroy` never wipes it — and
writes a stable `caddy_cert_store` block (bucket coords + encryption key) into
`config/secrets.yml`. From then on `run.sh` points every domain scenario at
that bucket in BYO mode.

Behaviour after bootstrap: domains are still **randomly** leased from the pool
(`scenarios/domains.yml`), but `certmagic-s3` keys certs by
`<prefix>/certificates/<acme-issuer>/<domain>`, so **the first run to land on a
domain issues + stores its wildcard; every later run that draws the same domain
reads it back instead of re-issuing.** The pool is finite, so each domain issues
exactly once per cert lifetime. Staging and `--prod-tls` runs never collide
(different issuer directory). The encryption key is the only way to read the
stored certs — save it like any root credential; losing or rotating it orphans
every stored cert. See [`setup/multi-node-cert-sharing.md`](../setup/multi-node-cert-sharing.md).

## Identity and access (UC-268..UC-294)

`suite/identity_*_test.go` and `suite/z_identity_chaos_test.go` cover named
credentials end to end (plans/identity-and-access.md §8, task T12).

- **Team tokens, not a token file.** The cross-tenant cases mint real team
  `avm_` tokens with the operator credential at setup (`POST /v1/tokens`) and
  revoke them on cleanup; `SB_ITEST_IDENTITY_FILE` is gone (D4). A token
  minted on one node reaches a worker or ingress node (no Raft state) within
  one mirror sync, and a request forwarded there is authenticated again, so
  `mintToken` waits until the API domain AND every worker and ingress node
  accept the token (one SSH tunnel per node per case) before the case uses
  it. A node the suite cannot reach over SSH is logged and not waited on.
- **The test issuer.** The nodes cannot reach the operator's machine, so they
  never fetch keys from it. The suite generates the keys, writes the issuer's
  JWKS and an identity file whose `issuers[].jwks_file` names it, installs
  both on every node over SSH (`/etc/sandboxd/itest-identity.yaml`, the path
  the scenarios' `SB_IDENTITY_FILE` names), reloads with SIGHUP, and mints ID,
  workload, Kubernetes service-account and MCP access tokens locally
  (`suite/harness/identity_issuer.go`, built on T6's `identitytest`). The
  file is absent at boot, which sandboxd treats as "OIDC answers 503 until a
  good file loads". The issuer also serves discovery, a device endpoint and a
  token endpoint on `https://127.0.0.1:<port>`, for the two clients that
  discover it: the remote-MCP OAuth client (UC-286, in the suite) and
  `aerolvm login --sso --device` (UC-282), which runs on a node and reaches
  the issuer through an SSH reverse forward on the same port.
- **Capabilities.** `identity` (SB_IDENTITY_ENABLED) and `identity-oidc` (the
  test issuer) are on `single-node`, `cluster-3-mixed`, the two
  `*-secrets-enterprise` scenarios and `cluster-hetero-lite-secrets`;
  `single-node-wasm` and the other enterprise hetero scenarios have
  `identity` only. `audit-export-s3` (cluster-3-mixed exports to its S3
  bucket; run.sh exports `AEROL_AUDIT_EXPORT_BUCKET`/`_PREFIX`) feeds
  UC-279. `token-mirror` marks a role-separated topology (UC-291, UC-272b).
- **Host-scoped PAT (`pat-scope-host`).** Enterprise mode requires
  `SB_PAT_SCOPE=host` (T10), so every enterprise scenario installs with
  `pat_scope = "host"` (Terraform → `install.sh --pat-scope host`). Through
  Caddy the PAT is then a 401, so run.sh mints an admin `avm_` token on the
  seed's loopback (`mint_suite_token`, the PAT on curl's stdin) and uses it
  for the health probes, the member wait and the whole suite (`AEROL_PAT`);
  the PAT itself goes to the suite as `AEROL_OPERATOR_PAT` for the cases that
  present it on a node's loopback.
- **Deployment capabilities.** `pat-scope-host` and `l4-proxy-protocol` say
  how a scenario was installed (run.sh mints the suite's token for the
  first); `pat-rotation` opts a scenario into UC-277's two rolling restarts.
  The CLI cases (UC-279's `aerolvm audit search` and `access review`,
  UC-282's `aerolvm login --sso --device`) run the `aerolvm` the suite
  builds from the working tree.
- **Disruptive cases** (`disruptive: true` scenarios only): UC-277 rotates
  the PAT on every node (`SB_PAT_TOKEN_PREVIOUS`, `SB_OPERATOR_VOLUME_SCOPE`),
  UC-283 refuses an enterprise boot without identity and with
  `SB_PAT_SCOPE=any`, UC-289 restarts the single enterprise node with
  `SB_AUDIT_API_FLOOD_CONTROL=coalesce`, UC-291 partitions a worker from the
  server tier for 90 s (iptables, with a dead-man heal on the node), UC-292
  kills the Raft leader during 50 token creates (it skips when the leader is
  the seed, which on a fresh fleet it usually is), and UC-293 rotates the
  issuer's key under load.

| Env var | Default | Purpose |
|---------|---------|---------|
| `AEROL_TOKEN_SPRAY_RPS` / `AEROL_TOKEN_SPRAY_SECONDS` | `2000` / `10` | UC-272b's spray at one worker (the plan's 10k/s is the offline benchmark's figure) |
| `AEROL_IDENTITY_CHAOS_RPS` | `1000` | UC-293's load while the key rotates |
| `AEROL_WASM_REGISTER_REF` | *(unset)* | UC-294's module ref (as UC-51); skips without it |
| `AEROL_UPGRADE_SANDBOXD_URL` / `AEROL_UPGRADE_SANDBOXD_SHA256` | *(unset)* | UC-281: the new build to roll onto a fleet provisioned from an older release; skips without them |

```bash
make integration-identity-gate                      # all five identity scenarios, cheapest first
make integration-single                             # tokens, SSO, MCP OAuth, CLI device login, dashboard
make integration-cluster-mixed                      # + forwards, fan-out, revoke propagation, audit search/review
make integration-secrets-enterprise-single          # + host-scoped PAT, PROXY protocol, enterprise boot gates, flood control
make integration-secrets-enterprise                 # + PAT rotation, leader-kill and key-rotation chaos
make integration-secrets-hetero-lite                # + worker-partition chaos, token spray
make integration-identity-only SCENARIO=cluster-3-mixed   # re-run the identity cases on a kept scenario
```

UC-281 needs a fleet on an older release and the new build's URL:

```bash
make itest-build && make itest-publish   # prints presigned tfvars: sandboxd_url, and checksums_url (its sandboxd line is the sha256)
AEROL_UPGRADE_SANDBOXD_URL=... AEROL_UPGRADE_SANDBOXD_SHA256=... AEROL_TEST_RUN='^TestIdentityRollingUpgradeGate$' \
  AEROL_ALLOW_DISRUPTIVE=1 integration-tests/run.sh cluster-3-mixed --version <tag before the identity stack>
```

## Egress domain filtering (UC-179..UC-204)

`suite/egress_fqdn_test.go`, `suite/egress_phase2_test.go`,
`suite/egress_phase3_test.go`, `suite/egress_firecracker_test.go` and
`suite/egress_private_cloud_test.go` cover hostname egress filtering
(plans/egress-domain-filtering.md P1-10, P1-20, Phases 2-4).

- **`egress-fqdn`** (advertised by `single-node`, `single-node-containerd`,
  `cluster-3-mixed-docker` and `cluster-3-mixed-gvisor`): UC-180..182 run real
  traffic through the node's egress gateway (allowed name over HTTPS, NXDOMAIN
  and a fast refusal for others, the 403 naming host and rule, the denial in
  `sandbox.audit()`, `host:port` and `*.` entries). UC-185 is the EF-78
  latency gate: with `AEROL_BENCH=1` it reads the `svc_egress_*` stages from
  Server-Timing and fails over the join (≤2 ms p50) and attach (≤10 ms p99)
  budgets (`AEROL_EGRESS_JOIN_P50_MS` / `AEROL_EGRESS_ATTACH_P99_MS` override).
- Phase 2, also on `egress-fqdn`: UC-190 changes a running sandbox's policy,
  UC-191 converges a named profile change and refuses deleting it while
  referenced, and UC-192 (EF-48) learns `pip install` in learn mode, then
  locks to the suggested list. UC-193..200 (EF-49) run each built-in profile's
  real tool with only that profile: pip, npm, `git clone`, a Hugging Face
  download, `go mod download`, `cargo fetch`, apt and `crane pull` (in place
  of `docker pull`, which would need Docker in Docker). They pull the tool
  images (python, node, alpine/git, golang, rust, ubuntu, crane) and reach the
  public registries, so a failure there may be registry drift: the built-in
  lists are kept by hand and these UCs are how operators catch a stale one
  (CEO D12).
- Phase 3, also on `egress-fqdn`: UC-201 (EF-52, EF-53) creates a
  `python:3.12-alpine` sandbox allowed `api.github.com` with an inspect rule
  for `GET /repos/**`. Python's `urllib`, trusting the node CA only through
  `SSL_CERT_FILE`, gets a 200 for the ruled GET through the gateway's TLS
  termination, and the gateway's own 403 (naming `network_egress_rules`) for a
  POST and for an unruled path. It calls the public GitHub API unauthenticated,
  so a 403 on the GET may be GitHub's rate limit; the failure prints the body.
  UC-202 (EF-54, P3-2) creates a `python:3.12-alpine` sandbox with a random
  `TEST_TOKEN` in its env and an inspect rule on `postman-echo.com` for
  `/headers` that injects `Authorization` from `env:TEST_TOKEN`. Inside, the
  env holds only `aerolvm-placeholder:TEST_TOKEN`; `urllib` sends that
  placeholder as `Authorization`, and the echoed headers must show the real
  token the gateway put in its place. It depends on the public
  `postman-echo.com` service being up.
  UC-203 (EF-55, P3-3) creates a `python:3.12-alpine` sandbox, pinned to the
  `docker` runtime (runc under either engine, never runsc, which refuses
  `binaries` with 501), allowed `pypi.org` and `files.pythonhosted.org` with a
  binaries-only rule on 443 for each naming `/usr/local/bin/pip`. Inside,
  `pip install requests` must pass without inspection (the gateway names pip by
  its script), and busybox `wget` to `https://pypi.org/simple/` must be
  refused at the TLS handshake. The node needs cgroup v2, which the Ubuntu
  22.04 AMIs have; on cgroup v1 every covered connection is refused
  (`binary_unknown`).
- Phase 4, on `single-node-fc` (`firecracker` + `egress-fqdn`): UC-204
  creates a Firecracker guest allowed `pypi.org`. Its traffic reaches the
  egress gateway over its own TAP: the listed name fetches over HTTPS, another
  is refused fast, `egress_status` is `active`, and a live switch to block-all
  shuts it. That scenario also runs the docker egress UCs above.
- UC-179 (CIDR allowlist), UC-183 (no `CAP_NET_RAW`) and UC-184 (block-all
  can't reach host services) only need `docker`.
- **`private-cloud`** (`single-node-private-cloud`, `make
  integration-single-private-cloud`): the node runs dnsmasq with internal names,
  an internal HTTP service and squid, wired into the egress operator file.
  UC-186..189 cover the upstream proxy with synthetic DNS, the internal zone
  (and its rebinding refusal), the deny floor and the control-port guard. The
  node keeps its internet gateway; a no-egress VPC with an offline install is
  the remaining part of P1-20.

## Create benchmark (UC-94 / UC-95)

`suite/benchmark_test.go` is an **opt-in** benchmark that reuses the live
deployment to measure sandbox creation. It only runs where the scenario
advertises the `benchmark` capability — **`cluster-hetero`** (every runtime),
**`cluster-3-mixed-docker`** (docker only), **`cluster-3-mixed-fc`** (docker +
firecracker), **`cluster-3-mixed-gvisor`** (docker + gvisor),
**`cluster-3-mixed-wasm`** (docker + wasm), and **`single-node-isolate`**
(isolate) — because it is slow and provisions many sandboxes. Everywhere else
UC-94/UC-95 skip (not-applicable).

- **UC-94 — create latency:** for each runtime the scenario has (docker,
  firecracker, gvisor, wasm, isolate) it creates `AEROL_BENCH_SAMPLES` sandboxes
  serially, reporting p50/p90/p99 + mean for three timings: **api** (the
  `Create()` client round-trip), **server** (the API's own `Server-Timing`
  header for the create — client↔cluster network excluded), and **running**
  (create→`started`). `api − server` is that network overhead, so you can tell a
  slow create from a slow link. For isolate, the bench uploads one JS bundle and
  pins a shared `tenant_id` so samples hit the warm group path.
- **UC-95 — fleet density:** creates docker sandboxes until the fleet rejects on
  capacity (HTTP 503 `capacity exceeded`), reports how many landed, then tears
  them all down. `AEROL_BENCH_MAX` bounds cost if admission never trips.

Every result is stamped with the **machine configuration** parsed from the
scenario's `*.tfvars` (per-node `instance_type`, role, `with_*` flags,
`default_instance_type`) so a latency number is read against the hardware it ran
on (e.g. firecracker on `c5.metal` vs docker on `t3.medium`).

Even on `cluster-hetero` the benchmark is **dormant by default** — it's a second
gate, `AEROL_BENCH=1`, on top of the capability, so a normal hetero run doesn't
pay the cost (UC-94/UC-95 show as ⚪ skip with that reason). Turn it on and it
runs inside the normal orchestrated suite, which provisions and tears down for
you (`run.sh` passes the parent environment through to `go test`):

```bash
# Full hetero run (docker + firecracker + gvisor + wasm):
make integration-benchmark

# Docker-focused 3× mixed cluster (full suite + docker bench; writes
# cluster-3-mixed-docker.json/.md and cluster-3-mixed-docker-bench.json):
make integration-benchmark-docker

# Firecracker-focused 3× mixed cluster (docker + firecracker only; cheaper):
make integration-benchmark-fc

# WASM-focused 3× mixed cluster (wasm latency benchmark only; no Docker
# sandbox creates). Provisions cluster-3-mixed-wasm, runs UC-94 with
# AEROL_BENCH_RUNTIMES=wasm (UC-95 skips). Full integration coverage
# (docker + wasm UCs) is `make integration-cluster-mixed-wasm`.
make integration-benchmark-wasm

# gVisor-focused 3× mixed cluster (docker + gvisor only; cheap t3 spot boxes):
make integration-benchmark-gvisor

# V8-isolate (workerd) create-latency on single-node-isolate (t3.medium):
# AEROL_BENCH_RUNTIMES=isolate; UC-95 skipped (no CapCluster).
make integration-benchmark-isolate

# Manual env form (hetero):
AEROL_BENCH=1 \
AEROL_BENCH_OUT=integration-tests/reports/cluster-hetero-bench.json \
  make integration-cluster-hetero
```

To iterate without re-provisioning, bring the cluster up once with `keep`, then
re-run only UC-94/UC-95 with `make integration-benchmark-only` (hetero) or
`make integration-benchmark-fc-only` (mixed-fc) — they read the API URL + PAT
from TF state and force `AEROL_BENCH=1`, so nothing to export:

```bash
make integration-cluster-hetero keep         # provision, leave it up
make integration-benchmark-only              # re-run just the bench against it

make integration-cluster-mixed-docker keep   # 3× mixed docker benchmark cluster
make integration-benchmark-docker-only       # re-run docker bench against it

make integration-cluster-mixed-fc keep       # 3× mixed FC cluster
make integration-benchmark-fc-only         # re-run UC-94/UC-95 against it

make integration-cluster-mixed-wasm keep   # 3× mixed WASM cluster (full suite)
make integration-benchmark-wasm-only       # re-run wasm bench against kept cluster

make integration-cluster-mixed-gvisor keep # 3× mixed gVisor cluster
make integration-benchmark-gvisor-only     # re-run UC-94/UC-95 against it

make integration-single-isolate keep       # single-node isolate (functional UCs)
make integration-benchmark-isolate-only    # re-run UC-94 isolate latency

# Narrow the UC-94 sweep on hetero / mixed-fc / mixed-gvisor benches:
AEROL_BENCH_RUNTIMES=docker,gvisor,wasm make integration-benchmark-only
# …or firecracker-only latency (UC-95 skips when docker is excluded):
AEROL_BENCH_RUNTIMES=firecracker make integration-benchmark-fc-only
# …or gvisor-only latency (UC-95 skips when docker is excluded):
AEROL_BENCH_RUNTIMES=gvisor make integration-benchmark-gvisor-only
# …or add docker density/latency back on the wasm cluster:
AEROL_BENCH_RUNTIMES=docker,wasm make integration-benchmark-wasm-only

make integration-destroy                     # tear the kept cluster down
make integration-destroy SCENARIO=cluster-3-mixed-docker
make integration-destroy SCENARIO=cluster-3-mixed-fc
make integration-destroy SCENARIO=cluster-3-mixed-gvisor
make integration-destroy SCENARIO=cluster-3-mixed-wasm
make integration-destroy SCENARIO=single-node-isolate
```

Percentiles + the density ceiling also print as `bench[...]` log lines (captured
by `go test -json`); the `AEROL_BENCH_OUT` JSON adds the machine block.

**Docker benchmark path.** `make integration-benchmark-docker` provisions
`cluster-3-mixed-docker`, runs the **full integration suite** with
`AEROL_BENCH_RUNTIMES=docker` (same shape as gvisor/fc benchmarks), and writes:
- `integration-tests/reports/cluster-3-mixed-docker.json` + `.md` — full UC matrix
- `integration-tests/reports/cluster-3-mixed-docker-bench.json` + `-bench.md` — UC-94/UC-95 timings

Re-run only the bench against a kept cluster with `make integration-benchmark-docker-only`.
Use `make integration-cluster-mixed-docker` when you want the full suite **without**
the benchmark (UC-94/UC-95 skip unless `AEROL_BENCH=1`).

**Failure logs** (`cluster-3-mixed-docker-failure-logs.txt`) are collected only when
a run **fails** or infra is inconclusive — not on a green pass (same as every other
scenario). Your bench run passed UC-94/UC-95, so no failure-log file was expected.
To pull daemon logs from a kept cluster any time:

```bash
make integration-collect-logs SCENARIO=cluster-3-mixed-docker
```

**WASM warm pool.** wasm scenarios boot with the warm-worker pool on so creates
skip the cold module compile — CPython-on-wasm is ~10s cold on a t3.
`make integration-benchmark-wasm` provisions `cluster-3-mixed-wasm` and runs
**wasm-only** benchmarks (`--bench-only`, `AEROL_BENCH_RUNTIMES=wasm`): UC-94
times wasm creates, UC-95 skips, and no full-suite Docker sandboxes are created.
Use `make integration-cluster-mixed-wasm` for the full docker+wasm integration
suite. Pool depth defaults to
`2` by default at provision time so UC-94 measures warm hits without exhausting
small nodes; `make integration-cluster-mixed-wasm` (non-benchmark) also keeps
depth `2`.
Depth is baked into **node boot env**, so a cluster brought up before a pool
depth change shows cold numbers until re-provisioned.

**Firecracker benchmark path.** UC-94 creates one Firecracker template before
timing and measures sandbox clones with `template_id`, not plain OCI image cold
boots. Override the template source with `AEROL_BENCH_FC_TEMPLATE_IMAGE` when
you need a different base image.

| Env var | Default | Purpose |
|---------|---------|---------|
| `AEROL_BENCH` | *(unset)* | **master switch** — must be `1` or the bench skips |
| `AEROL_BENCH_RUNTIMES` | *(all advertised)* | comma list narrowing the UC-94 sweep, e.g. `docker,gvisor,wasm` (skip firecracker) or `firecracker` (isolate) |
| `AEROL_BENCH_SAMPLES` | `10` | sandboxes timed per runtime (UC-94) |
| `AEROL_BENCH_MAX` | `200` | safety cap on the density probe (UC-95) |
| `AEROL_BENCH_OUT` | *(unset)* | path to write the JSON artifact; logs only if unset |
| `AEROL_BENCH_TFVARS` | `../scenarios/<scenario>.tfvars` | override the machine-config source |
| `AEROL_BENCH_FC_TEMPLATE_IMAGE` | `docker://alpine:3.20` | Firecracker template image used for UC-94 clone latency |
| `AEROL_WASM_MODULE_REF` | *(unset)* | staged `.wasm` ref; wasm latency skips without it |
| `AEROL_WASM_POOL_DEPTH` | `2` | warm wasm workers per module digest (provision-time; `0` when wasm off) |

## What runs where

| Layer | Command | Needs AWS? |
|-------|---------|-----------|
| Harness self-tests (caps logic, report classifier, prod-safety tripwires) | `make test` (`go test ./...`) | No — offline, in CI |
| Live integration suite | `make integration-*` / `go test -tags=integration ./integration-tests/suite/...` | Yes |

The live suite is behind the `integration` build tag, so the everyday
`make test` never reaches AWS.

## Safety model

- **State:** `-backend-config=key=integration/<scenario>/...` + separate
  `TF_DATA_DIR`. The prod key (`prod/terraform.tfstate`) is never opened.
- **One worktree per scenario:** every worktree of a clone shares a
  scenario's state key and cluster name, so `run.sh` claims the name in
  `.tf/<scenario>/.state-claim` before anything is applied. While another
  worktree holds the claim (or a domain pin for that scenario), a run,
  `--destroy-only`, `--collect-logs-only`, `--bench-only` or
  `--obs-snapshot-only` here is refused and names the file. Teardown drops the
  claim after a successful destroy; a kept stack keeps it. Test domains work
  the same way: a lease skips every domain any worktree has pinned.
- **Tripwires** (`lib/provision.sh check-safety`, unit-tested in `safety/`):
  abort before any apply if the state key targets prod, the leased domain is
  empty or collides with the prod domain, or `cluster_name` lacks the `itest`
  marker. A domain scenario with no leased domain (e.g. `domains.yml` missing)
  is refused before the tripwires even run.
- **Config overlay:** generated at runtime from `config/cluster.yml` with AOCR
  auto-import + fleet **disabled** and the leased domain substituted — never a
  committed copy, so it can't drift.
- **Teardown:** `run.sh` trap on EXIT/INT/TERM + the standalone reaper.
