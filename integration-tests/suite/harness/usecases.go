// Package harness holds the scenario/capability model, the use-case registry,
// and the thin SDK client wrapper shared by every integration test.
//
// The registry is the single source of truth the report generator joins against
// to decide, per scenario, whether a use case PASSED, FAILED, was SKIPPED
// (scenario capabilities don't satisfy it) or is PENDING (no test implemented
// yet). Keeping IDs + required capabilities here — not scattered across test
// files — is what lets report/gen.go produce the coverage matrix without
// re-deriving intent from test names.
package harness

// Capability is a property a deployment scenario either has or doesn't. A use
// case lists the capabilities it needs; a scenario that lacks one causes the
// use case to SKIP there (reported as not-applicable, not failed).
type Capability string

const (
	CapDocker      Capability = "docker"      // docker runtime available
	CapFirecracker Capability = "firecracker" // a firecracker-capable worker
	CapGvisor      Capability = "gvisor"      // a gvisor-capable worker
	CapWasm        Capability = "wasm"        // wasm runtime + staged module
	// CapIsolate gates the V8-isolate (workerd) use cases (UC-103..105). Like
	// CapGvisor it is advertisement-only: the runtime is enabled purely by
	// provisioning (default_with_isolate=true → install.sh --with-isolate writes
	// SB_ENABLE_ISOLATE=true + installs workerd), not by any run.sh config-overlay
	// flip. A scenario advertises it when its node was provisioned --with-isolate;
	// where the runtime is off, the isolate UCs skip (not-applicable) rather than
	// hard-fail. Unlike CapWasm it needs no node-side module staging — the UCs
	// upload JS bundles over POST /v1/js-bundles at runtime.
	CapIsolate Capability = "isolate" // V8-isolate (workerd) runtime available
	// CapIsolateJail gates UC-109: the node runs isolate with
	// SB_ISOLATE_USE_JAIL=true (the default) and the suite may SSH in to
	// inspect the workerd process. Only single-node-isolate-jail advertises it;
	// the other isolate scenarios still run jail-off, so their UC-103..105
	// coverage is unaffected by a jail regression and vice versa.
	CapIsolateJail Capability = "isolate-jail"
	CapGPU         Capability = "gpu"     // a GPU worker
	CapDomain      Capability = "domain"  // public domain + TLS (not local-mode)
	CapCluster     Capability = "cluster" // multi-node cluster (raft/forwarding)
	// CapMixedArchNegative gates UC-79: inject a foreign-arch snapshot ref and
	// assert the arm64 cluster refuses to resume it.
	CapMixedArchNegative Capability = "mixed-arch-negative"
	// CapCustomDomains gates the custom-domain attach path (UC-35/36). It's
	// distinct from CapDomain: a deployment can have a public domain + TLS yet
	// run with SB_ENABLE_CUSTOM_DOMAINS=false, in which case the API rejects
	// AddCustomDomain. Only scenarios that opt the feature on (and provision the
	// env) advertise this, so the custom-domain UCs skip instead of hard-failing
	// where the feature is off.
	CapCustomDomains Capability = "custom-domains"
	// CapExternalDNSZone gates the custom-domain verification path (UC-35/36).
	// A real custom domain must, by design, live OUTSIDE the deployment base
	// domain (the API rejects hosts under the wildcard zone) AND prove ownership
	// via a `_aerol-verify.<host>` TXT record before attach succeeds. Satisfying
	// that requires the harness to control a second DNS zone it can provision
	// verification (and CNAME) records in — the leased base zone is not enough.
	// Scenarios advertise this only when they wire up such a zone; otherwise the
	// custom-domain reachability UCs skip instead of failing against a gate they
	// structurally cannot pass.
	CapExternalDNSZone Capability = "external-dns-zone"
	// CapPlatformVolumes gates the platform-volume UCs (UC-81..UC-84). A
	// deployment advertises it only when the operator has enabled platform
	// volumes AND configured a shared backend (SB_PLATFORM_VOLUMES_ENABLED=true
	// + an S3 bucket or NFS export). The tests are backend-agnostic — they
	// attach by name, write, and read back — so the same UCs run whether the
	// scenario configured S3 or NFS. Where the feature is off, the UCs skip
	// (not-applicable) rather than fail against a 412.
	CapPlatformVolumes Capability = "platform-volumes"
	// CapBenchmark gates the create-benchmark UCs (UC-94/UC-95). It is
	// deliberately separate from the runtime capabilities: the benchmark is
	// slow and provisions many sandboxes (the density probe runs until the
	// fleet rejects on capacity), so it must be opt-in even on a scenario that
	// otherwise has every runtime. Only scenarios that explicitly advertise it
	// — currently cluster-hetero — run the benchmark; everywhere else the UCs
	// skip (not-applicable) instead of inflating cost on a normal pass.
	CapBenchmark Capability = "benchmark"
	// CapDockerPool is consumed by run.sh's config overlay, not by any UC's
	// Requires: it flips docker.pool.enabled in the scenario's cluster.yml so
	// UC-94 measures the warm-hit create path. It is deliberately separate
	// from CapDocker because each parked slot holds a default-shaped capacity
	// reservation, lowering the UC-95 density ceiling — scenarios opt in
	// (plans/docker-warm-pool.md §9 documents the adjusted gates).
	CapDockerPool Capability = "docker-pool"
	// CapDockerNetnsPool is likewise consumed by run.sh's config overlay: it
	// flips docker.netns_pool.enabled so cold docker creates adopt prepaid
	// pause-container network namespaces. Separate from CapDockerPool because
	// the two pools are independent (netns slots hold no capacity
	// reservations, so this one leaves the UC-95 density gate untouched).
	CapDockerNetnsPool Capability = "docker-netns-pool"
	// CapDockerEngine is consumed by run.sh's engine selection, not by any UC's
	// Requires. It is an OPT-OUT: containerd is the DEFAULT engine for every
	// scenario (run.sh writes SB_CONTAINER_ENGINE=containerd), and only a
	// scenario advertising this cap runs dockerd instead. Exactly two do — the
	// local dev install (local-mode) and the docker A/B benchmark baseline
	// (cluster-3-mixed-docker, kept on docker so it stays a valid comparison
	// against cluster-3-mixed-containerd). This encodes the target end-state of
	// the docker->containerd migration: "local install uses docker, every real
	// deployment uses containerd."
	CapDockerEngine Capability = "docker-engine"
	// CapContainerdEngine does NOT select the engine — that is now the default
	// (see CapDockerEngine). It gates the containerd-SPECIFIC coverage: the
	// Phase 5 soak/coexistence UCs (UC-99..102, plans/containerd-engine.md
	// §6/§8) and the distinctly-labeled `containerd` benchmark row + density.
	// Advertised only on the dedicated containerd validation scenarios
	// (single-node-containerd, cluster-3-mixed-containerd) so UC-102's
	// dockerd-coexistence restart stays off the runtime/metal scenarios where a
	// pure-containerd host makes it not-applicable.
	CapContainerdEngine Capability = "containerd-engine"
	// CapObservability gates UC-106/107 ("Grafana up", "Prometheus sees all
	// sandboxd nodes") and tells run.sh to pass -var deploy_obs=true so
	// Terraform/obs.tf provisions the dedicated obs EC2. Advertisement +
	// provisioning only — same shape as CapGvisor/CapIsolate.
	CapObservability Capability = "observability"
	// Security-hardening capabilities (plans/integration-test-security.md §6.3).
	// Advertisement-only, same shape as CapGvisor/CapIsolate: provisioning turns
	// the feature on, the capability tells the matrix the case is applicable.
	//
	// CapSecrets marks a scenario where the secret/audit cases are meaningful
	// at all. It is deliberately separate from CapCluster: the single-node
	// profile exercises the provider seam and the audit chain with the cluster
	// fan-out reduced to a no-op.
	CapSecrets Capability = "secrets"
	// CapSecretsKMS means SB_SECRET_PROVIDER=awskms against a REAL key. The KMS
	// provider does not enforce the recipient set (its Open ignores nodeID and
	// leans on IAM), so recipient-binding cases must EXCLUDE it rather than
	// re-run against it.
	CapSecretsKMS Capability = "secrets-kms"
	// CapEnterprise means SB_ENTERPRISE_MODE=true. Mostly used in Excludes:
	// cases that push config into a state the enterprise validator refuses
	// (backup count below 2, zero retention) must not run here.
	CapEnterprise Capability = "enterprise"
	// CapClusterMTLS means every node holds a CA-signed cert with a node:<id>
	// SAN and no insecure escape hatch is set.
	CapClusterMTLS Capability = "cluster-mtls"
	// CapAuditExport means an off-node exporter is configured AND its sink is
	// readable by the suite (an S3 prefix, or the audit-receiver's probe
	// endpoint). Both halves matter: enterprise boot requires an off-node
	// backend, but a case can only assert delivery if it can read the sink.
	CapAuditExport Capability = "audit-export"
	// CapAuditWitness means the external witness is wired to a receiver that
	// retains chain heads and issues receipts.
	CapAuditWitness Capability = "audit-witness"
	// CapSimulations gates the suite/sims workload catalogue and UC-108
	// (per-sim pass/fail). Opt-in like CapBenchmark: slow, provisions long-
	// lived services, and needs AEROL_SIMS=1. UC-108 must never roll up to a
	// single "all green" — each sim records independently.
	CapSimulations Capability = "simulations"
)

// UseCase is one row of the coverage matrix.
type UseCase struct {
	ID    string
	Title string
	// Requires lists capabilities a scenario must have for this UC to run.
	Requires []Capability
	// Excludes lists capabilities that make this UC INAPPLICABLE. A scenario
	// holding any of them skips the case exactly as a missing Requires does.
	//
	// This exists because some cases must mutate daemon config into a state a
	// hardened profile refuses to boot with: UC-116 sets
	// SB_SECRET_RECIPIENT_BACKUP_COUNT=1 and UC-123 sets zero retention, both
	// of which internal/config rejects under SB_ENTERPRISE_MODE. Without
	// Excludes those cases run on an enterprise scenario and take the node
	// down instead of asserting anything. Expressing it as a positive
	// "non-enterprise" capability was rejected: every scenario would have to
	// remember to advertise it, so a forgotten entry fails OPEN — the node
	// still dies. Excludes fails closed by default.
	Excludes []Capability
	// Implemented marks whether a test function exists yet. False => the
	// report shows PENDING (a real gap) rather than a green/skip. The full
	// suite is implemented, so this is true for every current entry; it stays
	// in the model so a newly-added UC without a test surfaces as PENDING.
	Implemented bool
}

// KnownCapabilities is every capability the model defines.
//
// It exists because the registry well-formedness test used to carry its own
// hand-written list of valid capabilities, which went stale the moment T7-T10
// added the six secrets capabilities: a UC requiring one of them failed as a
// "typo" even though the constant was right there. One list, asserted against
// the constants, so adding a capability cannot silently break the guard that
// is supposed to catch typos.
var KnownCapabilities = map[Capability]bool{
	CapDocker: true, CapFirecracker: true, CapGvisor: true, CapWasm: true,
	CapIsolate: true, CapIsolateJail: true, CapGPU: true, CapDomain: true,
	CapCluster: true, CapCustomDomains: true, CapExternalDNSZone: true,
	CapMixedArchNegative: true, CapPlatformVolumes: true, CapBenchmark: true,
	CapDockerPool: true, CapDockerNetnsPool: true, CapDockerEngine: true,
	CapContainerdEngine: true, CapObservability: true, CapSimulations: true,
	CapSecrets: true, CapSecretsKMS: true, CapEnterprise: true,
	CapClusterMTLS: true, CapAuditExport: true, CapAuditWitness: true,
}

// Registry is the full use-case catalogue. Order is the matrix row order.
//
// Every use case now has a test (Phases 1-2 fanned out the full suite), so all
// are Implemented=true. A use case a given scenario can't satisfy SKIPs
// (reported not-applicable, not PENDING) via harness.Require; one that needs an
// out-of-band fixture (a staged wasm module, fault injection, registry creds)
// t.Skips with a reason. PENDING now only appears if a brand-new UC is added to
// this registry without a test — which is exactly the gap signal we want.
var Registry = []UseCase{
	// A. Provisioning & control plane
	{ID: "UC-01", Title: "Local install healthy on :21212", Requires: nil, Implemented: true},
	{ID: "UC-02", Title: "Single-node bootstrap; sandboxd active", Requires: nil, Implemented: true},
	{ID: "UC-03", Title: "3x mixed cluster forms; members=3", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-04", Title: "Heterogeneous cluster roles match tfvars", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-05", Title: "Raft leader elected", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-06", Title: "Member count == expected", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-07", Title: "Wildcard DNS resolves to ingress", Requires: []Capability{CapDomain}, Implemented: true},
	{ID: "UC-08", Title: "Control-plane API reachable over HTTPS", Requires: []Capability{CapDomain}, Implemented: true},
	{ID: "UC-09", Title: "Valid TLS chain (apex + wildcard)", Requires: []Capability{CapDomain}, Implemented: true},
	{ID: "UC-10", Title: "Auth enforced: no PAT -> 401", Requires: nil, Implemented: true},

	// B. Sandbox lifecycle
	{ID: "UC-11", Title: "Create docker sandbox -> running", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-12", Title: "Get sandbox by id", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-13", Title: "List sandboxes includes it", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-14", Title: "Stop sandbox -> stopped", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-15", Title: "Start stopped sandbox -> running", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-16", Title: "Delete sandbox -> 404", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-17", Title: "Create-with-id idempotent", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-18", Title: "Resize CPU/mem/disk", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-19", Title: "Update lifecycle (idle auto-stop)", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-20", Title: "Snapshot create", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-21", Title: "Register snapshot + create from it", Requires: []Capability{CapDocker}, Implemented: true},

	// C. Runtimes
	{ID: "UC-23", Title: "Docker-runtime sandbox runs", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-24", Title: "Firecracker-runtime sandbox runs", Requires: []Capability{CapFirecracker}, Implemented: true},
	{ID: "UC-25", Title: "gVisor-runtime sandbox runs", Requires: []Capability{CapGvisor}, Implemented: true},
	{ID: "UC-26", Title: "WASM-runtime sandbox runs", Requires: []Capability{CapWasm}, Implemented: true},
	{ID: "UC-27", Title: "Kata -> not yet implemented (negative)", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-28", Title: "GPU + gVisor rejected (negative)", Requires: []Capability{CapGvisor}, Implemented: true},

	// D. Networking & ingress
	{ID: "UC-29", Title: "Expose port returns preview URL", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-30", Title: "Preview URL reachable over HTTPS after expose_port", Requires: []Capability{CapDocker, CapDomain}, Implemented: true},
	{ID: "UC-31", Title: "Expose port idempotent (same URL)", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-32", Title: "Default <id>.<domain> unreachable until expose_port opts in", Requires: []Capability{CapDocker, CapDomain}, Implemented: true},
	{ID: "UC-33", Title: "Unexpose port -> route gone", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-34", Title: "L4 raw TCP host-port reachable", Requires: []Capability{CapDocker, CapDomain}, Implemented: true},
	{ID: "UC-35", Title: "Add custom domain -> DNS instructions", Requires: []Capability{CapDocker, CapDomain, CapCustomDomains, CapExternalDNSZone}, Implemented: true},
	{ID: "UC-36", Title: "Custom domain reachable after CNAME", Requires: []Capability{CapDocker, CapDomain, CapCustomDomains, CapExternalDNSZone}, Implemented: true},
	{ID: "UC-37", Title: "Network usage counters returned", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-38", Title: "Network limits patch enforced", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-97", Title: "Private-by-default create: no public URL until expose_port opts the sandbox in; exec works while private", Requires: []Capability{CapDocker}, Implemented: true},
	// UC-98 is the live enforcement probe for the netrules egress firewall:
	// a deny rule must actually DROP packets from inside the sandbox, under
	// whichever SB_NETRULES_BACKEND the nodes run (exec or netlink). Unit
	// tests prove rule translation; only this proves traffic stops.
	{ID: "UC-98", Title: "Egress deny rule drops real traffic (netrules enforcement probe)", Requires: []Capability{CapDocker}, Implemented: true},

	// E. Exec, files, sessions, SSH
	{ID: "UC-39", Title: "Toolbox exec returns output", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-40", Title: "Upload file into sandbox", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-41", Title: "Download file; bytes round-trip", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-42", Title: "Create session + run command", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-43", Title: "SSH with per-sandbox key", Requires: []Capability{CapDocker, CapDomain}, Implemented: true},
	{ID: "UC-44", Title: "Exec on every available runtime", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-45", Title: "Sessions proxy streams", Requires: []Capability{CapDocker}, Implemented: true},

	// F. Templates, images, wasm modules
	{ID: "UC-46", Title: "Build image from Dockerfile", Requires: []Capability{CapDocker}, Implemented: true},
	// Templates build root filesystems for the Firecracker runtime; on a
	// docker-only build the server rejects create with "requires
	// SB_ENABLE_FIRECRACKER". Gate on firecracker so docker-only scenarios
	// (local-mode, single-node) skip rather than hard-fail.
	{ID: "UC-47", Title: "Create template", Requires: []Capability{CapFirecracker}, Implemented: true},
	{ID: "UC-48", Title: "List + get template", Requires: []Capability{CapFirecracker}, Implemented: true},
	{ID: "UC-49", Title: "Rebuild template", Requires: []Capability{CapFirecracker}, Implemented: true},
	{ID: "UC-50", Title: "Delete template", Requires: []Capability{CapFirecracker}, Implemented: true},
	{ID: "UC-51", Title: "Register wasm module + list/get", Requires: []Capability{CapWasm}, Implemented: true},
	{ID: "UC-52", Title: "Push wasm module to registry", Requires: []Capability{CapWasm}, Implemented: true},

	// G. Cluster correctness
	{ID: "UC-53", Title: "New sandbox gets a placement", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-54", Title: "Non-owner request forwards to owner", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-55", Title: "Sandbox index consistent across nodes", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-56", Title: "Drain node -> sandboxes evacuate", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-57", Title: "Uncordon restores schedulability", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-58", Title: "Owner failover -> replica serves", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-58b", Title: "Recreate-via-failover preserves identity", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-58c", Title: "Kill owner mid secret fan-out (GAP-1 chaos)", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-59", Title: "WASM live-migrate across nodes", Requires: []Capability{CapCluster, CapWasm}, Implemented: true},
	{ID: "UC-60", Title: "Orphan reclaim-local + delete-orphan", Requires: []Capability{CapCluster}, Implemented: true},
	{ID: "UC-67", Title: "Cross-node SSH rejects a forged key", Requires: []Capability{CapCluster, CapDomain}, Implemented: true},

	// H. Capacity, admission, ops, idempotency
	{ID: "UC-61", Title: "/v1/capacity reports host capacity", Requires: nil, Implemented: true},
	{ID: "UC-62", Title: "Admission rejects over capacity (serial)", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-63", Title: "admin/reconcile runs clean", Requires: nil, Implemented: true},
	{ID: "UC-64", Title: "/v1/metrics scrape returns output", Requires: nil, Implemented: true},
	{ID: "UC-65", Title: "Concurrent duplicate create (serial)", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-66", Title: "mounts list", Requires: []Capability{CapDocker}, Implemented: true},

	// I. SDK API surface — gap-fill. These exercise SDK methods that the suite
	// above leaves untested even though the daemon supports them: the streaming
	// exec transport, the full session lifecycle (beyond create+log), tag-filtered
	// list, the build-then-create / register-snapshot ergonomic wrappers, the
	// clone-generation token, the rich Dockerfile builder, and the DNS ingress
	// target. The suite doubles as the Go-SDK integration test (see client.go), so
	// an SDK method with no UC here is an untested public method.
	{ID: "UC-68", Title: "Interactive exec stream (stdin -> stdout, exit code)", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-69", Title: "Exec with workdir + env", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-70", Title: "Session lifecycle (list/get/signal/resize)", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-71", Title: "Session recording downloadable", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-72", Title: "Clone-generation token returned", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-73", Title: "List filtered by tags", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-74", Title: "Create with built image graph (CreateWithImage)", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-75", Title: "Register snapshot + create from it", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-76", Title: "Rich Dockerfile builder (env/workdir/entrypoint/cmd/user/expose)", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-77", Title: "DNS ingress target published", Requires: []Capability{CapDomain}, Implemented: true},

	// J. Architecture homogeneity (arm64 Firecracker hosts)
	{ID: "UC-78", Title: "Foreign-arch snapshot ref rejected (offline guard)", Requires: nil, Implemented: true},
	{ID: "UC-79", Title: "Foreign-arch snapshot rejected on arm64 cluster (live)", Requires: []Capability{CapCluster, CapFirecracker, CapMixedArchNegative}, Implemented: true},
	{ID: "UC-80", Title: "Firecracker template clones have distinct kernel entropy", Requires: []Capability{CapFirecracker}, Implemented: true},

	// K. Platform volumes (named, operator-backed persistent storage).
	// Backend-agnostic (S3 or NFS, whatever the scenario configured). Exercised
	// through the native SDK's platformVolumes field; Daytona volume CRUD +
	// reference-aware delete are covered offline (service/facade unit tests).
	{ID: "UC-81", Title: "Attach platform volume; write + read-back inside sandbox", Requires: []Capability{CapDocker, CapPlatformVolumes}, Implemented: true},
	{ID: "UC-82", Title: "Volume persists across destroy; re-attach by name sees data", Requires: []Capability{CapDocker, CapPlatformVolumes}, Implemented: true},
	{ID: "UC-83", Title: "Two sandboxes share one volume (both read same data)", Requires: []Capability{CapDocker, CapPlatformVolumes}, Implemented: true},
	{ID: "UC-84", Title: "Read-only volume mount rejects writes", Requires: []Capability{CapDocker, CapPlatformVolumes}, Implemented: true},
	{ID: "UC-85", Title: "Platform volumes rejected on WASM runtime", Requires: []Capability{CapWasm, CapPlatformVolumes}, Implemented: true},
	{ID: "UC-86", Title: "Platform volumes rejected on Firecracker runtime", Requires: []Capability{CapFirecracker, CapPlatformVolumes}, Implemented: true},
	// Regression guards for the cluster-hetero fix pass (plans/cluster-hetero-failures-fix.md).
	// UC-87 guards B1: a node that runs a specialized runtime must ADVERTISE it
	// in gossip capacity, or placement rejects every create for that runtime
	// ("no worker placement target available"). The bug was a --with-gvisor node
	// advertising only [docker wasm].
	{ID: "UC-87", Title: "Specialized runtimes are advertised in gossip capacity", Requires: []Capability{CapCluster}, Implemented: true},
	// UC-88 guards B2: the firecracker cold-boot OCI path must build a rootfs
	// into the per-sandbox jailer chroot. The bug was mkfs writing into a chroot
	// dir that didn't exist yet ("No such file or directory ... filesystem size").
	{ID: "UC-88", Title: "Firecracker cold-boots a sandbox from a plain OCI image", Requires: []Capability{CapFirecracker}, Implemented: true},
	// UC-89 guards B4: the SSH gateway must listen on the ingress public host.
	// The bug gated it on IsWorker() only, so the public :2220 (which DNS points
	// at the ingress) refused every connection.
	{ID: "UC-89", Title: "SSH gateway listens on the ingress public host", Requires: []Capability{CapCluster, CapDomain}, Implemented: true},

	// UC-90..93 guard the cluster-hetero ROUTING fix pass: a request that lands
	// on a node which can't serve it locally (templates, locally-built images,
	// a specialized runtime) must be routed to a capable worker rather than run
	// in place and fail. The cheap offline guard is the SelectPlacement hetero
	// matrix in internal/cluster/placement_test.go; these are the live
	// end-to-end confirmations on the 8-node cluster-hetero scenario.
	//
	// UC-90: a runtime create must be PLACED on a worker that advertises that
	// runtime in gossip (not merely "a create happened to succeed").
	{ID: "UC-90", Title: "Runtime create places on a capability-matching worker", Requires: []Capability{CapCluster}, Implemented: true},
	// UC-91: a create that omits runtime must run under the placement worker's
	// own configured default (e.g. gvisor), never be silently forced to docker
	// by the router. Guards the gvisor-by-default isolation contract.
	{ID: "UC-91", Title: "Unspecified-runtime create is honored, not forced to docker", Requires: []Capability{CapCluster}, Implemented: true},
	// UC-92: CreateWithImage through a non-worker ingress. The local
	// aerolvm-build/* image must reach the worker the create is placed on.
	{ID: "UC-92", Title: "CreateWithImage through a non-worker ingress reaches a docker worker", Requires: []Capability{CapCluster, CapDocker}, Implemented: true},
	// UC-93: the firecracker template lifecycle must work when the API entry
	// node is not the firecracker worker (templates are per-worker artifacts).
	{ID: "UC-93", Title: "Firecracker template lifecycle works through a non-FC entry node", Requires: []Capability{CapCluster, CapFirecracker}, Implemented: true},
	// F. Performance / capacity benchmarks (opt-in via CapBenchmark).
	// UC-94 measures per-runtime sandbox create latency (API-return + time to
	// running) over a sample, reporting p50/p90/p99. UC-95 probes effective
	// fleet density by creating sandboxes until the API rejects on capacity,
	// then tears them all down. Both reuse the hetero cluster substrate.
	// UC-94 needs only CapBenchmark, not CapCluster: create latency is meaningful
	// single-node too (the single-node-fc c5.metal box is the cheap way to profile
	// the firecracker driver in isolation — no Raft/placement/forward in the
	// number). The bench body already handles the no-cluster case: waitBenchmarkReady
	// early-returns when CapCluster is absent, so it skips the members/leader wait.
	{ID: "UC-94", Title: "Benchmark: per-runtime sandbox create latency", Requires: []Capability{CapBenchmark}, Implemented: true},
	{ID: "UC-95", Title: "Benchmark: fleet density to capacity rejection", Requires: []Capability{CapCluster, CapBenchmark}, Implemented: true},
	{ID: "UC-96", Title: "Docker create readiness delivered via unix-socket push", Requires: []Capability{CapCluster, CapDocker}, Implemented: true},
	{ID: "UC-96b", Title: "Docker socket push works for non-root container images", Requires: []Capability{CapCluster, CapDocker}, Implemented: true},
	{ID: "UC-96c", Title: "Docker socket push works under gVisor runtime", Requires: []Capability{CapCluster, CapDocker, CapGvisor}, Implemented: true},
	{ID: "UC-96d", Title: "Socket-ready signal implies a genuinely serving agent (exec succeeds)", Requires: []Capability{CapCluster, CapDocker}, Implemented: true},

	// Containerd-engine soak gates (plans/containerd-engine.md Phase 5 / §8).
	// CapContainerdEngine keeps them off docker-default scenarios until an
	// operator opts a topology into SB_CONTAINER_ENGINE=containerd.
	{ID: "UC-99", Title: "Neighbor isolation: egress-blocked sandbox cannot reach peer on same bridge", Requires: []Capability{CapContainerdEngine}, Implemented: true},
	{ID: "UC-100", Title: "sandboxd restart reconcile: live sandboxes + parked + netns slots survive", Requires: []Capability{CapContainerdEngine}, Implemented: true},
	{ID: "UC-101", Title: "containerd restart: shims survive and events resubscribe", Requires: []Capability{CapContainerdEngine}, Implemented: true},
	{ID: "UC-102", Title: "dockerd coexistence: AEROLVM-USER jump survives dockerd restart", Requires: []Capability{CapContainerdEngine}, Implemented: true},

	// L. V8-isolate runtime (workerd) — plans/isolate-runtime.md. Gated on
	// CapIsolate, which a scenario advertises only when its node was provisioned
	// --with-isolate (SB_ENABLE_ISOLATE=true + a workerd binary). These are the
	// repeatable live coverage for the isolate runtime — before them the only
	// isolate validation on real infra was an ad-hoc manual recipe.
	//
	// UC-103 is the end-to-end "isolate runs": upload a JS bundle over
	// POST /v1/js-bundles, create a runtime=isolate sandbox referencing it, and
	// drive its fetch handler via toolbox exec (the isolate driver maps an exec
	// command to a fetch on that URL path). Proves workerd installed, the group
	// spawned, the bundle loaded, and the fetch handler served.
	{ID: "UC-103", Title: "Isolate-runtime sandbox runs (upload bundle + create + exec-fetch)", Requires: []Capability{CapIsolate}, Implemented: true},
	// UC-104 is the per-sandbox egress-attribution proof (the §4 redesign shipped
	// in v0.7.16 / PR #340). Two isolate sandboxes in the SAME tenant group get
	// DIFFERENT egress policies enforced: an allow-listed sandbox reaches its
	// allowed host but is refused a non-allowed one, while a block-all sandbox in
	// the same group is refused everything. Attribution is the egress slot socket,
	// not a forgeable header — so this is what turns "egress works" from an
	// offline claim into a live, multi-tenant guarantee.
	{ID: "UC-104", Title: "Isolate per-sandbox egress allowlist enforced (block-all + allow differ in one tenant)", Requires: []Capability{CapIsolate}, Implemented: true},
	// UC-105 exercises the js-bundle catalogue CRUD the isolate runtime uploads
	// through (POST/GET/DELETE /v1/js-bundles): upload returns a digest, list/get
	// surface it, delete removes it. The owner-scoping + in-use-refusal edges are
	// covered offline; this is the live round-trip.
	{ID: "UC-105", Title: "Isolate js-bundle catalogue CRUD (upload/list/get/delete)", Requires: []Capability{CapIsolate}, Implemented: true},
	// UC-109 is the real-host proof of the workerd jail (plans/isolate-runtime.md
	// §2.1): with SB_ISOLATE_USE_JAIL=true an isolate sandbox still serves, and
	// the workerd process behind it runs as the jail uid (not root), with
	// NoNewPrivs and an enforcing seccomp filter (/proc/<pid>/status Seccomp: 2),
	// inside a chroot whose root is the group directory under
	// SB_ISOLATE_JAIL_CHROOT_BASE, in its own cgroup under
	// SB_ISOLATE_JAIL_CGROUP_ROOT. Offline tests prove each piece; only a Linux
	// root can prove them together, which is why this is the gate for trusting
	// the jail with untrusted tenant code (and for enterprise mode).
	{ID: "UC-109", Title: "Isolate jail realized on a real host (non-root uid, chroot, seccomp, cgroup) while serving", Requires: []Capability{CapIsolate, CapIsolateJail}, Implemented: true},

	// Investor-benchmark observability (plans/investor-benchmark-observability.md).
	// UC-106/107 prove the obs stack is actually up; UC-108 asserts each
	// simulation's recorded success signal independently (never a single rollup).
	{ID: "UC-106", Title: "Observability: Grafana reachable + Prometheus datasource healthy", Requires: []Capability{CapObservability}, Implemented: true},
	{ID: "UC-107", Title: "Observability: all expected sandboxd nodes are up in Prometheus", Requires: []Capability{CapObservability, CapCluster}, Implemented: true},
	{ID: "UC-108", Title: "Simulations: each recorded sim success signal is green (per-sim)", Requires: []Capability{CapSimulations}, Implemented: true},

	// ---------------------------------------------------------------------
	// Secrets, audit and the enterprise posture (plans/integration-test-security.md
	// §7). UC-110 onward. Groups A-D land here; E-M follow in T13-T16b.
	// ---------------------------------------------------------------------

	// A. Sealing and fan-out (F1, F2).
	//
	// NOTE ON THE PLAN (verified against the tree): §7 group A describes a
	// "secret.seal" audit event. No such event exists. internal/service emits
	// on OPEN, not on seal: the stored kinds are secret_open, egress, gap,
	// retention_checkpoint and retention_redacted (secret_audit.go:51-58), and
	// the only emitter is beginSecretAuditOwned, called from the env, mounts,
	// registry and cluster-placement DECRYPT paths. Asserting on a seal event
	// would have been a test of something the product never writes. UC-110
	// therefore asserts the observable equivalent: material sealed at create is
	// unreadable by default, and reading it back emits exactly one secret_open
	// naming the actor and carrying no plaintext.
	{ID: "UC-110", Title: "Sealed credentials: create succeeds, one secret_open on read, no plaintext in the record", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-111", Title: "HA create reaches failover_ready with a holder set larger than the owner alone", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-112", Title: "Sealed row present on every recipient and absent on non-recipients (peer HEAD)", Requires: []Capability{CapSecrets, CapCluster, CapClusterMTLS}, Implemented: true},
	{ID: "UC-113", Title: "Peer secret push is idempotent: replay yields one row at the same generation", Requires: []Capability{CapSecrets, CapCluster, CapClusterMTLS}, Implemented: true},
	{ID: "UC-114", Title: "Peer secret push from a foreign identity is refused", Requires: []Capability{CapSecrets, CapCluster, CapClusterMTLS}, Implemented: true},
	{ID: "UC-115", Title: "Zero-ACK HA create is retracted, leaving no orphan sandbox or row", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	// Excludes enterprise: config.go refuses SB_SECRET_RECIPIENT_BACKUP_COUNT<2
	// under SB_ENTERPRISE_MODE, so running this there takes the node down
	// instead of asserting anything.
	{ID: "UC-116", Title: "Recipient-set size tracks SB_SECRET_RECIPIENT_BACKUP_COUNT, capped at cluster size", Requires: []Capability{CapSecrets, CapCluster}, Excludes: []Capability{CapEnterprise}, Implemented: true},

	// B. Cross-node failover open — the critical path (F3). All disruptive.
	//
	// UC-117 is this program's milestone: it is the case §0's probe stood in
	// for, and §6.2b requires it to PASS (not merely not-FAIL) on S2, and to be
	// neither a stub nor hetero-only.
	{ID: "UC-117", Title: "Owner death: HA sandbox recreates on a recipient AND its credentials still work", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-118", Title: "Recreated sandbox's sealed env survives owner death intact", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-119", Title: "A non-recipient owner fails legibly rather than booting with an empty env", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-120", Title: "Owner killed mid-fan-out: recreates, or fails loudly — never half-sealed", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},

	// C. Reseal on membership change (F4).
	{ID: "UC-121", Title: "Adding a node reseals existing HA sandboxes; generation advances exactly once", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-122", Title: "Draining a recipient reseals to a replacement and tombstones the old copy", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	// Excludes enterprise: config.go refuses zero retention under
	// SB_ENTERPRISE_MODE (same failure shape as UC-116).
	{ID: "UC-123", Title: "A retired recipient can no longer open, and its tomb is swept", Requires: []Capability{CapSecrets, CapCluster}, Excludes: []Capability{CapEnterprise}, Implemented: true},
	{ID: "UC-124", Title: "Concurrent reseal triggers converge on one generation and one recipient set", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	// UC-125 must run on an ENTERPRISE scenario: daemon.go makes a boot
	// re-fanout error fatal under enterprise while a plain cluster only logs a
	// warning, so S2 would pass while the enterprise posture deadlocks.
	{ID: "UC-125", Title: "Whole-cluster restart restores holder counts; failover_ready is not stuck false", Requires: []Capability{CapSecrets, CapCluster, CapEnterprise}, Implemented: true},

	// D. Env sealing and the API contract (F5).
	{ID: "UC-126", Title: "Get and List omit env by default", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-127", Title: "include_env=true returns env and emits exactly one audit event naming the actor", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-128", Title: "Env is absent from the Raft placement spec", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-129", Title: "On disk: no plaintext env column; the sealed row round-trips across an update", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-130", Title: "A corrupted sealed env fails the sandbox loud, not empty", Requires: []Capability{CapSecrets}, Implemented: true},

	// E. Audit chain, read API, fan-out (F6, F7).
	{ID: "UC-131", Title: "POST /v1/audit/verify passes on a live node after a workload", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-132", Title: "Tamper detection: a corrupted JSONL line fails verification and names the break", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-133", Title: "Audit reads fan out: a non-owner node returns history the owner never had", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-134", Title: "Coverage is honest: an unreachable node is reported missing, not dropped", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-135", Title: "Evidence survives owner death: the history is still complete after a failover", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-136", Title: "Post-delete history is readable within the grace window and scoped to its incarnation", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-137", Title: "Index-off returns the same events as index-on; an incomplete index 503s", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-138", Title: "Pagination walks a multi-page history with no duplicates and no gaps", Requires: []Capability{CapSecrets}, Implemented: true},

	// F. Export connectors and witness (F9, F10, F11).
	{ID: "UC-139", Title: "file backend: records land in SB_AUDIT_EXPORT_FILE_PATH, one chained object per line", Requires: []Capability{CapSecrets, CapAuditExport}, Implemented: true},
	{ID: "UC-140", Title: "s3 backend: objects land under the prefix and reconstruct the chain", Requires: []Capability{CapSecrets, CapAuditExport}, Implemented: true},
	{ID: "UC-141", Title: "webhook backend: the receiver sees records with a valid HMAC and bearer token", Requires: []Capability{CapSecrets, CapAuditExport}, Implemented: true},
	{ID: "UC-142", Title: "Backoff / at-least-once: a failing sink is retried until every record lands", Requires: []Capability{CapSecrets, CapAuditExport}, Implemented: true},
	{ID: "UC-143", Title: "Witness: chain heads reach the receiver, receipts persist, the health gauge is 1", Requires: []Capability{CapSecrets, CapAuditWitness, CapEnterprise}, Implemented: true},
	{ID: "UC-144", Title: "Witness fail-closed at boot: a receipt disagreeing with the local chain refuses the node", Requires: []Capability{CapSecrets, CapAuditWitness, CapEnterprise}, Implemented: true},
	{ID: "UC-145", Title: "Ingest endpoint: a tokened event is accepted, an untokened one refused, listener loopback-only", Requires: []Capability{CapSecrets, CapCluster, CapEnterprise}, Implemented: true},
	{ID: "UC-145b", Title: "Retention prune holds while export lags, then verifies across the checkpoint boundary", Requires: []Capability{CapSecrets, CapAuditWitness, CapEnterprise}, Implemented: true},

	// G. Quota, rate limits, overflow (F8).
	{ID: "UC-146", Title: "Per-identity audit rate limit returns 429 with Retry-After; a second identity is unaffected", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-147", Title: "Per-node audit ceiling is separate from the operator limit", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-148", Title: "Overflow gap: a flood past the queue max leaves a gap marker and the chain still verifies", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-149", Title: "Overflow spill: the same flood drains from disk and the chain is complete", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-150", Title: "Egress attribution names the right sandbox and the per-sandbox cap bounds its share", Requires: []Capability{CapSecrets, CapEnterprise, CapIsolate}, Implemented: true},

	// H. Cluster mTLS and authz (F12, F13).
	{ID: "UC-151", Title: "Every node presents DNS:node:<id>; ca.key exists only on the seed", Requires: []Capability{CapClusterMTLS, CapCluster}, Implemented: true},
	{ID: "UC-152", Title: "A plaintext call to the cluster-internal port is refused", Requires: []Capability{CapClusterMTLS, CapCluster}, Implemented: true},
	{ID: "UC-153", Title: "A self-signed cert carrying a valid node SAN is rejected by the peer listener", Requires: []Capability{CapClusterMTLS, CapCluster}, Implemented: true},
	// Re-scoped (§7 prerequisite box): the plan's positive half was false —
	// internalOp routes can never accept a PAT, and refusing it is correct.
	{ID: "UC-154", Title: "Operator-only routes accept the fleet PAT; internal mTLS routes refuse it", Requires: []Capability{CapSecrets}, Implemented: true},
	{ID: "UC-155", Title: "A removed peer's certificate is revoked", Requires: []Capability{CapClusterMTLS, CapCluster}, Implemented: true},

	// I. Enterprise profile (F14). UC-158 and UC-159 are folded into the
	// matrix test rather than standing alone: the off-node-exporter refusal is
	// one more forbidden row, and "the matrix must not leave the fleet
	// degraded" is a property of EVERY row, which asserting once at the end
	// would not attribute to the row that broke it.
	{ID: "UC-156", Title: "Enterprise boot-gate matrix: each forbidden combination refuses with its documented message", Requires: []Capability{CapEnterprise}, Implemented: true},
	{ID: "UC-157", Title: "A CA signing key in the daemon TLS directory refuses an enterprise boot", Requires: []Capability{CapEnterprise, CapCluster}, Implemented: true},
	{ID: "UC-158", Title: "An on-node-only audit exporter refuses an enterprise boot", Requires: []Capability{CapEnterprise}, Implemented: true},
	{ID: "UC-159", Title: "After every boot-gate row the node rejoins cleanly; the matrix leaves no degraded fleet", Requires: []Capability{CapEnterprise}, Implemented: true},

	// J. Storage retirement and fleet-scale reads (F15, F18, F19).
	{ID: "UC-160", Title: "Draining a worker raises a storage-retirement obligation; attesting it records the discharge", Requires: []Capability{CapSecrets, CapCluster}, Implemented: true},
	{ID: "UC-161", Title: "Fleet-scale reads stay paged: limit is honoured and the cursor advances", Requires: []Capability{CapCluster}, Implemented: true},
	// Scope corrected twice — see the T15 findings box in the plan. Neither a
	// live 11-node ingress tier nor a `terraform plan` is available, so this
	// asserts the drift that actually bites: the Terraform literal against
	// the daemon constant.
	{ID: "UC-162", Title: "The Terraform ingress gate matches MaxReplicatedIngressRouteNodes and keeps its escape hatch", Requires: []Capability{CapEnterprise}, Implemented: true},

	// K. Isolate jail under enterprise (F16, F17).
	{ID: "UC-163", Title: "Enterprise + isolate: workerd is jailed (non-root, chroot, seccomp, pid cap) while serving", Requires: []Capability{CapEnterprise, CapIsolate, CapIsolateJail}, Implemented: true},
	{ID: "UC-164", Title: "Per-sandbox egress attribution holds under the jail, and the audit names the right sandbox", Requires: []Capability{CapEnterprise, CapIsolate, CapIsolateJail}, Implemented: true},
}

// byID is a lookup built once for the report generator.
var byID = func() map[string]UseCase {
	m := make(map[string]UseCase, len(Registry))
	for _, uc := range Registry {
		m[uc.ID] = uc
	}
	return m
}()

// Lookup returns the use case for an ID and whether it exists.
func Lookup(id string) (UseCase, bool) {
	uc, ok := byID[id]
	return uc, ok
}
