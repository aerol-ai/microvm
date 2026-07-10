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
	CapGPU         Capability = "gpu"         // a GPU worker
	CapDomain      Capability = "domain"      // public domain + TLS (not local-mode)
	CapCluster     Capability = "cluster"     // multi-node cluster (raft/forwarding)
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
)

// UseCase is one row of the coverage matrix.
type UseCase struct {
	ID    string
	Title string
	// Requires lists capabilities a scenario must have for this UC to run.
	Requires []Capability
	// Implemented marks whether a test function exists yet. False => the
	// report shows PENDING (a real gap) rather than a green/skip. The full
	// suite is implemented, so this is true for every current entry; it stays
	// in the model so a newly-added UC without a test surfaces as PENDING.
	Implemented bool
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
	{ID: "UC-94", Title: "Benchmark: per-runtime sandbox create latency", Requires: []Capability{CapCluster, CapBenchmark}, Implemented: true},
	{ID: "UC-95", Title: "Benchmark: fleet density to capacity rejection", Requires: []Capability{CapCluster, CapBenchmark}, Implemented: true},
	{ID: "UC-96", Title: "Docker create readiness delivered via unix-socket push", Requires: []Capability{CapCluster, CapDocker}, Implemented: true},
	{ID: "UC-96b", Title: "Docker socket push works for non-root container images", Requires: []Capability{CapCluster, CapDocker}, Implemented: true},
	{ID: "UC-96c", Title: "Docker socket push works under gVisor runtime", Requires: []Capability{CapCluster, CapDocker, CapGvisor}, Implemented: true},
	{ID: "UC-96d", Title: "Socket-ready signal implies a genuinely serving agent (exec succeeds)", Requires: []Capability{CapCluster, CapDocker}, Implemented: true},
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
