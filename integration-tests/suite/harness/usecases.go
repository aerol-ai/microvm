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
	{ID: "UC-30", Title: "Preview URL reachable over HTTPS", Requires: []Capability{CapDocker, CapDomain}, Implemented: true},
	{ID: "UC-31", Title: "Expose port idempotent (same URL)", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-32", Title: "Default <id>.<domain> reachable", Requires: []Capability{CapDocker, CapDomain}, Implemented: true},
	{ID: "UC-33", Title: "Unexpose port -> route gone", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-34", Title: "L4 raw TCP host-port reachable", Requires: []Capability{CapDocker, CapDomain}, Implemented: true},
	{ID: "UC-35", Title: "Add custom domain -> DNS instructions", Requires: []Capability{CapDocker, CapDomain, CapCustomDomains, CapExternalDNSZone}, Implemented: true},
	{ID: "UC-36", Title: "Custom domain reachable after CNAME", Requires: []Capability{CapDocker, CapDomain, CapCustomDomains, CapExternalDNSZone}, Implemented: true},
	{ID: "UC-37", Title: "Network usage counters returned", Requires: []Capability{CapDocker}, Implemented: true},
	{ID: "UC-38", Title: "Network limits patch enforced", Requires: []Capability{CapDocker}, Implemented: true},

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
