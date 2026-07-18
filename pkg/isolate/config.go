// Package isolate is the workerd engine wrapper for the V8-isolate runtime
// (plans/isolate-runtime.md §7, the analog of pkg/wasm for WASM). It owns one
// workerd process per isolate group: it generates the group's capnp config and
// the controller worker, spawns and supervises the process, and drives
// per-sandbox dynamic isolate loading through the controller.
//
// Architecture (validated by the §2.2 spike): each group process runs a
// CONTROLLER worker with a `workerLoader` binding. Sandbox traffic arrives at
// the controller keyed by the x-sb-id header (the driver sets it; clients
// cannot forge it because the driver's proxy owns the socket). The controller
// calls env.LOADER.get(id, provider); on a cache miss the provider fetches the
// sandbox's bundle from the HOST service binding — a tiny bundle-server the Go
// host serves over a unix socket — so the driver never has to restart the
// process or push code through workerd's config. Loaded isolates are cached by
// id (the warm path: ~0.3ms) and auto-evicted when idle; a re-fetch on the
// next request transparently reloads.
package isolate

import (
	"fmt"
	"strconv"
	"strings"
)

// controllerModuleName is the controller worker's entry module.
const controllerModuleName = "controller.js"

// controllerJS is the group controller worker. It is intentionally tiny and
// bundle-agnostic — the only per-group state is the loader cache. It:
//   - rejects requests with no x-sb-id (the driver always sets it);
//   - dynamically loads the isolate for that id, fetching the bundle from the
//     HOST binding on a cache miss;
//   - attributes egress per sandbox by SLOT: the host assigns each egressing
//     sandbox an egress slot and returns it in the bundle spec, so the loaded
//     worker's globalOutbound binds to that slot's dedicated static egress
//     service (env["EGRESS_"+slot]) — one host UDS per slot, ownership known at
//     accept time (plans/isolate-runtime.md §4);
//   - strips the control header before handing the request to the isolate.
const controllerJS = `export default {
  async fetch(request, env) {
    const id = request.headers.get("x-sb-id");
    if (!id) return new Response("isolate: missing x-sb-id", { status: 400 });
    // Resolve the bundle from the host first so "no such sandbox" is a clean
    // 404 and a bundle-server error is a 502 — both distinct from the isolate's
    // own fetch handler throwing (that surfaces as the isolate's response /
    // 500). The provider closure below reuses this spec; the loader still only
    // COMPILES the isolate on a cache miss, so the warm path stays a cached
    // invoke plus one local-socket bundle probe.
    const probe = await env.HOST.fetch("http://host/bundle/" + encodeURIComponent(id));
    if (probe.status === 404) return new Response("no such sandbox", { status: 404 });
    if (!probe.ok) return new Response("isolate bundle fetch " + probe.status, { status: 502 });
    const spec = await probe.json();
    // Egress attribution is by SOCKET, not header. workerd only accepts a real
    // static service binding as globalOutbound — a JS-object Fetcher is rejected
    // ("not of type 'Fetcher'") and a dynamically-loaded worker stub is rejected
    // ("Entrypoints to dynamically-loaded workers cannot be transferred"). So the
    // host pre-declares a pool of per-slot egress services (EGRESS_0..) each on
    // its own UDS, assigns this sandbox a slot, and returns egress_slot here; we
    // bind globalOutbound to that slot's service. The loaded worker is given NO
    // other bindings, so it can reach ONLY its own slot — attribution is
    // structural and unforgeable. A sandbox with no slot (block-all, or the pool
    // is exhausted) binds EGRESS_DENY, which fail-closed 403s (spike-proven
    // 2026-07-18; plans/isolate-runtime.md §4).
    const slot = spec.egress_slot;
    const outbound = (slot === undefined || slot === null || slot < 0)
      ? env.EGRESS_DENY
      : env["EGRESS_" + slot];
    const worker = env.LOADER.get(id, async () => ({
      compatibilityDate: spec.compatibility_date,
      mainModule: spec.main_module,
      modules: spec.modules,
      globalOutbound: outbound,
    }));
    const fwd = new Request(request);
    fwd.headers.delete("x-sb-id");
    return await worker.getEntrypoint().fetch(fwd);
  }
};
`

// controlSocketName / hostSocketName are the unix sockets under a group's run
// dir: the controller listens on the first (driver → isolate traffic), the Go
// host serves the bundle-server on the second (controller → host bundle fetch).
const (
	controlSocketName    = "control.sock"
	hostSocketName       = "host.sock"
	egressDenySocketName = "egress-deny.sock"
)

// egressSlotSocketName is the host UDS for egress slot n (§4). The pool is
// pre-declared in the group config, but the host binds a slot's socket only when
// it assigns that slot to a sandbox — so runtime cost tracks egressing
// sandboxes, not pool size.
func egressSlotSocketName(n int) string { return fmt.Sprintf("egress-%d.sock", n) }

// capnpConfig renders the workerd config for one group. controlSock is where
// workerd listens for sandbox traffic; hostSock is the Go bundle-server the
// controller's provider fetches from; egressSocks is the pre-declared pool of
// per-slot egress services (§4) — one static service per slot, each bound to a
// host UDS the driver assigns per egressing sandbox; denySock backs EGRESS_DENY,
// the fail-closed service block-all / no-slot sandboxes bind. loaderID scopes
// the workerLoader cache (per-group, so two groups never share loaded isolates).
//
// External services are dialed lazily by workerd (spike-confirmed 2026-07-18):
// declaring K egress services whose UDS have no listener yet is fine — workerd
// only connects on a subrequest, so an unassigned slot is never dialed.
func capnpConfig(controlSock, hostSock string, egressSocks []string, denySock, loaderID string) string {
	var svcs, binds strings.Builder
	for i, sock := range egressSocks {
		fmt.Fprintf(&svcs, "    (name = \"egress%d\", external = (address = \"unix:%s\", http = ())),\n", i, sock)
		fmt.Fprintf(&binds, "    (name = \"EGRESS_%d\", service = \"egress%d\"),\n", i, i)
	}
	return fmt.Sprintf(`using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "controller", worker = .controller),
    (name = "host", external = (address = "unix:%s", http = ())),
    (name = "egressDeny", external = (address = "unix:%s", http = ())),
%s  ],
  sockets = [
    (name = "control", address = "unix:%s", http = (), service = "controller"),
  ]
);
const controller :Workerd.Worker = (
  modules = [ (name = "%s", esModule = embed "%s") ],
  compatibilityDate = "2026-01-01",
  compatibilityFlags = ["experimental"],
  bindings = [
    (name = "LOADER", workerLoader = (id = %s)),
    (name = "HOST", service = "host"),
    (name = "EGRESS_DENY", service = "egressDeny"),
%s  ],
);
`, hostSock, denySock, svcs.String(), controlSock, controllerModuleName, controllerModuleName, strconv.Quote(loaderID), binds.String())
}

// bundleWireJSON is the shape the bundle-server returns and the controller
// provider consumes. Field names match the JS in controllerJS.
type bundleWireJSON struct {
	CompatibilityDate string            `json:"compatibility_date"`
	MainModule        string            `json:"main_module"`
	Modules           map[string]string `json:"modules"`
	// EgressSlot is the sandbox's assigned egress slot (§4). Nil (omitted) means
	// no slot — the controller binds EGRESS_DENY (block-all or pool exhausted).
	EgressSlot *int `json:"egress_slot,omitempty"`
}

// validateLoaderID guards the workerLoader cache id (it is embedded in the
// generated config); reuse the same strictness the jail's group key has so a
// crafted group key can't inject capnp.
func validateLoaderID(id string) error {
	if id == "" {
		return fmt.Errorf("isolate: empty loader id")
	}
	for _, c := range id {
		if !(c == '-' || c == '_' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("isolate: loader id %q has an invalid character %q", id, c)
		}
	}
	// Match jail.SanitizeGroupKey: '..' is path-ambiguous even though '.' is
	// individually allowed, and the id lands in a run-dir path.
	if strings.Contains(id, "..") {
		return fmt.Errorf("isolate: loader id %q must not contain '..'", id)
	}
	return nil
}
