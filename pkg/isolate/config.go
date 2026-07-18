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
//   - attributes egress per sandbox: each sandbox's globalOutbound is a tiny
//     shim isolate (also via LOADER) that stamps x-sb-id before hitting the
//     shared EGRESS service, so the Go proxy knows ownership at accept time
//     (plans/isolate-runtime.md §4 Phase 3);
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
    // Egress: the sandbox worker's globalOutbound is the STATIC egress service
    // (a real Fetcher). It cannot be a per-sandbox shim loaded via env.LOADER —
    // workerd rejects a dynamically-loaded worker's stub/entrypoint as
    // globalOutbound of ANOTHER dynamic worker ("Entrypoints to dynamically-
    // loaded workers cannot be transferred"). So per-request x-sb-id
    // attribution via a shim is not expressible this way; the Go egress server
    // therefore sees no attribution and fail-closed DENIES all egress (the
    // Phase-2 deny-all posture). Restoring per-sandbox allowlists needs a
    // workerd-supported attribution mechanism (plans/isolate-runtime.md §4
    // follow-up) — until then egress is deny-all, which is safe.
    const worker = env.LOADER.get(id, async () => ({
      compatibilityDate: spec.compatibility_date,
      mainModule: spec.main_module,
      modules: spec.modules,
      globalOutbound: env.EGRESS,
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
	controlSocketName = "control.sock"
	hostSocketName    = "host.sock"
	egressSocketName  = "egress.sock"
)

// capnpConfig renders the workerd config for one group. controlSock is where
// workerd listens for sandbox traffic; hostSock is the Go bundle-server the
// controller's provider fetches from; egressSock is the deny-all (Phase 2) /
// per-sandbox (Phase 3) egress service. loaderID scopes the workerLoader cache
// (per-group, so two groups never share loaded isolates).
func capnpConfig(controlSock, hostSock, egressSock, loaderID string) string {
	return fmt.Sprintf(`using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "controller", worker = .controller),
    (name = "host", external = (address = "unix:%s", http = ())),
    (name = "egress", external = (address = "unix:%s", http = ())),
  ],
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
    (name = "EGRESS", service = "egress"),
  ],
);
`, hostSock, egressSock, controlSock, controllerModuleName, controllerModuleName, strconv.Quote(loaderID))
}

// bundleWireJSON is the shape the bundle-server returns and the controller
// provider consumes. Field names match the JS in controllerJS.
type bundleWireJSON struct {
	CompatibilityDate string            `json:"compatibility_date"`
	MainModule        string            `json:"main_module"`
	Modules           map[string]string `json:"modules"`
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
