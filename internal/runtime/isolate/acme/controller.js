export default {
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
    const denied = slot === undefined || slot === null || slot < 0;
    const outbound = denied ? env.EGRESS_DENY : env["EGRESS_" + slot];
    // The cache key carries the slot: a live policy change that moves the
    // sandbox between a slot and EGRESS_DENY must not reuse an isolate whose
    // globalOutbound is still bound to the old slot.
    const worker = env.LOADER.get(id + "#" + (denied ? "deny" : slot), async () => ({
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
