import assert from "node:assert/strict";
import test from "node:test";

import { MicroVM } from "./index.js";

const sandboxJSON = { id: "sb-1", name: "a", image: "alpine", status: "started", lifecycle: {} };

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

/** A fetch that answers `respond` unless the request's signal aborts first. */
function client(respond: (request: Request) => Promise<Response> | Response, signal?: AbortSignal) {
  const calls: Request[] = [];
  const sdk = new MicroVM({
    patToken: "pat",
    apiUrl: "https://api.example.com",
    signal,
    fetch: (input, init) => {
      const request = new Request(input, init);
      calls.push(request);
      return new Promise<Response>((resolve, reject) => {
        const abort = () => reject(init?.signal?.reason ?? new Error("aborted"));
        if (init?.signal?.aborted) return abort();
        init?.signal?.addEventListener("abort", abort, { once: true });
        Promise.resolve(respond(request)).then(resolve, reject);
      });
    },
  });
  return { sdk, calls };
}

const never = () => new Promise<Response>(() => undefined);

// AbortSignal.timeout's timer does not keep Node's event loop alive, and a
// fake fetch holds no socket that would, so the tests use a plain timer.
function timeoutSignal(ms: number): AbortSignal {
  const controller = new AbortController();
  setTimeout(() => controller.abort(new DOMException("The operation timed out.", "TimeoutError")), ms);
  return controller.signal;
}

test("a per-call signal ends a request that does not answer", async () => {
  const { sdk } = client(never);
  const started = Date.now();
  await assert.rejects(sdk.get("sb-1", undefined, { signal: timeoutSignal(50) }), (err: unknown) => {
    assert.equal((err as Error).name, "TimeoutError");
    return true;
  });
  assert.ok(Date.now() - started < 2000);
});

test("a per-call signal ends a retry wait", async () => {
  const { sdk, calls } = client(() => json(503, { error: "busy", code: "overloaded" }, { "retry-after": "10" }));
  const started = Date.now();
  await assert.rejects(sdk.list(undefined, { signal: timeoutSignal(100) }));
  assert.ok(Date.now() - started < 2000);
  assert.equal(calls.length, 1);
});

test("the client-wide signal still ends a call that has its own", async () => {
  const controller = new AbortController();
  const { sdk } = client(never, controller.signal);
  const pending = sdk.get("sb-1", undefined, { signal: new AbortController().signal });
  controller.abort(new Error("client stopped"));
  await assert.rejects(pending, /client stopped/);
});

test("one call's signal does not touch other calls or the sandboxes it returned", async () => {
  const { sdk } = client((request) =>
    request.url.endsWith("/process/execute") ? json(200, { exit_code: 0, stdout: "ok", stderr: "" }) : json(200, sandboxJSON),
  );
  const controller = new AbortController();
  const sandbox = await sdk.get("sb-1", undefined, { signal: controller.signal });
  controller.abort(new Error("call over"));
  await sandbox.refresh();
  assert.equal((await sandbox.exec("echo ok")).stdout, "ok");
  assert.equal((await sdk.get("sb-1")).id, "sb-1");
});

test("sandbox calls and the namespaced helpers take a signal too", async () => {
  const { sdk } = client((request) => (request.url.endsWith("/v1/sandboxes/sb-1") ? json(200, sandboxJSON) : never()));
  const sandbox = await sdk.get("sb-1");
  const signal = () => timeoutSignal(30);
  await assert.rejects(sandbox.exec("sleep 10", { signal: signal() }), { name: "TimeoutError" });
  await assert.rejects(sandbox.uploadFile("/f", "x", {}, { signal: signal() }), { name: "TimeoutError" });
  await assert.rejects(sandbox.customDomains.list({ signal: signal() }), { name: "TimeoutError" });
  await assert.rejects(sdk.tokens.list({ signal: signal() }), { name: "TimeoutError" });
  await assert.rejects(sdk.dns.target({ signal: signal() }), { name: "TimeoutError" });
  await assert.rejects(sdk.destroyAll({ tags: { a: "b" } }, { signal: signal() }), { name: "TimeoutError" });
});

test("an already aborted signal sends nothing", async () => {
  const { sdk, calls } = client(() => json(200, sandboxJSON));
  const controller = new AbortController();
  controller.abort(new Error("too late"));
  await assert.rejects(sdk.get("sb-1", undefined, { signal: controller.signal }), /too late/);
  assert.equal(calls.length, 1);
});
