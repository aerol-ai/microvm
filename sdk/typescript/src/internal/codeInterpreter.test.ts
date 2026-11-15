import assert from "node:assert/strict";
import test from "node:test";

import {
  MicroVM,
  MicroVMApiError,
  MicroVMCodeRunError,
  MicroVMCodeTimeoutError,
  MicroVMNotFoundError,
  MicroVMUnsupportedFeatureError,
  type CodeResult,
  type ExecutionError,
} from "../index.js";

const base = "/v1/sandboxes/sb-1/toolbox";
const contextJSON = { id: "ctx-1", language: "python", cwd: "/work", createdAt: "2026-11-15T10:00:00Z", active: true };

type Call = { method: string; path: string; body?: unknown };

// A fake sandboxd whose agent lists `features` on /version (null: an agent
// too old to list any). `reply` answers the interpreter routes.
function fakeSandbox(
  features: string[] | null = ["code.interpreter"],
  reply: (call: Call) => { status?: number; body?: unknown } = () => ({ body: contextJSON }),
) {
  const calls: Call[] = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    retry: { baseDelayMs: 1, maxDelayMs: 1 },
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      const text = request.method === "GET" ? "" : await request.text();
      const call: Call = { method: request.method, path: url.pathname, body: text ? JSON.parse(text) : undefined };
      calls.push(call);
      let status = 200;
      let payload: unknown;
      if (url.pathname.endsWith("/toolbox/version")) {
        payload = features === null ? { version: "0.7.5" } : { version: "0.7.5", features };
      } else if (url.pathname.includes("/process/interpreter/")) {
        const answer = reply(call);
        status = answer.status ?? 200;
        payload = answer.body;
      } else {
        payload = {
          id: "sb-1", image: "python:3.12", status: "started", public_url: "", cpu: 1, memory_mb: 512, disk_gb: 1,
          network_block_all: false, toolbox_enabled: true, exposed_ports: [],
          created_at: "2026-05-07T10:00:00Z", updated_at: "2026-05-07T10:00:00Z", last_active_at: "2026-05-07T10:00:00Z",
        };
      }
      return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
    },
  });
  return { sdk, calls };
}

// A WebSocket stand-in: the test opens it, feeds it frames and closes it.
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  readonly url: string;
  readonly protocols: string[];
  readyState = 0;
  sent: string[] = [];
  closed = false;
  private readonly listeners = new Map<string, Array<(event?: unknown) => void>>();

  constructor(url: string, protocols?: string | string[]) {
    this.url = url;
    this.protocols = Array.isArray(protocols) ? protocols : protocols ? [protocols] : [];
    FakeWebSocket.instances.push(this);
  }

  addEventListener(name: string, listener: (event?: unknown) => void): void {
    this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]);
  }

  removeEventListener(): void {}

  send(data: string): void {
    if (this.readyState !== 1) throw new Error("InvalidStateError: not open");
    this.sent.push(data);
  }

  close(): void {
    this.closed = true;
    this.readyState = 3;
  }

  emit(name: string, event?: unknown): void {
    if (name === "open") this.readyState = 1;
    for (const listener of this.listeners.get(name) ?? []) listener(event);
  }

  frame(payload: Record<string, unknown>): void {
    // The server's frames always carry these five fields.
    this.emit("message", { data: JSON.stringify({ text: "", name: "", value: "", traceback: "", ...payload }) });
  }

  closeWith(code: number, reason = ""): void {
    this.readyState = 3;
    this.emit("close", { code, reason, wasClean: code !== 1006 });
  }

  sentJSON(): unknown[] {
    return this.sent.map((data) => JSON.parse(data));
  }
}

async function withFakeWebSocket(run: () => Promise<void>): Promise<void> {
  const original = globalThis.WebSocket;
  FakeWebSocket.instances = [];
  globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
  try {
    await run();
  } finally {
    globalThis.WebSocket = original;
  }
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

/** The socket runCode opens once its feature check is done. */
async function openedSocket(): Promise<FakeWebSocket> {
  for (let i = 0; i < 50 && FakeWebSocket.instances.length === 0; i++) await tick();
  const ws = FakeWebSocket.instances[0];
  assert.ok(ws, "runCode opened no socket");
  ws.emit("open");
  return ws;
}

test("runCode streams output, collects results and resolves on close 1000", async () => {
  await withFakeWebSocket(async () => {
    const { sdk, calls } = fakeSandbox();
    const sandbox = await sdk.get("sb-1");
    const seen: string[] = [];
    const results: CodeResult[] = [];
    const run = sandbox.runCode("x = 5\nx", {
      context: { ...contextJSON },
      envs: { DEBUG: "1" },
      timeoutSeconds: 0,
      onStdout: (text) => seen.push(`out:${text}`),
      onStderr: (text) => seen.push(`err:${text}`),
      onResult: (result) => results.push(result),
    });
    const ws = await openedSocket();
    assert.equal(ws.url, "wss://api.example.com/v1/sandboxes/sb-1/toolbox/process/interpreter/execute");
    assert.deepEqual(ws.protocols, ["sandbox.bearer", "pat-token"]);
    assert.deepEqual(ws.sentJSON(), [{ code: "x = 5\nx", contextId: "ctx-1", envs: { DEBUG: "1" }, timeout: 0, richOutput: true }]);

    ws.frame({ type: "execution_count", count: 3 });
    ws.frame({ type: "stdout", text: "hello\n" });
    ws.frame({ type: "stderr", text: "warn\n" });
    ws.frame({ type: "result", text: "", html: "<b>t</b>", data: { a: [1] }, is_main_result: false });
    ws.frame({ type: "result", text: "5", png: "iVBO", json: { v: 5 }, extra: { "application/x-b": 1, "application/x-a": 2 }, is_main_result: true });
    ws.frame({ type: "keepalive" });
    ws.emit("message", { data: "not json" });
    ws.emit("message", { data: new Uint8Array([1, 2]).buffer });
    ws.frame({ type: "control", text: "completed" });
    ws.closeWith(1000);

    const execution = await run;
    assert.deepEqual(seen, ["out:hello\n", "err:warn\n"]);
    assert.deepEqual(execution.logs, { stdout: ["hello\n"], stderr: ["warn\n"] });
    assert.equal(execution.executionCount, 3);
    assert.equal(execution.interrupted, false);
    assert.equal(execution.error, undefined);
    assert.equal(execution.text, "5");
    assert.equal(execution.results.length, 2);
    assert.deepEqual(results, execution.results);
    assert.deepEqual(execution.results[0].formats(), ["html", "data"]);
    assert.equal(execution.results[0].text, undefined);
    assert.deepEqual(execution.results[1].formats(), ["text", "png", "json", "application/x-a", "application/x-b"]);
    assert.deepEqual(execution.results[1].json, { v: 5 });
    assert.equal(execution.results[1].isMainResult, true);
    assert.deepEqual(calls.slice(1).map((call) => call.path), [`${base}/version`]);
  });
});

test("runCode with a language runs in its default context and leaves unset fields out", async () => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox();
    const run = sdk.runCode("sb-1", "console.log(1)", { language: "javascript", envs: {} });
    const ws = await openedSocket();
    assert.deepEqual(ws.sentJSON(), [{ code: "console.log(1)", language: "javascript", richOutput: true }]);
    ws.closeWith(1005);
    const execution = await run;
    assert.equal(execution.text, undefined);
    assert.equal(execution.executionCount, undefined);
  });
});

test("runCode refuses a context and a language together before any request", async () => {
  await withFakeWebSocket(async () => {
    const { sdk, calls } = fakeSandbox();
    await assert.rejects(sdk.runCode("sb-1", "1", { context: "ctx-1", language: "python" }), /set context or language, not both/);
    assert.equal(calls.length, 0);
    assert.equal(FakeWebSocket.instances.length, 0);
  });
});

test("runCode reports the code's exception in Execution.error and still resolves", async () => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox();
    const errors: ExecutionError[] = [];
    const run = sdk.runCode("sb-1", "1/0", { context: "ctx-1", onError: (error) => errors.push(error) });
    const ws = await openedSocket();
    ws.frame({ type: "error", name: "ZeroDivisionError", value: "division by zero", traceback: "Traceback ..." });
    ws.frame({ type: "control", text: "completed" });
    ws.closeWith(1000);
    const execution = await run;
    const want = { name: "ZeroDivisionError", value: "division by zero", traceback: "Traceback ..." };
    assert.deepEqual(execution.error, want);
    assert.deepEqual(errors, [want]);
  });
});

test("runCode marks an interrupted run", async () => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox();
    const run = sdk.runCode("sb-1", "while True: pass");
    const ws = await openedSocket();
    ws.frame({ type: "control", text: "interrupted" });
    ws.closeWith(1000);
    assert.equal((await run).interrupted, true);
  });
});

test("runCode rejects with MicroVMCodeTimeoutError on close 4008, keeping the output so far", async () => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox();
    const run = sdk.runCode("sb-1", "import time; print('a'); time.sleep(99)", { timeoutSeconds: 1 });
    const ws = await openedSocket();
    assert.equal((ws.sentJSON()[0] as { timeout: number }).timeout, 1);
    ws.frame({ type: "stdout", text: "a\n" });
    ws.frame({ type: "control", text: "interrupted" });
    ws.closeWith(4008, "execution timed out");
    await assert.rejects(run, (err: unknown) => {
      assert.ok(err instanceof MicroVMCodeTimeoutError);
      assert.ok(err instanceof MicroVMCodeRunError);
      assert.equal(err.name, "MicroVMCodeTimeoutError");
      assert.equal(err.closeCode, 4008);
      assert.equal(err.message, "code run timed out: execution timed out");
      assert.deepEqual(err.execution.logs.stdout, ["a\n"]);
      assert.equal(err.execution.interrupted, true);
      return true;
    });
  });
});

test("runCode rejects with MicroVMCodeRunError on an error close", async () => {
  const cases: Array<{ code: number; reason: string; errorEvent?: unknown; message: string }> = [
    { code: 1008, reason: "context not found: ctx-9", message: "code run failed (close 1008): context not found: ctx-9" },
    { code: 1001, reason: "worker process ended", message: "code run failed (close 1001): worker process ended" },
    { code: 1011, reason: "", message: "code run failed (close 1011)" },
    {
      code: 1006,
      reason: "",
      errorEvent: { error: new Error("Unexpected server response: 502") },
      message: "code run failed (close 1006): Unexpected server response: 502",
    },
  ];
  for (const tc of cases) {
    await withFakeWebSocket(async () => {
      const { sdk } = fakeSandbox();
      const run = sdk.runCode("sb-1", "print(1)", { context: "ctx-9" });
      const ws = await openedSocket();
      ws.frame({ type: "stdout", text: "1\n" });
      if (tc.errorEvent) ws.emit("error", tc.errorEvent);
      ws.closeWith(tc.code, tc.reason);
      await assert.rejects(run, (err: unknown) => {
        assert.ok(err instanceof MicroVMCodeRunError);
        assert.ok(!(err instanceof MicroVMCodeTimeoutError));
        assert.equal(err.closeCode, tc.code);
        assert.equal(err.reason, tc.reason);
        assert.equal(err.message, tc.message);
        assert.deepEqual(err.execution.logs.stdout, ["1\n"]);
        return true;
      });
    });
  }
});

test("aborting runCode sends an interrupt and resolves with the confirmed interrupted run", async () => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox();
    const controller = new AbortController();
    const run = sdk.runCode("sb-1", "while True: pass", { signal: controller.signal });
    const ws = await openedSocket();
    controller.abort();
    assert.deepEqual(ws.sentJSON()[1], { type: "interrupt" });
    ws.frame({ type: "control", text: "interrupted" });
    ws.closeWith(1000);
    const execution = await run;
    assert.equal(execution.interrupted, true);
  });
});

test("aborting runCode gives up after the grace when the sandbox never answers", async (t) => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox();
    const controller = new AbortController();
    const run = sdk.runCode("sb-1", "while True: pass", { signal: controller.signal });
    const ws = await openedSocket();
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const reason = new Error("stop");
    controller.abort(reason);
    assert.deepEqual(ws.sentJSON()[1], { type: "interrupt" });
    t.mock.timers.tick(4_999);
    assert.equal(ws.closed, false);
    t.mock.timers.tick(1);
    await assert.rejects(run, (err: unknown) => err === reason);
    assert.equal(ws.closed, true);
  });
});

test("aborting runCode before the socket opens sends nothing", async () => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox();
    const controller = new AbortController();
    const run = sdk.runCode("sb-1", "1", { signal: controller.signal });
    for (let i = 0; i < 50 && FakeWebSocket.instances.length === 0; i++) await tick();
    const ws = FakeWebSocket.instances[0];
    controller.abort();
    await assert.rejects(run, { name: "AbortError" });
    assert.equal(ws.closed, true);
    ws.emit("open");
    assert.deepEqual(ws.sent, []);
  });
});

test("runCode with an aborted signal makes no request", async () => {
  await withFakeWebSocket(async () => {
    const { sdk, calls } = fakeSandbox();
    await assert.rejects(sdk.runCode("sb-1", "1", { signal: AbortSignal.abort() }), { name: "AbortError" });
    assert.equal(calls.length, 0);
    assert.equal(FakeWebSocket.instances.length, 0);
  });
});

test("a throwing callback interrupts the run and rejects with its error", async () => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox();
    const boom = new Error("boom");
    const run = sdk.runCode("sb-1", "print(1)", {
      onStdout: () => {
        throw boom;
      },
    });
    const ws = await openedSocket();
    ws.frame({ type: "stdout", text: "1\n" });
    await assert.rejects(run, (err: unknown) => err === boom);
    assert.deepEqual(ws.sentJSON()[1], { type: "interrupt" });
    assert.equal(ws.closed, true);
  });
});

test("every interpreter call fails closed on an agent without code.interpreter", async () => {
  for (const features of [null, [], ["exec.argv"]]) {
    await withFakeWebSocket(async () => {
      const { sdk, calls } = fakeSandbox(features);
      const attempts: Array<() => Promise<unknown>> = [
        () => sdk.runCode("sb-1", "1"),
        () => sdk.createCodeContext("sb-1"),
        () => sdk.listCodeContexts("sb-1"),
        () => sdk.getCodeContext("sb-1", "ctx-1"),
        () => sdk.deleteCodeContext("sb-1", "ctx-1"),
        () => sdk.restartCodeContext("sb-1", "ctx-1"),
      ];
      for (const attempt of attempts) {
        await assert.rejects(attempt(), (err: unknown) => {
          assert.ok(err instanceof MicroVMUnsupportedFeatureError);
          assert.deepEqual(err.features, ["code.interpreter"]);
          return true;
        });
      }
      assert.equal(calls.filter((call) => call.path.includes("/interpreter")).length, 0);
      assert.equal(FakeWebSocket.instances.length, 0);
    });
  }
});

test("code context calls use the interpreter routes and check the agent once", async () => {
  const { sdk, calls } = fakeSandbox(["code.interpreter"], (call) => {
    if (call.method === "GET" && call.path === `${base}/process/interpreter/context`) {
      return { body: { contexts: [contextJSON] } };
    }
    if (call.method === "DELETE") return { body: { message: "Context deleted successfully" } };
    return { body: { ...contextJSON, language: "javascript" } };
  });
  const sandbox = await sdk.get("sb-1");
  const created = await sandbox.createCodeContext({ language: "javascript", cwd: "/srv" });
  assert.deepEqual(created, { ...contextJSON, language: "javascript" });
  assert.deepEqual(await sandbox.createCodeContext(), { ...contextJSON, language: "javascript" });
  assert.deepEqual(await sandbox.listCodeContexts(), [contextJSON]);
  await sandbox.getCodeContext("ctx/1");
  await sandbox.deleteCodeContext(created);
  assert.deepEqual(await sandbox.restartCodeContext("ctx-1"), { ...contextJSON, language: "javascript" });
  assert.deepEqual(calls.slice(1), [
    { method: "GET", path: `${base}/version`, body: undefined },
    { method: "POST", path: `${base}/process/interpreter/context`, body: { language: "javascript", cwd: "/srv" } },
    { method: "POST", path: `${base}/process/interpreter/context`, body: {} },
    { method: "GET", path: `${base}/process/interpreter/context`, body: undefined },
    { method: "GET", path: `${base}/process/interpreter/context/ctx%2F1`, body: undefined },
    { method: "DELETE", path: `${base}/process/interpreter/context/ctx-1`, body: undefined },
    { method: "POST", path: `${base}/process/interpreter/context/ctx-1/restart`, body: undefined },
  ]);
});

test("listCodeContexts reads a missing list as empty", async () => {
  const { sdk } = fakeSandbox(["code.interpreter"], () => ({ body: { contexts: null } }));
  assert.deepEqual(await sdk.listCodeContexts("sb-1"), []);
});

test("code context errors surface as API errors, and create and restart are never re-sent", async () => {
  const { sdk, calls } = fakeSandbox(["code.interpreter"], (call) => {
    if (call.method === "GET") return { status: 404, body: { error: "not_found", message: "context not found" } };
    if (call.method === "DELETE") return { status: 400, body: { error: "bad_request", message: "the default context cannot be deleted" } };
    return { status: 502, body: { error: "bad_gateway", message: "toolbox unavailable" } };
  });
  await assert.rejects(sdk.getCodeContext("sb-1", "nope"), MicroVMNotFoundError);
  await assert.rejects(sdk.deleteCodeContext("sb-1", "default"), (err: unknown) => {
    assert.ok(err instanceof MicroVMApiError);
    assert.equal(err.status, 400);
    return true;
  });
  await assert.rejects(sdk.createCodeContext("sb-1", { language: "python" }), (err: unknown) => (err as MicroVMApiError).status === 502);
  await assert.rejects(sdk.restartCodeContext("sb-1", "ctx-1"), (err: unknown) => (err as MicroVMApiError).status === 502);
  assert.equal(calls.filter((call) => call.method === "POST").length, 2, "a create or restart was re-sent");
});
