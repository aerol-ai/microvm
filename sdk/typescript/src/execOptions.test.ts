import assert from "node:assert/strict";
import test from "node:test";

import { MicroVM, MicroVMUnsupportedFeatureError } from "./index.js";

// A fake sandboxd whose toolbox plays an agent that lists `features` on
// /version (undefined: an agent too old to list any). Records every request.
function fakeSandbox(features: string[] | undefined, execResult: Record<string, unknown> = {}) {
  const calls: { method: string; path: string; body?: unknown }[] = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const path = new URL(request.url).pathname;
      const text = request.method === "GET" ? "" : await request.text();
      calls.push({ method: request.method, path, body: text ? JSON.parse(text) : undefined });
      let payload: unknown;
      if (path.endsWith("/toolbox/version")) {
        payload = features === undefined ? { version: "0.6.11" } : { version: "0.6.11", features };
      } else if (path.endsWith("/toolbox/process/execute")) {
        payload = { stdout: "", stderr: "", exit_code: 0, duration_ms: 1, ...execResult };
      } else {
        payload = {
          id: "sb-1", image: "ubuntu:22.04", status: "started", public_url: "", cpu: 1, memory_mb: 512, disk_gb: 1,
          network_block_all: false, toolbox_enabled: true, exposed_ports: [],
          created_at: "2026-05-07T10:00:00Z", updated_at: "2026-05-07T10:00:00Z", last_active_at: "2026-05-07T10:00:00Z",
        };
      }
      return new Response(JSON.stringify(payload), { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  return { sdk, calls };
}

const execPath = "/v1/sandboxes/sb-1/toolbox/process/execute";
const versionPath = "/v1/sandboxes/sb-1/toolbox/version";

test("exec sends output caps when the agent lists them and reads the truncated flags", async () => {
  const { sdk, calls } = fakeSandbox(["exec.max_output_bytes"], { stdout: "aaaa", stdout_truncated: true });
  const sandbox = await sdk.get("sb-1");
  const result = await sandbox.exec({ command: "yes a", maxStdoutBytes: 4, maxStderrBytes: 100 });
  assert.deepEqual(calls.slice(1), [
    { method: "GET", path: versionPath, body: undefined },
    { method: "POST", path: execPath, body: { command: "yes a", max_stdout_bytes: 4, max_stderr_bytes: 100 } },
  ]);
  assert.equal(result.stdout, "aaaa");
  assert.equal(result.stdoutTruncated, true);
  assert.equal(result.stderrTruncated, false);
});

test("exec with output caps fails closed on an older agent and never runs the command", async () => {
  for (const features of [[], undefined, ["files.copy"]]) {
    const { sdk, calls } = fakeSandbox(features);
    const sandbox = await sdk.get("sb-1");
    await assert.rejects(sandbox.exec({ command: "yes", maxStderrBytes: 1024 }), (err: unknown) => {
      assert.ok(err instanceof MicroVMUnsupportedFeatureError);
      assert.deepEqual(err.features, ["exec.max_output_bytes"]);
      assert.match(err.message, /restart the sandbox/);
      return true;
    });
    assert.equal(calls.filter((call) => call.path === execPath).length, 0, "the exec was sent");
  }
});

test("exec without caps makes no /version call, and older agents read as untruncated", async () => {
  const { sdk, calls } = fakeSandbox([]);
  const sandbox = await sdk.get("sb-1");
  const result = await sandbox.exec("ls");
  assert.deepEqual(calls.slice(1).map((call) => call.path), [execPath]);
  assert.equal(result.stdoutTruncated, false);
  assert.equal(result.stderrTruncated, false);
});

test("exec sends argv when the agent lists it, and an older agent never gets it", async () => {
  const argv = ["printf", "%s|", "a b", "$HOME", "; echo pwned"];
  {
    const { sdk, calls } = fakeSandbox(["exec.argv"]);
    const sandbox = await sdk.get("sb-1");
    await sandbox.exec({ argv });
    assert.deepEqual(calls.slice(1), [
      { method: "GET", path: versionPath, body: undefined },
      { method: "POST", path: execPath, body: { argv } },
    ]);
  }
  for (const features of [undefined, ["exec.max_output_bytes"]]) {
    const { sdk, calls } = fakeSandbox(features);
    const sandbox = await sdk.get("sb-1");
    await assert.rejects(sandbox.exec({ argv, maxStdoutBytes: 10 }), (err: unknown) => {
      assert.ok(err instanceof MicroVMUnsupportedFeatureError);
      assert.ok(err.features.includes("exec.argv"));
      return true;
    });
    assert.equal(calls.filter((call) => call.path === execPath).length, 0, "the exec was sent");
  }
});

// A WebSocket stand-in that records frames and lets the test open it.
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  binaryType = "blob";
  readyState = 0;
  sent: Array<string | Uint8Array> = [];
  closed = false;
  private readonly listeners = new Map<string, Array<(event?: unknown) => void>>();

  constructor() {
    FakeWebSocket.instances.push(this);
  }

  addEventListener(name: string, listener: (event?: unknown) => void): void {
    this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]);
  }

  send(data: string | Uint8Array): void {
    if (this.readyState !== 1) {
      throw new Error("InvalidStateError: still connecting");
    }
    this.sent.push(data);
  }

  close(): void {
    this.closed = true;
  }

  emit(name: string, event?: unknown): void {
    if (name === "open") {
      this.readyState = 1;
    }
    for (const listener of this.listeners.get(name) ?? []) {
      listener(event);
    }
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

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

test("execStream sends argv only after the agent lists it, with early writes kept in order", async () => {
  await withFakeWebSocket(async () => {
    const { sdk, calls } = fakeSandbox(["exec.argv"]);
    const sandbox = await sdk.get("sb-1");
    const handle = sandbox.execStream({ argv: ["cat", "a b"] });
    const ws = FakeWebSocket.instances[0];
    ws.emit("open");
    handle.write("typed early");
    assert.equal(ws.sent.length, 0, "nothing may precede the start message");
    await flush();
    await flush();
    assert.deepEqual(JSON.parse(ws.sent[0] as string), { argv: ["cat", "a b"], tty: false, cols: 0, rows: 0 });
    assert.equal(new TextDecoder().decode(ws.sent[1] as Uint8Array), "typed early");
    assert.equal(calls.filter((call) => call.path === versionPath).length, 1);
    ws.emit("message", { data: JSON.stringify({ type: "exit", code: 0 }) });
    assert.equal((await handle.done).code, 0);
  });
});

test("execStream with argv on an older agent never sends the start message", async () => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox([]);
    const sandbox = await sdk.get("sb-1");
    const handle = sandbox.execStream({ argv: ["ls"] });
    const ws = FakeWebSocket.instances[0];
    ws.emit("open");
    await assert.rejects(handle.done, (err: unknown) => {
      assert.ok(err instanceof MicroVMUnsupportedFeatureError);
      assert.deepEqual(err.features, ["exec.argv"]);
      return true;
    });
    assert.deepEqual(ws.sent, []);
    assert.equal(ws.closed, true);
  });
});

test("execStream refuses command and argv together", async () => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox(["exec.argv"]);
    const sandbox = await sdk.get("sb-1");
    assert.throws(() => sandbox.execStream({ command: "ls", argv: ["ls"] }), /set command or argv, not both/);
    assert.equal(FakeWebSocket.instances.length, 0);
  });
});

test("execStream with argv survives the check failing before the socket opens", async () => {
  await withFakeWebSocket(async () => {
    const { sdk } = fakeSandbox(undefined);
    const sandbox = await sdk.get("sb-1");
    const handle = sandbox.execStream({ argv: ["ls"] });
    // Let the /version check fail first, then open the socket.
    await flush();
    await flush();
    const ws = FakeWebSocket.instances[0];
    ws.emit("open");
    await assert.rejects(handle.done, MicroVMUnsupportedFeatureError);
    assert.deepEqual(ws.sent, []);
  });
});
