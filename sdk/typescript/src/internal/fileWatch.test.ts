import assert from "node:assert/strict";
import test, { mock } from "node:test";

import { APIClient, WATCH_START_TIMEOUT_MS } from "./client.js";
import { MicroVM } from "../MicroVM.js";
import { MicroVMApiError, MicroVMUnsupportedFeatureError } from "../errors.js";
import type { FileEvent } from "../types.js";

// A stand-in for the runtime's WebSocket, driven by hand.
class FakeWatchSocket {
  static instances: FakeWatchSocket[] = [];

  readonly url: string;
  readonly protocols: string[];
  closed = false;
  private readonly listeners = new Map<string, Array<(event?: unknown) => void>>();

  constructor(url: string, protocols?: string | string[]) {
    this.url = url;
    this.protocols = Array.isArray(protocols) ? protocols : protocols ? [protocols] : [];
    FakeWatchSocket.instances.push(this);
  }

  addEventListener(name: string, listener: (event?: unknown) => void): void {
    const listeners = this.listeners.get(name) ?? [];
    listeners.push(listener);
    this.listeners.set(name, listeners);
  }

  send(): void {
    throw new Error("a file watch client sends nothing");
  }

  close(): void {
    this.closed = true;
  }

  emit(name: string, event?: unknown): void {
    for (const listener of this.listeners.get(name) ?? []) {
      listener(event);
    }
  }

  frame(value: unknown): void {
    this.emit("message", { data: JSON.stringify(value) });
  }

  // A refused handshake, as Node's WebSocket reports it: an error, then a close.
  refuse(detail: string): void {
    this.emit("error", { message: detail });
    this.emit("close", { code: 1006, reason: "", wasClean: false });
  }
}

async function withFakeSocket(fn: () => Promise<void>): Promise<void> {
  const original = globalThis.WebSocket;
  FakeWatchSocket.instances = [];
  globalThis.WebSocket = FakeWatchSocket as unknown as typeof WebSocket;
  try {
    await fn();
  } finally {
    globalThis.WebSocket = original;
  }
}

function lastSocket(): FakeWatchSocket {
  const ws = FakeWatchSocket.instances.at(-1);
  assert.ok(ws, "no WebSocket was opened");
  return ws;
}

// settles reports whether p has settled after the pending callbacks ran.
async function settles(p: Promise<unknown>): Promise<boolean> {
  let done = false;
  p.then(
    () => (done = true),
    () => (done = true),
  );
  await new Promise((resolve) => setImmediate(resolve));
  return done;
}

function jsonResponse(body: unknown, status: number, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

test("watchFiles opens the toolbox watch route with the path, recursive and the bearer subprotocol", async () => {
  await withFakeSocket(async () => {
    const client = new APIClient({ baseURL: "https://api.example.com/", patToken: "pat-token" });

    const plain = client.watchFiles("sb-1", "/work dir/a&b", () => undefined);
    let ws = lastSocket();
    assert.equal(ws.url, "wss://api.example.com/v1/sandboxes/sb-1/toolbox/files/watch?path=%2Fwork%20dir%2Fa%26b");
    assert.deepEqual(ws.protocols, ["sandbox.bearer", "pat-token"]);
    ws.emit("open");
    ws.frame({ type: "start", path: "/work dir/a&b" });
    (await plain).stop();

    const recursive = client.watchFiles("sb-1", "/work", () => undefined, { recursive: true });
    ws = lastSocket();
    assert.equal(ws.url, "wss://api.example.com/v1/sandboxes/sb-1/toolbox/files/watch?path=%2Fwork&recursive=true");
    ws.emit("open");
    ws.frame({ type: "start", path: "/work", recursive: true });
    (await recursive).stop();

    const insecure = new APIClient({ baseURL: "http://127.0.0.1:21212", patToken: "t" });
    void insecure.watchFiles("sb-2", "/w", () => undefined, { recursive: false });
    assert.equal(lastSocket().url, "ws://127.0.0.1:21212/v1/sandboxes/sb-2/toolbox/files/watch?path=%2Fw");
  });
});

test("watchFiles resolves only after start, then delivers every event in order", async () => {
  await withFakeSocket(async () => {
    const client = new APIClient({ baseURL: "https://api.example.com", patToken: "pat-token" });
    const events: FileEvent[] = [];
    const pending = client.watchFiles("sb-1", "/work", (event) => events.push(event), { recursive: true });
    const ws = lastSocket();
    ws.emit("open");
    assert.equal(await settles(pending), false, "resolved before the watch was in place");

    ws.frame({ type: "start", path: "/work", recursive: true });
    const handle = await pending;
    ws.frame({
      type: "events",
      events: [
        { type: "create", path: "/work/a.txt" },
        { type: "write", path: "/work/a.txt" },
        { type: "create", path: "/work/sub", is_dir: true },
        { type: "overflow", reason: "kernel_queue" },
        { type: "rename", path: "/work/a.txt" },
        { type: "chmod", path: "/work/b" },
        { type: "remove", path: "/work/b" },
        { type: "something-new", path: "/work/c" },
      ],
    });
    ws.frame({ type: "unknown-frame" });
    ws.emit("message", { data: "not json" });
    ws.emit("message", { data: new ArrayBuffer(2) });
    ws.frame({ type: "events", events: [{ type: "create", path: "/work/later" }] });

    assert.deepEqual(events, [
      { type: "create", path: "/work/a.txt", isDir: false },
      { type: "write", path: "/work/a.txt", isDir: false },
      { type: "create", path: "/work/sub", isDir: true },
      { type: "overflow", path: "", isDir: false, reason: "kernel_queue" },
      { type: "rename", path: "/work/a.txt", isDir: false },
      { type: "chmod", path: "/work/b", isDir: false },
      { type: "remove", path: "/work/b", isDir: false },
      { type: "something-new", path: "/work/c", isDir: false },
      { type: "create", path: "/work/later", isDir: false },
    ]);
    handle.stop();
  });
});

test("watchFiles: an end frame fails wait() with the sandbox's reason", async () => {
  await withFakeSocket(async () => {
    const client = new APIClient({ baseURL: "https://api.example.com", patToken: "pat-token" });
    const events: FileEvent[] = [];
    const pending = client.watchFiles("sb-1", "/work", (event) => events.push(event));
    const ws = lastSocket();
    ws.emit("open");
    ws.frame({ type: "start", path: "/work" });
    const handle = await pending;
    ws.frame({ type: "events", events: [{ type: "remove", path: "/work", is_dir: true }] });
    ws.frame({ type: "end", reason: "the watched folder was removed" });
    ws.emit("close", { code: 1000, wasClean: true });
    await assert.rejects(handle.wait(), { message: "the watched folder was removed" });
    assert.equal(ws.closed, true);
    assert.deepEqual(events, [{ type: "remove", path: "/work", isDir: true }]);
  });
});

test("watchFiles: stop() ends the watch cleanly, twice is fine, and no event follows it", async () => {
  await withFakeSocket(async () => {
    const client = new APIClient({ baseURL: "https://api.example.com", patToken: "pat-token" });
    const events: FileEvent[] = [];
    const pending = client.watchFiles("sb-1", "/work", (event) => {
      events.push(event);
      if (event.path === "/work/stop-here") handle.stop();
    });
    const ws = lastSocket();
    ws.emit("open");
    ws.frame({ type: "start", path: "/work" });
    const handle = await pending;
    ws.frame({
      type: "events",
      events: [
        { type: "create", path: "/work/a" },
        { type: "create", path: "/work/stop-here" },
        { type: "create", path: "/work/after" },
      ],
    });
    handle.stop();
    ws.emit("close", { code: 1005, wasClean: true });
    await handle.wait();
    assert.equal(ws.closed, true);
    assert.deepEqual(
      events.map((e) => e.path),
      ["/work/a", "/work/stop-here"],
    );
    ws.frame({ type: "events", events: [{ type: "create", path: "/work/late" }] });
    assert.equal(events.length, 2);
  });
});

test("watchFiles: a dropped connection or a throwing callback fails wait()", async () => {
  await withFakeSocket(async () => {
    const client = new APIClient({ baseURL: "https://api.example.com", patToken: "pat-token" });

    let pending = client.watchFiles("sb-1", "/work", () => undefined);
    let ws = lastSocket();
    ws.emit("open");
    ws.frame({ type: "start", path: "/work" });
    let handle = await pending;
    ws.emit("close", { code: 1006, reason: "", wasClean: false });
    await assert.rejects(handle.wait(), /file watch stream closed \(code=1006 wasClean=false\)/);

    const boom = new Error("callback broke");
    pending = client.watchFiles("sb-1", "/work", () => {
      throw boom;
    });
    ws = lastSocket();
    ws.emit("open");
    ws.frame({ type: "start", path: "/work" });
    handle = await pending;
    ws.frame({ type: "events", events: [{ type: "create", path: "/work/a" }] });
    await assert.rejects(handle.wait(), (err) => err === boom);
    assert.equal(ws.closed, true);
  });
});

test("watchFiles: a socket that closes after opening but before start rejects", async () => {
  await withFakeSocket(async () => {
    let probes = 0;
    const client = new APIClient({
      baseURL: "https://api.example.com",
      patToken: "pat-token",
      fetch: async () => {
        probes++;
        return jsonResponse({ error: "x" }, 500);
      },
    });
    const pending = client.watchFiles("sb-1", "/work", () => undefined);
    const ws = lastSocket();
    ws.emit("open");
    ws.emit("close", { code: 1011, reason: "boom", wasClean: false });
    await assert.rejects(pending, /file watch closed before it started \(code=1011 reason="boom" wasClean=false\)/);
    assert.equal(probes, 0, "an opened socket needs no diagnosis");
  });
});

test("watchFiles: an agent without the route is reported as too old for files.watch", async () => {
  await withFakeSocket(async () => {
    for (const [name, response] of [
      ["route header", () => jsonResponse({ error: "not found" }, 404, { "X-Toolbox-Route": "none" })],
      ["plain not found body", () => jsonResponse({ error: "not found" }, 404)],
    ] as const) {
      const seen: Request[] = [];
      const client = new APIClient({
        baseURL: "https://api.example.com",
        patToken: "pat-token",
        team: "blue",
        fetch: async (input, init) => {
          seen.push(new Request(input, init));
          return response();
        },
      });
      const pending = client.watchFiles("sb-old", "/work", () => undefined, { recursive: true });
      lastSocket().refuse("Unexpected server response: 404");
      await assert.rejects(pending, (err: unknown) => {
        assert.ok(err instanceof MicroVMUnsupportedFeatureError, `${name}: got ${String(err)}`);
        assert.deepEqual(err.features, ["files.watch"]);
        assert.equal(err.sandboxID, "sb-old");
        assert.match(err.message, /restart the sandbox, or re-create its Firecracker template/);
        return true;
      });
      // The diagnosis is one plain GET of the same route, with the caller's credentials.
      assert.equal(seen.length, 1);
      assert.equal(seen[0].method, "GET");
      assert.equal(seen[0].url, "https://api.example.com/v1/sandboxes/sb-old/toolbox/files/watch?path=%2Fwork&recursive=true");
      assert.equal(seen[0].headers.get("authorization"), "Bearer pat-token");
      assert.equal(seen[0].headers.get("x-aerolvm-team"), "blue");
    }
  });
});

test("watchFiles: other refusals are API errors with the server's status and message", async () => {
  await withFakeSocket(async () => {
    const cases: Array<[number, string]> = [
      [501, "file watching needs a gVisor or Firecracker sandbox"],
      [404, "path not found: /missing"],
      [404, "sandbox not found"],
      [409, "not a folder: /work/f.txt"],
      [429, "too many file watches open in this sandbox; stop one first"],
    ];
    for (const [status, message] of cases) {
      const client = new APIClient({
        baseURL: "https://api.example.com",
        patToken: "pat-token",
        fetch: async () => jsonResponse({ error: message }, status),
      });
      const pending = client.watchFiles("sb-1", "/missing", () => undefined);
      lastSocket().refuse(`Unexpected server response: ${status}`);
      await assert.rejects(pending, (err: unknown) => {
        assert.ok(err instanceof MicroVMApiError, `${status} ${message}: got ${String(err)}`);
        assert.ok(!(err instanceof MicroVMUnsupportedFeatureError));
        assert.equal(err.status, status);
        assert.equal(err.message, message);
        return true;
      });
    }
  });
});

test("watchFiles: when the diagnosis cannot explain the failure, the stream's own error is kept", async () => {
  await withFakeSocket(async () => {
    // toolboxd accepted the watch and refused only the plain-HTTP upgrade.
    let client = new APIClient({
      baseURL: "https://api.example.com",
      patToken: "pat-token",
      fetch: async () => new Response("Bad Request\n", { status: 400, headers: { "Sec-Websocket-Version": "13" } }),
    });
    let pending = client.watchFiles("sb-1", "/work", () => undefined);
    lastSocket().refuse("Unexpected server response: 502");
    await assert.rejects(pending, (err: unknown) => {
      assert.ok(!(err instanceof MicroVMApiError));
      assert.match((err as Error).message, /file watch failed to start \(Unexpected server response: 502\)/);
      return true;
    });

    // The diagnosis itself cannot reach the server.
    client = new APIClient({
      baseURL: "https://api.example.com",
      patToken: "pat-token",
      fetch: async () => {
        throw new TypeError("fetch failed");
      },
    });
    pending = client.watchFiles("sb-1", "/work", () => undefined);
    lastSocket().refuse("connect ECONNREFUSED");
    await assert.rejects(pending, /file watch failed to start \(connect ECONNREFUSED\)/);
  });
});

test("watchFiles without a WebSocket runtime rejects", async () => {
  const original = globalThis.WebSocket;
  try {
    (globalThis as { WebSocket?: unknown }).WebSocket = undefined;
    const client = new APIClient({ baseURL: "https://api.example.com", patToken: "pat-token" });
    await assert.rejects(client.watchFiles("sb-1", "/work", () => undefined), /WebSocket is not available/);
  } finally {
    globalThis.WebSocket = original;
  }
});

test("MicroVM.watchFiles and Sandbox.watchFiles watch the right sandbox", async () => {
  await withFakeSocket(async () => {
    const microvm = new MicroVM({
      apiUrl: "https://api.example.com",
      patToken: "pat-token",
      fetch: async () =>
        jsonResponse(
          {
            id: "sb-obj",
            image: "ubuntu:22.04",
            status: "running",
            public_url: "",
            cpu: 1,
            memory_mb: 512,
            disk_gb: 5,
            os_user: "root",
            network_block_all: false,
            toolbox_enabled: true,
            created_at: "2026-11-06T00:00:00Z",
            updated_at: "2026-11-06T00:00:00Z",
            last_active_at: "2026-11-06T00:00:00Z",
          },
          200,
        ),
    });
    const viaClient = microvm.watchFiles("sb-direct", "/work", () => undefined, { recursive: true });
    let ws = lastSocket();
    assert.equal(ws.url, "wss://api.example.com/v1/sandboxes/sb-direct/toolbox/files/watch?path=%2Fwork&recursive=true");
    ws.emit("open");
    ws.frame({ type: "start", path: "/work", recursive: true });
    (await viaClient).stop();

    const sandbox = await microvm.get("sb-obj");
    const viaSandbox = sandbox.watchFiles("/srv", () => undefined);
    ws = lastSocket();
    assert.equal(ws.url, "wss://api.example.com/v1/sandboxes/sb-obj/toolbox/files/watch?path=%2Fsrv");
    ws.emit("open");
    ws.frame({ type: "start", path: "/srv" });
    const handle = await viaSandbox;
    handle.stop();
    await handle.wait();
  });
});

test("watchFiles gives up when the start frame never comes, and a started watch has no such limit", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await withFakeSocket(async () => {
      const client = new APIClient({ baseURL: "https://api.example.com", patToken: "pat-token" });
      const pending = client.watchFiles("sb-1", "/work", () => undefined);
      const ws = lastSocket();
      ws.emit("open");
      mock.timers.tick(WATCH_START_TIMEOUT_MS - 1);
      assert.equal(await settles(pending), false);
      mock.timers.tick(1);
      await assert.rejects(pending, /did not start within 60s/);
      assert.equal(ws.closed, true);

      const second = client.watchFiles("sb-1", "/work", () => undefined);
      const ws2 = lastSocket();
      ws2.emit("open");
      ws2.frame({ type: "start", path: "/work", recursive: false });
      const handle = await second;
      mock.timers.tick(WATCH_START_TIMEOUT_MS * 2);
      assert.equal(ws2.closed, false);
      handle.stop();
    });
  } finally {
    mock.timers.reset();
  }
});
