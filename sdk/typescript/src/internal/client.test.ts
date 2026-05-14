import assert from "node:assert/strict";
import test from "node:test";

import { APIClient, SandboxResource } from "./client.js";
import { Image } from "../Image.js";
import type { Sandbox } from "../types.js";

test("internal client uses config object and auth header", async () => {
  let seenAuthorization = "";
  const client = new APIClient({
    baseURL: "https://api.example.com/",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenAuthorization = new Request(input, init).headers.get("authorization") ?? "";
      return jsonResponse(apiSandbox("sb-config"));
    },
  });

  const sandbox = await client.get("sb-config");
  assert.equal(client.baseURL, "https://api.example.com");
  assert.equal(seenAuthorization, "Bearer pat-token");
  assert.ok(sandbox instanceof SandboxResource);
});

test("internal client create maps request and response", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(apiSandbox("sb-create", {
        lifecycle: {
          stop_if_idle_for: 3_600_000_000_000,
          destroy_at_age: 86_400_000_000_000,
        },
      }));
    },
  });

  const sandbox = await client.create({
    image: "ubuntu:22.04",
    memoryMB: 2048,
    networkBlockAll: true,
    lifecycle: {
      stopIfIdleFor: 3_600_000_000_000,
      destroyAtAge: 86_400_000_000_000,
    },
  });
  assert.equal(sandbox.id, "sb-create");
  assert.ok(seenRequest);
  assert.equal(seenRequest.headers.get("authorization"), "Bearer pat-token");
  assert.deepEqual(await seenRequest.json(), {
    image: "ubuntu:22.04",
    memory_mb: 2048,
    network_block_all: true,
    lifecycle: {
      stop_if_idle_for: 3_600_000_000_000,
      destroy_at_age: 86_400_000_000_000,
    },
  });
  assert.deepEqual(sandbox.lifecycle, {
    stopIfIdleFor: 3_600_000_000_000,
    destroyAtAge: 86_400_000_000_000,
  });
});

test("internal client createSnapshot maps request and response", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse({
        name: "snapshots/demo:v1",
        image: "snapshots/demo:v1",
        image_id: "sha256:snap-1",
        source_sandbox_id: "sb-create",
        created_at: "2026-05-14T10:00:00Z",
      });
    },
  });

  const snapshot = await client.createSnapshot("sb-create", "snapshots/demo:v1");
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "POST");
  assert.deepEqual(await seenRequest.json(), { name: "snapshots/demo:v1" });
  assert.equal(snapshot.name, "snapshots/demo:v1");
  assert.equal(snapshot.imageID, "sha256:snap-1");
  assert.equal(snapshot.sourceSandboxID, "sb-create");
});

test("internal client updateLifecycle sends flat request body", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(apiSandbox("sb-lifecycle", {
        lifecycle: {
          stop_if_idle_for: 7_200_000_000_000,
          destroy_at_age: 172_800_000_000_000,
        },
      }));
    },
  });

  const sandbox = await client.updateLifecycle("sb-lifecycle", {
    stopIfIdleFor: 7_200_000_000_000,
    destroyAtAge: 172_800_000_000_000,
  });

  assert.equal(sandbox.id, "sb-lifecycle");
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "PUT");
  assert.deepEqual(await seenRequest.json(), {
    stop_if_idle_for: 7_200_000_000_000,
    destroy_at_age: 172_800_000_000_000,
  });
  assert.deepEqual(sandbox.lifecycle, {
    stopIfIdleFor: 7_200_000_000_000,
    destroyAtAge: 172_800_000_000_000,
  });
});

test("internal client uploadFile sends multipart form", async () => {
  let request: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      request = new Request(input, init);
      return new Response(null, { status: 201 });
    },
  });

  await client.uploadFile("sb-upload", "/workspace/file.txt", "hello");
  assert.ok(request);
  const form = await request.formData();
  assert.equal(form.get("path"), "/workspace/file.txt");
  const file = form.get("file");
  assert.ok(file instanceof File);
  assert.equal(await file.text(), "hello");
});

test("sandbox resource methods refresh and resize data", async () => {
  let call = 0;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    fetch: async (input, init) => {
      call += 1;
      const request = new Request(input, init);
      if (request.method === "POST" && request.url.endsWith("/resize")) {
        return jsonResponse(apiSandbox("sb-resource", { cpu: 8, memory_mb: 8192 }));
      }
      if (request.method === "PUT" && request.url.endsWith("/lifecycle")) {
        return jsonResponse(apiSandbox("sb-resource", {
          lifecycle: {
            stop_if_idle_for: 7_200_000_000_000,
            destroy_if_idle_for: 14_400_000_000_000,
          },
        }));
      }
      return jsonResponse(apiSandbox("sb-resource", { public_url: call === 1 ? "https://old.example.com" : "https://new.example.com" }));
    },
  });

  const sandbox = await client.get("sb-resource");
  await sandbox.refresh();
  assert.equal(sandbox.publicURL, "https://new.example.com");
  await sandbox.resize({ cpu: 8, memoryMB: 8192 });
  assert.equal(sandbox.cpu, 8);
  assert.equal(sandbox.memoryMB, 8192);
  await sandbox.updateLifecycle({ stopIfIdleFor: 7_200_000_000_000, destroyIfIdleFor: 14_400_000_000_000 });
  assert.deepEqual(sandbox.lifecycle, {
    stopIfIdleFor: 7_200_000_000_000,
    destroyIfIdleFor: 14_400_000_000_000,
  });
});

test("sandbox resource createSnapshot delegates to client", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      if (request.method === "POST" && request.url.endsWith("/snapshot")) {
        return jsonResponse({
          name: "snapshots/resource:v1",
          image: "snapshots/resource:v1",
          source_sandbox_id: "sb-resource",
          created_at: "2026-05-14T10:00:00Z",
        });
      }
      return jsonResponse(apiSandbox("sb-resource"));
    },
  });

  const sandbox = await client.get("sb-resource");
  const snapshot = await sandbox.createSnapshot("snapshots/resource:v1");
  assert.equal(snapshot.sourceSandboxID, "sb-resource");
});

test("internal client decodes API errors", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    fetch: async () => jsonResponse({ error: "bad request" }, 400),
  });

  await assert.rejects(() => client.create({ image: "ubuntu:22.04" }), /bad request/);
});

test("internal client execStream uses sandbox bearer subprotocol", async () => {
  const originalWebSocket = globalThis.WebSocket;
  const stdoutChunks: Uint8Array[] = [];
  const stderrChunks: Uint8Array[] = [];

  class FakeWebSocket {
    static instances: FakeWebSocket[] = [];

    readonly url: string;
    readonly protocols: string[];
    binaryType = "blob";
    sent: Array<string | Uint8Array> = [];
    closed = false;
    private readonly listeners = new Map<string, Array<(event?: unknown) => void>>();

    constructor(url: string, protocols?: string | string[]) {
      this.url = url;
      this.protocols = Array.isArray(protocols) ? protocols : protocols ? [protocols] : [];
      FakeWebSocket.instances.push(this);
    }

    addEventListener(name: string, listener: (event?: unknown) => void): void {
      const listeners = this.listeners.get(name) ?? [];
      listeners.push(listener);
      this.listeners.set(name, listeners);
    }

    send(data: string | Uint8Array): void {
      this.sent.push(data);
    }

    close(): void {
      this.closed = true;
    }

    emit(name: string, event?: unknown): void {
      for (const listener of this.listeners.get(name) ?? []) {
        listener(event);
      }
    }
  }

  try {
    globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;

    const client = new APIClient({
      baseURL: "https://api.example.com",
      patToken: "pat-token",
    });

    const handle = client.execStream("sb-stream", {
      command: "npm install",
      onStdout: (chunk) => stdoutChunks.push(chunk),
      onStderr: (chunk) => stderrChunks.push(chunk),
    });

    const ws = FakeWebSocket.instances[0];
    assert.ok(ws);
    assert.equal(ws.url, "wss://api.example.com/v1/sandboxes/sb-stream/toolbox/process/exec/stream");
    assert.deepEqual(ws.protocols, ["sandbox.bearer", "pat-token"]);

    ws.emit("open");
    assert.equal(ws.sent[0], JSON.stringify({ command: "npm install", tty: false, cols: 0, rows: 0 }));

    ws.emit("message", { data: new Uint8Array([0x01, 0x68, 0x69]).buffer });
    ws.emit("message", { data: new Uint8Array([0x02, 0x6f, 0x6b]).buffer });
    ws.emit("message", { data: JSON.stringify({ type: "exit", code: 0 }) });

    const result = await handle.done;
    assert.equal(result.code, 0);
    assert.equal(new TextDecoder().decode(stdoutChunks[0]), "hi");
    assert.equal(new TextDecoder().decode(stderrChunks[0]), "ok");
  } finally {
    globalThis.WebSocket = originalWebSocket;
  }
});

test("internal client execStream close keeps waiting for exit", async () => {
  const originalWebSocket = globalThis.WebSocket;

  class FakeWebSocket {
    static instances: FakeWebSocket[] = [];

    readonly url: string;
    readonly protocols: string[];
    binaryType = "blob";
    sent: Array<string | Uint8Array> = [];
    closed = false;
    private readonly listeners = new Map<string, Array<(event?: unknown) => void>>();

    constructor(url: string, protocols?: string | string[]) {
      this.url = url;
      this.protocols = Array.isArray(protocols) ? protocols : protocols ? [protocols] : [];
      FakeWebSocket.instances.push(this);
    }

    addEventListener(name: string, listener: (event?: unknown) => void): void {
      const listeners = this.listeners.get(name) ?? [];
      listeners.push(listener);
      this.listeners.set(name, listeners);
    }

    send(data: string | Uint8Array): void {
      this.sent.push(data);
    }

    close(): void {
      this.closed = true;
    }

    emit(name: string, event?: unknown): void {
      for (const listener of this.listeners.get(name) ?? []) {
        listener(event);
      }
    }
  }

  try {
    globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;

    const client = new APIClient({
      baseURL: "https://api.example.com",
      patToken: "pat-token",
    });

    const handle = client.execStream("sb-stream", { command: "npm install" });
    const ws = FakeWebSocket.instances[0];
    assert.ok(ws);

    ws.emit("open");
    handle.close();

    assert.equal(ws.sent[1], JSON.stringify({ type: "close" }));
    assert.equal(ws.closed, false);

    ws.emit("message", { data: JSON.stringify({ type: "exit", code: 0 }) });
    const result = await handle.done;
    assert.equal(result.code, 0);
  } finally {
    globalThis.WebSocket = originalWebSocket;
  }
});

test("internal client execStream rejects when stream closes before exit", async () => {
  const originalWebSocket = globalThis.WebSocket;

  class FakeWebSocket {
    static instances: FakeWebSocket[] = [];

    readonly url: string;
    readonly protocols: string[];
    binaryType = "blob";
    sent: Array<string | Uint8Array> = [];
    private readonly listeners = new Map<string, Array<(event?: unknown) => void>>();

    constructor(url: string, protocols?: string | string[]) {
      this.url = url;
      this.protocols = Array.isArray(protocols) ? protocols : protocols ? [protocols] : [];
      FakeWebSocket.instances.push(this);
    }

    addEventListener(name: string, listener: (event?: unknown) => void): void {
      const listeners = this.listeners.get(name) ?? [];
      listeners.push(listener);
      this.listeners.set(name, listeners);
    }

    send(data: string | Uint8Array): void {
      this.sent.push(data);
    }

    close(): void {}

    emit(name: string, event?: unknown): void {
      for (const listener of this.listeners.get(name) ?? []) {
        listener(event);
      }
    }
  }

  try {
    globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;

    const client = new APIClient({
      baseURL: "https://api.example.com",
      patToken: "pat-token",
    });

    const handle = client.execStream("sb-stream", { command: "npm install" });
    const ws = FakeWebSocket.instances[0];
    assert.ok(ws);

    ws.emit("open");
    ws.emit("close");

    await assert.rejects(handle.done, /stream closed before exit/);
  } finally {
    globalThis.WebSocket = originalWebSocket;
  }
});

test("internal client attachSession close detaches transport", async () => {
  const originalWebSocket = globalThis.WebSocket;

  class FakeWebSocket {
    static instances: FakeWebSocket[] = [];

    readonly url: string;
    readonly protocols: string[];
    binaryType = "blob";
    sent: Array<string | Uint8Array> = [];
    closed = false;
    private readonly listeners = new Map<string, Array<(event?: unknown) => void>>();

    constructor(url: string, protocols?: string | string[]) {
      this.url = url;
      this.protocols = Array.isArray(protocols) ? protocols : protocols ? [protocols] : [];
      FakeWebSocket.instances.push(this);
    }

    addEventListener(name: string, listener: (event?: unknown) => void): void {
      const listeners = this.listeners.get(name) ?? [];
      listeners.push(listener);
      this.listeners.set(name, listeners);
    }

    send(data: string | Uint8Array): void {
      this.sent.push(data);
    }

    close(): void {
      this.closed = true;
    }

    emit(name: string, event?: unknown): void {
      for (const listener of this.listeners.get(name) ?? []) {
        listener(event);
      }
    }
  }

  try {
    globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;

    const client = new APIClient({
      baseURL: "https://api.example.com",
      patToken: "pat-token",
    });

    const handle = client.attachSession("sb-stream", "ses-1");
    const ws = FakeWebSocket.instances[0];
    assert.ok(ws);

    ws.emit("open");
    handle.close();

    assert.equal(ws.url, "wss://api.example.com/v1/sandboxes/sb-stream/sessions/ses-1/attach");
    assert.deepEqual(ws.protocols, ["sandbox.bearer", "pat-token"]);
    assert.equal(ws.sent[0], JSON.stringify({ type: "close" }));
    assert.equal(ws.closed, true);
  } finally {
    globalThis.WebSocket = originalWebSocket;
  }
});

test("internal client create forwards runtime selector and parses response", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(apiSandbox("sb-runtime", { runtime: "gvisor" }));
    },
  });

  const sandbox = await client.create({ image: "ubuntu:22.04", runtime: "gvisor" });
  assert.ok(seenRequest);
  const body = (await seenRequest.json()) as { runtime?: string };
  assert.equal(body.runtime, "gvisor", "request body should carry runtime selector");
  assert.equal(sandbox.runtime, "gvisor", "response should expose runtime");
});

test("internal client create defaults runtime to '' when sandboxd omits the field", async () => {
  // Older sandboxd builds don't send the runtime field. The SDK must surface
  // it as the empty string rather than undefined so the type stays narrow.
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async () => jsonResponse(apiSandbox("sb-legacy")),
  });
  const sandbox = await client.create({ image: "ubuntu:22.04" });
  assert.equal(sandbox.runtime, "");
});

test("internal client getNetworkUsage maps response shape", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse({
        sandbox_id: "sb-net",
        bytes_in: 1024,
        bytes_out: 2048,
        bytes_in_limit: 4096,
        bytes_out_limit: 0,
        quota_exceeded: false,
        quota_exceeded_at: null,
        last_sampled_at: "2026-05-15T10:00:00Z",
      });
    },
  });

  const usage = await client.getNetworkUsage("sb-net");
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "GET");
  assert.ok(seenRequest.url.endsWith("/v1/sandboxes/sb-net/network/usage"));
  assert.deepEqual(usage, {
    sandboxID: "sb-net",
    bytesIn: 1024,
    bytesOut: 2048,
    bytesInLimit: 4096,
    bytesOutLimit: 0,
    quotaExceeded: false,
    quotaExceededAt: undefined,
    lastSampledAt: "2026-05-15T10:00:00Z",
  });
});

test("internal client getNetworkUsage handles absent last_sampled_at (pre-first-tick)", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async () =>
      jsonResponse({
        sandbox_id: "sb-fresh",
        bytes_in: 0,
        bytes_out: 0,
        bytes_in_limit: 0,
        bytes_out_limit: 0,
        quota_exceeded: false,
      }),
  });

  const usage = await client.getNetworkUsage("sb-fresh");
  assert.equal(usage.lastSampledAt, undefined);
});

test("internal client setNetworkLimits sends PATCH with provided fields only", async () => {
  let seenRequest: Request | undefined;
  let seenBody: unknown;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      seenBody = await seenRequest.clone().json();
      return jsonResponse({
        sandbox_id: "sb-net",
        bytes_in: 0,
        bytes_out: 0,
        bytes_in_limit: 4096,
        bytes_out_limit: 0,
        quota_exceeded: false,
        quota_exceeded_at: null,
        last_sampled_at: "2026-05-15T10:01:00Z",
      });
    },
  });

  const usage = await client.setNetworkLimits("sb-net", { networkBytesInLimit: 4096 });
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "PATCH");
  assert.ok(seenRequest.url.endsWith("/v1/sandboxes/sb-net/network/limits"));
  // Unset egress limit must be omitted entirely so the server reads "leave alone".
  assert.deepEqual(seenBody, { network_bytes_in_limit: 4096 });
  assert.equal(usage.bytesInLimit, 4096);
});

test("internal client create with Image builds first then creates", async () => {
  const seenRequests: { url: string; method: string; body: unknown }[] = [];
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      const body = req.method === "POST" ? await req.json().catch(() => undefined) : undefined;
      seenRequests.push({ url: req.url, method: req.method, body });
      if (req.url.endsWith("/v1/images/build")) {
        return jsonResponse({ image: "aerolvm-build/abc123:latest" });
      }
      return jsonResponse(apiSandbox("sb-from-image", { image: "aerolvm-build/abc123:latest" }));
    },
  });

  const image = Image.base("ubuntu:22.04").runCommands("apt-get update", "apt-get install -y curl");
  const sandbox = await client.create({ image });

  assert.equal(sandbox.id, "sb-from-image");
  assert.equal(seenRequests.length, 2);
  assert.equal(seenRequests[0].method, "POST");
  assert.ok(seenRequests[0].url.endsWith("/v1/images/build"));
  assert.deepEqual(seenRequests[0].body, {
    dockerfile_content:
      "FROM ubuntu:22.04\nRUN apt-get update\nRUN apt-get install -y curl\n",
  });
  assert.ok(seenRequests[1].url.endsWith("/v1/sandboxes"));
  assert.deepEqual(seenRequests[1].body, { image: "aerolvm-build/abc123:latest" });
});

test("internal client buildImage maps 404 to actionable error", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async () =>
      new Response("404 page not found\n", { status: 404, headers: { "content-type": "text/plain" } }),
  });

  await assert.rejects(
    client.buildImage(Image.base("alpine")),
    (err: Error) => /does not support Image builds/.test(err.message) && /string image reference/.test(err.message),
  );
});

test("internal client create with bare image string skips build call", async () => {
  const seenURLs: string[] = [];
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      seenURLs.push(req.url);
      return jsonResponse(apiSandbox("sb-string"));
    },
  });

  await client.create({ image: "ubuntu:22.04" });
  assert.equal(seenURLs.length, 1);
  assert.ok(seenURLs[0].endsWith("/v1/sandboxes"));
});

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function apiSandbox(id: string, overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    id,
    image: "ubuntu:22.04",
    status: "started",
    public_url: `https://${id}.example.com`,
    container_id: `container-${id}`,
    container_ip: "10.0.0.10",
    cpu: 2,
    memory_mb: 2048,
    disk_gb: 20,
    os_user: "root",
    env: { KEY: "VALUE" },
    network_block_all: false,
    toolbox_enabled: true,
    exposed_ports: [],
    created_at: "2026-05-07T10:00:00Z",
    updated_at: "2026-05-07T10:00:00Z",
    last_active_at: "2026-05-07T10:00:00Z",
    last_error: "",
    container_command: ["bash", "-lc", "echo hello"],
    lifecycle: {},
    ...overrides,
  };
}

void ({} as Sandbox);