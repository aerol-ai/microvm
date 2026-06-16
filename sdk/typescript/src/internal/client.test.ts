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

test("internal client cloneGeneration reads token via toolbox proxy", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse({ generation: "2d0d8c69", resumed_at: 1700000000000000000 });
    },
  });

  const gen = await client.cloneGeneration("sb-clone");

  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "GET");
  assert.equal(seenRequest.url, "https://api.example.com/v1/sandboxes/sb-clone/toolbox/clone-generation");
  assert.equal(gen.generation, "2d0d8c69");
  assert.equal(gen.resumedAt, 1700000000000000000);
});

test("internal client create serializes selective egress CIDRs", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(apiSandbox("sb-egress"));
    },
  });
  await client.create({
    image: "ubuntu:22.04",
    networkAllowOut: ["1.1.1.0/24", "8.8.8.8/32"],
  });
  assert.ok(seenRequest);
  const body = (await seenRequest.json()) as Record<string, unknown>;
  assert.deepEqual(body.network_allow_out, ["1.1.1.0/24", "8.8.8.8/32"]);
  assert.equal(body.network_deny_out, undefined);
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
        failover: { policy: "recreate" },
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
    failover: { policy: "recreate" },
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
    failover: { policy: "recreate" },
  });
  assert.deepEqual(sandbox.lifecycle, {
    stopIfIdleFor: 3_600_000_000_000,
    destroyAtAge: 86_400_000_000_000,
  });
  assert.deepEqual(sandbox.failover, { policy: "recreate" });
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

test("internal client registerSnapshot maps image path and response", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse({
        name: "py-base",
        image: "python:3.12-slim",
        source_sandbox_id: "",
        created_at: "2026-05-15T10:00:00Z",
        region_id: "us",
        cpu: 2,
        gpu: 1,
        memory_mb: 4096,
        disk_gb: 10,
      }, 201);
    },
  });

  const snapshot = await client.registerSnapshot({
    name: "py-base",
    image: "python:3.12-slim",
    regionID: "us",
    cpu: 2,
    gpu: 1,
    memoryMB: 4096,
    diskGB: 10,
  });

  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "POST");
  assert.equal(seenRequest.url, "https://api.example.com/v1/snapshots");
  assert.deepEqual(await seenRequest.json(), {
    name: "py-base",
    image: "python:3.12-slim",
    region_id: "us",
    cpu: 2,
    gpu: 1,
    memory_mb: 4096,
    disk_gb: 10,
  });
  assert.equal(snapshot.regionID, "us");
  assert.equal(snapshot.cpu, 2);
  assert.equal(snapshot.gpu, 1);
  assert.equal(snapshot.memoryMB, 4096);
  assert.equal(snapshot.diskGB, 10);
});

test("internal client registerSnapshotFromImage sends dockerfile path", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse({
        name: "built",
        image: "snapshots/built:resolved",
        source_sandbox_id: "",
        created_at: "2026-05-15T10:00:00Z",
        entrypoint: ["/bin/sh", "-c", "echo hi"],
      }, 201);
    },
  });

  const snapshot = await client.registerSnapshotFromImage(
    "built",
    Image.base("debian:bookworm-slim").runCommands("apt-get update"),
    { entrypoint: ["/bin/sh", "-c", "echo hi"] },
  );

  assert.ok(seenRequest);
  const payload = await seenRequest.json() as Record<string, unknown>;
  assert.equal(payload.name, "built");
  assert.match(String(payload.dockerfile_content), /FROM debian:bookworm-slim/);
  assert.match(String(payload.dockerfile_content), /RUN apt-get update/);
  assert.equal("image" in payload, false);
  assert.deepEqual(payload.entrypoint, ["/bin/sh", "-c", "echo hi"]);
  assert.deepEqual(snapshot.entrypoint, ["/bin/sh", "-c", "echo hi"]);
});

test("internal client registerSnapshot validates input before sending", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    fetch: async () => {
      throw new Error("should not send request");
    },
  });

  await assert.rejects(() => client.registerSnapshot({ name: "", image: "alpine" }), /name is required/);
  await assert.rejects(() => client.registerSnapshot({ name: "x" }), /image or dockerfile_content is required/);
  await assert.rejects(
    () => client.registerSnapshot({ name: "x", image: "alpine", dockerfileContent: "FROM busybox" }),
    /image and dockerfile_content are mutually exclusive/,
  );
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

test("internal client create round-trips serverless lifecycle flag", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(apiSandbox("sb-serverless", {
        lifecycle: {
          stop_if_idle_for: 300_000_000_000,
          serverless: true,
        },
      }));
    },
  });

  const sandbox = await client.create({
    image: "ubuntu:22.04",
    lifecycle: {
      stopIfIdleFor: 300_000_000_000,
      serverless: true,
    },
  });

  assert.ok(seenRequest);
  const body = (await seenRequest.json()) as { lifecycle?: Record<string, unknown> };
  assert.deepEqual(body.lifecycle, {
    stop_if_idle_for: 300_000_000_000,
    serverless: true,
  });
  assert.equal(sandbox.lifecycle.serverless, true);
  assert.equal(sandbox.lifecycle.stopIfIdleFor, 300_000_000_000);
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

test("internal client buildImage forwards push options and returns pushed ref", async () => {
  const seenBodies: any[] = [];
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      seenBodies.push(await req.json());
      return jsonResponse({ image: "aerolvm-build/abc123:latest", pushed: "ghcr.io/x/y:v1" });
    },
  });

  const result = await client.buildImage(Image.base("alpine"), {
    push: { registry: "ghcr.io/x/y", tag: "v1", server: "ghcr.io", username: "u", password: "p" },
  });
  assert.equal(result.image, "aerolvm-build/abc123:latest");
  assert.equal(result.pushed, "ghcr.io/x/y:v1");
  assert.deepEqual(seenBodies[0].push, {
    registry: "ghcr.io/x/y",
    tag: "v1",
    server: "ghcr.io",
    username: "u",
    password: "p",
  });
});

test("internal client buildImage rejects push without credentials", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async () => jsonResponse({ image: "x" }),
  });
  await assert.rejects(
    client.buildImage(Image.base("alpine"), {
      push: { registry: "ghcr.io/x/y", username: "", password: "p" },
    }),
    /push.username and push.password are required/,
  );
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

test("internal client addCustomDomain POSTs hostname and parses list", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(
        {
          custom_domains: [
            {
              hostname: "api.acme.com",
              status: "pending_dns",
              created_at: "2026-05-24T10:00:00Z",
              updated_at: "2026-05-24T10:00:00Z",
            },
          ],
        },
        201,
      );
    },
  });

  const domains = await client.addCustomDomain("sb-cd", "api.acme.com");
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "POST");
  assert.ok(seenRequest.url.endsWith("/v1/sandboxes/sb-cd/custom-domains"));
  assert.deepEqual(await seenRequest.json(), { hostname: "api.acme.com" });
  assert.equal(domains.length, 1);
  assert.equal(domains[0].hostname, "api.acme.com");
  assert.equal(domains[0].status, "pending_dns");
  assert.equal(domains[0].lastError, undefined);
});

test("internal client addCustomDomain forwards target_port when port option set", async () => {
  let sentBody: { hostname?: string; target_port?: number } | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      sentBody = (await req.json()) as { hostname?: string; target_port?: number };
      return jsonResponse(
        {
          custom_domains: [
            {
              hostname: "api.acme.com",
              status: "pending_dns",
              target_port: 3333,
              created_at: "2026-05-24T10:00:00Z",
              updated_at: "2026-05-24T10:00:00Z",
            },
          ],
        },
        201,
      );
    },
  });

  const domains = await client.addCustomDomain("sb-cd", "api.acme.com", { port: 3333 });
  assert.equal(sentBody?.hostname, "api.acme.com");
  assert.equal(sentBody?.target_port, 3333);
  assert.equal(domains[0].targetPort, 3333);
});

test("internal client addCustomDomain omits target_port when port option absent or zero", async () => {
  const seen: Array<Record<string, unknown>> = [];
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      seen.push((await req.json()) as Record<string, unknown>);
      return jsonResponse({ custom_domains: [] }, 201);
    },
  });

  await client.addCustomDomain("sb-cd", "api.acme.com");
  await client.addCustomDomain("sb-cd", "api.acme.com", {});
  await client.addCustomDomain("sb-cd", "api.acme.com", { port: 0 });
  for (const body of seen) {
    assert.equal("target_port" in body, false);
  }
});

test("internal client addCustomDomain preserves hostname case sent by caller", async () => {
  let sentBody: { hostname?: string } | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      sentBody = (await req.json()) as { hostname?: string };
      return jsonResponse({ custom_domains: [] }, 201);
    },
  });

  await client.addCustomDomain("sb-cd", "API.Acme.COM");
  assert.equal(sentBody?.hostname, "API.Acme.COM");
});

test("internal client listCustomDomains GETs and maps response", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse({
        custom_domains: [
          {
            hostname: "a.example.com",
            status: "ready",
            created_at: "2026-05-24T10:00:00Z",
            updated_at: "2026-05-24T10:05:00Z",
          },
          {
            hostname: "b.example.com",
            status: "failed",
            last_error: "dns lookup failed",
            created_at: "2026-05-24T10:01:00Z",
            updated_at: "2026-05-24T10:06:00Z",
          },
        ],
      });
    },
  });

  const domains = await client.listCustomDomains("sb-cd");
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "GET");
  assert.ok(seenRequest.url.endsWith("/v1/sandboxes/sb-cd/custom-domains"));
  assert.equal(domains.length, 2);
  assert.equal(domains[0].status, "ready");
  assert.equal(domains[1].status, "failed");
  assert.equal(domains[1].lastError, "dns lookup failed");
});

test("internal client removeCustomDomain DELETEs encoded hostname and resolves void", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return new Response(null, { status: 204 });
    },
  });

  const result = await client.removeCustomDomain("sb-cd", "weird host.example.com");
  assert.equal(result, undefined);
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "DELETE");
  assert.ok(seenRequest.url.endsWith("/v1/sandboxes/sb-cd/custom-domains/weird%20host.example.com"));
});

test("internal client addCustomDomain throws with server status on conflict", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async () => jsonResponse({ error: "hostname already bound to another sandbox" }, 409),
  });

  await assert.rejects(
    () => client.addCustomDomain("sb-cd", "api.acme.com"),
    /hostname already bound/,
  );
});

test("internal client addCustomDomain surfaces 412 precondition errors", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async () => jsonResponse({ error: "custom domains require SB_PUBLIC_DOMAIN" }, 412),
  });

  await assert.rejects(
    () => client.addCustomDomain("sb-cd", "api.acme.com"),
    /SB_PUBLIC_DOMAIN/,
  );
});

test("sandbox resource customDomains accessor delegates to client", async () => {
  const calls: string[] = [];
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      if (req.url.endsWith("/v1/sandboxes/sb-cd")) {
        return jsonResponse(apiSandbox("sb-cd"));
      }
      if (req.method === "POST" && req.url.endsWith("/custom-domains")) {
        calls.push("add");
        return jsonResponse(
          {
            custom_domains: [
              {
                hostname: "staging.acme.com",
                status: "pending_dns",
                created_at: "2026-05-24T10:00:00Z",
                updated_at: "2026-05-24T10:00:00Z",
              },
            ],
          },
          201,
        );
      }
      if (req.method === "GET" && req.url.endsWith("/custom-domains")) {
        calls.push("list");
        return jsonResponse({ custom_domains: [] });
      }
      if (req.method === "DELETE" && req.url.includes("/custom-domains/")) {
        calls.push("remove");
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected ${req.method} ${req.url}`);
    },
  });

  const sandbox = await client.get("sb-cd");
  const added = await sandbox.customDomains.add("staging.acme.com");
  assert.equal(added[0].hostname, "staging.acme.com");
  await sandbox.customDomains.list();
  await sandbox.customDomains.remove("staging.acme.com");
  assert.deepEqual(calls, ["add", "list", "remove"]);
});

test("internal client create forwards customDomains as snake_case", async () => {
  let body: { custom_domains?: unknown } | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      body = (await req.json()) as { custom_domains?: unknown };
      return jsonResponse(apiSandbox("sb-cd-create"));
    },
  });

  await client.create({ image: "ubuntu:22.04", customDomains: ["api.acme.com", "www.acme.com"] });
  assert.deepEqual(body?.custom_domains, ["api.acme.com", "www.acme.com"]);
});

test("internal client ingressDNS GETs and returns target verbatim", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse({
        hostname: "ingress.example.com",
        source: "hostname",
      });
    },
  });

  const target = await client.ingressDNS();
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "GET");
  assert.ok(seenRequest.url.endsWith("/v1/ingress/dns"));
  assert.equal(target.hostname, "ingress.example.com");
  assert.equal(target.source, "hostname");
  assert.equal(target.ips, undefined);
});

test("internal client ingressDNS maps IPs source", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async () =>
      jsonResponse({ ips: ["203.0.113.10", "203.0.113.11"], source: "ips" }),
  });

  const target = await client.ingressDNS();
  assert.equal(target.source, "ips");
  assert.deepEqual(target.ips, ["203.0.113.10", "203.0.113.11"]);
  assert.equal(target.hostname, undefined);
});

test("internal client customDomainDNS GETs and maps records + target", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse({
        records: [
          {
            hostname: "api.acme.com",
            type: "CNAME",
            name: "api",
            value: "ingress.example.com",
          },
          {
            hostname: "acme.com",
            type: "A",
            name: "@",
            value: "203.0.113.10",
            notes: "Cloudflare users: set proxy status to DNS only (gray cloud).",
          },
        ],
        target: {
          hostname: "ingress.example.com",
          ips: ["203.0.113.10"],
          source: "mixed",
        },
      });
    },
  });

  const result = await client.customDomainDNS("sb-cd");
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "GET");
  assert.ok(seenRequest.url.endsWith("/v1/sandboxes/sb-cd/custom-domains/dns"));
  assert.equal(result.records.length, 2);
  assert.equal(result.records[0].type, "CNAME");
  assert.equal(result.records[0].value, "ingress.example.com");
  assert.equal(result.records[1].type, "A");
  assert.match(result.records[1].notes ?? "", /Cloudflare/);
  assert.equal(result.target.source, "mixed");
  assert.equal(result.target.hostname, "ingress.example.com");
  assert.deepEqual(result.target.ips, ["203.0.113.10"]);
});

test("sandbox resource customDomains.dns delegates to client", async () => {
  let dnsCalls = 0;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      if (req.url.endsWith("/v1/sandboxes/sb-cd")) {
        return jsonResponse(apiSandbox("sb-cd"));
      }
      if (req.method === "GET" && req.url.endsWith("/custom-domains/dns")) {
        dnsCalls++;
        return jsonResponse({
          records: [
            {
              hostname: "api.acme.com",
              type: "CNAME",
              name: "api",
              value: "ingress.example.com",
            },
          ],
          target: { hostname: "ingress.example.com", source: "hostname" },
        });
      }
      throw new Error(`unexpected ${req.method} ${req.url}`);
    },
  });

  const sandbox = await client.get("sb-cd");
  const result = await sandbox.customDomains.dns();
  assert.equal(dnsCalls, 1);
  assert.equal(result.records[0].hostname, "api.acme.com");
  assert.equal(result.target.source, "hostname");
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
