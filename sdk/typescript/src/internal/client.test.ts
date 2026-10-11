import assert from "node:assert/strict";
import { createServer, type RequestListener } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { APIClient, SandboxResource } from "./client.js";
import { Image } from "../Image.js";
import type { CreateOptions, Sandbox } from "../types.js";

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

test("internal client create serializes platform volumes", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(apiSandbox("sb-vol"));
    },
  });
  await client.create({
    image: "ubuntu:22.04",
    platformVolumes: [
      { name: "data", path: "/workspace" },
      { name: "cache", path: "/cache", readOnly: true },
    ],
  });
  assert.ok(seenRequest);
  const body = (await seenRequest.json()) as Record<string, unknown>;
  // read_only is omitted (undefined) for the read-write entry after JSON
  // serialization, and present+true for the read-only one.
  assert.deepEqual(body.platform_volumes, [
    { name: "data", path: "/workspace" },
    { name: "cache", path: "/cache", read_only: true },
  ]);
});

test("internal client create omits allowPublicTraffic when unset", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(apiSandbox("sb-default-private"));
    },
  });
  await client.create({ image: "ubuntu:22.04" });
  assert.ok(seenRequest);
  const body = (await seenRequest.json()) as Record<string, unknown>;
  assert.equal(body.allow_public_traffic, undefined);
});

test("internal client create serializes allowPublicTraffic=false", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(apiSandbox("sb-nopublic"));
    },
  });
  await client.create({ image: "ubuntu:22.04", allowPublicTraffic: false });
  assert.ok(seenRequest);
  const body = (await seenRequest.json()) as Record<string, unknown>;
  assert.equal(body.allow_public_traffic, false);
});

test("internal client create serializes maskRequestHost", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(apiSandbox("sb-mask"));
    },
  });
  await client.create({ image: "ubuntu:22.04", maskRequestHost: "localhost" });
  assert.ok(seenRequest);
  const body = (await seenRequest.json()) as Record<string, unknown>;
  assert.equal(body.mask_request_host, "localhost");
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

test("internal client create sends gpus and template_id in the wire shape", async () => {
  const cases: Array<{ name: string; options: Partial<CreateOptions>; want: Record<string, unknown> }> = [
    {
      name: "nvidia with count and device ids",
      options: { gpus: { vendor: "nvidia", count: 2, deviceIDs: ["0", "GPU-abc123"] } },
      want: { gpus: { vendor: "nvidia", count: 2, device_ids: ["0", "GPU-abc123"] } },
    },
    {
      name: "vendor only leaves count and device_ids out",
      options: { gpus: { vendor: "amd" } },
      want: { gpus: { vendor: "amd" } },
    },
    {
      name: "firecracker template",
      options: { runtime: "firecracker", templateId: "py311" },
      want: { runtime: "firecracker", template_id: "py311" },
    },
    {
      name: "neither set stays omitted",
      options: {},
      want: {},
    },
  ];

  for (const tc of cases) {
    let body: Record<string, unknown> | undefined;
    const client = new APIClient({
      baseURL: "https://api.example.com",
      patToken: "pat-token",
      fetch: async (input, init) => {
        body = (await new Request(input, init).json()) as Record<string, unknown>;
        return jsonResponse(apiSandbox("sb-create-fields"));
      },
    });
    await client.create({ image: "python:3.11", ...tc.options });
    assert.deepEqual(body, { image: "python:3.11", ...tc.want }, tc.name);
  }
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

// 421 Misdirected Request: an owner answered for a sandbox it does not hold
// (HTTP/2 connection coalescing or a stale route after failover). The server
// closes the connection, so a retry reconnects and the ingress re-routes it.
test("internal client retries 421 Misdirected Request", async () => {
  let calls = 0;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    retry: { maxRetries: 2, baseDelayMs: 1, maxDelayMs: 1 },
    fetch: async () => {
      calls++;
      if (calls === 1) {
        return new Response(JSON.stringify({ error: "misdirected request; reconnect" }), {
          status: 421,
          headers: { "content-type": "application/json" },
        });
      }
      return jsonResponse(apiSandbox("sb-421"));
    },
  });
  const sandbox = await client.get("sb-421");
  assert.equal(calls, 2);
  assert.ok(sandbox instanceof SandboxResource);
});

// A re-sent exec runs the caller's command again (the Rust SDK once ran a 40 s
// command 4 times), so exec must not retry once the request may have arrived.
test("internal client exec is not re-sent after the server read it", async () => {
  const seen: string[] = [];
  await withServer((req) => {
    seen.push(`${req.method} ${req.url}`);
    req.resume();
    // Read the whole request, then hang up without answering: the command
    // may be running, and the client cannot know.
    req.on("end", () => req.socket.destroy());
  }, async (baseURL) => {
    let attempts = 0;
    const client = new APIClient({
      baseURL,
      patToken: "pat-token",
      retry: { maxRetries: 3, baseDelayMs: 1, maxDelayMs: 1 },
      fetch: (input, init) => {
        attempts++;
        return fetch(input, init);
      },
    });
    await assert.rejects(client.exec("sb-exec", { command: "sleep 40" }), TypeError);
    assert.equal(attempts, 1);
  });
  assert.deepEqual(seen, ["POST /v1/sandboxes/sb-exec/toolbox/process/execute"]);
});

test("internal client exec retries a refused connection", async () => {
  // Grab a free port, then close it so the connect is refused.
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  await new Promise((resolve) => server.close(resolve));

  let attempts = 0;
  const client = new APIClient({
    baseURL: `http://127.0.0.1:${port}`,
    patToken: "pat-token",
    retry: { maxRetries: 2, baseDelayMs: 1, maxDelayMs: 1 },
    fetch: (input, init) => {
      attempts++;
      return fetch(input, init);
    },
  });
  await assert.rejects(client.exec("sb-exec", { command: "true" }), TypeError);
  assert.equal(attempts, 3);
});

test("internal client get still retries a connection closed after the request was read", async () => {
  let served = 0;
  await withServer((req, res) => {
    served++;
    req.resume();
    if (served === 1) {
      req.on("end", () => req.socket.destroy());
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(apiSandbox("sb-get-retry")));
  }, async (baseURL) => {
    let attempts = 0;
    const client = new APIClient({
      baseURL,
      patToken: "pat-token",
      retry: { maxRetries: 2, baseDelayMs: 1, maxDelayMs: 1 },
      fetch: (input, init) => {
        attempts++;
        return fetch(input, init);
      },
    });
    const sandbox = await client.get("sb-get-retry");
    assert.equal(sandbox.id, "sb-get-retry");
    assert.equal(attempts, 2);
  });
  assert.equal(served, 2);
});

test("internal client exec retries only transport errors that prove the request was never sent", async () => {
  const errno = (code: string, syscall?: string, message = code): NodeJS.ErrnoException =>
    Object.assign(new Error(message), { code, syscall });
  // Shape every error the way undici's fetch does: a TypeError whose cause
  // carries the Node / undici code.
  const fetchFailed = (cause: unknown) => new TypeError("fetch failed", { cause });
  const cases: Array<{ name: string; error: unknown; retried: boolean }> = [
    { name: "connection refused", error: fetchFailed(errno("ECONNREFUSED", "connect")), retried: true },
    {
      name: "connection refused on every address",
      error: fetchFailed(Object.assign(
        new AggregateError([errno("ECONNREFUSED", "connect"), errno("ECONNREFUSED", "connect")]),
        { code: "ECONNREFUSED" },
      )),
      retried: true,
    },
    { name: "DNS lookup failed transiently", error: fetchFailed(errno("EAI_AGAIN", "getaddrinfo")), retried: true },
    { name: "undici connect timeout", error: fetchFailed(errno("UND_ERR_CONNECT_TIMEOUT")), retried: true },
    { name: "TCP connect timed out", error: fetchFailed(errno("ETIMEDOUT", "connect")), retried: true },
    {
      name: "TCP connect timed out on every address",
      error: fetchFailed(Object.assign(
        new AggregateError([errno("ETIMEDOUT", "connect"), errno("ETIMEDOUT", "connect")]),
        { code: "ETIMEDOUT" },
      )),
      retried: true,
    },
    { name: "open socket timed out", error: fetchFailed(errno("ETIMEDOUT", "read")), retried: false },
    { name: "ETIMEDOUT with no syscall", error: fetchFailed(errno("ETIMEDOUT")), retried: false },
    { name: "headers timeout", error: fetchFailed(errno("UND_ERR_HEADERS_TIMEOUT")), retried: false },
    { name: "body timeout", error: fetchFailed(errno("UND_ERR_BODY_TIMEOUT")), retried: false },
    { name: "connection reset", error: fetchFailed(errno("ECONNRESET", "read")), retried: false },
    { name: "broken pipe", error: fetchFailed(errno("EPIPE", "write")), retried: false },
    { name: "other side closed", error: fetchFailed(errno("UND_ERR_SOCKET", undefined, "other side closed")), retried: false },
    { name: "socket hang up", error: fetchFailed(new Error("socket hang up")), retried: false },
  ];

  for (const tc of cases) {
    let attempts = 0;
    const client = new APIClient({
      baseURL: "https://api.example.com",
      patToken: "pat-token",
      retry: { maxRetries: 2, baseDelayMs: 1, maxDelayMs: 1 },
      fetch: async () => {
        attempts++;
        throw tc.error;
      },
    });
    await assert.rejects(client.exec("sb-exec", { command: "true" }), (err) => err === tc.error, tc.name);
    assert.equal(attempts, tc.retried ? 3 : 1, tc.name);
  }
});

test("internal client exec retries 429 and 503 but surfaces other gateway statuses", async () => {
  const cases: Array<{ status: number; retried: boolean }> = [
    { status: 429, retried: true },
    { status: 503, retried: true },
    { status: 421, retried: false },
    { status: 502, retried: false },
    { status: 504, retried: false },
  ];

  for (const tc of cases) {
    let attempts = 0;
    const client = new APIClient({
      baseURL: "https://api.example.com",
      patToken: "pat-token",
      retry: { maxRetries: 2, baseDelayMs: 1, maxDelayMs: 1 },
      fetch: async () => {
        attempts++;
        if (attempts === 1) {
          return jsonResponse({ error: `status ${tc.status}` }, tc.status);
        }
        return jsonResponse({ stdout: "ok\n", stderr: "", exit_code: 0, duration_ms: 1 });
      },
    });
    const run = client.exec("sb-exec", { command: "echo ok" });
    if (tc.retried) {
      assert.equal((await run).stdout, "ok\n", `status ${tc.status}`);
      assert.equal(attempts, 2, `status ${tc.status}`);
    } else {
      await assert.rejects(run, { message: `status ${tc.status}` });
      assert.equal(attempts, 1, `status ${tc.status}`);
    }
  }
});

async function withServer(handler: RequestListener, fn: (baseURL: string) => Promise<void>): Promise<void> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

test("internal client getAudit sends filters and maps the page", async () => {
  let seenRequest: Request | undefined;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse({
        events: [
          {
            time: "2026-10-06T10:00:00Z",
            kind: "egress",
            result: "failure",
            reason: "host_not_allowed",
            destination: "evil.example:443",
            network: "tcp",
            event_id: "ae-1",
            incarnation_id: "inc-1",
          },
        ],
        coverage: { answered: ["node-a"], missing: null, partial: false },
        next_cursor: "c2",
      });
    },
  });

  const page = await client.getAudit("sb-audit", { kind: "egress", limit: 50, cursor: "c1", incarnationID: "inc-1" });
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "GET");
  const url = new URL(seenRequest.url);
  assert.equal(url.pathname, "/v1/sandboxes/sb-audit/audit");
  assert.equal(url.searchParams.get("kind"), "egress");
  assert.equal(url.searchParams.get("limit"), "50");
  assert.equal(url.searchParams.get("cursor"), "c1");
  assert.equal(url.searchParams.get("incarnation_id"), "inc-1");
  assert.equal(page.events[0].reason, "host_not_allowed");
  assert.equal(page.events[0].eventID, "ae-1");
  assert.deepEqual(page.coverage, { answered: ["node-a"], missing: [], partial: false });
  assert.equal(page.nextCursor, "c2");
});

test("internal client getAudit without options sends no query and tolerates null events", async () => {
  let seenURL = "";
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seenURL = new Request(input, init).url;
      return jsonResponse({ events: null });
    },
  });
  const page = await client.getAudit("sb-x");
  assert.ok(seenURL.endsWith("/v1/sandboxes/sb-x/audit"));
  assert.deepEqual(page, { events: [], coverage: { answered: [], missing: [], partial: false } });
});

test("sandbox.audit reads its own sandbox's log", async () => {
  const urls: string[] = [];
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      urls.push(req.url);
      if (req.method === "POST") return jsonResponse(apiSandbox("sb-own"));
      return jsonResponse({ events: [], coverage: { answered: [], missing: [], partial: false } });
    },
  });
  const sandbox = await client.create({ image: "ubuntu:22.04" });
  await sandbox.audit({ kind: "egress" });
  assert.ok(urls[urls.length - 1].endsWith("/v1/sandboxes/sb-own/audit?kind=egress"));
});

test("get maps egress_status for gateway-mode sandboxes", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async () => jsonResponse({ ...apiSandbox("sb-eg"), egress_status: "held" }),
  });
  const sandbox = await client.get("sb-eg");
  assert.equal(sandbox.egressStatus, "held");
});

test("checkNetworkPolicy posts the policy and maps the answer", async () => {
  let seen: Request | undefined;
  let body: Record<string, unknown> = {};
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seen = new Request(input, init);
      body = JSON.parse(String(init?.body));
      return jsonResponse({ allowed: true, matched_rule: "*.github.com", default_verdict: "deny", outside_ceiling: "x.example" });
    },
  });
  const res = await client.checkNetworkPolicy({ networkAllowOut: ["*.github.com"], destination: "api.github.com" });
  assert.ok(seen && seen.url.endsWith("/v1/network/policy/check"));
  assert.equal(seen?.method, "POST");
  assert.deepEqual(body.network_allow_out, ["*.github.com"]);
  assert.equal(body.destination, "api.github.com");
  assert.deepEqual(res, { allowed: true, matchedRule: "*.github.com", defaultVerdict: "deny", outsideCeiling: "x.example" });
});

test("setNetworkPolicy PUTs the whole policy and maps the effective one", async () => {
  let seen: Request | undefined;
  let body: Record<string, unknown> = {};
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      seen = new Request(input, init);
      body = JSON.parse(String(init?.body));
      return jsonResponse({ network_block_all: false, network_allow_out: ["pypi.org"], network_deny_out: null, egress_profiles: ["python"], effective_hostname_count: 3, egress_status: "active" });
    },
  });
  const res = await client.setNetworkPolicy("sb-pol", { networkAllowOut: ["pypi.org"], egressProfiles: ["python"] });
  assert.ok(seen && seen.url.endsWith("/v1/sandboxes/sb-pol/network/policy"));
  assert.equal(seen?.method, "PUT");
  assert.deepEqual(body, { network_block_all: false, network_allow_out: ["pypi.org"], network_deny_out: [], egress_profiles: ["python"] });
  assert.deepEqual(res, { networkBlockAll: false, networkAllowOut: ["pypi.org"], networkDenyOut: [], egressProfiles: ["python"], networkEgressMode: "enforce", networkEgressRules: [], effectiveHostnameCount: 3, egressStatus: "active" });
});

test("sandbox.setNetworkPolicy updates its own policy fields", async () => {
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      if (req.method === "POST") return jsonResponse(apiSandbox("sb-own"));
      assert.ok(req.url.endsWith("/v1/sandboxes/sb-own/network/policy"));
      return jsonResponse({ network_block_all: true, network_allow_out: [], network_deny_out: [] });
    },
  });
  const sandbox = await client.create({ image: "ubuntu:22.04" });
  const res = await sandbox.setNetworkPolicy({ networkBlockAll: true });
  assert.equal(res.networkBlockAll, true);
  assert.equal(sandbox.networkBlockAll, true);
  assert.equal(sandbox.egressStatus, undefined);
});

test("egress profile CRUD maps the wire shape", async () => {
  const seen: { method: string; url: string; body?: unknown }[] = [];
  const profile = { name: "python", allow_out: ["pypi.org"], description: "pip", generation: 2, created_at: "c", updated_at: "u" };
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      seen.push({ method: req.method, url: req.url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (req.method === "DELETE") return new Response(null, { status: 204 });
      if (req.url.includes("/egress-profiles?")) return jsonResponse({ profiles: [profile], next_cursor: "python" });
      if (req.url.endsWith("/egress-profiles")) return jsonResponse({ profiles: null });
      return jsonResponse(profile);
    },
  });
  const put = await client.putEgressProfile("python", { allowOut: ["pypi.org"], description: "pip" });
  assert.deepEqual(put, { name: "python", allowOut: ["pypi.org"], description: "pip", generation: 2, createdAt: "c", updatedAt: "u" });
  assert.deepEqual(seen[0], { method: "PUT", url: "https://api.example.com/v1/egress-profiles/python", body: { allow_out: ["pypi.org"], description: "pip" } });
  assert.equal((await client.getEgressProfile("python")).generation, 2);
  const page = await client.listEgressProfiles({ cursor: "a", limit: 10 });
  assert.equal(page.nextCursor, "python");
  assert.ok(seen[2].url.endsWith("/v1/egress-profiles?cursor=a&limit=10"));
  assert.deepEqual(await client.listEgressProfiles(), { profiles: [] });
  await client.deleteEgressProfile("python");
  assert.equal(seen[4].method, "DELETE");
});

test("sandboxes carry their egress profiles", async () => {
  let body: Record<string, unknown> = {};
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (_input, init) => {
      if (init?.body) body = JSON.parse(String(init.body));
      return jsonResponse({ ...apiSandbox("sb-p"), egress_profiles: ["python"], egress_profiles_applied: [{ name: "python", generation: 2 }] });
    },
  });
  const sandbox = await client.create({ image: "alpine", egressProfiles: ["python"] });
  assert.deepEqual(body.egress_profiles, ["python"]);
  assert.deepEqual(sandbox.egressProfiles, ["python"]);
  assert.deepEqual(sandbox.egressProfilesApplied, [{ name: "python", generation: 2 }]);
});

test("learn mode: create, the policy answer and the learned read", async () => {
  const bodies: Record<string, unknown>[] = [];
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      if (init?.body) bodies.push(JSON.parse(String(init.body)));
      if (req.url.endsWith("/network/learned")) {
        return jsonResponse({
          mode: "learn",
          truncated: false,
          entries: [{ host: "pypi.org", ports: [443], first_seen: "a", last_seen: "b", hits: 3 }],
          cidrs: null,
          suggested_allow_out: ["pypi.org"],
          suggested_profile: { allow_out: ["x.example"], description: "d" },
        });
      }
      if (req.url.endsWith("/network/policy")) {
        return jsonResponse({ network_block_all: false, network_allow_out: [], network_deny_out: [], network_egress_mode: "learn" });
      }
      return jsonResponse({ ...apiSandbox("sb-learn"), network_egress_mode: "learn" });
    },
  });
  const sandbox = await client.create({ image: "alpine", networkEgressMode: "learn" });
  assert.equal(bodies[0].network_egress_mode, "learn");
  assert.equal(sandbox.networkEgressMode, "learn");
  const pol = await sandbox.setNetworkPolicy({ networkEgressMode: "learn" });
  assert.equal(pol.networkEgressMode, "learn");
  assert.equal(bodies[1].network_egress_mode, "learn");
  const learned = await sandbox.learned();
  assert.deepEqual(learned.entries[0], { host: "pypi.org", ports: [443], firstSeen: "a", lastSeen: "b", hits: 3 });
  assert.deepEqual(learned.cidrs, []);
  assert.deepEqual(learned.suggestedProfile, { allowOut: ["x.example"], description: "d" });
});

test("egress rules: create, the policy answer and the sandbox's own copy", async () => {
  const bodies: Record<string, unknown>[] = [];
  const rule = { host: "api.github.com", methods: ["GET"], paths: ["/repos/acme/**"], inspect: true };
  let policyRules: unknown = [rule];
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      if (init?.body) bodies.push(JSON.parse(String(init.body)));
      if (req.url.endsWith("/network/policy")) {
        return jsonResponse({ network_block_all: false, network_allow_out: ["api.github.com"], network_deny_out: [], network_egress_rules: policyRules });
      }
      return jsonResponse({ ...apiSandbox("sb-rules"), network_egress_rules: [{ ...rule, ports: [443] }] });
    },
  });
  const sandbox = await client.create({ image: "alpine", networkAllowOut: ["api.github.com"], networkEgressRules: [rule] });
  assert.deepEqual(bodies[0].network_egress_rules, [rule]);
  assert.deepEqual(sandbox.networkEgressRules, [{ ...rule, ports: [443] }]);

  const pol = await sandbox.setNetworkPolicy({ networkAllowOut: ["api.github.com"], networkEgressRules: [rule] });
  assert.deepEqual(bodies[1].network_egress_rules, [rule]);
  assert.deepEqual(pol.networkEgressRules, [rule]);
  assert.deepEqual(sandbox.networkEgressRules, [rule]);

  policyRules = null;
  const cleared = await sandbox.setNetworkPolicy({ networkAllowOut: ["api.github.com"] });
  assert.equal("network_egress_rules" in bodies[2], false);
  assert.deepEqual(cleared.networkEgressRules, []);
  assert.equal(sandbox.networkEgressRules, undefined);
});

test("egress rules: inject goes out as secret_ref and comes back as secretRef", async () => {
  const bodies: Record<string, unknown>[] = [];
  const rule = { host: "api.github.com", inspect: true, paths: ["/repos/**"], inject: { header: "Authorization", secretRef: "env:GITHUB_TOKEN" } };
  const wire = { host: "api.github.com", inspect: true, paths: ["/repos/**"], inject: { header: "Authorization", secret_ref: "env:GITHUB_TOKEN" } };
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      if (init?.body) bodies.push(JSON.parse(String(init.body)));
      if (req.url.endsWith("/network/policy")) {
        return jsonResponse({ network_block_all: false, network_allow_out: ["api.github.com"], network_deny_out: [], network_egress_rules: [wire] });
      }
      return jsonResponse({ ...apiSandbox("sb-inject"), network_egress_rules: [{ ...wire, ports: [443] }] });
    },
  });
  const sandbox = await client.create({
    image: "alpine",
    env: { GITHUB_TOKEN: "Bearer ghp_x" },
    networkAllowOut: ["api.github.com"],
    networkEgressRules: [rule],
  });
  assert.deepEqual(bodies[0].network_egress_rules, [wire]);
  assert.deepEqual(sandbox.networkEgressRules, [{ ...rule, ports: [443] }]);

  // A rule without inject goes out unchanged, with no inject key at all.
  const pol = await sandbox.setNetworkPolicy({ networkAllowOut: ["api.github.com"], networkEgressRules: [rule, { host: "api.github.com" }] });
  assert.deepEqual(bodies[1].network_egress_rules, [wire, { host: "api.github.com" }]);
  assert.deepEqual(pol.networkEgressRules, [rule]);
  assert.deepEqual(sandbox.networkEgressRules, [rule]);
});

test("egress rules: binaries go out and come back as written", async () => {
  const bodies: Record<string, unknown>[] = [];
  const git = { host: "github.com", ports: [22], binaries: ["/usr/bin/git"] };
  const pip = { host: "pypi.org", ports: [443], binaries: ["/usr/local/bin/pip"] };
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      if (init?.body) bodies.push(JSON.parse(String(init.body)));
      if (req.url.endsWith("/network/policy")) {
        return jsonResponse({ network_block_all: false, network_allow_out: ["github.com:22", "pypi.org"], network_deny_out: [], network_egress_rules: [git, pip] });
      }
      return jsonResponse({ ...apiSandbox("sb-binaries"), network_egress_rules: [git, pip] });
    },
  });
  const sandbox = await client.create({ image: "alpine", networkAllowOut: ["github.com:22", "pypi.org"], networkEgressRules: [git, pip] });
  assert.deepEqual(bodies[0].network_egress_rules, [git, pip]);
  assert.deepEqual(sandbox.networkEgressRules, [git, pip]);

  // A rule without binaries goes out with no binaries key at all.
  const pol = await sandbox.setNetworkPolicy({ networkAllowOut: ["github.com:22", "pypi.org"], networkEgressRules: [git, { host: "pypi.org" }] });
  assert.deepEqual(bodies[1].network_egress_rules, [git, { host: "pypi.org" }]);
  assert.deepEqual(pol.networkEgressRules, [git, pip]);
  assert.deepEqual(sandbox.networkEgressRules, [git, pip]);
});
