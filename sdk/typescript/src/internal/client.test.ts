import assert from "node:assert/strict";
import test from "node:test";

import { APIClient, SandboxResource } from "./client.js";
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
      return jsonResponse(apiSandbox("sb-create"));
    },
  });

  const sandbox = await client.create({ image: "ubuntu:22.04", memoryMB: 2048, networkBlockAll: true });
  assert.equal(sandbox.id, "sb-create");
  assert.ok(seenRequest);
  assert.equal(seenRequest.headers.get("authorization"), "Bearer pat-token");
  assert.deepEqual(await seenRequest.json(), {
    image: "ubuntu:22.04",
    memory_mb: 2048,
    network_block_all: true,
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
      return jsonResponse(apiSandbox("sb-resource", { public_url: call === 1 ? "https://old.example.com" : "https://new.example.com" }));
    },
  });

  const sandbox = await client.get("sb-resource");
  await sandbox.refresh();
  assert.equal(sandbox.publicURL, "https://new.example.com");
  await sandbox.resize({ cpu: 8, memoryMB: 8192 });
  assert.equal(sandbox.cpu, 8);
  assert.equal(sandbox.memoryMB, 8192);
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
    ...overrides,
  };
}

void ({} as Sandbox);