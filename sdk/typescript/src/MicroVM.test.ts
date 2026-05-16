import assert from "node:assert/strict";
import test from "node:test";

import { Image } from "./Image.js";
import { MicroVM } from "./MicroVM.js";
import { Sandbox } from "./Sandbox.js";

test("MicroVM uses explicit config and returns Sandbox resources", async () => {
  let seenAuthorization = "";
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com/",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      seenAuthorization = request.headers.get("authorization") ?? "";
      return new Response(JSON.stringify({
        id: "sb-structured",
        image: "ubuntu:22.04",
        status: "started",
        public_url: "https://sb-structured.example.com",
        cpu: 2,
        memory_mb: 2048,
        disk_gb: 20,
        os_user: "root",
        network_block_all: false,
        toolbox_enabled: true,
        exposed_ports: [],
        created_at: "2026-05-07T10:00:00Z",
        updated_at: "2026-05-07T10:00:00Z",
        last_active_at: "2026-05-07T10:00:00Z",
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const sandbox = await sdk.get("sb-structured");
  assert.equal(sdk.apiUrl, "https://api.example.com");
  assert.equal(seenAuthorization, "Bearer pat-token");
  assert.ok(sandbox instanceof Sandbox);
  assert.equal(sandbox.id, "sb-structured");
});

test("MicroVM create returns SSH key material", async () => {
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com/",
    fetch: async () => new Response(JSON.stringify({
      id: "sb-create",
      image: "ubuntu:22.04",
      status: "started",
      public_url: "https://sb-create.example.com",
      cpu: 2,
      memory_mb: 2048,
      disk_gb: 20,
      os_user: "root",
      network_block_all: false,
      toolbox_enabled: true,
      ssh_public_key: "ssh-ed25519 AAAA sandbox",
      ssh_private_key: "PRIVATE",
      exposed_ports: [],
      created_at: "2026-05-07T10:00:00Z",
      updated_at: "2026-05-07T10:00:00Z",
      last_active_at: "2026-05-07T10:00:00Z",
    }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  });

  const sandbox = await sdk.create({ image: "ubuntu:22.04" });

  assert.equal(sandbox.id, "sb-create");
  assert.equal(sandbox.sshPublicKey, "ssh-ed25519 AAAA sandbox");
  assert.equal(sandbox.sshPrivateKey, "PRIVATE");
  assert.deepEqual(sandbox.lifecycle, {});
});

test("MicroVM updateLifecycle returns wrapped sandboxes", async () => {
  const seen: Array<{ method: string; url: string; body: unknown }> = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const bodyText = request.method === "GET" || request.method === "DELETE" ? undefined : await request.text();
      seen.push({
        method: request.method,
        url: request.url,
        body: bodyText ? JSON.parse(bodyText) : undefined,
      });

      if (request.url.endsWith("/v1/sandboxes/sb-lifecycle/lifecycle") && request.method === "PUT") {
        return new Response(JSON.stringify({
          id: "sb-lifecycle",
          image: "ubuntu:22.04",
          status: "started",
          public_url: "https://sb-lifecycle.example.com",
          cpu: 2,
          memory_mb: 2048,
          disk_gb: 20,
          os_user: "root",
          network_block_all: false,
          toolbox_enabled: true,
          exposed_ports: [],
          created_at: "2026-05-07T10:00:00Z",
          updated_at: "2026-05-07T11:00:00Z",
          last_active_at: "2026-05-07T10:30:00Z",
          lifecycle: {
            stop_if_idle_for: 7_200_000_000_000,
            destroy_at_age: 172_800_000_000_000,
          },
        }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      throw new Error(`unexpected request: ${request.method} ${request.url}`);
    },
  });

  const sandbox = await sdk.updateLifecycle("sb-lifecycle", {
    stopIfIdleFor: 7_200_000_000_000,
    destroyAtAge: 172_800_000_000_000,
  });

  assert.deepEqual(seen[0]?.body, {
    stop_if_idle_for: 7_200_000_000_000,
    destroy_at_age: 172_800_000_000_000,
  });
  assert.deepEqual(sandbox.lifecycle, {
    stopIfIdleFor: 7_200_000_000_000,
    destroyAtAge: 172_800_000_000_000,
  });
});

test("MicroVM createSnapshot returns snapshot metadata", async () => {
  const seen: Array<{ method: string; url: string; body: unknown }> = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const bodyText = request.method === "GET" || request.method === "DELETE" ? undefined : await request.text();
      seen.push({
        method: request.method,
        url: request.url,
        body: bodyText ? JSON.parse(bodyText) : undefined,
      });
      return new Response(JSON.stringify({
        name: "snapshots/demo:v1",
        image: "snapshots/demo:v1",
        image_id: "sha256:snap-1",
        source_sandbox_id: "sb-demo",
        created_at: "2026-05-14T10:00:00Z",
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const snapshot = await sdk.createSnapshot("sb-demo", "snapshots/demo:v1");
  assert.deepEqual(seen[0]?.body, { name: "snapshots/demo:v1" });
  assert.equal(snapshot.imageID, "sha256:snap-1");
  assert.equal(snapshot.sourceSandboxID, "sb-demo");
});

test("MicroVM registerSnapshot returns persisted snapshot metadata", async () => {
  const seen: Array<{ method: string; url: string; body: unknown }> = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const bodyText = request.method === "GET" || request.method === "DELETE" ? undefined : await request.text();
      seen.push({
        method: request.method,
        url: request.url,
        body: bodyText ? JSON.parse(bodyText) : undefined,
      });
      return new Response(JSON.stringify({
        name: "py-base",
        image: "python:3.12-slim",
        source_sandbox_id: "",
        created_at: "2026-05-15T10:00:00Z",
        region_id: "us",
        cpu: 2,
        memory_mb: 4096,
        disk_gb: 10,
      }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const snapshot = await sdk.registerSnapshot({
    name: "py-base",
    image: "python:3.12-slim",
    regionID: "us",
    cpu: 2,
    memoryMB: 4096,
    diskGB: 10,
  });

  assert.deepEqual(seen[0]?.body, {
    name: "py-base",
    image: "python:3.12-slim",
    region_id: "us",
    cpu: 2,
    memory_mb: 4096,
    disk_gb: 10,
  });
  assert.equal(snapshot.regionID, "us");
  assert.equal(snapshot.memoryMB, 4096);
});

test("MicroVM registerSnapshotFromImage sends dockerfile_content", async () => {
  const seen: Array<{ method: string; url: string; body: unknown }> = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const bodyText = request.method === "GET" || request.method === "DELETE" ? undefined : await request.text();
      seen.push({
        method: request.method,
        url: request.url,
        body: bodyText ? JSON.parse(bodyText) : undefined,
      });
      return new Response(JSON.stringify({
        name: "built",
        image: "snapshots/built:resolved",
        source_sandbox_id: "",
        created_at: "2026-05-15T10:00:00Z",
      }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const snapshot = await sdk.registerSnapshotFromImage(
    "built",
    Image.base("debian:bookworm-slim").runCommands("apt-get update"),
    { entrypoint: ["/bin/sh", "-c", "echo hi"] },
  );

  const payload = seen[0]?.body as Record<string, unknown>;
  assert.equal(payload?.name, "built");
  assert.match(String(payload?.dockerfile_content), /FROM debian:bookworm-slim/);
  assert.equal("image" in payload, false);
  assert.deepEqual(payload?.entrypoint, ["/bin/sh", "-c", "echo hi"]);
  assert.equal(snapshot.image, "snapshots/built:resolved");
});

test("MicroVM create serializes mounts and mounts endpoint returns redacted specs", async () => {
  const seen: Array<{ method: string; url: string; body: unknown }> = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const bodyText = request.method === "GET" || request.method === "DELETE" ? undefined : await request.text();
      seen.push({
        method: request.method,
        url: request.url,
        body: bodyText ? JSON.parse(bodyText) : undefined,
      });

      if (request.url.endsWith("/v1/sandboxes") && request.method === "POST") {
        return new Response(JSON.stringify({
          id: "sb-mounted",
          image: "ubuntu:22.04",
          status: "started",
          public_url: "https://sb-mounted.example.com",
          cpu: 2,
          memory_mb: 2048,
          disk_gb: 20,
          os_user: "root",
          network_block_all: false,
          toolbox_enabled: true,
          exposed_ports: [],
          created_at: "2026-05-07T10:00:00Z",
          updated_at: "2026-05-07T10:00:00Z",
          last_active_at: "2026-05-07T10:00:00Z",
        }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (request.url.endsWith("/v1/sandboxes/sb-mounted/mounts") && request.method === "GET") {
        return new Response(JSON.stringify({
          mounts: [
            {
              type: "s3",
              target: "/workspace",
              source: "s3://bucket/prefix",
              options: { region: "us-east-1" },
              read_only: true,
              has_credentials: true,
            },
          ],
        }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      throw new Error(`unexpected request: ${request.method} ${request.url}`);
    },
  });

  await sdk.create({
    image: "ubuntu:22.04",
    mounts: [
      {
        type: "s3",
        target: "/workspace",
        source: "s3://bucket/prefix",
        options: { region: "us-east-1" },
        credentials: { access_key_id: "AKIA", secret_access_key: "SECRET" },
        readOnly: true,
      },
    ],
  });
  const mounts = await sdk.mounts("sb-mounted");

  assert.deepEqual(seen[0]?.body, {
    image: "ubuntu:22.04",
    mounts: [
      {
        type: "s3",
        target: "/workspace",
        source: "s3://bucket/prefix",
        options: { region: "us-east-1" },
        credentials: { access_key_id: "AKIA", secret_access_key: "SECRET" },
        read_only: true,
      },
    ],
  });
  assert.deepEqual(mounts, [
    {
      type: "s3",
      target: "/workspace",
      source: "s3://bucket/prefix",
      options: { region: "us-east-1" },
      readOnly: true,
      hasCredentials: true,
    },
  ]);
});

test("Sandbox session methods map API shapes", async () => {
  const seen: Array<{ method: string; url: string; body: unknown }> = [];
  const sandboxPayload = {
    id: "sb-1",
    image: "ubuntu:22.04",
    status: "started",
    public_url: "https://sb-1.example.com",
    cpu: 2,
    memory_mb: 2048,
    disk_gb: 20,
    os_user: "root",
    network_block_all: false,
    toolbox_enabled: true,
    exposed_ports: [],
    created_at: "2026-05-07T10:00:00Z",
    updated_at: "2026-05-07T10:00:00Z",
    last_active_at: "2026-05-07T10:00:00Z",
  };
  const sessionPayload = {
    id: "ses-1",
    name: "default",
    argv: ["bash"],
    workdir: "/workspace",
    pty: true,
    status: "running",
    exit_code: 0,
    created_at: "2026-05-07T10:00:00Z",
    started_at: "2026-05-07T10:00:01Z",
    recording: true,
    bytes: 42,
    attached: 1,
  };

  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const bodyText = request.method === "GET" || request.method === "DELETE" ? undefined : await request.text();
      seen.push({
        method: request.method,
        url: request.url,
        body: bodyText ? JSON.parse(bodyText) : undefined,
      });

      if (request.url.endsWith("/v1/sandboxes/sb-1") && request.method === "GET") {
        return new Response(JSON.stringify(sandboxPayload), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (request.url.endsWith("/v1/sandboxes/sb-1/sessions") && request.method === "POST") {
        return new Response(JSON.stringify(sessionPayload), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (request.url.endsWith("/v1/sandboxes/sb-1/sessions") && request.method === "GET") {
        return new Response(JSON.stringify({ sessions: [sessionPayload] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (request.url.endsWith("/v1/sandboxes/sb-1/sessions/ses-1") && request.method === "GET") {
        return new Response(JSON.stringify({ ...sessionPayload, bytes: 99 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (request.url.endsWith("/v1/sandboxes/sb-1/sessions/ses-1/signal") && request.method === "POST") {
        return new Response(null, { status: 204 });
      }
      if (request.url.endsWith("/v1/sandboxes/sb-1/sessions/ses-1/resize") && request.method === "POST") {
        return new Response(null, { status: 204 });
      }
      if (request.url.endsWith("/v1/sandboxes/sb-1/sessions/ses-1/log") && request.method === "GET") {
        return new Response("hello world", { status: 200 });
      }
      if (request.url.endsWith("/v1/sandboxes/sb-1/sessions/ses-1/recording") && request.method === "GET") {
        return new Response('{"version":2}', { status: 200 });
      }
      if (request.url.endsWith("/v1/sandboxes/sb-1/sessions/ses-1") && request.method === "DELETE") {
        return new Response(null, { status: 204 });
      }

      throw new Error(`unexpected request: ${request.method} ${request.url}`);
    },
  });

  const sandbox = await sdk.get("sb-1");
  const created = await sandbox.createSession({ name: "default", command: "bash", workDir: "/workspace", pty: true, cols: 120, rows: 40 });
  const listed = await sandbox.listSessions();
  const loaded = await sandbox.getSession("ses-1");
  await sandbox.signalSession("ses-1", "TERM");
  await sandbox.resizeSession("ses-1", 120, 40);
  const log = await sandbox.sessionLog("ses-1");
  const recording = await sandbox.sessionRecording("ses-1");
  await sandbox.deleteSession("ses-1");

  assert.equal(created.name, "default");
  assert.equal(listed.length, 1);
  assert.equal(loaded.bytes, 99);
  assert.equal(new TextDecoder().decode(log), "hello world");
  assert.equal(new TextDecoder().decode(recording), '{"version":2}');
  assert.deepEqual(seen[1]?.body, { name: "default", command: "bash", workdir: "/workspace", pty: true, cols: 120, rows: 40 });
  assert.deepEqual(seen[4]?.body, { signal: "TERM" });
  assert.deepEqual(seen[5]?.body, { cols: 120, rows: 40 });
});

test("MicroVM reads PAT token and API URL from environment", async () => {
  const originalPat = process.env.SB_PAT_TOKEN;
  const originalURL = process.env.SB_API_URL;
  process.env.SB_PAT_TOKEN = "env-pat";
  process.env.SB_API_URL = "https://env.example.com/";

  try {
    let seenURL = "";
    let seenAuthorization = "";
    const sdk = new MicroVM({
      fetch: async (input, init) => {
        const request = new Request(input, init);
        seenURL = request.url;
        seenAuthorization = request.headers.get("authorization") ?? "";
        return new Response(JSON.stringify([]), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });

    await sdk.list();
    assert.equal(sdk.apiUrl, "https://env.example.com");
    assert.equal(seenAuthorization, "Bearer env-pat");
    assert.match(seenURL, /^https:\/\/env\.example\.com\/v1\/sandboxes$/);
  } finally {
    if (originalPat === undefined) {
      delete process.env.SB_PAT_TOKEN;
    } else {
      process.env.SB_PAT_TOKEN = originalPat;
    }
    if (originalURL === undefined) {
      delete process.env.SB_API_URL;
    } else {
      process.env.SB_API_URL = originalURL;
    }
  }
});

test("MicroVM requires a PAT token", () => {
  assert.throws(() => {
    new MicroVM({ apiUrl: "https://api.example.com" });
  }, /PAT token is required/);
});

// Mirrors pkg/api/v1/list_filter_test.go: every supplied tag must land in the
// query string verbatim under the `tag.` prefix the server's parseTagFilter
// keys on. If this drifts (e.g. someone switches to `?tags[user_id]=...`), the
// server silently returns the full list and breaks multi-tenant scoping.
test("MicroVM.list forwards tag filters as ?tag.<k>=<v>", async () => {
  let seenURL = "";
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input) => {
      seenURL = new Request(input).url;
      return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  await sdk.list({ tags: { user_id: "alice", project_id: "p1" } });
  const url = new URL(seenURL);
  assert.equal(url.pathname, "/v1/sandboxes");
  assert.equal(url.searchParams.get("tag.user_id"), "alice");
  assert.equal(url.searchParams.get("tag.project_id"), "p1");
});

// URL-encoding is delegated to encodeURIComponent in buildTagQuery; this pins
// that both keys and values with reserved characters (=, &, spaces) survive
// the round trip via the server's url.Values decode.
test("MicroVM.list URL-encodes tag keys and values", async () => {
  let seenURL = "";
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input) => {
      seenURL = new Request(input).url;
      return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  await sdk.list({ tags: { "user/id": "alice bob", "needs=encode": "v&v" } });
  const url = new URL(seenURL);
  assert.equal(url.searchParams.get("tag.user/id"), "alice bob");
  assert.equal(url.searchParams.get("tag.needs=encode"), "v&v");
});

// Backward-compat: list() with no options and list({}) must produce the
// pre-filter URL byte-for-byte so existing fixtures, request matchers, and
// proxies don't see a stray "?".
test("MicroVM.list omits the query string when no tags are supplied", async () => {
  const urls: string[] = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input) => {
      urls.push(new Request(input).url);
      return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  await sdk.list();
  await sdk.list({});
  await sdk.list({ tags: {} });
  for (const u of urls) {
    assert.equal(u, "https://api.example.com/v1/sandboxes");
  }
});

test("MicroVM health maps ssh gateway state", async () => {
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async () => new Response(JSON.stringify({
      status: "degraded",
      sandboxes: 1,
      docker: "ok",
      caddy: "ok",
      ssh_gateway: "disabled",
      version: "dev",
    }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  });

  const health = await sdk.health();

  assert.equal(health.sshGateway, "disabled");
});

test("Sandbox execStream uses sandbox bearer subprotocol", async () => {
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

    const sdk = new MicroVM({
      patToken: "pat-token",
      apiUrl: "https://api.example.com",
      fetch: async () => new Response(JSON.stringify({
        id: "sb-stream",
        image: "ubuntu:22.04",
        status: "started",
        public_url: "https://sb-stream.example.com",
        cpu: 2,
        memory_mb: 2048,
        disk_gb: 20,
        os_user: "root",
        network_block_all: false,
        toolbox_enabled: true,
        exposed_ports: [],
        created_at: "2026-05-07T10:00:00Z",
        updated_at: "2026-05-07T10:00:00Z",
        last_active_at: "2026-05-07T10:00:00Z",
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    });

    const sandbox = await sdk.get("sb-stream");
    const handle = sandbox.execStream({
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

test("MicroVM execStream uses sandbox bearer subprotocol", async () => {
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

    close(): void {
      this.emit("close");
    }

    emit(name: string, event?: unknown): void {
      for (const listener of this.listeners.get(name) ?? []) {
        listener(event);
      }
    }
  }

  try {
    globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;

    const sdk = new MicroVM({ patToken: "pat-token", apiUrl: "https://api.example.com" });
    sdk.execStream("sb-stream", { command: "bash", tty: true, cols: 120, rows: 40 });

    const ws = FakeWebSocket.instances[0];
    assert.ok(ws);
    assert.equal(ws.url, "wss://api.example.com/v1/sandboxes/sb-stream/toolbox/process/exec/stream");
    assert.deepEqual(ws.protocols, ["sandbox.bearer", "pat-token"]);

    ws.emit("open");
    assert.deepEqual(JSON.parse(String(ws.sent[0])), {
      command: "bash",
      tty: true,
      cols: 120,
      rows: 40,
    });
  } finally {
    globalThis.WebSocket = originalWebSocket;
  }
});

test("Sandbox attachSession uses sandbox bearer subprotocol", async () => {
  const originalWebSocket = globalThis.WebSocket;
  const stdoutChunks: Uint8Array[] = [];
  const stderrChunks: Uint8Array[] = [];
  const exits: Array<{ code: number; signal?: string }> = [];

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

    const sdk = new MicroVM({
      patToken: "pat-token",
      apiUrl: "https://api.example.com",
      fetch: async () => new Response(JSON.stringify({
        id: "sb-stream",
        image: "ubuntu:22.04",
        status: "started",
        public_url: "https://sb-stream.example.com",
        cpu: 2,
        memory_mb: 2048,
        disk_gb: 20,
        os_user: "root",
        network_block_all: false,
        toolbox_enabled: true,
        exposed_ports: [],
        created_at: "2026-05-07T10:00:00Z",
        updated_at: "2026-05-07T10:00:00Z",
        last_active_at: "2026-05-07T10:00:00Z",
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    });

    const sandbox = await sdk.get("sb-stream");
    const handle = sandbox.attachSession("ses-1", {
      cols: 120,
      rows: 40,
      onStdout: (chunk) => stdoutChunks.push(chunk),
      onStderr: (chunk) => stderrChunks.push(chunk),
      onExit: (info) => exits.push(info),
    });

    const ws = FakeWebSocket.instances[0];
    assert.ok(ws);
    assert.equal(ws.url, "wss://api.example.com/v1/sandboxes/sb-stream/sessions/ses-1/attach");
    assert.deepEqual(ws.protocols, ["sandbox.bearer", "pat-token"]);

    ws.emit("open");
    assert.equal(ws.sent[0], JSON.stringify({ type: "resize", cols: 120, rows: 40 }));

    handle.write("pwd\n");
    handle.signal("INT");

    ws.emit("message", { data: new Uint8Array([0x01, 0x68, 0x69]).buffer });
    ws.emit("message", { data: new Uint8Array([0x02, 0x6f, 0x6b]).buffer });
    ws.emit("message", { data: JSON.stringify({ type: "exit", code: 7, signal: "TERM" }) });

    const result = await handle.done;
    assert.equal(result.code, 7);
    assert.equal(result.signal, "TERM");
    assert.equal(new TextDecoder().decode(stdoutChunks[0]), "hi");
    assert.equal(new TextDecoder().decode(stderrChunks[0]), "ok");
    assert.deepEqual(exits, [{ code: 7, signal: "TERM" }]);
    assert.equal(new TextDecoder().decode(ws.sent[1] as Uint8Array), "pwd\n");
    assert.equal(ws.sent[2], JSON.stringify({ type: "signal", signal: "INT" }));
  } finally {
    globalThis.WebSocket = originalWebSocket;
  }
});