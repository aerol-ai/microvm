import assert from "node:assert/strict";
import test from "node:test";

import { Client, SandboxHandle } from "./client.js";
import type { CreateOptions, ExecRequest, Sandbox } from "./types.js";

test("constructor trims base URL", () => {
  const client = new Client("https://api.example.com/");
  assert.equal(client.baseURL, "https://api.example.com");
});

test("create sends auth header and snake_case body", async () => {
  let seenRequest: Request | undefined;
  const client = new Client("https://api.example.com/", "token", {
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return jsonResponse(apiSandbox("sb-create"));
    },
  });

  const sandbox = await client.create({ image: "ubuntu:22.04", memoryMB: 2048, networkBlockAll: true });
  assert.ok(sandbox instanceof SandboxHandle);
  assert.equal(sandbox.id, "sb-create");
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "POST");
  assert.equal(seenRequest.headers.get("authorization"), "Bearer token");
  assert.deepEqual(await seenRequest.json(), {
    image: "ubuntu:22.04",
    memory_mb: 2048,
    network_block_all: true,
  });
});

test("list returns wrapped handles with mapped fields", async () => {
  const client = new Client("https://api.example.com", "", {
    fetch: async () => jsonResponse([apiSandbox("sb-a"), apiSandbox("sb-b", { status: "stopped", exposed_ports: [apiPort("sb-b", 3000)] })]),
  });

  const sandboxes = await client.list();
  assert.equal(sandboxes.length, 2);
  assert.ok(sandboxes[0] instanceof SandboxHandle);
  assert.equal(sandboxes[1].status, "stopped");
  assert.equal(sandboxes[1].exposedPorts?.[0]?.publicURL, "https://sb-b-3000.example.com");
});

test("get uses sandbox path", async () => {
  let seenURL = "";
  const client = new Client("https://api.example.com", "", {
    fetch: async (input, init) => {
      seenURL = new Request(input, init).url;
      return jsonResponse(apiSandbox("sb-get"));
    },
  });

  const sandbox = await client.get("sb-get");
  assert.equal(sandbox.id, "sb-get");
  assert.match(seenURL, /\/v1\/sandboxes\/sb-get$/);
});

test("start uses start path", async () => {
  let seenPath = "";
  const client = new Client("https://api.example.com", "", {
    fetch: async (input, init) => {
      seenPath = new URL(new Request(input, init).url).pathname;
      return jsonResponse(apiSandbox("sb-start"));
    },
  });

  await client.start("sb-start");
  assert.equal(seenPath, "/v1/sandboxes/sb-start/start");
});

test("stop uses stop path", async () => {
  let seenPath = "";
  const client = new Client("https://api.example.com", "", {
    fetch: async (input, init) => {
      seenPath = new URL(new Request(input, init).url).pathname;
      return jsonResponse(apiSandbox("sb-stop", { status: "stopped" }));
    },
  });

  await client.stop("sb-stop");
  assert.equal(seenPath, "/v1/sandboxes/sb-stop/stop");
});

test("destroy uses delete and accepts no content", async () => {
  let method = "";
  const client = new Client("https://api.example.com", "", {
    fetch: async (input, init) => {
      method = new Request(input, init).method;
      return new Response(null, { status: 204 });
    },
  });

  await client.destroy("sb-destroy");
  assert.equal(method, "DELETE");
});

test("resize sends snake_case payload", async () => {
  let body: unknown;
  const client = new Client("https://api.example.com", "", {
    fetch: async (input, init) => {
      body = await new Request(input, init).json();
      return jsonResponse(apiSandbox("sb-resize", { cpu: 4, memory_mb: 4096 }));
    },
  });

  const sandbox = await client.resize("sb-resize", { cpu: 4, memoryMB: 4096 });
  assert.deepEqual(body, { cpu: 4, memory_mb: 4096 });
  assert.equal(sandbox.cpu, 4);
  assert.equal(sandbox.memoryMB, 4096);
});

test("exec sends mapped request and returns mapped result", async () => {
  let body: unknown;
  const client = new Client("https://api.example.com", "", {
    fetch: async (input, init) => {
      body = await new Request(input, init).json();
      return jsonResponse({ stdout: "ok", stderr: "", exit_code: 0, duration_ms: 5 });
    },
  });

  const result = await client.exec("sb-exec", { command: "echo ok", workDir: "/workspace", timeoutSeconds: 30 });
  assert.deepEqual(body, { command: "echo ok", workdir: "/workspace", timeout_seconds: 30 });
  assert.deepEqual(result, { stdout: "ok", stderr: "", exitCode: 0, durationMS: 5 });
});

test("uploadFile sends form data", async () => {
  let request: Request | undefined;
  const client = new Client("https://api.example.com", "token", {
    fetch: async (input, init) => {
      request = new Request(input, init);
      return new Response(null, { status: 201 });
    },
  });

  await client.uploadFile("sb-upload", "/workspace/file.txt", "hello");
  assert.ok(request);
  assert.equal(request.headers.get("authorization"), "Bearer token");
  const form = await request.formData();
  assert.equal(form.get("path"), "/workspace/file.txt");
  const file = form.get("file");
  assert.ok(file instanceof File);
  assert.equal(file.name, "file.txt");
  assert.equal(await file.text(), "hello");
});

test("downloadFile encodes path and returns bytes", async () => {
  let seenURL = "";
  const client = new Client("https://api.example.com", "", {
    fetch: async (input, init) => {
      seenURL = new Request(input, init).url;
      return new Response(new Uint8Array([1, 2, 3]));
    },
  });

  const data = await client.downloadFile("sb-download", "/workspace/file name.txt");
  assert.deepEqual(Array.from(data), [1, 2, 3]);
  assert.match(seenURL, /path=%2Fworkspace%2Ffile%20name.txt$/);
});

test("exposePort returns public URL", async () => {
  const client = new Client("https://api.example.com", "", {
    fetch: async () => jsonResponse({ public_url: "https://sb-port-3000.example.com" }),
  });

  const publicURL = await client.exposePort("sb-port", 3000);
  assert.equal(publicURL, "https://sb-port-3000.example.com");
});

test("unexposePort uses delete", async () => {
  let method = "";
  const client = new Client("https://api.example.com", "", {
    fetch: async (input, init) => {
      method = new Request(input, init).method;
      return new Response(null, { status: 204 });
    },
  });

  await client.unexposePort("sb-port", 3000);
  assert.equal(method, "DELETE");
});

test("health returns mapped fields", async () => {
  const client = new Client("https://api.example.com", "", {
    fetch: async () => jsonResponse({ status: "ok", sandboxes: 2, docker: "ok", caddy: "ok", version: "dev" }),
  });

  const health = await client.health();
  assert.equal(health.status, "ok");
  assert.equal(health.sandboxes, 2);
});

test("sandbox handle refresh updates fields", async () => {
  let call = 0;
  const client = new Client("https://api.example.com", "", {
    fetch: async () => {
      call += 1;
      return jsonResponse(apiSandbox("sb-refresh", { public_url: call === 1 ? "https://old.example.com" : "https://new.example.com" }));
    },
  });

  const sandbox = await client.get("sb-refresh");
  await sandbox.refresh();
  assert.equal(sandbox.publicURL, "https://new.example.com");
});

test("sandbox handle start updates fields", async () => {
  const client = new Client("https://api.example.com", "", {
    fetch: async () => jsonResponse(apiSandbox("sb-start-handle", { status: "started", public_url: "https://started.example.com" })),
  });

  const sandbox = new SandboxHandle(client, fromSandbox({ ...sampleSandbox("sb-start-handle"), status: "stopped" }));
  await sandbox.start();
  assert.equal(sandbox.status, "started");
  assert.equal(sandbox.publicURL, "https://started.example.com");
});

test("sandbox handle stop updates fields", async () => {
  const client = new Client("https://api.example.com", "", {
    fetch: async () => jsonResponse(apiSandbox("sb-stop-handle", { status: "stopped" })),
  });

  const sandbox = new SandboxHandle(client, fromSandbox(sampleSandbox("sb-stop-handle")));
  await sandbox.stop();
  assert.equal(sandbox.status, "stopped");
});

test("sandbox handle resize updates fields", async () => {
  const client = new Client("https://api.example.com", "", {
    fetch: async () => jsonResponse(apiSandbox("sb-resize-handle", { cpu: 8, memory_mb: 8192 })),
  });

  const sandbox = new SandboxHandle(client, fromSandbox(sampleSandbox("sb-resize-handle")));
  await sandbox.resize({ cpu: 8, memoryMB: 8192 });
  assert.equal(sandbox.cpu, 8);
  assert.equal(sandbox.memoryMB, 8192);
});

test("sandbox handle exec delegates string command", async () => {
  const client = new Client("https://api.example.com", "", {
    fetch: async (input, init) => {
      const request = new Request(input, init);
      assert.deepEqual(await request.json(), { command: "echo 42" });
      return jsonResponse({ stdout: "42", stderr: "", exit_code: 0, duration_ms: 1 });
    },
  });

  const sandbox = new SandboxHandle(client, fromSandbox(sampleSandbox("sb-exec-handle")));
  const result = await sandbox.exec("echo 42");
  assert.equal(result.stdout, "42");
});

test("json error payload becomes Error message", async () => {
  const client = new Client("https://api.example.com", "", {
    fetch: async () => jsonResponse({ error: "bad request" }, 400),
  });

  await assert.rejects(() => client.create({ image: "ubuntu:22.04" }), /bad request/);
});

test("non-json error falls back to status code", async () => {
  const client = new Client("https://api.example.com", "", {
    fetch: async () => new Response("bad gateway", { status: 502 }),
  });

  await assert.rejects(() => client.health(), /request failed with status 502/);
});

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function sampleSandbox(id: string): Sandbox {
  return {
    id,
    image: "ubuntu:22.04",
    status: "started",
    publicURL: `https://${id}.example.com`,
    containerID: `container-${id}`,
    containerIP: "10.0.0.10",
    cpu: 2,
    memoryMB: 2048,
    diskGB: 20,
    osUser: "root",
    env: { KEY: "VALUE" },
    networkBlockAll: false,
    toolboxEnabled: true,
    exposedPorts: [],
    createdAt: "2026-05-07T10:00:00Z",
    updatedAt: "2026-05-07T10:00:00Z",
    lastActiveAt: "2026-05-07T10:00:00Z",
    lastError: "",
    containerCommand: ["bash", "-lc", "echo hello"],
  };
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

function apiPort(id: string, port: number): Record<string, unknown> {
  return {
    sandbox_id: id,
    port,
    public_url: `https://${id}-${port}.example.com`,
    created_at: "2026-05-07T10:00:00Z",
  };
}

function fromSandbox(sandbox: Sandbox): Sandbox {
  return JSON.parse(JSON.stringify(sandbox)) as Sandbox;
}