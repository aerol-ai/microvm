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

test("Sandbox exec accepts a plain command string", async () => {
  const execBodies: unknown[] = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com/",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      if (new URL(request.url).pathname.endsWith("/toolbox/process/execute")) {
        execBodies.push(await request.json());
        return new Response(JSON.stringify({ stdout: "hello\n", stderr: "", exit_code: 0, duration_ms: 3 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({
        id: "sb-exec",
        image: "ubuntu:22.04",
        status: "started",
        public_url: "",
        cpu: 1,
        memory_mb: 512,
        disk_gb: 1,
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

  const sandbox = await sdk.create({ image: "ubuntu:22.04" });
  const result = await sandbox.exec("echo hello");
  await sandbox.exec({ command: "echo hello", workDir: "/tmp" });

  assert.equal(result.stdout, "hello\n");
  assert.equal(result.exitCode, 0);
  assert.deepEqual(execBodies, [
    { command: "echo hello" },
    { command: "echo hello", workdir: "/tmp" },
  ]);
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

test("MicroVM requires a PAT token", async () => {
  await withEnv({ SB_PAT_TOKEN: undefined, SB_API_TOKEN: undefined }, () => {
    assert.throws(() => {
      new MicroVM({ apiUrl: "https://api.example.com" });
    }, /PAT token is required.*SB_API_TOKEN/);
  });
});

/** Runs fn with these env vars set (undefined unsets), then restores them. */
async function withEnv(vars: Record<string, string | undefined>, fn: () => void | Promise<void>): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(vars)) {
    saved[name] = process.env[name];
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }
  try {
    await fn();
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}

/** A fetch that records every request's auth and team headers and answers from `reply`. */
function recordingFetch(reply: (request: Request) => Response | Promise<Response>) {
  const seen: Array<{ method: string; url: string; authorization: string | null; team: string | null; body: unknown }> = [];
  const fetchFn = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const text = await request.clone().text();
    seen.push({
      method: request.method,
      url: request.url,
      authorization: request.headers.get("authorization"),
      team: request.headers.get("x-aerolvm-team"),
      body: text === "" ? undefined : JSON.parse(text),
    });
    return reply(request);
  };
  return { seen, fetchFn };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

const whoamiBody = {
  principal: { kind: "token", id: "tok_abc123def456", name: "ci" },
  role: "runner",
  team: "payments",
  expires_at: "2027-01-02T03:04:05Z",
};

test("MicroVM resolves the token and team from options and the environment", async () => {
  const cases: Array<{
    name: string;
    config: { patToken?: string; team?: string };
    env: Record<string, string | undefined>;
    wantAuthorization: string;
    wantTeam: string | null;
  }> = [
    { name: "SB_PAT_TOKEN only", config: {}, env: { SB_PAT_TOKEN: "pat" }, wantAuthorization: "Bearer pat", wantTeam: null },
    { name: "SB_API_TOKEN alias", config: {}, env: { SB_API_TOKEN: "avm_alias" }, wantAuthorization: "Bearer avm_alias", wantTeam: null },
    { name: "SB_PAT_TOKEN beats SB_API_TOKEN", config: {}, env: { SB_PAT_TOKEN: "pat", SB_API_TOKEN: "avm_alias" }, wantAuthorization: "Bearer pat", wantTeam: null },
    { name: "option beats both", config: { patToken: "opt" }, env: { SB_PAT_TOKEN: "pat", SB_API_TOKEN: "avm_alias" }, wantAuthorization: "Bearer opt", wantTeam: null },
    { name: "SB_TEAM sends the header", config: {}, env: { SB_API_TOKEN: "avm_alias", SB_TEAM: " payments " }, wantAuthorization: "Bearer avm_alias", wantTeam: "payments" },
    { name: "team option beats SB_TEAM", config: { team: "ml" }, env: { SB_PAT_TOKEN: "pat", SB_TEAM: "payments" }, wantAuthorization: "Bearer pat", wantTeam: "ml" },
    { name: "an empty team option overrides SB_TEAM", config: { team: "" }, env: { SB_PAT_TOKEN: "pat", SB_TEAM: "payments" }, wantAuthorization: "Bearer pat", wantTeam: null },
    { name: "blank SB_TEAM sends nothing", config: {}, env: { SB_PAT_TOKEN: "pat", SB_TEAM: "   " }, wantAuthorization: "Bearer pat", wantTeam: null },
  ];
  for (const tc of cases) {
    await withEnv({ SB_PAT_TOKEN: undefined, SB_API_TOKEN: undefined, SB_TEAM: undefined, ...tc.env }, async () => {
      const { seen, fetchFn } = recordingFetch(() => jsonResponse(200, whoamiBody));
      const sdk = new MicroVM({ ...tc.config, apiUrl: "https://api.example.com", fetch: fetchFn });
      await sdk.whoami();
      assert.equal(seen[0]?.authorization, tc.wantAuthorization, tc.name);
      assert.equal(seen[0]?.team, tc.wantTeam, tc.name);
      assert.equal(sdk.team, tc.wantTeam ?? "", tc.name);
    });
  }
});

test("MicroVM.whoami maps the principal, role, team and expiry", async () => {
  const { seen, fetchFn } = recordingFetch((request) =>
    new URL(request.url).pathname === "/v1/whoami" && request.method === "GET"
      ? jsonResponse(200, whoamiBody)
      : jsonResponse(404, { error: "unexpected" }),
  );
  const sdk = new MicroVM({ patToken: "avm_x", apiUrl: "https://api.example.com", fetch: fetchFn });
  assert.deepEqual(await sdk.whoami(), {
    principal: { kind: "token", id: "tok_abc123def456", name: "ci" },
    role: "runner",
    team: "payments",
    expiresAt: "2027-01-02T03:04:05Z",
  });

  // The operator has no team and a credential that never expires.
  const operator = new MicroVM({
    patToken: "pat",
    apiUrl: "https://api.example.com",
    fetch: async () => jsonResponse(200, { principal: { kind: "operator", id: "operator" }, role: "admin" }),
  });
  assert.deepEqual(await operator.whoami(), { principal: { kind: "operator", id: "operator" }, role: "admin" });
  assert.equal(seen.length, 1);
});

test("MicroVM.tokens create/list/revoke hit /v1/tokens and send the team on every call", async () => {
  const stored = {
    id: "tok_abc123def456",
    name: "ci",
    role: "runner",
    team: "payments",
    created_by: "operator",
    created_at: "2026-10-17T09:00:00Z",
    expires_at: "2027-01-02T03:04:05Z",
    expired: false,
  };
  const { seen, fetchFn } = recordingFetch((request) => {
    const path = new URL(request.url).pathname;
    if (request.method === "POST" && path === "/v1/tokens") return jsonResponse(201, { ...stored, token: "avm_secret" });
    if (request.method === "GET" && path === "/v1/tokens") return jsonResponse(200, { tokens: [{ ...stored, expired: true }] });
    if (request.method === "DELETE" && path.startsWith("/v1/tokens/")) return new Response(null, { status: 204 });
    return jsonResponse(404, { error: "unexpected" });
  });
  const sdk = new MicroVM({ patToken: "avm_admin", apiUrl: "https://api.example.com", team: "ops", fetch: fetchFn });

  const created = await sdk.tokens.create({ name: "ci", role: "runner", team: "payments", expiresIn: "90d" });
  assert.deepEqual(created, {
    id: "tok_abc123def456",
    name: "ci",
    role: "runner",
    team: "payments",
    createdBy: "operator",
    createdAt: "2026-10-17T09:00:00Z",
    expiresAt: "2027-01-02T03:04:05Z",
    expired: false,
    token: "avm_secret",
  });
  assert.deepEqual(seen[0]?.body, { name: "ci", role: "runner", team: "payments", expires_in: "90d" });

  const list = await sdk.tokens.list();
  assert.equal(list.tokens.length, 1);
  assert.equal(list.tokens[0]?.expired, true);
  assert.equal("token" in (list.tokens[0] ?? {}), false);

  // A repeat revoke is another 204; the id is one escaped path segment.
  await sdk.tokens.revoke("tok_abc123def456");
  await sdk.tokens.revoke("tok_abc123def456");
  await sdk.tokens.revoke("../sandboxes");
  await assert.rejects(sdk.tokens.revoke("  "), /token id is required/);

  assert.deepEqual(
    seen.map((r) => `${r.method} ${new URL(r.url).pathname}`),
    [
      "POST /v1/tokens",
      "GET /v1/tokens",
      "DELETE /v1/tokens/tok_abc123def456",
      "DELETE /v1/tokens/tok_abc123def456",
      "DELETE /v1/tokens/..%2Fsandboxes",
    ],
  );
  for (const r of seen) {
    assert.equal(r.team, "ops", `${r.method} ${r.url} must carry the team`);
  }
});

test("MicroVM.tokens.list normalizes a null list", async () => {
  const sdk = new MicroVM({
    patToken: "pat",
    apiUrl: "https://api.example.com",
    fetch: async () => jsonResponse(200, { tokens: null }),
  });
  assert.deepEqual(await sdk.tokens.list(), { tokens: [] });
});

test("MicroVM.tokens surfaces the server's refusal message", async () => {
  const sdk = new MicroVM({
    patToken: "avm_viewer",
    apiUrl: "https://api.example.com",
    retry: { maxRetries: 0 },
    fetch: async () =>
      jsonResponse(403, {
        error: "role viewer on team payments cannot token.write; ask an admin for role admin on all teams",
        required_permission: "token.write",
        role: "viewer",
      }),
  });
  await assert.rejects(
    sdk.tokens.create({ name: "ci", role: "runner", team: "payments", expiresIn: "90d" }),
    /role viewer on team payments cannot token\.write/,
  );
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

test("MicroVM.get and list include_env opt-in", async () => {
  const urls: string[] = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input) => {
      urls.push(new Request(input).url);
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/sandboxes")) {
        return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({ id: "sb-1" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  await sdk.get("sb-1", { includeEnv: true });
  await sdk.list({ tags: { team: "a" }, includeEnv: true });
  assert.equal(urls[0], "https://api.example.com/v1/sandboxes/sb-1?include_env=true");
  const listURL = new URL(urls[1]);
  assert.equal(listURL.searchParams.get("tag.team"), "a");
  assert.equal(listURL.searchParams.get("include_env"), "true");
});

// Empty filters should produce the canonical collection URL without a stray
// query delimiter.
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

test("MicroVM.list drains cluster page tokens", async () => {
  const urls: string[] = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input) => {
      const url = new Request(input).url;
      urls.push(url);
      const token = new URL(url).searchParams.get("page_token");
      if (!token) {
        return new Response(JSON.stringify([{ id: "sb-1", image: "alpine", status: "started" }]), {
          status: 200,
          headers: {
            "content-type": "application/json",
            "X-Cluster-List-Partial": "false",
            "X-Cluster-List-Placement-Ready": "true",
            "X-Cluster-List-Next-Page-Token": "tok-1",
          },
        });
      }
      return new Response(JSON.stringify([{ id: "sb-2", image: "alpine", status: "started" }]), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "X-Cluster-List-Partial": "false",
          "X-Cluster-List-Placement-Ready": "true",
        },
      });
    },
  });
  const items = await sdk.list();
  assert.deepEqual(items.map((s) => s.id), ["sb-1", "sb-2"]);
  assert.equal(urls[1], "https://api.example.com/v1/sandboxes?page_token=tok-1");
});

test("MicroVM.listPages yields without accumulating later pages", async () => {
  let calls = 0;
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async () => {
      calls++;
      return new Response(JSON.stringify([{ id: `sb-${calls}`, image: "alpine", status: "started" }]), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "X-Cluster-List-Placement-Ready": "true",
          ...(calls === 1 ? { "X-Cluster-List-Next-Page-Token": "tok-1" } : {}),
        },
      });
    },
  });
  const pages = sdk.listPages();
  const first = await pages.next();
  if (first.done) throw new Error("first page missing");
  assert.equal(calls, 1);
  assert.deepEqual(first.value.map((s) => s.id), ["sb-1"]);
  const second = await pages.next();
  if (second.done) throw new Error("second page missing");
  assert.equal(calls, 2);
  assert.deepEqual(second.value.map((s) => s.id), ["sb-2"]);
  assert.equal((await pages.next()).done, true);
});

test("MicroVM.list errors on partial cluster coverage", async () => {
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async () =>
      new Response("[]", {
        status: 200,
        headers: {
          "content-type": "application/json",
          "X-Cluster-List-Partial": "true",
          "X-Cluster-List-Placement-Ready": "true",
        },
      }),
  });
  await assert.rejects(() => sdk.list(), /incomplete cluster list/);
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

test("MicroVM.dns.target GETs /v1/ingress/dns and maps response", async () => {
  let seenRequest: Request | undefined;
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return new Response(
        JSON.stringify({ hostname: "ingress.example.com", source: "hostname" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  const target = await sdk.dns.target();
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "GET");
  assert.ok(seenRequest.url.endsWith("/v1/ingress/dns"));
  assert.equal(target.hostname, "ingress.example.com");
  assert.equal(target.source, "hostname");
});
// Template lifecycle round-trips. We don't drive the daemon's async build
// pipeline in these unit tests — we mock the wire shape and pin that the
// SDK maps snake_case fields to the camelCase public surface, sends the
// right method/path, and decodes the 202-with-template response on rebuild.

test("MicroVM.createTemplate POSTs /v1/templates and maps the response", async () => {
  let seenRequest: Request | undefined;
  let seenBody = "";
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      seenRequest = req;
      seenBody = await req.text();
      return new Response(JSON.stringify({
        id: "tpl-create",
        image: "docker://python:3.11",
        status: "pending",
        min_size_mib: 512,
        created_at: "2026-05-27T10:00:00Z",
        updated_at: "2026-05-27T10:00:00Z",
        has_snapshot: false,
        has_overlay: false,
      }), {
        status: 202,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const tpl = await sdk.createTemplate({
    id: "tpl-create",
    image: "docker://python:3.11",
    minSizeMiB: 512,
  });

  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "POST");
  assert.ok(seenRequest.url.endsWith("/v1/templates"));
  assert.deepEqual(JSON.parse(seenBody), {
    id: "tpl-create",
    image: "docker://python:3.11",
    min_size_mib: 512,
  });
  assert.equal(tpl.id, "tpl-create");
  assert.equal(tpl.status, "pending");
  assert.equal(tpl.minSizeMiB, 512);
  assert.equal(tpl.hasSnapshot, false);
});

test("MicroVM.listTemplates handles empty and populated responses", async () => {
  let response: unknown = null; // mimic the daemon returning JSON null for empty
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async () => new Response(JSON.stringify(response), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  });

  assert.deepEqual(await sdk.listTemplates(), []);

  response = [
    {
      id: "tpl-1",
      image: "docker://alpine:3.19",
      status: "ready",
      created_at: "2026-05-27T10:00:00Z",
      updated_at: "2026-05-27T10:05:00Z",
      ready_at: "2026-05-27T10:04:00Z",
      has_snapshot: true,
      has_overlay: false,
      push_state: "active",
    },
  ];
  const rows = await sdk.listTemplates();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].id, "tpl-1");
  assert.equal(rows[0].status, "ready");
  assert.equal(rows[0].hasSnapshot, true);
  assert.equal(rows[0].pushState, "active");
});

test("MicroVM.rebuildTemplate POSTs the rebuild path and surfaces 412 errors", async () => {
  let seenRequest: Request | undefined;
  let returnStatus = 202;
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      if (returnStatus === 412) {
        return new Response(JSON.stringify({
          error: "template not eligible for rebuild: current status=pending",
        }), { status: 412, headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({
        id: "tpl-rebuild",
        image: "docker://alpine:3.19",
        status: "unhealthy",
        created_at: "2026-05-27T10:00:00Z",
        updated_at: "2026-05-27T10:10:00Z",
        has_snapshot: true,
        has_overlay: false,
      }), { status: 202, headers: { "content-type": "application/json" } });
    },
  });

  // Happy path — 202 with the (now unhealthy) row.
  const tpl = await sdk.rebuildTemplate("tpl-rebuild");
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "POST");
  assert.ok(seenRequest.url.endsWith("/v1/templates/tpl-rebuild/rebuild"));
  assert.equal(tpl.status, "unhealthy");

  // Not-rebuildable arm — the SDK must surface the 412 as a thrown error.
  returnStatus = 412;
  await assert.rejects(
    () => sdk.rebuildTemplate("tpl-rebuild"),
    /not eligible for rebuild/,
  );
});

test("MicroVM.createWasmModule POSTs /v1/wasm-modules and maps the response", async () => {
  let seenRequest: Request | undefined;
  let seenBody = "";
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      seenRequest = req;
      seenBody = await req.text();
      return new Response(JSON.stringify({
        id: "abc123",
        module_ref: "file:///opt/mod.wasm",
        status: "ready",
        module_size_bytes: 4096,
        digest: "abc123",
        entrypoint: "_start",
        has_warm: true,
        created_at: "2026-05-27T10:00:00Z",
        updated_at: "2026-05-27T10:00:00Z",
        ready_at: "2026-05-27T10:00:00Z",
      }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const mod = await sdk.createWasmModule({
    moduleRef: "file:///opt/mod.wasm",
    entrypoint: "_start",
  });

  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "POST");
  assert.ok(seenRequest.url.endsWith("/v1/wasm-modules"));
  assert.deepEqual(JSON.parse(seenBody), {
    module_ref: "file:///opt/mod.wasm",
    entrypoint: "_start",
  });
  assert.equal(mod.id, "abc123");
  assert.equal(mod.status, "ready");
  assert.equal(mod.moduleRef, "file:///opt/mod.wasm");
  assert.equal(mod.hasWarm, true);
});

test("MicroVM.listWasmModules handles empty and populated responses", async () => {
  let response: unknown = null;
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async () => new Response(JSON.stringify(response), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  });

  assert.deepEqual(await sdk.listWasmModules(), []);

  response = [{
    id: "mod-1",
    module_ref: "https://example.com/agent.wasm",
    status: "ready",
    has_warm: false,
    created_at: "2026-05-27T10:00:00Z",
    updated_at: "2026-05-27T10:00:00Z",
  }];
  const rows = await sdk.listWasmModules();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].moduleRef, "https://example.com/agent.wasm");
});

test("MicroVM.deleteWasmModule sends DELETE on the per-id path", async () => {
  let seenRequest: Request | undefined;
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return new Response(null, { status: 204 });
    },
  });

  await sdk.deleteWasmModule("mod-x");
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "DELETE");
  assert.ok(seenRequest.url.endsWith("/v1/wasm-modules/mod-x"));
});

test("MicroVM.deleteTemplate sends DELETE on the per-id path", async () => {
  let seenRequest: Request | undefined;
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      seenRequest = new Request(input, init);
      return new Response(null, { status: 204 });
    },
  });

  await sdk.deleteTemplate("tpl-x");
  assert.ok(seenRequest);
  assert.equal(seenRequest.method, "DELETE");
  assert.ok(seenRequest.url.endsWith("/v1/templates/tpl-x"));
});

// Names are unique per owner and looked up with ?name=. getByName must trust
// the reply only when it holds at most one sandbox carrying that name: an old
// server ignores the filter and returns a normal list page.
test("MicroVM.getByName sends ?name= and verifies the reply", async () => {
  const replies: Record<string, string> = {
    agent: JSON.stringify([{ id: "sb-1", name: "agent", tags: { team: "x" } }]),
    missing: "[]",
    old: JSON.stringify([{ id: "sb-1", name: "a" }, { id: "sb-2", name: "b" }]),
    mismatch: JSON.stringify([{ id: "sb-3", name: "someone-else" }]),
  };
  const urls: string[] = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input) => {
      const url = new URL(new Request(input).url);
      urls.push(url.toString());
      return new Response(replies[url.searchParams.get("name") ?? ""] ?? "[]", {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const found = await sdk.getByName(" agent ");
  assert.equal(found?.id, "sb-1");
  assert.equal(found?.name, "agent");
  assert.deepEqual(found?.tags, { team: "x" });
  const first = new URL(urls[0]);
  assert.equal(first.pathname, "/v1/sandboxes");
  assert.equal(first.searchParams.get("name"), "agent");

  assert.equal(await sdk.getByName("missing"), null);
  await assert.rejects(sdk.getByName("old"), /does not support sandbox name lookup/);
  await assert.rejects(sdk.getByName("mismatch"), /does not support sandbox name lookup/);
  await assert.rejects(sdk.getByName("  "), /name is required/);
});

test("MicroVM.list forwards a name filter and create sends name and tags", async () => {
  const seen: { url: string; body?: string }[] = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      seen.push({ url: req.url, body: req.method === "POST" ? await req.text() : undefined });
      if (req.method === "POST") {
        return new Response(JSON.stringify({ id: "sb-new", name: "agent", tags: { a: "b" } }), {
          status: 201,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  await sdk.list({ name: "agent", tags: { team: "x" }, includeEnv: true });
  const listURL = new URL(seen[0].url);
  assert.equal(listURL.searchParams.get("name"), "agent");
  assert.equal(listURL.searchParams.get("tag.team"), "x");
  assert.equal(listURL.searchParams.get("include_env"), "true");

  const created = await sdk.create({ image: "alpine:3.20", name: "agent", tags: { a: "b" } });
  const body = JSON.parse(seen[1].body ?? "{}");
  assert.equal(body.name, "agent");
  assert.deepEqual(body.tags, { a: "b" });
  assert.equal(created.name, "agent");
  assert.deepEqual(created.tags, { a: "b" });
});

test("MicroVM getSnapshot/listSnapshots/deleteSnapshot hit the v1 snapshot surface", async () => {
  const seen: Array<{ method: string; url: string }> = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      seen.push({ method: request.method, url: request.url });
      const u = new URL(request.url);
      if (request.method === "DELETE") {
        return new Response(null, { status: 204 });
      }
      if (u.pathname === "/v1/snapshots/py-base") {
        return new Response(
          JSON.stringify({ name: "py-base", image: "python:3.12", source_sandbox_id: "", created_at: "2026-05-15T10:00:00Z" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (u.pathname === "/v1/snapshots") {
        return new Response(
          JSON.stringify({ snapshots: [{ name: "py-base", image: "python:3.12", source_sandbox_id: "", created_at: "2026-05-15T10:00:00Z" }], has_more: true }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected ${request.method} ${request.url}`);
    },
  });

  const snap = await sdk.getSnapshot("py-base");
  assert.equal(snap.name, "py-base");

  const page = await sdk.listSnapshots({ limit: 1, startingAfter: "cursor" });
  assert.equal(page.hasMore, true);
  assert.equal(page.snapshots.length, 1);
  assert.equal(page.snapshots[0]?.name, "py-base");

  await sdk.deleteSnapshot("py-base");

  assert.ok(seen.some((s) => s.method === "GET" && s.url.endsWith("/v1/snapshots/py-base")));
  assert.ok(seen.some((s) => s.method === "GET" && s.url.includes("/v1/snapshots?limit=1&starting_after=cursor")));
  assert.ok(seen.some((s) => s.method === "DELETE" && s.url.endsWith("/v1/snapshots/py-base")));
});

test("MicroVM passes retry.maxRetryAfterMs and signal to its client", async () => {
  let calls = 0;
  const sdk = new MicroVM({
    patToken: "pat",
    apiUrl: "https://api.example.com",
    retry: { maxRetryAfterMs: 50 },
    fetch: async () => {
      calls++;
      if (calls === 1) {
        return new Response(JSON.stringify({ error: "busy" }), { status: 503, headers: { "retry-after": "120" } });
      }
      return jsonResponse(200, { tokens: [] });
    },
  });
  const start = performance.now();
  await sdk.tokens.list();
  assert.ok(performance.now() - start < 2000, "a 120 s Retry-After is cut to 50 ms");
  assert.equal(calls, 2);

  const aborted = new MicroVM({
    patToken: "pat",
    apiUrl: "https://api.example.com",
    signal: AbortSignal.abort(new Error("stopped")),
    fetch: async (_input, init) => {
      init?.signal?.throwIfAborted();
      return jsonResponse(200, { tokens: [] });
    },
  });
  await assert.rejects(aborted.tokens.list(), { message: "stopped" });
});
