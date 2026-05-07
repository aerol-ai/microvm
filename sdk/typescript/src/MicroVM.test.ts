import assert from "node:assert/strict";
import test from "node:test";

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