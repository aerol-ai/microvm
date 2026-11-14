import assert from "node:assert/strict";
import test from "node:test";

import { APIClient } from "./client.js";

// Cloud identity per sandbox (plans/sandbox-cloud-identity.md): the create
// option, the identity a sandbox shows, and the admin role-tag calls.

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

const sandboxIdentity = {
  role_tag: "deploy",
  audience: "sts.amazonaws.com",
  subject: "team:payments:role:deploy",
  aws_role_arn: "arn:aws:iam::123456789012:role/deploy",
  token_file: "/run/aerolvm/identity/token",
  token_expires_at: "2026-11-06T12:00:00Z",
};

test("create sends the identity option and the sandbox shows its identity", async () => {
  let body: Record<string, unknown> = {};
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (_input, init) => {
      if (init?.body) body = JSON.parse(String(init.body));
      return jsonResponse({
        id: "sb-id",
        image: "alpine",
        status: "started",
        lifecycle: {},
        identity: sandboxIdentity,
      });
    },
  });
  const sandbox = await client.create({
    image: "alpine",
    identity: { roleTag: "deploy", awsRoleArn: "arn:aws:iam::123456789012:role/deploy" },
  });
  assert.deepEqual(body.identity, { role_tag: "deploy", aws_role_arn: "arn:aws:iam::123456789012:role/deploy" });
  assert.deepEqual(sandbox.identity, {
    roleTag: "deploy",
    audience: "sts.amazonaws.com",
    subject: "team:payments:role:deploy",
    awsRoleArn: "arn:aws:iam::123456789012:role/deploy",
    tokenFile: "/run/aerolvm/identity/token",
    tokenExpiresAt: "2026-11-06T12:00:00Z",
  });
  // toJSON copies the identity rather than sharing it.
  const copy = sandbox.toJSON();
  assert.notEqual(copy.identity, sandbox.identity);
  assert.deepEqual(copy.identity, sandbox.identity);
});

test("a sandbox without an identity shows none and create sends none", async () => {
  let body: Record<string, unknown> = {};
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (_input, init) => {
      if (init?.body) body = JSON.parse(String(init.body));
      return jsonResponse({ id: "sb-plain", image: "alpine", status: "started", lifecycle: {} });
    },
  });
  const sandbox = await client.create({ image: "alpine" });
  assert.equal("identity" in body, false);
  assert.equal(sandbox.identity, undefined);
});

test("identity role calls map the wire shape", async () => {
  const seen: { method: string; url: string; body?: unknown }[] = [];
  const role = { tag: "deploy", min_role: "runner", team: "payments", created_at: "c", updated_at: "u" };
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    fetch: async (input, init) => {
      const req = new Request(input, init);
      seen.push({ method: req.method, url: req.url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (req.method === "DELETE") return new Response(null, { status: 204 });
      if (req.url.includes("/identity/roles?")) return jsonResponse({ roles: [role], next_cursor: "deploy" });
      if (req.url.endsWith("/identity/roles")) return jsonResponse({ roles: null });
      return jsonResponse(role);
    },
  });
  const put = await client.putIdentityRole("deploy", { minRole: "runner", team: "payments" });
  assert.deepEqual(put, { tag: "deploy", minRole: "runner", team: "payments", createdAt: "c", updatedAt: "u" });
  assert.deepEqual(seen[0], {
    method: "PUT",
    url: "https://api.example.com/v1/identity/roles/deploy?team=payments",
    body: { min_role: "runner" },
  });
  const page = await client.listIdentityRoles({ team: "payments", cursor: "a", limit: 10 });
  assert.equal(page.nextCursor, "deploy");
  assert.equal(page.roles[0].minRole, "runner");
  assert.ok(seen[1].url.endsWith("/v1/identity/roles?team=payments&cursor=a&limit=10"));
  assert.deepEqual(await client.listIdentityRoles(), { roles: [] });
  await client.deleteIdentityRole("deploy", { team: "payments" });
  assert.deepEqual([seen[3].method, seen[3].url], ["DELETE", "https://api.example.com/v1/identity/roles/deploy?team=payments"]);
  // The operator namespace: no team parameter at all.
  await client.putIdentityRole("ops", { minRole: "admin" });
  assert.equal(seen[4].url, "https://api.example.com/v1/identity/roles/ops");
  await client.deleteIdentityRole("ops");
  assert.equal(seen[5].url, "https://api.example.com/v1/identity/roles/ops");
});

test("identity role calls retry on the safe tier", async () => {
  let calls = 0;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat-token",
    retry: { maxRetries: 2, baseDelayMs: 1, maxDelayMs: 1 },
    fetch: async () => {
      calls++;
      if (calls === 1) return new Response("bad gateway", { status: 502 });
      return jsonResponse({ tag: "deploy", min_role: "runner", created_at: "c", updated_at: "u" });
    },
  });
  const role = await client.putIdentityRole("deploy", { minRole: "runner" });
  assert.equal(role.tag, "deploy");
  assert.equal(calls, 2);
});
