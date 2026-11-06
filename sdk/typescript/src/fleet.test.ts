import assert from "node:assert/strict";
import test from "node:test";

import { MicroVM, MicroVMConflictError } from "./index.js";

interface FakeSandbox {
  id: string;
  name: string;
  image: string;
  status: string;
  tags: Record<string, string>;
  lifecycle: Record<string, never>;
}

/**
 * A fake sandboxd in a fetch function: sandboxes kept by name the way the
 * real server keeps them (names unique per owner, a second create of a name
 * is a 409). `lookupBarrier` holds the first N name lookups until all N
 * arrive, so N concurrent callers all miss before any of them creates.
 */
class FakeSandboxd {
  sandboxes = new Map<string, FakeSandbox>();
  requests: string[] = [];
  nextID = 0;
  pageSize = 2;
  conflictWithoutName = false;
  deleteStatus = new Map<string, number>();
  private barrierLeft: number;
  private release: (() => void) | undefined;
  private readonly barrier: Promise<void>;

  constructor(lookupBarrier = 0) {
    this.barrierLeft = lookupBarrier;
    this.barrier = new Promise((resolve) => {
      this.release = resolve;
    });
  }

  add(name: string, tags: Record<string, string> = {}, image = "alpine"): string {
    const id = `sb-${String(++this.nextID).padStart(3, "0")}`;
    this.sandboxes.set(id, { id, name, image, status: "started", tags, lifecycle: {} });
    return id;
  }

  count(method: string): number {
    return this.requests.filter((r) => r.startsWith(`${method} `)).length;
  }

  client(): MicroVM {
    return new MicroVM({
      patToken: "pat",
      apiUrl: "https://api.example.com",
      retry: { maxRetries: 0 },
      fetch: (input, init) => this.handle(new Request(input, init)),
    });
  }

  private async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    this.requests.push(`${request.method} ${url.pathname}${url.search}`);
    if (request.method === "GET" && url.pathname === "/v1/sandboxes") {
      const name = url.searchParams.get("name");
      if (name !== null) {
        if (this.barrierLeft > 0) {
          this.barrierLeft--;
          if (this.barrierLeft === 0) this.release?.();
          await this.barrier;
        }
        return json(200, [...this.sandboxes.values()].filter((s) => s.name === name));
      }
      const tags = [...url.searchParams].filter(([k]) => k.startsWith("tag.")).map(([k, v]) => [k.slice(4), v]);
      const matched = [...this.sandboxes.values()]
        .filter((s) => tags.every(([k, v]) => s.tags[k] === v))
        .sort((a, b) => a.id.localeCompare(b.id));
      const start = Number(url.searchParams.get("page_token") ?? "0");
      const headers: Record<string, string> = {};
      if (start + this.pageSize < matched.length) headers["X-Cluster-List-Next-Page-Token"] = String(start + this.pageSize);
      return json(200, matched.slice(start, start + this.pageSize), headers);
    }
    if (request.method === "POST" && url.pathname === "/v1/sandboxes") {
      const body = (await request.json()) as { name?: string; image?: string; tags?: Record<string, string> };
      if (this.conflictWithoutName) return json(409, { error: "sandbox id already reserved" });
      if (body.name && [...this.sandboxes.values()].some((s) => s.name === body.name)) {
        return json(409, { error: "sandbox name already in use" });
      }
      const id = this.add(body.name ?? "", body.tags ?? {}, body.image ?? "");
      return json(201, this.sandboxes.get(id));
    }
    if (request.method === "DELETE" && url.pathname.startsWith("/v1/sandboxes/")) {
      const id = url.pathname.slice("/v1/sandboxes/".length);
      const status = this.deleteStatus.get(id) ?? (this.sandboxes.delete(id) ? 204 : 404);
      return status === 204 ? new Response(null, { status }) : json(status, { error: `delete failed with ${status}` });
    }
    return json(404, { error: "not found" });
  }
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

test("getOrCreate creates when the name is free", async () => {
  const fake = new FakeSandboxd();
  const { sandbox, created } = await fake.client().getOrCreate("agent-1", { image: "alpine", tags: { team: "x" } });
  assert.equal(created, true);
  assert.equal(sandbox.name, "agent-1");
  assert.deepEqual(sandbox.tags, { team: "x" });
  assert.deepEqual([fake.count("GET"), fake.count("POST")], [1, 1]);
});

test("getOrCreate returns the existing sandbox without creating", async () => {
  const fake = new FakeSandboxd();
  const id = fake.add("agent-1", {}, "ubuntu");
  const { sandbox, created } = await fake.client().getOrCreate("agent-1", { image: "alpine" });
  assert.equal(created, false);
  assert.equal(sandbox.id, id);
  assert.equal(sandbox.image, "ubuntu");
  assert.equal(fake.count("POST"), 0);
});

test("getOrCreate gives concurrent callers one sandbox", async () => {
  const callers = 8;
  const fake = new FakeSandboxd(callers);
  const client = fake.client();
  const results = await Promise.all(Array.from({ length: callers }, () => client.getOrCreate("shared", { image: "alpine" })));
  assert.equal(new Set(results.map((r) => r.sandbox.id)).size, 1);
  assert.equal(results.filter((r) => r.created).length, 1);
  assert.equal(fake.sandboxes.size, 1);
  assert.equal(fake.count("POST"), callers);
});

test("getOrCreate raises a conflict on something other than the name", async () => {
  const fake = new FakeSandboxd();
  fake.conflictWithoutName = true;
  await assert.rejects(fake.client().getOrCreate("agent-1", { image: "alpine" }), (err: unknown) => {
    assert.ok(err instanceof MicroVMConflictError);
    assert.equal(err.message, "sandbox id already reserved");
    return true;
  });
});

test("getOrCreate rejects a missing or mismatched name", async () => {
  const client = new FakeSandboxd().client();
  await assert.rejects(client.getOrCreate("  ", { image: "alpine" }), /sandbox name is required/);
  await assert.rejects(client.getOrCreate("a", { image: "alpine", name: "b" }), /differs/);
  const { created } = await client.getOrCreate(" agent-1 ", { image: "alpine", name: "agent-1" });
  assert.equal(created, true);
});

