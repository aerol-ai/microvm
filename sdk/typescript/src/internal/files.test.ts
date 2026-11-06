import assert from "node:assert/strict";
import test from "node:test";

import { APIClient, DEFAULT_LIST_LIMIT, SandboxResource } from "./client.js";
import { MicroVMApiError, MicroVMFileTooLargeError, MicroVMUnsupportedFeatureError } from "../errors.js";
import type { Sandbox } from "../types.js";

// File verbs beyond upload and download (plans/agent-sandbox-feature-
// parity.md, F1): the toolbox routes they call, the /version check before an
// option an older agent would ignore, and each verb's retry rule.

interface Call {
  method: string;
  route: string;
  query: Record<string, string>;
}

type Reply = (call: Call, n: number) => { status: number; body?: unknown; headers?: Record<string, string> };

function fakeToolbox(reply: Reply, features: string[] = ["files.verbs"]) {
  const calls: Call[] = [];
  const counts = new Map<string, number>();
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat",
    retry: { maxRetries: 3, baseDelayMs: 1, maxDelayMs: 1 },
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname.endsWith("/toolbox/version")) {
        return new Response(JSON.stringify({ version: "test", features }), { status: 200 });
      }
      const call = {
        method: request.method,
        route: url.pathname.split("/toolbox")[1] ?? "",
        query: Object.fromEntries(url.searchParams),
      };
      const key = `${call.method} ${call.route}`;
      const n = counts.get(key) ?? 0;
      counts.set(key, n + 1);
      calls.push(call);
      const { status, body, headers } = reply(call, n);
      return new Response(body === undefined ? null : JSON.stringify(body), { status, headers });
    },
  });
  return { client, calls };
}

const err = (error: string, code?: string) => (code ? { error, code } : { error });

test("listFiles sends a depth and cap and reads the extended info", async () => {
  const { client, calls } = fakeToolbox(() => ({
    status: 200,
    headers: { "X-Toolbox-Truncated": "true" },
    body: [
      { name: "a", isDir: true, size: 64, size_bytes: 64, path: "/w/a" },
      { name: "big", size: 2147483647, size_bytes: 5 * 2 ** 30, path: "/w/big" },
      { name: "link", size: 4, size_bytes: 4, path: "/w/link", symlink_target: "a" },
      { name: "old", size: 7 },
    ],
  }));
  const list = await client.listFiles("sb-1", "/w/");
  assert.deepEqual(calls[0].query, { path: "/w/", depth: "1", limit: String(DEFAULT_LIST_LIMIT), extended: "true" });
  assert.equal(list.truncated, true);
  assert.deepEqual(
    list.entries.map((e) => e.path),
    ["/w/a", "/w/big", "/w/link", "/w/old"],
  );
  assert.equal(list.entries[1].size, 5 * 2 ** 30);
  assert.equal(list.entries[2].symlinkTarget, "a");
  assert.equal(list.entries[3].size, 7);
  assert.equal(list.entries[0].isDir, true);

  await client.listFiles("sb-1", "/w", { depth: 3, limit: 5 });
  assert.equal(calls[1].query.depth, "3");
  assert.equal(calls[1].query.limit, "5");
  await assert.rejects(client.listFiles("sb-1", "/w", { depth: 0 }));
});

test("an older agent fails closed before any file call", async () => {
  const { client, calls } = fakeToolbox(() => ({ status: 204 }), []);
  for (const call of [
    () => client.listFiles("sb-1", "/"),
    () => client.moveFile("sb-1", "/a", "/b"),
    () => client.copyFile("sb-1", "/a", "/b"),
    () => client.makeDir("sb-1", "/d"),
  ]) {
    await assert.rejects(call(), (e: unknown) => e instanceof MicroVMUnsupportedFeatureError);
  }
  assert.equal(calls.length, 0);
  // An older agent does what these ask anyway, so no check is needed.
  await client.moveFile("sb-1", "/a", "/b", { overwrite: true });
  await client.makeDir("sb-1", "/d", { parents: true });
  assert.equal(calls[0].query.overwrite, "true");
  assert.equal(calls[1].query.parents, "true");
});

test("getFileInfo falls back for an older agent; fileExists tells a missing file from a missing sandbox", async () => {
  const answers: Record<string, { status: number; body: unknown }> = {
    "/new": { status: 200, body: { name: "new", size: 2147483647, size_bytes: 3 * 2 ** 30, path: "/new" } },
    "/old": { status: 200, body: { name: "old", size: 12 } },
    "/gone": { status: 404, body: err("stat /gone: no such file or directory", "file_not_found") },
    "/gone-old": { status: 404, body: err("stat /gone-old: no such file or directory") },
    "/no-sandbox": { status: 404, body: err("sandbox not found") },
    "/broken": { status: 403, body: err("permission denied") },
  };
  const { client, calls } = fakeToolbox((call) => answers[call.query.path]);
  const info = await client.getFileInfo("sb-1", "/new");
  assert.equal(info.size, 3 * 2 ** 30);
  assert.equal(calls[0].query.extended, "true");
  const old = await client.getFileInfo("sb-1", "/old");
  assert.deepEqual([old.size, old.path], [12, "/old"]);
  assert.equal(await client.fileExists("sb-1", "/new"), true);
  assert.equal(await client.fileExists("sb-1", "/gone"), false);
  assert.equal(await client.fileExists("sb-1", "/gone-old"), false);
  await assert.rejects(client.fileExists("sb-1", "/no-sandbox"), MicroVMApiError);
  await assert.rejects(client.fileExists("sb-1", "/broken"), MicroVMApiError);
});

test("a retried delete or mkdir counts work already done; the first attempt still reports it", async () => {
  // n counts per route and every delete is one route (the path is in the
  // query), so the cases that fail only their first try count their own.
  const tries = new Map<string, number>();
  const { client, calls } = fakeToolbox((call, n) => {
    const path = call.query.path;
    tries.set(path, (tries.get(path) ?? 0) + 1);
    if (path.startsWith("/lost")) {
      if (n === 0) return { status: 502 };
      return call.method === "DELETE"
        ? { status: 404, body: err("lstat: no such file or directory", "file_not_found") }
        : { status: 409, body: err(`${path} already exists`, "folder_exists") };
    }
    if (path === "/route-missing") return tries.get(path) === 1 ? { status: 503, headers: { "Retry-After": "0" } } : { status: 404, body: err("not found") };
    if (path === "/refused") {
      // A 429 is answered before any work: the path was never there.
      return tries.get(path) === 1
        ? { status: 429, headers: { "Retry-After": "0" } }
        : { status: 404, body: err("lstat: no such file or directory", "file_not_found") };
    }
    if (path === "/missing") return { status: 404, body: err("lstat /missing: no such file or directory", "file_not_found") };
    if (path === "/a-file") return { status: 409, body: err("mkdir /a-file: file exists") };
    return { status: 204 };
  });
  await client.deleteFile("sb-1", "/lost-del", { recursive: true });
  assert.equal(calls[0].query.recursive, "true");
  await client.makeDir("sb-1", "/lost-dir", { mode: 0o1750 });
  assert.deepEqual(calls[2].query, { path: "/lost-dir", parents: "false", mode: "1750" });
  await assert.rejects(client.deleteFile("sb-1", "/missing"), (e: unknown) => e instanceof MicroVMApiError && e.status === 404 && e.code === "file_not_found");
  await assert.rejects(client.makeDir("sb-1", "/a-file"), (e: unknown) => e instanceof MicroVMApiError && e.status === 409);
  // An uncoded 404 on a retry may be an agent without the route.
  await assert.rejects(client.deleteFile("sb-1", "/route-missing"), MicroVMApiError);
  // After a 429 the server did nothing, so a coded 404 on the retry means
  // the path never existed, not that this call deleted it.
  await assert.rejects(client.deleteFile("sb-1", "/refused"), (e: unknown) => e instanceof MicroVMApiError && e.status === 404 && e.code === "file_not_found");
  assert.equal(tries.get("/refused"), 2);
});

test("move and copy retry only a 429 or 503", async () => {
  const { client, calls } = fakeToolbox((call, n) => {
    switch (call.query.source) {
      case "/refused-once":
        return n === 0 ? { status: 503 } : { status: 204 };
      case "/bad-gateway":
        return { status: 502 };
      case "/taken":
        return { status: 409, body: err("rename /taken /b: file exists") };
    }
    return { status: 204 };
  });
  await client.moveFile("sb-1", "/refused-once", "/b");
  assert.equal(calls.length, 2);
  await assert.rejects(client.moveFile("sb-1", "/bad-gateway", "/b"), (e: unknown) => e instanceof MicroVMApiError && e.status === 502);
  assert.equal(calls.length, 3, "a 502 on a move was re-sent");
  await assert.rejects(client.moveFile("sb-1", "/taken", "/b"), (e: unknown) => e instanceof MicroVMApiError && e.status === 409);
  await assert.rejects(client.copyFile("sb-1", "/bad-gateway", "/c", { recursive: true }));
  assert.deepEqual(calls[calls.length - 1], {
    method: "POST",
    route: "/files/copy",
    query: { source: "/bad-gateway", destination: "/c", overwrite: "false", recursive: "true" },
  });
});

test("searchFiles and findInFiles", async () => {
  const { client } = fakeToolbox((call) => {
    if (call.query.pattern === "none") {
      return { status: 200, body: call.route.endsWith("/search") ? { files: null } : null };
    }
    return call.route.endsWith("/search")
      ? { status: 200, body: { files: ["/w/a.ts"] } }
      : { status: 200, body: [{ file: "/w/a.ts", line: 2, content: "import x" }] };
  });
  assert.deepEqual(await client.searchFiles("sb-1", "/w", "*.ts"), ["/w/a.ts"]);
  assert.deepEqual(await client.findInFiles("sb-1", "/w", "import"), [{ file: "/w/a.ts", line: 2, content: "import x" }]);
  assert.deepEqual(await client.searchFiles("sb-1", "/w", "none"), []);
  assert.deepEqual(await client.findInFiles("sb-1", "/w", "none"), []);
});

test("file call errors surface", async () => {
  const { client } = fakeToolbox(() => ({ status: 507, body: err("sandbox disk is full: write: no space left on device") }));
  for (const call of [
    () => client.listFiles("sb-1", "/"),
    () => client.copyFile("sb-1", "/a", "/b"),
    () => client.deleteFile("sb-1", "/a"),
  ]) {
    await assert.rejects(call(), (e: unknown) => e instanceof MicroVMApiError && e.status === 507 && e.message.includes("disk is full"));
  }
});

test("SandboxResource file methods delegate", async () => {
  const { client, calls } = fakeToolbox((call) => {
    if (call.route === "/files/info") return { status: 200, body: { name: "x" } };
    if (call.method === "GET") return { status: 200, body: call.route === "/files/search" ? { files: [] } : [] };
    return { status: 204 };
  });
  const sandbox = new SandboxResource(client, { id: "sb-1" } as Sandbox);
  await sandbox.listFiles("/");
  await sandbox.getFileInfo("/x");
  assert.equal(await sandbox.fileExists("/x"), true);
  await sandbox.deleteFile("/x");
  await sandbox.makeDir("/d", { parents: true });
  await sandbox.moveFile("/a", "/b", { overwrite: true });
  await sandbox.copyFile("/a", "/b");
  await sandbox.searchFiles("/", "*");
  await sandbox.findInFiles("/", "x");
  assert.deepEqual(
    calls.map((c) => c.route),
    ["/files", "/files/info", "/files/info", "/files", "/files/folder", "/files/move", "/files/copy", "/files/search", "/files/find"],
  );
});

test("uploadFile sends write options after the version check, on the right retry tier", async () => {
  const { client, calls } = fakeToolbox(
    (call, n) => (call.query.path === undefined && n === 0 ? { status: 502 } : { status: 201, body: {} }),
    ["files.write_options"],
  );
  // A plain upload re-sends after a 502.
  await client.uploadFile("sb-1", "/a", "x");
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].query, {});
  // createOnly is not re-sent after a 502: the first send may have made the file.
  const second = fakeToolbox((_, n) => (n === 0 ? { status: 502 } : { status: 201, body: {} }), ["files.write_options"]);
  await assert.rejects(second.client.uploadFile("sb-1", "/a", "x", { createOnly: true, atomic: true, mode: 0o600 }), (e: unknown) => e instanceof MicroVMApiError && e.status === 502);
  assert.equal(second.calls.length, 1);
  assert.deepEqual(second.calls[0].query, { create_only: "true", atomic: "true", mode: "600" });
});

test("uploadFile options fail closed on an older agent", async () => {
  const { client, calls } = fakeToolbox(() => ({ status: 201, body: {} }), []);
  for (const options of [{ append: true }, { createOnly: true }, { atomic: true }, { mode: 0o644 }]) {
    await assert.rejects(client.uploadFile("sb-1", "/a", "x", options), (e: unknown) => e instanceof MicroVMUnsupportedFeatureError);
  }
  assert.equal(calls.length, 0);
  await client.uploadFile("sb-1", "/a", "x");
  assert.equal(calls.length, 1);
  const sandbox = new SandboxResource(fakeToolbox(() => ({ status: 201, body: {} }), ["files.write_options"]).client, { id: "sb-1" } as Sandbox);
  await sandbox.uploadFile("/a", "x", { append: true });
});

test("uploadDir sends the folder as a gzipped tar with extract=true, once", async () => {
  const { mkdtemp, mkdir, writeFile, symlink, link, chmod } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { gunzipSync } = await import("node:zlib");
  const root = await mkdtemp(join(tmpdir(), "uploaddir-"));
  await mkdir(join(root, "pkg"));
  await writeFile(join(root, "a.txt"), "alpha");
  await writeFile(join(root, "pkg", "b.ts"), "beta");
  await chmod(join(root, "pkg", "b.ts"), 0o750);
  await symlink("a.txt", join(root, "link"));
  await link(join(root, "a.txt"), join(root, "hard.txt"));

  const seen: { url: string; path: string; archive: Uint8Array }[] = [];
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat",
    retry: { maxRetries: 3, baseDelayMs: 1, maxDelayMs: 1 },
    fetch: async (input, init) => {
      const request = new Request(input, init);
      if (request.url.endsWith("/toolbox/version")) {
        return new Response(JSON.stringify({ version: "t", features: ["files.extract"] }));
      }
      const form = await request.formData();
      const file = form.get("file") as Blob;
      seen.push({ url: request.url, path: String(form.get("path")), archive: gunzipSync(new Uint8Array(await file.arrayBuffer())) });
      return new Response(null, { status: 503 });
    },
  });
  await assert.rejects(client.uploadDir("sb-1", root, "/work/app"), (e: unknown) => e instanceof MicroVMApiError && e.status === 503);
  assert.equal(seen.length, 1, "a folder upload was re-sent");
  assert.ok(seen[0].url.endsWith("/v1/sandboxes/sb-1/toolbox/files/upload?extract=true"));
  assert.equal(seen[0].path, "/work/app");
  const archive = seen[0].archive;
  const text = new TextDecoder().decode(archive);
  const names: string[] = [];
  for (let offset = 0; offset + 512 <= archive.length && archive[offset] !== 0; ) {
    const name = text.slice(offset, offset + 100).replace(/\0.*$/s, "");
    const size = parseInt(text.slice(offset + 124, offset + 136), 8);
    names.push(`${name}:${text[offset + 156]}`);
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  // Walk order; the hard link is a plain file ("0"), the link a symlink ("2").
  assert.deepEqual(names, ["a.txt:0", "hard.txt:0", "link:2", "pkg/:5", "pkg/b.ts:0"]);
  assert.ok(text.includes("alpha") && text.includes("beta"));

  const old = fakeToolbox(() => ({ status: 201 }), []);
  await assert.rejects(old.client.uploadDir("sb-1", root, "/w"), (e: unknown) => e instanceof MicroVMUnsupportedFeatureError);
  await assert.rejects(old.client.uploadDir("sb-1", join(root, "a.txt"), "/w"), /not a folder/);
  assert.equal(old.calls.length, 0);
  const ok = fakeToolbox(() => ({ status: 201, body: {} }), ["files.extract"]);
  await new SandboxResource(ok.client, { id: "sb-1" } as Sandbox).uploadDir(root, "/w");
  assert.equal(ok.calls.length, 1);
});

test("downloadFile and downloadFileStream honour maxBytes; downloads retry until the file starts", async () => {
  let calls = 0;
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat",
    retry: { maxRetries: 3, baseDelayMs: 1, maxDelayMs: 1 },
    fetch: async (input) => {
      calls++;
      const path = new URL(String(input)).searchParams.get("path");
      if (path === "/flaky" && calls === 1) return new Response(null, { status: 503 });
      if (path === "/streamed") {
        // No Content-Length: the size shows only as it arrives.
        return new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode("xxxxx")); c.enqueue(new TextEncoder().encode("xxxxx")); c.close(); } }));
      }
      return new Response("0123456789", { headers: { "content-length": "10" } });
    },
  });
  assert.equal(new TextDecoder().decode(await client.downloadFile("sb-1", "/flaky")), "0123456789");
  assert.equal(calls, 2);
  await assert.rejects(client.downloadFile("sb-1", "/sized", { maxBytes: 5 }), (e: unknown) => e instanceof MicroVMFileTooLargeError && e.maxBytes === 5);
  assert.equal((await client.downloadFile("sb-1", "/sized", { maxBytes: 10 })).length, 10);
  const stream = await client.downloadFileStream("sb-1", "/streamed", { maxBytes: 7 });
  const reader = stream.getReader();
  const got: number[] = [];
  await assert.rejects(
    (async () => {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return;
        got.push(...value);
      }
    })(),
    MicroVMFileTooLargeError,
  );
  assert.equal(got.length, 7);
  assert.equal((await client.downloadFile("sb-1", "/streamed", { maxBytes: 10 })).length, 10);
  const unlimited = await client.downloadFileStream("sb-1", "/sized");
  assert.equal(new TextDecoder().decode(new Uint8Array(await new Response(unlimited).arrayBuffer())), "0123456789");
});

test("uploadFileStream streams the body once", async () => {
  const seen: { url: string; body: string }[] = [];
  const client = new APIClient({
    baseURL: "https://api.example.com",
    patToken: "pat",
    retry: { maxRetries: 3, baseDelayMs: 1, maxDelayMs: 1 },
    fetch: async (input, init) => {
      const request = new Request(input, init);
      if (request.url.endsWith("/toolbox/version")) {
        return new Response(JSON.stringify({ version: "t", features: ["files.write_options"] }));
      }
      seen.push({ url: request.url, body: await request.text() });
      return new Response(null, { status: seen.length === 1 ? 503 : 201 });
    },
  });
  async function* chunks() {
    yield new TextEncoder().encode("a".repeat(3000));
    yield new TextEncoder().encode("b".repeat(3000));
  }
  await assert.rejects(client.uploadFileStream("sb-1", "/w/big.bin", chunks()), (e: unknown) => e instanceof MicroVMApiError && e.status === 503);
  assert.equal(seen.length, 1, "a streamed upload was re-sent");
  assert.ok(seen[0].body.includes('name="path"\r\n\r\n/w/big.bin\r\n'));
  assert.ok(seen[0].body.includes("a".repeat(3000) + "b".repeat(3000)));
  const stream = new ReadableStream<Uint8Array>({ start(c) { c.enqueue(new TextEncoder().encode("s")); c.close(); } });
  const sandbox = new SandboxResource(client, { id: "sb-1" } as Sandbox);
  await sandbox.uploadFileStream("/w/s", stream, { createOnly: true });
  assert.ok(seen[1].url.endsWith("?create_only=true"));
  const read = new SandboxResource(
    new APIClient({ baseURL: "https://api.example.com", patToken: "pat", fetch: async () => new Response("hi") }),
    { id: "sb-1" } as Sandbox,
  );
  assert.equal(new TextDecoder().decode(await read.downloadFile("/w/s")), "hi");
  assert.equal(await new Response(await read.downloadFileStream("/w/s")).text(), "hi");
});
