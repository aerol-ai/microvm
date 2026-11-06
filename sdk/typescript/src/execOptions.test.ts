import assert from "node:assert/strict";
import test from "node:test";

import { MicroVM, MicroVMUnsupportedFeatureError } from "./index.js";

// A fake sandboxd whose toolbox plays an agent that lists `features` on
// /version (undefined: an agent too old to list any). Records every request.
function fakeSandbox(features: string[] | undefined, execResult: Record<string, unknown> = {}) {
  const calls: { method: string; path: string; body?: unknown }[] = [];
  const sdk = new MicroVM({
    patToken: "pat-token",
    apiUrl: "https://api.example.com",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const path = new URL(request.url).pathname;
      const text = request.method === "GET" ? "" : await request.text();
      calls.push({ method: request.method, path, body: text ? JSON.parse(text) : undefined });
      let payload: unknown;
      if (path.endsWith("/toolbox/version")) {
        payload = features === undefined ? { version: "0.6.11" } : { version: "0.6.11", features };
      } else if (path.endsWith("/toolbox/process/execute")) {
        payload = { stdout: "", stderr: "", exit_code: 0, duration_ms: 1, ...execResult };
      } else {
        payload = {
          id: "sb-1", image: "ubuntu:22.04", status: "started", public_url: "", cpu: 1, memory_mb: 512, disk_gb: 1,
          network_block_all: false, toolbox_enabled: true, exposed_ports: [],
          created_at: "2026-05-07T10:00:00Z", updated_at: "2026-05-07T10:00:00Z", last_active_at: "2026-05-07T10:00:00Z",
        };
      }
      return new Response(JSON.stringify(payload), { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  return { sdk, calls };
}

const execPath = "/v1/sandboxes/sb-1/toolbox/process/execute";
const versionPath = "/v1/sandboxes/sb-1/toolbox/version";

test("exec sends output caps when the agent lists them and reads the truncated flags", async () => {
  const { sdk, calls } = fakeSandbox(["exec.max_output_bytes"], { stdout: "aaaa", stdout_truncated: true });
  const sandbox = await sdk.get("sb-1");
  const result = await sandbox.exec({ command: "yes a", maxStdoutBytes: 4, maxStderrBytes: 100 });
  assert.deepEqual(calls.slice(1), [
    { method: "GET", path: versionPath, body: undefined },
    { method: "POST", path: execPath, body: { command: "yes a", max_stdout_bytes: 4, max_stderr_bytes: 100 } },
  ]);
  assert.equal(result.stdout, "aaaa");
  assert.equal(result.stdoutTruncated, true);
  assert.equal(result.stderrTruncated, false);
});

test("exec with output caps fails closed on an older agent and never runs the command", async () => {
  for (const features of [[], undefined, ["files.copy"]]) {
    const { sdk, calls } = fakeSandbox(features);
    const sandbox = await sdk.get("sb-1");
    await assert.rejects(sandbox.exec({ command: "yes", maxStderrBytes: 1024 }), (err: unknown) => {
      assert.ok(err instanceof MicroVMUnsupportedFeatureError);
      assert.deepEqual(err.features, ["exec.max_output_bytes"]);
      assert.match(err.message, /restart the sandbox/);
      return true;
    });
    assert.equal(calls.filter((call) => call.path === execPath).length, 0, "the exec was sent");
  }
});

test("exec without caps makes no /version call, and older agents read as untruncated", async () => {
  const { sdk, calls } = fakeSandbox([]);
  const sandbox = await sdk.get("sb-1");
  const result = await sandbox.exec("ls");
  assert.deepEqual(calls.slice(1).map((call) => call.path), [execPath]);
  assert.equal(result.stdoutTruncated, false);
  assert.equal(result.stderrTruncated, false);
});
