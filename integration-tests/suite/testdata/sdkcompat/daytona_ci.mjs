// UC-718: the official Daytona TypeScript SDK's codeInterpreter against the
// deployment's /daytona facade, run by sdkcompat_interp_test.go from a cache
// folder holding the pinned SDK. env: SB_API_URL, SB_PAT_TOKEN, CI_IMAGE
// (Daytona's default image may lack python, so the runner passes one).
import { Daytona } from "@daytona/sdk";

const must = (cond, msg) => { if (!cond) { console.error("FAIL:", msg); process.exitCode = 1; throw new Error(msg); } console.log("ok:", msg); };
const daytona = new Daytona({ apiKey: process.env.SB_PAT_TOKEN, apiUrl: `${process.env.SB_API_URL}/daytona`, target: "us" });
const sandbox = await daytona.create({ image: process.env.CI_IMAGE || "python:3.12-slim" }, { timeout: 180 });
try {
  const ci = sandbox.codeInterpreter;
  let streamed = "";
  let r = await ci.runCode("x = 5", {});
  must(!r.error, "default context: assignment runs");
  r = await ci.runCode("print(x * 2)", { onStdout: (m) => { streamed += m.output; } });
  must(r.stdout.trim() === "10" && streamed.trim() === "10", `default context keeps state (got ${JSON.stringify(r.stdout)})`);
  r = await ci.runCode("1/0");
  must(r.error && r.error.name === "ZeroDivisionError", `error frame (got ${JSON.stringify(r.error)})`);
  const ctx = await ci.createContext();
  must(ctx.id && ctx.language === "python" && ctx.active === true, `createContext ${JSON.stringify(ctx)}`);
  await ci.runCode("y = 'iso'", { context: ctx });
  r = await ci.runCode("print(y)", { context: ctx });
  must(r.stdout.trim() === "iso", "context keeps its own state");
  r = await ci.runCode("print('x' in globals())", { context: ctx });
  must(r.stdout.trim() === "False", "contexts are isolated from the default");
  const list = await ci.listContexts();
  must(list.some((c) => c.id === ctx.id) && !list.some((c) => c.id === "default"), "listContexts shows the new context and hides default");
  r = await ci.runCode("import os; os.system('echo from-subprocess')");
  must(r.stdout.includes("from-subprocess"), "subprocess output is captured");
  r = await ci.runCode("import os; print(os.environ.get('CI_VAR'))", { envs: { CI_VAR: "per-run" } });
  must(r.stdout.trim() === "per-run", "per-run env");
  r = await ci.runCode("import os; print(os.environ.get('CI_VAR'))");
  must(r.stdout.trim() === "None", "per-run env is restored");
  let timedOut = false;
  try {
    r = await ci.runCode("import time; time.sleep(30)", { timeout: 2 });
  } catch (e) { timedOut = true; }
  must(timedOut || (r && r.stdout === "" ), "timeout interrupts a long run");
  r = await ci.runCode("print('after timeout', x)");
  must(r.stdout.trim() === "after timeout 5", "state survives an interrupted run");
  await ci.deleteContext(ctx);
  const after = await ci.listContexts();
  must(!after.some((c) => c.id === ctx.id), "deleteContext removes it");
  console.log("DAYTONA_TS_PASS");
} finally {
  await sandbox.delete();
}
