// UC-722: the AerolVM TypeScript SDK built from sdk/typescript, run by
// sdkcompat_interp_test.go. env: SB_API_URL, SB_PAT_TOKEN, SDK_PATH (the
// built dist/index.js), CI_IMAGE, optional CI_MODULE (a WASM module ref).
const { MicroVM } = await import(process.env.SDK_PATH);
const must = (c, m) => { if (!c) { console.error("FAIL:", m); process.exit(1); } console.log("ok:", m); };
const client = new MicroVM();
const opts = process.env.CI_MODULE ? { runtime: "wasm", moduleRef: process.env.CI_MODULE } : { image: process.env.CI_IMAGE || "python:3.12-slim" };
const sb = await client.create(opts);
try {
  await sb.runCode("x = 5");
  let streamed = "";
  let ex = await sb.runCode("print(x); x * 2", { onStdout: (t) => { streamed += t; } });
  must(ex.text === "10" && streamed === "5\n", `state + result (${ex.text}, ${JSON.stringify(streamed)})`);
  ex = await sb.runCode("1/0");
  must(ex.error && ex.error.name === "ZeroDivisionError", "error");
  const ctx = await sb.createCodeContext({ cwd: "/tmp" });
  await sb.runCode("y = 2", { context: ctx });
  ex = await sb.runCode("y * 21", { context: ctx });
  must(ex.text === "42", "context state");
  must((await sb.listCodeContexts()).some((c) => c.id === ctx.id), "list");
  await sb.restartCodeContext(ctx);
  ex = await sb.runCode("y", { context: ctx });
  must(ex.error && ex.error.name === "NameError", "restart");
  await sb.deleteCodeContext(ctx);
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 1000);
  let interrupted = false;
  try { ex = await sb.runCode("import time; time.sleep(20)", { signal: ac.signal }); interrupted = ex.interrupted; } catch (e) { interrupted = true; console.log("abort raised:", e.name); }
  must(interrupted, "AbortSignal interrupts");
  ex = await sb.runCode("x");
  must(ex.text === "5", "state survives interrupt");
  console.log("AEROLVM_TS_PASS");
} finally {
  await sb.destroy();
}
