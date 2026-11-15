// UC-720: the official E2B Code Interpreter JS SDK against the deployment's
// /e2b facade, run by sdkcompat_interp_test.go from a cache folder holding
// the pinned SDK. env: E2B_API_URL, E2B_SANDBOX_URL, E2B_API_KEY, optional
// CI_TEMPLATE (default code-interpreter-v1).
import { Sandbox } from "@e2b/code-interpreter";
const must = (c, m) => { if (!c) { console.error("FAIL:", m); process.exit(1); } console.log("ok:", m); };
const sbx = await Sandbox.create(process.env.CI_TEMPLATE || undefined);
try {
  let ex = await sbx.runCode("x = 1");
  must(!ex.error, "assignment");
  const lines = [];
  ex = await sbx.runCode("print('a'); x + 41", { onStdout: (m) => lines.push(m.line) });
  must(ex.text === "42", `text ${ex.text}`);
  must(lines.join("").includes("a"), "onStdout");
  ex = await sbx.runCode("1/0");
  must(ex.error && ex.error.name === "ZeroDivisionError", "error");
  const ctx = await sbx.createCodeContext({ cwd: "/tmp" });
  must(ctx.cwd === "/tmp", "createCodeContext");
  await sbx.runCode("q = 3", { context: ctx });
  ex = await sbx.runCode("q * 14", { context: ctx });
  must(ex.text === "42", "context state");
  await sbx.restartCodeContext(ctx);
  ex = await sbx.runCode("q", { context: ctx });
  must(ex.error && ex.error.name === "NameError", "restart wipes state");
  await sbx.removeCodeContext(ctx);
  console.log("E2B_JS_PASS");
} finally {
  await sbx.kill();
}
