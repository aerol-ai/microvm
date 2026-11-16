"""UC-721: the official E2B Code Interpreter Python SDK against the
deployment's /e2b facade, run by sdkcompat_interp_test.go in a venv with the
pinned SDK. env: E2B_API_URL=<base>/e2b, E2B_SANDBOX_URL=<base>/e2b/runtime,
E2B_API_KEY=<PAT>.
Optional: CI_LANGS="python,javascript,typescript,bash,r,java" (languages present in the mapped image), CI_TEMPLATE."""
import os, sys
from e2b_code_interpreter import Sandbox

def must(cond, msg):
    if not cond:
        print("FAIL:", msg); sys.exit(1)
    print("ok:", msg)

tmpl = os.environ.get("CI_TEMPLATE")
sbx = Sandbox.create(template=tmpl) if tmpl else Sandbox.create()
try:
    out = []
    ex = sbx.run_code("x = 1", on_stdout=lambda m: out.append(m.line))
    must(ex.error is None, "run_code assignment")
    ex = sbx.run_code("print('a'); x + 41", on_stdout=lambda m: out.append(m.line))
    must(ex.text == "42", f"main result text ({ex.text!r})")
    must(ex.logs.stdout == ["a\n"], f"logs.stdout ({ex.logs.stdout!r})")
    must(any("a" in s for s in out), "on_stdout streamed")
    must(ex.execution_count == 2, f"execution_count ({ex.execution_count})")
    ex = sbx.run_code("'quoted'")
    must(ex.text == "quoted", f"text/plain quotes stripped ({ex.text!r})")
    ex = sbx.run_code("class H:\n    def _repr_html_(self): return '<b>hi</b>'\nH()")
    must(ex.results and ex.results[0].html == "<b>hi</b>", "rich html result")
    ex = sbx.run_code("display('one'); display('two'); 3")
    must(len(ex.results) == 3 and ex.results[-1].is_main_result, f"display + main ({[r.text for r in ex.results]})")
    ex = sbx.run_code("undefined_name")
    must(ex.error is not None and ex.error.name == "NameError", f"error ({ex.error})")
    ctx = sbx.create_code_context(cwd="/tmp")
    must(ctx.cwd == "/tmp" and ctx.language == "python", f"create_code_context {ctx}")
    ex = sbx.run_code("import os; os.getcwd()", context=ctx)
    must(ex.text == "/tmp", f"context cwd ({ex.text!r})")
    ex = sbx.run_code("import os; os.getcwd()")
    must(ex.text == "/home/user", f"default cwd /home/user ({ex.text!r})")
    ids = [c.id for c in sbx.list_code_contexts()]
    must(ctx.id in ids and len(ids) >= 3, f"list_code_contexts includes defaults ({len(ids)})")
    sbx.run_code("y = 9", context=ctx)
    sbx.restart_code_context(ctx)
    ex = sbx.run_code("y", context=ctx)
    must(ex.error is not None and ex.error.name == "NameError", "restart wipes state")
    sbx.remove_code_context(ctx)
    must(ctx.id not in [c.id for c in sbx.list_code_contexts()], "remove_code_context")
    ex = sbx.run_code("import os; os.environ.get('V')", envs={"V": "z"})
    must(ex.text == "z", "envs")
    try:
        sbx.run_code("import time; time.sleep(30)", timeout=2)
        must(False, "timeout should raise")
    except Exception as e:
        print("timeout raised:", type(e).__name__)
    ex = sbx.run_code("x")
    must(ex.text == "1", f"state survives a client timeout ({ex.text!r})")
    langs = [l for l in os.environ.get("CI_LANGS", "python").split(",") if l]
    probes = {
        "javascript": ("let j = 20; j + 1", "21"),
        "typescript": ("const t: number = 7; t * 6", "42"),
        "bash": ("echo $((6*7))", None),
        "r": ("x <- 41; x + 1", None),
        "java": ("int k = 6; k * 7", "42"),
    }
    for lang in langs:
        if lang == "python":
            continue
        code, want = probes[lang]
        ex = sbx.run_code(code, language=lang)
        got = ex.text if want is not None else "".join(ex.logs.stdout) + (ex.text or "")
        must(ex.error is None and (want is None and "42" in got or got == want), f"{lang}: {got!r} err={ex.error}")
    print("E2B_PY_PASS")
finally:
    sbx.kill()
