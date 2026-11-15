"""UC-723: the AerolVM Python SDK (sync and async clients) installed from
sdk/python, run by sdkcompat_interp_test.go. env: SB_API_URL, SB_PAT_TOKEN,
CI_IMAGE, optional CI_RUNTIME, CI_MODULE (a WASM module ref), CI_LANGS."""
import asyncio, os, sys
from microvm import MicroVM
from microvm.aio import AsyncMicroVM

def must(cond, msg):
    if not cond:
        print("FAIL:", msg); sys.exit(1)
    print("ok:", msg)

kw = {"image": os.environ.get("CI_IMAGE", "python:3.12-slim")}
if os.environ.get("CI_RUNTIME"):
    kw["runtime"] = os.environ["CI_RUNTIME"]
if os.environ.get("CI_MODULE"):
    kw = {"runtime": "wasm", "module_ref": os.environ["CI_MODULE"]}
client = MicroVM()
sb = client.create(**kw)
try:
    sb.run_code("x = 5")
    out = []
    ex = sb.run_code("print(x); x * 2", on_stdout=lambda s: out.append(s))
    must(ex.text == "10" and ex.logs.stdout == ["5\n"] and "".join(out) == "5\n", f"state + main result ({ex.text!r}, {ex.logs.stdout!r})")
    must(ex.execution_count == 2, f"execution_count {ex.execution_count}")
    ex = sb.run_code("1/0")
    must(ex.error is not None and ex.error.name == "ZeroDivisionError", f"error {ex.error}")
    ex = sb.run_code("class H:\n    def _repr_html_(self): return '<i>h</i>'\nH()")
    must(any(r.html == "<i>h</i>" for r in ex.results), "rich html result")
    ctx = sb.create_code_context(cwd="/tmp")
    must(ctx.cwd == "/tmp" and ctx.active, f"create_code_context {ctx}")
    sb.run_code("y = 1", context=ctx)
    must(sb.run_code("y + 1", context=ctx).text == "2", "context state")
    must(any(c.id == ctx.id for c in sb.list_code_contexts()), "list")
    got = sb.get_code_context(ctx.id)
    must(got.id == ctx.id, "get")
    sb.restart_code_context(ctx)
    ex = sb.run_code("y", context=ctx)
    must(ex.error is not None and ex.error.name == "NameError", "restart wipes state")
    sb.delete_code_context(ctx)
    must(not any(c.id == ctx.id for c in sb.list_code_contexts()), "delete")
    try:
        sb.run_code("import time; time.sleep(20)", timeout_seconds=1)
        must(False, "timeout should raise")
    except Exception as e:
        print("timeout raised:", type(e).__name__)
    for lang, code, want in [("javascript", "let a = 40; a + 2", "42"), ("typescript", "const b: number = 6; b * 7", "42"),
                             ("bash", "echo $((40+2))", None), ("r", "40 + 2", None), ("java", "int c = 6; c * 7", "42")]:
        if lang not in os.environ.get("CI_LANGS", "").split(","):
            continue
        ex = sb.run_code(code, language=lang)
        got = ex.text if want else ("".join(ex.logs.stdout) + (ex.text or ""))
        must(ex.error is None and ((want and got == want) or (not want and "42" in got)), f"{lang}: {got!r} err={ex.error}")

    async def aio():
        ac = AsyncMicroVM()
        asb = await ac.get(sb.id) if hasattr(ac, "get") else None
        if asb is None:
            return
        await asb.run_code("z = 7")
        ex = await asb.run_code("z * 6")
        must(ex.text == "42", "async client keeps state")
        await ac.close() if hasattr(ac, "close") else None
    asyncio.run(aio())
    print("AEROLVM_PY_PASS")
finally:
    sb.destroy()
