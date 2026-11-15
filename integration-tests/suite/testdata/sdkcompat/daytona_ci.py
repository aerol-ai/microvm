"""UC-719: the official Daytona Python SDK's code_interpreter against the
deployment's /daytona facade, run by sdkcompat_interp_test.go in a venv with
the pinned SDK. env: SB_API_URL, SB_PAT_TOKEN, CI_IMAGE."""
import os, sys
from daytona import Daytona, DaytonaConfig, CreateSandboxFromImageParams

def must(cond, msg):
    if not cond:
        print("FAIL:", msg); sys.exit(1)
    print("ok:", msg)

d = Daytona(DaytonaConfig(api_key=os.environ["SB_PAT_TOKEN"], api_url=os.environ["SB_API_URL"] + "/daytona", target="us"))
sb = d.create(CreateSandboxFromImageParams(image=os.environ.get("CI_IMAGE", "python:3.12-slim")), timeout=180)
try:
    ci = sb.code_interpreter
    chunks = []
    r = ci.run_code("x = 5")
    must(r.error is None, "assignment runs")
    r = ci.run_code("print(x * 2)", on_stdout=lambda m: chunks.append(m.output))
    must(r.stdout.strip() == "10" and "".join(chunks).strip() == "10", f"state kept, streamed ({r.stdout!r})")
    r = ci.run_code("raise ValueError('boom')")
    must(r.error is not None and r.error.name == "ValueError" and r.error.value == "boom", f"error ({r.error})")
    ctx = ci.create_context()
    must(ctx.language == "python" and ctx.active, f"create_context {ctx}")
    ci.run_code("z = 41", context=ctx)
    r = ci.run_code("print(z + 1)", context=ctx)
    must(r.stdout.strip() == "42", "context state")
    must(any(c.id == ctx.id for c in ci.list_contexts()), "list_contexts")
    timed_out = False
    try:
        ci.run_code("import time; time.sleep(30)", timeout=2)
    except Exception as e:  # DaytonaTimeoutError
        timed_out = "timeout" in type(e).__name__.lower() or "timed out" in str(e).lower()
        print("timeout raised:", type(e).__name__, e)
    must(timed_out, "timeout raises")
    r = ci.run_code("print(x)")
    must(r.stdout.strip() == "5", "state survives interrupt")
    ci.delete_context(ctx)
    must(not any(c.id == ctx.id for c in ci.list_contexts()), "delete_context")
    print("DAYTONA_PY_PASS")
finally:
    d.delete(sb)
