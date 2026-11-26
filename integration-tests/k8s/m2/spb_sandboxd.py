"""spb_sandboxd.py: SP-B's "sandboxd" step (plans/security-gaps-m1-m4.md
§4.3): AerolVM's own sandboxd on this Nitro machine, Firecracker backend
nitro (spb-sandboxd.sh started it), driven through its v1 API the way a
user would. spb.py sandboxd calls run().

Checks, each recorded:
  - GET /v1/runtimes offers firecracker-nitro (backend nitro) and not
    firecracker;
  - N creates of runtime firecracker-nitro, one after another: each one
    starts, runs a command, writes and reads a file, reaches the internet
    through its TAP, and is deleted; create time from the API;
  - the guest: its kernel, its boot line (no pci=off, the agent's init),
    whether it sees VMX (information);
  - stop and start on the first sandbox: a file written before the stop is
    there after the start, the env comes back, the address is the same,
    and the boot ID is new (no memory is kept on Nitro);
  - what a Nitro sandbox cannot do answers 501 with the runtime's name
    (a snapshot); a create for "firecracker" is refused here;
  - the Nitro budget: 1-vCPU sandboxes created until one is refused; the
    refusal is AerolVM's capacity answer (503, naming the limit), not a
    Firecracker failure, and every one that started is deleted;
  - nothing left: no Firecracker process and no sandbox TAP after the
    deletes.

Stdlib only. API_URL and the token file can be pointed at a stand-in
(SPB_API, SPB_PAT_FILE) so the safety tests run it off the machine.
"""
import json
import os
import time
import urllib.error
import urllib.request

API = os.environ.get("SPB_API", "http://127.0.0.1:21212")
PAT_FILE = os.environ.get("SPB_PAT_FILE", "/root/pat")
IMAGE = "alpine:3.20"
NITRO = "firecracker-nitro"
COLD_GO_MS = 2000.0


def _token():
    with open(PAT_FILE) as f:
        return f.read().strip()


def call(method, path, body=None, timeout=300):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers={
        "Authorization": "Bearer " + _token(), "Content-Type": "application/json"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, status = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    except (urllib.error.URLError, OSError) as e:
        return 0, {"error": str(e)}, (time.monotonic() - t0) * 1000
    ms = (time.monotonic() - t0) * 1000
    try:
        js = json.loads(raw) if raw else None
    except ValueError:
        js = {"raw": raw[:300].decode(errors="replace")}
    return status, js, ms


def run_cmd(sid, command):
    st, js, _ = call("POST", "/v1/sandboxes/%s/toolbox/process/execute" % sid, {"command": command})
    out = ""
    if isinstance(js, dict):
        out = js.get("stdout") or js.get("result") or js.get("output") or ""
    return st, str(out).strip()


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    return round(s[min(len(s) - 1, max(0, int(p / 100 * (len(s) - 1) + 0.5)))], 1)


def firecracker_processes(proc="/proc"):
    """Processes named firecracker (0 where there is no /proc)."""
    n = 0
    for pid in os.listdir(proc) if os.path.isdir(proc) else []:
        try:
            with open(os.path.join(proc, pid, "comm")) as f:
                n += f.read().strip() == "firecracker"
        except OSError:
            pass
    return n


def sandbox_taps(net="/sys/class/net"):
    """Network devices named like sandboxd's TAPs (fctap...)."""
    return sum(1 for d in (os.listdir(net) if os.path.isdir(net) else []) if d.startswith("fctap"))


def runtimes(record, say):
    st, js, _ = call("GET", "/v1/runtimes")
    rows = {r.get("name"): r for r in ((js or {}).get("runtimes") or [])}
    nitro, kvm = rows.get(NITRO) or {}, rows.get("firecracker") or {}
    ok = st == 200 and nitro.get("available") is True and nitro.get("backend") == "nitro" and not kvm.get("available")
    record("sandboxd-runtimes", {"ok": ok, "status": st, "nitro": nitro, "firecracker_available": kvm.get("available")})
    say("sandboxd runtimes: firecracker-nitro available=%s backend=%s; firecracker available=%s"
        % (nitro.get("available"), nitro.get("backend"), kvm.get("available")))
    return ok


def one(i, say):
    """One sandbox, end to end. Returns (result dict, create ms or None)."""
    r = {"i": i}
    body = {"image": IMAGE, "runtime": NITRO, "memory_mb": 512, "cpu": 1}
    if i == 0:
        body["env"] = {"SPB_ENV": "kept-across-start"}
    st, js, ms = call("POST", "/v1/sandboxes", body)
    sid = (js or {}).get("id")
    if st >= 300 or not sid:
        r["create_error"] = "HTTP %s %s" % (st, json.dumps(js)[:400])
        return r, None
    r["id"] = sid
    try:
        r["status"] = (js or {}).get("status")
        r["runtime"], r["backend"] = (js or {}).get("runtime"), (js or {}).get("backend")
        st, out = run_cmd(sid, "echo ran-$(( 6 * 7 ))")
        r["exec"] = st == 200 and "ran-42" in out
        st, out = run_cmd(sid, "echo nitro-file > /tmp/spb.txt && cat /tmp/spb.txt")
        r["file"] = st == 200 and "nitro-file" in out
        st, out = run_cmd(sid, "wget -q -T 8 -O - http://checkip.amazonaws.com >/dev/null && echo net-ok || echo net-fail")
        r["egress"] = st == 200 and "net-ok" in out
        if i == 0:
            _, r["guest_kernel"] = run_cmd(sid, "uname -r")
            _, r["guest_cmdline"] = run_cmd(sid, "cat /proc/cmdline")
            _, r["guest_vmx"] = run_cmd(sid, "grep -c -w -e vmx -e svm /proc/cpuinfo || true")
            r.update(stop_start(sid, say))
            st, js, _ = call("POST", "/v1/sandboxes/%s/snapshot" % sid, {"name": "spb-nitro-snap"})
            r["snapshot_refused"] = st == 501 and NITRO in json.dumps(js)
            r["snapshot_answer"] = "HTTP %s %s" % (st, json.dumps(js)[:240])
    finally:
        st, _, _ = call("DELETE", "/v1/sandboxes/" + sid)
        r["deleted"] = st in (200, 202, 204)
    say("sandboxd sample %d: %s create %.0f ms exec=%s file=%s egress=%s deleted=%s"
        % (i, sid, ms, r.get("exec"), r.get("file"), r.get("egress"), r.get("deleted")))
    return r, ms


def stop_start(sid, say):
    """Stop and start one sandbox; what it keeps and what it does not."""
    r = {}
    run_cmd(sid, "echo persist > /root/spb-keep.txt && sync")
    _, boot_before = run_cmd(sid, "cat /proc/sys/kernel/random/boot_id")
    _, ip_before = run_cmd(sid, "ip -4 -o addr show eth0 | awk '{print $4}'")
    st, js, stop_ms = call("POST", "/v1/sandboxes/%s/stop" % sid)
    r["stop_answer"] = "HTTP %s %s" % (st, json.dumps(js)[:240])
    stopped = st < 300
    st, js, start_ms = call("POST", "/v1/sandboxes/%s/start" % sid)
    r["start_answer"] = "HTTP %s %s" % (st, json.dumps(js)[:240])
    started = st < 300
    _, kept = run_cmd(sid, "cat /root/spb-keep.txt")
    _, env = run_cmd(sid, "echo $SPB_ENV")
    _, boot_after = run_cmd(sid, "cat /proc/sys/kernel/random/boot_id")
    _, ip_after = run_cmd(sid, "ip -4 -o addr show eth0 | awk '{print $4}'")
    r.update({
        "stop_ms": round(stop_ms), "start_ms": round(start_ms),
        "file_kept": kept == "persist", "env_kept": env == "kept-across-start",
        "same_address": bool(ip_before) and ip_before == ip_after,
        "new_boot": bool(boot_before) and bool(boot_after) and boot_before != boot_after,
    })
    r["stop_start_ok"] = stopped and started and r["file_kept"] and r["env_kept"] and r["same_address"] and r["new_boot"]
    say("sandboxd stop/start: stop %s ms, start %s ms; file kept %s, env kept %s, same address %s (%s), new boot %s"
        % (r["stop_ms"], r["start_ms"], r["file_kept"], r["env_kept"], r["same_address"], ip_after, r["new_boot"]))
    return r


def fill_budget(say, most=40):
    """Create 1-vCPU, 256 MiB sandboxes until one is refused."""
    made, refusal = [], None
    for _ in range(most):
        st, js, _ = call("POST", "/v1/sandboxes", {"image": IMAGE, "runtime": NITRO, "memory_mb": 256, "cpu": 1})
        if st < 300 and (js or {}).get("id"):
            made.append(js["id"])
            continue
        refusal = "HTTP %s %s" % (st, json.dumps(js)[:300])
        break
    for sid in made:
        call("DELETE", "/v1/sandboxes/" + sid)
    ok = refusal is not None and refusal.startswith("HTTP 503") and "Nitro" in refusal and len(made) > 0
    say("sandboxd budget: %d started before the refusal: %s" % (len(made), refusal))
    return {"budget_started": len(made), "budget_refusal": refusal, "budget_ok": ok}


def run(a, record, say):
    say("sandboxd: %d sandboxes of runtime %s through sandboxd's API" % (a.samples, NITRO))
    ok_runtimes = runtimes(record, say)
    results, create_ms = [], []
    for i in range(a.samples):
        r, ms = one(i, say)
        results.append(r)
        if ms is not None:
            create_ms.append(ms)
        if "create_error" in r:
            say("sandboxd sample %d failed: %s" % (i, r["create_error"][:600]))
    budget = fill_budget(say) if getattr(a, "budget", True) else {}
    st, js, _ = call("POST", "/v1/sandboxes", {"image": IMAGE, "runtime": "firecracker"})
    kvm_refused = st >= 400 and "firecracker-nitro" in json.dumps(js)
    if st < 300 and (js or {}).get("id"):
        call("DELETE", "/v1/sandboxes/" + js["id"])
    time.sleep(2)
    leftovers = {"firecracker_processes": firecracker_processes(), "sandbox_taps": sandbox_taps()}
    first = results[0] if results else {}
    cmdline = first.get("guest_cmdline", "")
    good = [r for r in results if r.get("exec") and r.get("file") and r.get("egress") and r.get("deleted")
            and r.get("runtime") == NITRO]
    out = {
        "samples": a.samples, "passed": len(good),
        "create_ms": {"p50_ms": pct(create_ms, 50), "p90_ms": pct(create_ms, 90), "max_ms": pct(create_ms, 100)},
        "runtimes_ok": ok_runtimes, "kvm_create_refused": kvm_refused, "kvm_create_answer": "HTTP %s %s" % (st, json.dumps(js)[:240]),
        "guest_kernel": first.get("guest_kernel"), "guest_cmdline": cmdline, "guest_vmx_lines": first.get("guest_vmx"),
        "boot_line_ok": "pci=off" not in cmdline.split() and "init=/usr/local/bin/toolboxd-init" in cmdline.split(),
        "stop_start_ok": first.get("stop_start_ok"), "stop_ms": first.get("stop_ms"), "start_ms": first.get("start_ms"),
        "stop_answer": first.get("stop_answer"), "start_answer": first.get("start_answer"),
        "snapshot_refused": first.get("snapshot_refused"), "snapshot_answer": first.get("snapshot_answer"),
        "leftovers": leftovers, "results": results,
    }
    out.update(budget)
    record("sandboxd", out)


def verdict(r):
    """(ok, text) for spb.py's verdict: every sandbox passed, the refusals
    and the runtime list are right, nothing was left, and a create is under
    SP-B's 2 s cold bar at the p50."""
    if not r:
        return False, "no result"
    p50 = (r.get("create_ms") or {}).get("p50_ms")
    left = r.get("leftovers") or {}
    ok = (r.get("samples", 0) > 0 and r.get("passed") == r.get("samples") and r.get("runtimes_ok")
          and r.get("kvm_create_refused") and r.get("boot_line_ok") and r.get("stop_start_ok") and r.get("snapshot_refused")
          and r.get("budget_ok", True)
          and left.get("firecracker_processes") == 0 and left.get("sandbox_taps") == 0
          and p50 is not None and p50 < COLD_GO_MS)
    text = ("%s of %s sandboxes passed through sandboxd (create p50 %s ms, go under %g); runtimes %s; firecracker refused %s; "
            "boot line %s; stop/start %s (stop %s ms, start %s ms); snapshot refused %s; budget %s (%s started, then %s); "
            "left: %s processes, %s TAPs; guest %s, vmx lines %s"
            % (r.get("passed"), r.get("samples"), p50, COLD_GO_MS, r.get("runtimes_ok"), r.get("kvm_create_refused"),
               r.get("boot_line_ok"), r.get("stop_start_ok"), r.get("stop_ms"), r.get("start_ms"), r.get("snapshot_refused"),
               r.get("budget_ok"), r.get("budget_started"), (r.get("budget_refusal") or "")[:120],
               left.get("firecracker_processes"), left.get("sandbox_taps"), r.get("guest_kernel"), r.get("guest_vmx_lines")))
    return bool(ok), text
