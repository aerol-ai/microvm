#!/usr/bin/env python3
"""spa-bench.py: spike SP-A (plans/security-gaps-m1-m4.md §4.2) on one machine.

Measures AerolVM's own Firecracker create paths against the single-node
sandboxd on this machine (http://127.0.0.1:21212), the same way on a
nested-virtualization VM and on metal:

    spa-bench.py base --samples N --cycles C --idle-cycles I
        cold create from an image, template build, template-snapshot
        create, then pause and resume (v1 stop, v1 start): C cycles with a
        process counting in the guest, I cycles with an idle guest
    spa-bench.py warm --samples N
        template creates with the warm VMM pool on
        (SB_FIRECRACKER_VMM_POOL_ENABLED=true)

Pause and resume, beyond the first run (2026-11-20): a start that fails is
tried up to RETRIES more times, each a new VMM loading the same snapshot.
If the failure belongs to the snapshot, every try fails; if it is a race,
some pass. The first failures' VMM output goes to the results.

Stdlib only. Prints "SPA ..." lines (the user data copies them to the
serial console) and writes /root/spa-<phase>.json. Times are the API round
trip on the node and the server's create time from Server-Timing. Every
sandbox it makes, it deletes.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

# SPA_API, SPA_HOME and SPA_CYCLE_GAP point a run at a stand-in API with its
# files off the machine (integration-tests/safety/m2_spikes_test.go).
API = os.environ.get("SPA_API", "http://127.0.0.1:21212")
IMAGE = "alpine:3.20"
HOME = os.environ.get("SPA_HOME", "/root")
# Seconds between a resume and the next pause, so the guest runs a while.
CYCLE_GAP = float(os.environ.get("SPA_CYCLE_GAP", "1.2"))
# Seconds a resumed guest has to answer an exec with its /tmp marker.
EXEC_WAIT = float(os.environ.get("SPA_EXEC_WAIT", "5"))
STATE = HOME + "/spa-state.json"
RESULTS = HOME + "/spa-results"
RETRIES = 3
WARM_GO_MS = 100.0
TOKEN = ""


def say(*parts):
    print("SPA", *parts, flush=True)


def call(method, path, body=None, timeout=600):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers={
        "Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, status, hdr = r.read(), r.status, r.headers
    except urllib.error.HTTPError as e:
        raw, status, hdr = e.read(), e.code, e.headers
    ms = (time.monotonic() - t0) * 1000
    try:
        js = json.loads(raw) if raw else None
    except ValueError:
        js = {"raw": raw[:300].decode(errors="replace")}
    return status, js, hdr, ms


def stages(hdr):
    """Server-Timing as {name: (ms, desc)}; a header may come split."""
    out = {}
    for metric in ", ".join(hdr.get_all("Server-Timing") or []).split(","):
        fields = [f.strip() for f in metric.split(";") if f.strip()]
        if not fields:
            continue
        dur, desc = None, ""
        for f in fields[1:]:
            if f.startswith("dur="):
                dur = float(f[4:])
            elif f.startswith("desc="):
                desc = f[5:].strip('"')
        out[fields[0]] = (dur, desc)
    return out


def pct(values, p):
    """Nearest rank, as integration-tests/suite/benchmark_test.go does."""
    if not values:
        return None
    s = sorted(values)
    rank = min(len(s) - 1, max(0, int(p / 100 * (len(s) - 1) + 0.5)))
    return round(s[rank], 1)


def summary(name, values, **extra):
    d = {"name": name, "n": len(values), "p50_ms": pct(values, 50),
         "p90_ms": pct(values, 90), "p99_ms": pct(values, 99),
         "min_ms": round(min(values), 1) if values else None,
         "max_ms": round(max(values), 1) if values else None}
    d.update(extra)
    say(json.dumps(d))
    return d


def create(body):
    st, js, hdr, ms = call("POST", "/v1/sandboxes", body)
    if st >= 300 or not js or not js.get("id"):
        return None, ms, stages(hdr), "HTTP %s %s" % (st, json.dumps(js)[:300])
    sid = js["id"]
    # A create answers when the guest has done its vsock handshake; wait
    # anyway in case this build answers earlier.
    status = js.get("status")
    deadline = time.monotonic() + 120
    while status != "started" and time.monotonic() < deadline:
        time.sleep(0.05)
        _, g, _, _ = call("GET", "/v1/sandboxes/" + sid)
        status = (g or {}).get("status")
    if status != "started":
        return sid, ms, stages(hdr), "status %s" % status
    return sid, ms, stages(hdr), None


def delete(sid):
    if sid:
        call("DELETE", "/v1/sandboxes/" + sid)


def exec_(sid, command):
    st, js, _, ms = call("POST", "/v1/sandboxes/%s/toolbox/process/execute" % sid, {"command": command})
    out = ""
    if isinstance(js, dict):
        out = js.get("stdout") or js.get("result") or js.get("output") or ""
        if st >= 300:
            out = json.dumps(js)[:200]
    return st, str(out).strip(), ms


def wait_health():
    for _ in range(300):
        try:
            with urllib.request.urlopen(API + "/health", timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False


def vmm_exit_tail(sid, chars=1500):
    """The last 'firecracker vmm process exited' line sandboxd logged for
    this sandbox: Firecracker's own output and the guest console."""
    try:
        out = subprocess.run(["journalctl", "-u", "sandboxd", "--no-pager", "-o", "cat"],
                             capture_output=True, text=True, timeout=60).stdout
    except Exception as e:
        return "journal: %s" % e
    lines = [l for l in out.splitlines() if "vmm process exited" in l and sid in l]
    return lines[-1][-chars:] if lines else ""


def creates(label, body, n, gap=0.0, keep_stage=None):
    """n creates one after another, each deleted before the next."""
    api, server, failures, hits, notes, all_api = [], [], 0, 0, [], []
    for i in range(n):
        sid, ms, st, err = create(dict(body))
        if err:
            failures += 1
            notes.append(err)
            say("%s sample %d failed: %s" % (label, i, err))
            delete(sid)
            continue
        all_api.append(ms)
        if keep_stage:
            dur, desc = st.get(keep_stage, (None, ""))
            if desc != "hit":
                notes.append("miss")
                delete(sid)
                if gap:
                    time.sleep(gap)
                continue
            hits += 1
        api.append(ms)
        if "create" in st and st["create"][0] is not None:
            server.append(st["create"][0])
        if i == 0 or (keep_stage and hits == 1):
            code, out, _ = exec_(sid, "echo agent-ok; uname -r")
            say("%s first sandbox exec: %s %s" % (label, code, out.replace("\n", " ")))
            say("%s stages: %s" % (label, {k: v[0] for k, v in st.items()}))
        delete(sid)
        if gap:
            time.sleep(gap)
    return api, server, failures, hits, notes, all_api


def phase_base(a):
    n = a.samples
    base = {"runtime": "firecracker", "image": IMAGE}
    results = {"leg": a.leg}
    # One cold create first, not counted: the first pull of the image.
    sid, ms, st, err = create(dict(base))
    say("first cold create (image pull, not counted): %.0f ms err=%s" % (ms, err))
    delete(sid)

    api, server, fails, _, notes, _ = creates("cold", base, n)
    results["cold"] = summary("cold create (OCI image -> rootfs -> boot)", api,
                              server=summary("cold create, server time", server)["p50_ms"],
                              failures=fails, notes=notes[:3])

    t0 = time.monotonic()
    st, js, _, _ = call("POST", "/v1/templates", {"image": "docker://" + IMAGE})
    tid = (js or {}).get("id")
    if not tid:
        say("template create failed: HTTP %s %s" % (st, json.dumps(js)[:300]))
        return results
    status = ""
    while time.monotonic() - t0 < 1200:
        _, js, _, _ = call("GET", "/v1/templates/" + tid)
        status = (js or {}).get("status", "")
        if status in ("ready", "ready_no_snapshot", "failed", "unhealthy"):
            break
        time.sleep(1)
    build_s = round(time.monotonic() - t0, 1)
    say("template %s %s after %ss" % (tid, status, build_s))
    results["template_build_s"] = build_s
    results["template_status"] = status
    json.dump({"template": tid}, open(STATE, "w"))
    if status != "ready":
        say("template not ready (%s): %s" % (status, json.dumps(js)[:400]))
        return results

    tbody = dict(base, template_id=tid)
    api, server, fails, _, notes, _ = creates("template", tbody, n)
    results["template"] = summary("template-snapshot create", api,
                                  server=summary("template-snapshot create, server time", server)["p50_ms"],
                                  failures=fails, notes=notes[:3])
    results["pause_resume_busy"] = pause_resume(tbody, a.cycles, busy=True)
    results["pause_resume_idle"] = pause_resume(tbody, a.idle_cycles, busy=False)
    say(pause_resume_verdict(results["pause_resume_busy"], a.cycles, results["pause_resume_idle"], a.idle_cycles))
    return results


def pause_resume_verdict(busy, n_busy, idle, n_idle):
    """Plan §4.2's bar is every cycle intact, not only none lost: a start
    that works but hands back a rebooted guest (a new boot ID), an empty
    /tmp or no exec answer lost the sandbox's memory just as surely."""
    parts, ok = [], True
    for label, res, n in (("busy", busy, n_busy), ("idle", idle, n_idle)):
        intact = res.get("cycles_intact", 0)
        if "error" in res or intact != n:
            ok = False
        parts.append("%s %d of %d intact (%d lost)" % (label, intact, n, res.get("cycles_lost", 0)))
    return "VERDICT pause/resume: %s (go: every cycle intact) -> %s" % ("; ".join(parts), "PASS" if ok else "FAIL")


def pause_resume(body, n, busy):
    """v1 stop writes the VM's memory snapshot; start restores it. The
    sandbox must come back with the same boot ID and its /tmp (tmpfs, in
    memory) intact; busy, a background counter must keep its value too. A
    failed start is tried up to RETRIES more times (a new VMM each time,
    the same snapshot); if all fail the cycle is lost and a fresh sandbox
    carries on, so one failure does not end the series."""
    label = "pause/resume (%s)" % ("busy" if busy else "idle")
    if n <= 0:
        return {"cycles": 0}

    def fresh():
        sid, _, _, err = create(dict(body))
        if err:
            return None, None, err
        if busy:
            exec_(sid, 'setsid nohup sh -c "i=0; while true; do i=\\$((i+1)); echo \\$i > /tmp/counter; sleep 1; done" </dev/null >/dev/null 2>&1 &')
        _, before, _ = exec_(sid, "cat /proc/sys/kernel/random/boot_id; echo spa-marker > /tmp/marker")
        return sid, before, None

    sid, before, err = fresh()
    if err:
        say("%s: create failed: %s" % (label, err))
        return {"error": err}
    stop_ms, start_ms, first_exec_ms, notes, cycles = [], [], [], [], []
    intact = start_fail = retry_ok = lost = 0
    dumps = 0
    last_counter = 0
    for i in range(n):
        time.sleep(CYCLE_GAP)
        rec = {"cycle": i, "sandbox": sid}
        s1, js, _, ms1 = call("POST", "/v1/sandboxes/%s/stop" % sid)
        rec["stop_ms"] = round(ms1, 1)
        if s1 >= 300:
            rec["outcome"] = "stop failed: HTTP %s %s" % (s1, json.dumps(js)[:300])
            notes.append("cycle %d stop %s: HTTP %s %s" % (i, sid, s1, json.dumps(js)[:300]))
            lost += 1
            cycles.append(rec)
            delete(sid)
            sid, before, err = fresh()
            last_counter = 0
            if err:
                break
            continue
        stop_ms.append(ms1)
        attempts, errors, ok = 0, [], False
        while attempts <= RETRIES:
            attempts += 1
            s2, js, _, ms2 = call("POST", "/v1/sandboxes/%s/start" % sid)
            if s2 < 300:
                ok = True
                if attempts == 1:
                    start_ms.append(ms2)
                break
            errors.append("HTTP %s %s" % (s2, json.dumps(js)[:240]))
        rec["start_attempts"], rec["start_errors"] = attempts, errors
        if errors:
            start_fail += 1
            say("%s cycle %d: start of %s failed %d time(s), then %s: %s"
                % (label, i, sid, len(errors), "worked" if ok else "lost", errors[0]))
            if dumps < 2:
                dumps += 1
                tail = vmm_exit_tail(sid)
                rec["vmm_exit_tail"] = tail
                say("%s cycle %d: last VMM output: %s" % (label, i, tail[-600:].replace("\\n", " | ")))
        if not ok:
            rec["outcome"] = "lost"
            lost += 1
            cycles.append(rec)
            delete(sid)
            sid, before, err = fresh()
            last_counter = 0
            if err:
                break
            continue
        if errors:
            retry_ok += 1
        t0 = time.monotonic()
        code, out = 0, ""
        while True:
            code, out, _ = exec_(sid, "cat /proc/sys/kernel/random/boot_id; cat /tmp/marker; cat /tmp/counter 2>/dev/null || echo 0")
            if (code < 300 and "spa-marker" in out) or time.monotonic() - t0 > EXEC_WAIT:
                break
            time.sleep(0.05)
        first_exec_ms.append((time.monotonic() - t0) * 1000)
        lines = out.split()
        counter = int(lines[2]) if len(lines) > 2 and lines[2].isdigit() else -1
        if lines[:1] == before.split()[:1] and "spa-marker" in out and counter >= last_counter:
            intact += 1
            rec["outcome"] = "intact"
        else:
            rec["outcome"] = "not intact: %s" % out[:120]
            notes.append("cycle %d: %s" % (i, out[:120]))
        last_counter = counter
        cycles.append(rec)
    delete(sid)
    json.dump(cycles, open("%s/cycles-%s.json" % (RESULTS, "busy" if busy else "idle"), "w"), indent=1)
    res = {
        "stop": summary("%s: pause (v1 stop: memory snapshot)" % label, stop_ms),
        "start": summary("%s: resume (v1 start: snapshot restore, first try)" % label, start_ms),
        "first_exec_after_start": summary("%s: first exec after resume" % label, first_exec_ms),
        "cycles": n, "cycles_intact": intact, "start_failures": start_fail,
        "start_retry_ok": retry_ok, "cycles_lost": lost, "notes": notes[:4]}
    say("%s: %d cycles; %d intact; %d first starts failed, %d of them worked on a later try (up to %d more), %d lost"
        % (label, n, intact, start_fail, retry_ok, RETRIES, lost))
    return res


def phase_warm(a):
    tid = json.load(open(STATE))["template"]
    body = {"runtime": "firecracker", "image": IMAGE, "template_id": tid}
    # The refiller fires at boot and then every 5 s; wait for the first hit.
    t0 = time.monotonic()
    first_hit = None
    while time.monotonic() - t0 < 180:
        sid, ms, st, err = create(dict(body))
        delete(sid)
        if not err and st.get("fc_warm", (None, ""))[1] == "hit":
            first_hit = round(time.monotonic() - t0, 1)
            break
        time.sleep(5)
    say("warm pool: first hit %s s after the restart's health check" % first_hit)
    time.sleep(8)
    # A gap between samples lets the refiller put each claimed VMM back.
    api, server, fails, hits, notes, all_api = creates("warm", body, a.samples, gap=2.5, keep_stage="fc_warm")
    res = summary("warm-pool create (hits only)", api,
                  server=summary("warm-pool create, server time (hits only)", server)["p50_ms"],
                  hits=hits, misses=notes.count("miss"), failures=fails, depth=a.depth)
    summary("warm-pool create (hits and misses)", all_api)
    p50 = res["p50_ms"]
    ok = p50 is not None and p50 < WARM_GO_MS and hits > 0
    say("VERDICT warm create p50 %s ms over %d hits of %d (go: under %g ms) -> %s"
        % (p50, hits, a.samples, WARM_GO_MS, "PASS" if ok else "FAIL"))
    return {"leg": a.leg, "warm": res}


def main():
    global TOKEN
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["base", "warm"])
    ap.add_argument("--samples", type=int, default=20)
    ap.add_argument("--cycles", type=int, default=40)
    ap.add_argument("--idle-cycles", type=int, default=20)
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--leg", default="")
    ap.add_argument("--pat-file", default=HOME + "/pat")
    a = ap.parse_args()
    TOKEN = open(a.pat_file).read().strip()
    os.makedirs(RESULTS, exist_ok=True)
    if not wait_health():
        say("sandboxd never answered /health")
        sys.exit(1)
    res = phase_base(a) if a.phase == "base" else phase_warm(a)
    json.dump(res, open("%s/spa-%s.json" % (HOME, a.phase), "w"), indent=1)
    say("RESULT %s %s" % (a.phase, json.dumps(res, separators=(",", ":"))[:3000]))


if __name__ == "__main__":
    main()
