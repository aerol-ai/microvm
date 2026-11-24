#!/usr/bin/env python3
"""vm-bench.py: part B's WASM warm creates, on the VM, against its own
sandboxd (vm-userdata.sh runs it once per block: single, split, single,
split).

    vm-bench.py --mode single|split --pair N --rounds R --busy-rounds B --pat-file F

  wasm-warm  R rounds of 8 warm creates of the python module, nothing else
             going on (#1430's "focused" number, +0.63 ms on Docker Desktop)
  wasm-busy  B rounds of 6 warm creates, alternating python and ruby, while
             both modules' pools refill (16 slots), with an exec and a stop
             and start of another sandbox in each round (#1430's busy mix,
             +1.79 ms there; its NFS mount create is left out: no NFS here)

Prints one "VMC" line per create and one N1 line per round per mode, the
round's median, in n1-stats.py's format. The round key is p<pair>r<round>:
block 1 (single) pairs with block 2 (split), block 3 with block 4.
"""
import argparse
import json
import statistics
import time
import urllib.request

URL = "http://127.0.0.1:21212"


def call(method, path, pat, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(URL + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + pat, "Content-Type": "application/json"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, code, st = r.read(), r.status, r.headers.get("Server-Timing", "")
    except urllib.error.HTTPError as e:
        raw, code, st = e.read(), e.code, e.headers.get("Server-Timing", "")
    ms = (time.monotonic() - t0) * 1000
    try:
        doc = json.loads(raw or b"{}")
    except ValueError:
        doc = {}
    return code, doc, ms, st


def create_dur(st):
    first = st.split(",")[0].strip()
    if first.startswith("create;dur="):
        return float(first.split("=", 1)[1])
    return -1.0


def warm_create(pat, module):
    code, doc, ms, st = call("POST", "/v1/sandboxes", pat, {"runtime": "wasm", "image": module, "module_ref": module})
    return code, doc.get("id", ""), ms, create_dur(st), st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True)
    ap.add_argument("--pair", type=int, required=True)
    ap.add_argument("--rounds", type=int, default=15)
    ap.add_argument("--busy-rounds", type=int, default=8)
    ap.add_argument("--pat-file", required=True)
    a = ap.parse_args()
    pat = open(a.pat_file).read().strip()

    def round_line(phase, r, rows):
        ok = [x for x in rows if x[0] in (200, 201) and x[3] >= 0]
        if not ok:
            print(f"N1 {phase} p{a.pair}r{r} {a.mode} client_ms=-1 create_ms=-1 code=0 id=none", flush=True)
            return
        c = statistics.median(x[2] for x in ok)
        w = statistics.median(x[3] for x in ok)
        print(f"N1 {phase} p{a.pair}r{r} {a.mode} client_ms={round(c)} create_ms={w:.2f} code=201 id=round", flush=True)

    # Focused: python only, nothing else running.
    for r in range(1, a.rounds + 1):
        rows = []
        for i in range(8):
            code, sid, ms, dur, st = warm_create(pat, "python")
            rows.append((code, sid, ms, dur))
            print(f"VMC wasm-warm p{a.pair}r{r} {a.mode} {i} code={code} client_ms={ms:.2f} create_ms={dur:.2f} st={st}", flush=True)
        for _, sid, _, _ in rows:
            if sid:
                call("DELETE", "/v1/sandboxes/" + sid, pat)
        round_line("wasm-warm", r, rows)
        time.sleep(6)  # the pool refills every 5 s

    # V8 (the N1 row for isolates): one bundle, then warm creates from it;
    # the isolate pool's blank hosts, depth 8.
    code, doc, _, _ = call("POST", "/v1/js-bundles", pat, {"name": "m1-n1",
        "source": "export default { async fetch(req) { return new Response(\"ok\") } }"})
    ref = doc.get("module_ref", "")
    print(f"VMN1 v8 bundle http={code} ref={'yes' if ref else 'none'} {'' if ref else str(doc)[:200]}", flush=True)
    for r in range(1, (a.rounds + 1) if ref else 1):
        rows = []
        for i in range(8):
            code, doc, ms, st = call("POST", "/v1/sandboxes", pat, {"runtime": "isolate", "image": "isolate", "module_ref": ref})
            dur = create_dur(st)
            rows.append((code, doc.get("id", ""), ms, dur))
            print(f"VMC v8-warm p{a.pair}r{r} {a.mode} {i} code={code} client_ms={ms:.2f} create_ms={dur:.2f} st={st}", flush=True)
        for _, sid, _, _ in rows:
            if sid:
                call("DELETE", "/v1/sandboxes/" + sid, pat)
        round_line("v8-warm", r, rows)
        time.sleep(6)

    # Busy: both modules' pools refill while creates, an exec and a stop and
    # start of a long-lived sandbox run in the same round.
    code, side, _ = warm_create(pat, "python")[:3]
    side = side if code in (200, 201) else ""
    for r in range(1, a.busy_rounds + 1):
        rows = []
        for i in range(6):
            mod = "python" if i % 2 == 0 else "ruby"
            code, sid, ms, dur, st = warm_create(pat, mod)
            rows.append((code, sid, ms, dur))
            print(f"VMC wasm-busy p{a.pair}r{r} {a.mode} {i} {mod} code={code} client_ms={ms:.2f} create_ms={dur:.2f} st={st}", flush=True)
            if i == 2 and side:
                ec, _, ems, _ = call("POST", f"/v1/sandboxes/{side}/toolbox/process/execute", pat, {"command": "python -c 'print(1)'"})
                print(f"VMC wasm-busy-exec p{a.pair}r{r} {a.mode} code={ec} ms={ems:.2f}", flush=True)
            if i == 4 and side:
                s1, _, sms, _ = call("POST", f"/v1/sandboxes/{side}/stop", pat, {})
                s2, _, tms, _ = call("POST", f"/v1/sandboxes/{side}/start", pat, {})
                print(f"VMC wasm-busy-stopstart p{a.pair}r{r} {a.mode} stop={s1} {sms:.2f} start={s2} {tms:.2f}", flush=True)
        for _, sid, _, _ in rows:
            if sid:
                call("DELETE", "/v1/sandboxes/" + sid, pat)
        round_line("wasm-busy", r, rows)
    if side:
        call("DELETE", "/v1/sandboxes/" + side, pat)
    print(f"VMN1 block done: {a.mode} pair {a.pair}", flush=True)


if __name__ == "__main__":
    main()
