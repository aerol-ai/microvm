#!/usr/bin/env python3
"""The few AerolVM API calls the cell's drills make (drills.sh), on the same
HTTP helper as load.py. Each command prints one JSON value and exits 0 on
success, 1 on an API error.

  api.py --url U --token-file F create --run R --n 3 [--recreate] [--allow-out CIDR ...] [--tag k=v] [--disk-gb N] [--zone Z] [--nonce X]
  api.py ... exec ID -- sh -c 'echo hi'
  api.py ... get ID
  api.py ... list --run R
  api.py ... wait --run R --n 3 [--status started] [--timeout 300]
  api.py ... delete-run --run R
  api.py ... session-start ID -- sh -c 'i=0; while :; do echo $i; i=$((i+1)); sleep 1; done'
  api.py ... session-log ID SESSION
  api.py ... put-profile NAME --allow-out CIDR ...
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from load import call, list_run  # noqa: E402


def out(v, ok=True):
    print(json.dumps(v))
    sys.exit(0 if ok else 1)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--token-file", required=True)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create")
    c.add_argument("--run", required=True)
    c.add_argument("--n", type=int, default=1)
    c.add_argument("--image", default="alpine:3.20")
    c.add_argument("--recreate", action="store_true")
    c.add_argument("--allow-out", nargs="*", default=[])
    c.add_argument("--profile", nargs="*", default=[])
    c.add_argument("--tag", nargs="*", default=[])
    c.add_argument("--disk-gb", type=int, default=0)
    # --zone places the sandbox in that zone (a placement rule).
    c.add_argument("--zone", default="")
    # The idempotency key is drill-<run>-<i>: a nonce makes a repeat of the
    # same run a new create instead of an answer from the first one.
    c.add_argument("--nonce", default="")

    e = sub.add_parser("exec")
    e.add_argument("id")
    e.add_argument("argv", nargs=argparse.REMAINDER)
    e.add_argument("--timeout", type=int, default=60)

    g = sub.add_parser("get")
    g.add_argument("id")

    ls = sub.add_parser("list")
    ls.add_argument("--run", required=True)

    w = sub.add_parser("wait")
    w.add_argument("--run", required=True)
    w.add_argument("--n", type=int, required=True)
    w.add_argument("--status", default="started")
    w.add_argument("--timeout", type=float, default=300)

    d = sub.add_parser("delete-run")
    d.add_argument("--run", required=True)

    ss = sub.add_parser("session-start")
    ss.add_argument("id")
    ss.add_argument("argv", nargs=argparse.REMAINDER)

    sl = sub.add_parser("session-log")
    sl.add_argument("id")
    sl.add_argument("session")

    sg = sub.add_parser("session-get")
    sg.add_argument("id")
    sg.add_argument("session")

    rw = sub.add_parser("raw")
    rw.add_argument("method")
    rw.add_argument("path")
    rw.add_argument("body", nargs="?", default=None)

    ow = sub.add_parser("owner")
    ow.add_argument("id")

    sub.add_parser("members")

    pp = sub.add_parser("put-profile")
    pp.add_argument("name")
    pp.add_argument("--allow-out", nargs="+", required=True)

    a = p.parse_args()
    token = open(a.token_file).read().strip()
    u = a.url

    def argv_of(rest):
        # argparse's REMAINDER also takes options given before "--" (such
        # as --timeout), so split there by hand.
        if "--" in rest:
            before, after = rest[:rest.index("--")], rest[rest.index("--") + 1:]
            if "--timeout" in before:
                a.timeout = int(before[before.index("--timeout") + 1])
            return after
        return rest

    if a.cmd == "create":
        ids = []
        for i in range(a.n):
            body = {"image": a.image, "runtime": "gvisor", "cpu": 0.1, "memory_mb": 128,
                    "tags": {"cell-run": a.run, **dict(t.split("=", 1) for t in a.tag)}}
            if a.recreate:
                body["failover"] = {"policy": "recreate"}
            if a.allow_out:
                body["network_allow_out"] = a.allow_out
            if a.profile:
                body["egress_profiles"] = a.profile
            if a.disk_gb:
                body["disk_gb"] = a.disk_gb
            if a.zone:
                body["placement"] = {"zone": a.zone}
            key = f"drill-{a.run}-{a.nonce}-{i}" if a.nonce else f"drill-{a.run}-{i}"
            code, res = call(u, token, "POST", "/v1/sandboxes", body, key=key, timeout=180)
            if not 200 <= code < 300:
                out({"code": code, "error": res, "created": ids}, ok=False)
            ids.append(res.get("id"))
        out(ids)

    if a.cmd == "exec":
        argv = argv_of(a.argv)
        code, res = call(u, token, "POST", f"/v1/sandboxes/{a.id}/toolbox/process/execute",
                         {"argv": argv, "timeout_seconds": a.timeout}, timeout=a.timeout + 30)
        if not 200 <= code < 300:
            out({"code": code, "error": res}, ok=False)
        out({"exit_code": res.get("exit_code", 0), "stdout": res.get("stdout", ""), "stderr": res.get("stderr", "")})

    if a.cmd == "get":
        code, res = call(u, token, "GET", f"/v1/sandboxes/{a.id}")
        out(res if 200 <= code < 300 else {"code": code, "error": res}, ok=200 <= code < 300)

    if a.cmd == "list":
        rows = list_run(u, token, a.run)
        out(rows if rows is not None else {"error": "list failed"}, ok=rows is not None)

    if a.cmd == "wait":
        deadline = time.time() + a.timeout
        n = 0
        while time.time() < deadline:
            rows = list_run(u, token, a.run) or []
            n = sum(1 for r in rows if r.get("status") == a.status)
            if n >= a.n:
                out({"n": n, "waited_s": round(a.timeout - (deadline - time.time()), 1)})
            time.sleep(3)
        out({"n": n, "timeout": True}, ok=False)

    if a.cmd == "delete-run":
        rows = list_run(u, token, a.run) or []
        bad = []
        for r in rows:
            code, res = call(u, token, "DELETE", f"/v1/sandboxes/{r['id']}")
            if not (200 <= code < 300 or code == 404):
                bad.append({"id": r["id"], "code": code})
        out({"deleted": len(rows) - len(bad), "failed": bad}, ok=not bad)

    if a.cmd == "session-start":
        argv = argv_of(a.argv)
        code, res = call(u, token, "POST", f"/v1/sandboxes/{a.id}/sessions", {"argv": argv})
        out(res if 200 <= code < 300 else {"code": code, "error": res}, ok=200 <= code < 300)

    if a.cmd == "session-log":
        import urllib.request
        req = urllib.request.Request(f"{u}/v1/sandboxes/{a.id}/sessions/{a.session}/log",
                                     headers={"Authorization": "Bearer " + token})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                out({"log": r.read().decode(errors="replace")})
        except Exception as ex:
            out({"error": f"{type(ex).__name__}: {ex}"}, ok=False)

    if a.cmd == "session-get":
        code, res = call(u, token, "GET", f"/v1/sandboxes/{a.id}/sessions/{a.session}")
        out(res if 200 <= code < 300 else {"code": code, "error": res}, ok=200 <= code < 300)

    if a.cmd == "raw":
        code, res = call(u, token, a.method, a.path, json.loads(a.body) if a.body else None)
        out({"code": code, "body": res}, ok=200 <= code < 300)

    if a.cmd == "owner":
        code, res = call(u, token, "GET", f"/v1/cluster/placements/{a.id}")
        if not 200 <= code < 300:
            out({"code": code, "error": res}, ok=False)
        owner = res.get("owner")
        out({"owner": (owner or {}).get("node_id", "") if isinstance(owner, dict) else (owner or ""),
             "orphaned": bool(res.get("orphaned"))})

    if a.cmd == "members":
        code, res = call(u, token, "GET", "/v1/cluster/members")
        rows = res if isinstance(res, list) else (res or {}).get("members", [])
        out([{"node_id": m.get("node_id"), "role": m.get("role"), "alive": m.get("alive"),
              "zone": ((m.get("capacity") or {}).get("labels") or {}).get("zone", ""),
              "can_admit": (m.get("capacity") or {}).get("can_admit"),
              "reasons": (m.get("capacity") or {}).get("reasons") or [],
              "disk_free_mb": (m.get("capacity") or {}).get("sandbox_disk_free_mb"),
              "disk_total_mb": (m.get("capacity") or {}).get("sandbox_disk_total_mb")} for m in rows],
            ok=200 <= code < 300)

    if a.cmd == "put-profile":
        code, res = call(u, token, "PUT", f"/v1/egress-profiles/{a.name}", {"allow_out": a.allow_out})
        out(res if 200 <= code < 300 else {"code": code, "error": res}, ok=200 <= code < 300)


if __name__ == "__main__":
    main()
