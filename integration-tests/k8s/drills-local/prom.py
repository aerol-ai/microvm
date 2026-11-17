#!/usr/bin/env python3
"""Prometheus reads for the local drills (drills-local.sh).

  prom.py --url U query 'sum by (aerolvm_component) (aerolvm_image_pull_queued)'
  prom.py --url U alerts [NAME ...]          # state and activeAt per alert
  prom.py --url U wait NAME [NAME ...] --state firing --timeout 1500
  prom.py --url U watch --out timeline.jsonl --interval 30 --alerts A B --exprs name=EXPR ...
  prom.py --url U history NAME --since UNIX # when ALERTS{alertname=NAME} was pending/firing

query prints one line per series: its labels, then the value. wait exits 0
once every named alert is in that state ("inactive" waits for it to be
gone) and 1 at the timeout; it prints each alert's first time in the state.
watch appends one JSON line per interval until killed.
"""
import argparse
import json
import sys
import time
import urllib.parse
import urllib.request


def get(url, path, **params):
    q = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"{url}{path}?{q}", timeout=30) as r:
        body = json.loads(r.read())
    if body.get("status") != "success":
        raise RuntimeError(body)
    return body["data"]


def query(url, expr):
    out = []
    for s in get(url, "/api/v1/query", query=expr)["result"]:
        out.append((s["metric"], float(s["value"][1])))
    return out


def alerts(url):
    out = {}
    for a in get(url, "/api/v1/alerts")["alerts"]:
        name = a["labels"].get("alertname")
        # One alert name can have several series; firing wins over pending.
        if name not in out or a["state"] == "firing":
            out[name] = {"state": a["state"], "activeAt": a.get("activeAt"), "value": a.get("value")}
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    sub = p.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("query")
    q.add_argument("expr")
    a = sub.add_parser("alerts")
    a.add_argument("names", nargs="*")
    w = sub.add_parser("wait")
    w.add_argument("names", nargs="+")
    w.add_argument("--state", default="firing")
    w.add_argument("--timeout", type=float, default=1500)
    wa = sub.add_parser("watch")
    wa.add_argument("--out", required=True)
    wa.add_argument("--interval", type=float, default=30)
    wa.add_argument("--alerts", nargs="*", default=[])
    wa.add_argument("--exprs", nargs="*", default=[])
    h = sub.add_parser("history")
    h.add_argument("name")
    h.add_argument("--since", type=float, required=True)
    args = p.parse_args()

    if args.cmd == "query":
        for labels, v in query(args.url, args.expr):
            name = ",".join(f"{k}={v}" for k, v in sorted(labels.items()) if k in (
                "__name__", "aerolvm_component", "pod", "key", "alertname", "alertstate"))
            print(f"{name or '{}'} {v:g}")
    elif args.cmd == "alerts":
        got = alerts(args.url)
        for n in (args.names or sorted(got)):
            print(json.dumps({"alert": n, **got.get(n, {"state": "inactive"})}))
    elif args.cmd == "wait":
        end, seen = time.time() + args.timeout, {}
        while time.time() < end:
            try:
                got = alerts(args.url)
            except Exception as e:  # a port-forward restarting
                print(f"prom: {e}", file=sys.stderr)
                time.sleep(10)
                continue
            for n in args.names:
                st = got.get(n, {}).get("state", "inactive")
                if st == args.state and n not in seen:
                    seen[n] = time.time()
                    print(json.dumps({"alert": n, "state": st, "at": round(seen[n]), "activeAt": got.get(n, {}).get("activeAt")}), flush=True)
            if len(seen) == len(args.names):
                return 0
            time.sleep(15)
        missing = [n for n in args.names if n not in seen]
        print(json.dumps({"timeout": True, "missing": missing}), flush=True)
        return 1
    elif args.cmd == "watch":
        exprs = [e.split("=", 1) for e in args.exprs]
        with open(args.out, "a") as fh:
            while True:
                row = {"t": round(time.time())}
                try:
                    for name, expr in exprs:
                        row[name] = {",".join(f"{k}={v}" for k, v in sorted(m.items())) or "_": v for m, v in query(args.url, expr)}
                    got = alerts(args.url)
                    row["alerts"] = {n: got.get(n, {}).get("state", "inactive") for n in args.alerts}
                except Exception as e:
                    row["error"] = str(e)[:200]
                fh.write(json.dumps(row) + "\n")
                fh.flush()
                time.sleep(args.interval)
    elif args.cmd == "history":
        end = time.time()
        data = get(args.url, "/api/v1/query_range",
                   query=f'max by (alertstate) (ALERTS{{alertname="{args.name}"}})',
                   start=args.since, end=end, step=15)
        for s in data["result"]:
            ts = [float(t) for t, _ in s["values"]]
            print(json.dumps({"alert": args.name, "state": s["metric"].get("alertstate"),
                              "first": round(min(ts)), "last": round(max(ts)), "samples": len(ts)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
