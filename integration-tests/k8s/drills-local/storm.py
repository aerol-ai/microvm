#!/usr/bin/env python3
"""Creates for the local drills (drills-local.sh): --concurrency callers,
each creating again as soon as its last create answered, for --duration
seconds. Unlike cell/load.py it never retries a create: every answer,
good or bad, is one line in --out, because the drills count them.

  storm.py --url U --token-file F --images localhost:5000/drill/app:v1 \
      --concurrency 20 --duration 600 --run R --out storm.jsonl [--delete]
      [--registry-auth-file auth.json]

--images takes several refs and spreads the callers over them (caller i
uses image i mod n). --public asks for public links, which the gateways'
ingress routes then carry. --delete deletes each sandbox as soon as it exists, so
a long storm does not fill the workers. --once makes each caller create
once and stop. The last line printed is a JSON summary: answers by HTTP
code and by the first words of the error.
"""
import argparse
import concurrent.futures
import json
import os
import re
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cell"))
from load import call  # noqa: E402

lock = threading.Lock()


def classify(code, out):
    if 200 <= code < 300:
        return "ok"
    msg = json.dumps(out) if not isinstance(out, str) else out
    m = re.search(r'"(?:error|message)":\s*"([^"]{0,200})', msg)
    text = (m.group(1) if m else msg)[:200].lower()
    for key in ("backing off", "too many requests", "429", "deadline exceeded", "timeout",
                "no room", "capacity", "no placement", "forbidden", "not allowed", "refused"):
        if key in text:
            return key
    return text[:60]


def caller(args, token, i, fh):
    image = args.images[i % len(args.images)]
    end = time.time() + args.duration
    n = 0
    while time.time() < end:
        body = {"image": image, "cpu": args.cpu, "memory_mb": args.memory_mb,
                "tags": {"drill-run": args.run}}
        if args.runtime:
            body["runtime"] = args.runtime
        if args.public:
            body["allow_public_traffic"] = True
        if args.registry_auth:
            body["registry"] = args.registry_auth
        t0 = time.time()
        code, out = call(args.url, token, "POST", "/v1/sandboxes", body, timeout=args.client_timeout)
        row = {"t0": round(t0, 3), "ms": int((time.time() - t0) * 1000), "caller": i,
               "image": image, "code": code, "class": classify(code, out)}
        if 200 <= code < 300:
            row["id"] = out.get("id")
        else:
            row["error"] = (json.dumps(out) if not isinstance(out, str) else out)[:300]
        with lock:
            fh.write(json.dumps(row) + "\n")
            fh.flush()
        if row.get("id") and args.delete:
            call(args.url, token, "DELETE", "/v1/sandboxes/" + row["id"], timeout=120)
        n += 1
        if args.once:
            return
        time.sleep(args.pause)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--token-file", required=True)
    p.add_argument("--images", nargs="+", required=True)
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--duration", type=float, default=60)
    p.add_argument("--pause", type=float, default=1.0)
    p.add_argument("--run", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--runtime", default="")
    p.add_argument("--cpu", type=float, default=0.1)
    p.add_argument("--memory-mb", type=int, default=128)
    p.add_argument("--client-timeout", type=float, default=700)
    p.add_argument("--delete", action="store_true")
    p.add_argument("--once", action="store_true")
    # Public sandboxes get ingress routes on every gateway (route-lag drill).
    p.add_argument("--public", action="store_true")
    # A private registry's credentials (Amazon ECR on EKS): a JSON file of
    # {"server", "username", "password"}, sent as each create's registry.
    p.add_argument("--registry-auth-file", default="")
    args = p.parse_args()
    args.registry_auth = json.load(open(args.registry_auth_file)) if args.registry_auth_file else None
    token = open(args.token_file).read().strip()
    with open(args.out, "a") as fh, concurrent.futures.ThreadPoolExecutor(args.concurrency) as ex:
        for f in [ex.submit(caller, args, token, i, fh) for i in range(args.concurrency)]:
            f.result()
    codes, classes = {}, {}
    with open(args.out) as fh:
        for line in fh:
            r = json.loads(line)
            codes[r["code"]] = codes.get(r["code"], 0) + 1
            classes[r["class"]] = classes.get(r["class"], 0) + 1
    print(json.dumps({"run": args.run, "codes": codes, "classes": classes}))


if __name__ == "__main__":
    main()
