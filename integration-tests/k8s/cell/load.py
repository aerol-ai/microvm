#!/usr/bin/env python3
"""Concurrent creates for the cell's chaos step (plans/kubernetes-v2-
architecture.md §19: "Kill the Raft leader and one worker during 50
concurrent creates: zero duplicate sandboxes, zero lost creates").

Each create carries its own Idempotency-Key and is retried with the same key
on a transport error, a 5xx or a 429, as an SDK would, for up to --deadline
seconds. A 4xx other than 429 is an answer, not a retry. When every worker
has finished, it lists the sandboxes and checks:

  - lost: a key that never got a 2xx;
  - duplicate: two keys that got the same sandbox, or one sandbox listed
    twice;
  - stray: a sandbox in the list that no key got (a retry that made a second
    sandbox).

It prints one JSON object. Exit 0 when all three are empty.

  load.py --url http://127.0.0.1:21212 --token-file F --count 50 --started-file S
"""
import argparse
import concurrent.futures
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid


def call(url, token, method, path, body=None, key=None, timeout=60):
    req = urllib.request.Request(url + path, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Idempotency-Key", key)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"null")
        except ValueError:
            return e.code, {"error": raw.decode(errors="replace")[:300]}
    except Exception as e:  # transport: refused, reset, timeout
        return 0, {"error": f"{type(e).__name__}: {e}"}


def list_run(url, token, run):
    """Every sandbox of one load run, following the cluster list's pages.
    The list pages over every placement in the cluster and filters each page
    by the tag, so a run's sandboxes are spread over pages; the next page's
    token comes back in X-Cluster-List-Next-Page-Token. None if a page fails."""
    out, page = [], ""
    for _ in range(1000):
        path = "/v1/sandboxes?tag.cell-run=" + run + ("&page_token=" + page if page else "")
        req = urllib.request.Request(url + path, headers={"Authorization": "Bearer " + token})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                body = json.loads(r.read() or b"[]")
                page = r.headers.get("X-Cluster-List-Next-Page-Token", "")
        except Exception:
            return None
        out.extend(body if isinstance(body, list) else body.get("sandboxes", []))
        if not page:
            return out
    return out


def create(args, token, i):
    # Spread the starts over --spread seconds, so creates are still arriving
    # while the chaos lands (the first run's 50 finished in 3.9 s, before
    # the deletes did).
    time.sleep(args.spread * i / max(args.count, 1))
    key = f"cell-{args.run}-{i}"
    body = {"image": args.image, "runtime": "gvisor", "cpu": 0.1, "memory_mb": 128,
            "failover": {"policy": "recreate"}, "tags": {"cell-run": args.run}}
    t0 = time.time()
    tries, errors = 0, []

    def done(code, **kw):
        return dict(key=key, code=code, tries=tries, t0=round(t0, 3), t1=round(time.time(), 3),
                    ms=int((time.time() - t0) * 1000), errors=errors[-3:], **kw)

    while True:
        tries += 1
        code, out = call(args.url, token, "POST", "/v1/sandboxes", body, key)
        if 200 <= code < 300:
            return done(code, id=out.get("id"))
        if 400 <= code < 500 and code != 429:
            return done(code, error=out)
        errors.append(f"{code}: {str(out)[:120]}")
        if time.time() - t0 > args.deadline:
            return done(code, error=out, gave_up=True)
        time.sleep(min(2.0, 0.25 * tries))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--token-file", required=True)
    p.add_argument("--count", type=int, default=50)
    p.add_argument("--image", default="alpine:3.20")
    p.add_argument("--deadline", type=float, default=180)
    p.add_argument("--spread", type=float, default=0, help="seconds over which the creates start")
    p.add_argument("--run", default=uuid.uuid4().hex[:8])
    # Touched once the first creates are in flight, so the chaos can start.
    p.add_argument("--started-file", default="")
    # Holds the time (Unix seconds) the chaos landed, written by cell.sh: the
    # report counts the creates in flight then and the ones started after.
    p.add_argument("--chaos-file", default="")
    # Only print one run's sandboxes (all pages) as JSON, for cell.sh.
    p.add_argument("--list-run", default="")
    args = p.parse_args()
    token = open(args.token_file).read().strip()
    if args.list_run:
        got = list_run(args.url, token, args.list_run)
        print(json.dumps(got if got is not None else []))
        sys.exit(0 if got is not None else 1)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.count) as pool:
        futures = [pool.submit(create, args, token, i) for i in range(args.count)]
        if args.started_file:
            time.sleep(1)
            open(args.started_file, "w").close()
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    ok = [r for r in results if 200 <= r["code"] < 300]
    lost = [r for r in results if not (200 <= r["code"] < 300)]
    ids = [r["id"] for r in ok]
    dup_ids = sorted({i for i in ids if ids.count(i) > 1})

    # The list, by this run's tag and every page, read until it holds every created
    # sandbox: right after the chaos a dead owner's sandboxes are missing
    # until they are recreated elsewhere. Missing past --deadline is lost.
    listed, mine, t_list = None, [], time.time()
    while True:
        got = list_run(args.url, token, args.run)
        if got is not None:
            listed = got
            mine = [s for s in listed if (s.get("tags") or {}).get("cell-run") == args.run]
            if set(ids) <= {s["id"] for s in mine}:
                break
        if time.time() - t_list > args.deadline:
            break
        time.sleep(2)
    listed_ids = [s["id"] for s in mine]
    listed_dups = sorted({i for i in listed_ids if listed_ids.count(i) > 1})
    stray = sorted(set(listed_ids) - set(ids))
    missing = sorted(set(ids) - set(listed_ids))

    chaos_at = None
    if args.chaos_file and os.path.exists(args.chaos_file):
        chaos_at = float(open(args.chaos_file).read().strip())
    report = {
        "chaos_at": chaos_at,
        "in_flight_at_chaos": sum(1 for r in results if chaos_at and r["t0"] <= chaos_at <= r["t1"]),
        "started_after_chaos": sum(1 for r in results if chaos_at and r["t0"] > chaos_at),
        "run": args.run, "creates": args.count, "succeeded": len(ok),
        "retried": sum(1 for r in results if r["tries"] > 1),
        "max_tries": max((r["tries"] for r in results), default=0),
        "spread_s": args.spread,
        "first_start": min((r["t0"] for r in results), default=None),
        "last_done": max((r["t1"] for r in results), default=None),
        "p50_ms": sorted(r["ms"] for r in ok)[len(ok) // 2] if ok else None,
        "retry_errors": sorted({e for r in results for e in r["errors"]})[:10],
        "max_ms": max((r["ms"] for r in ok), default=None),
        "lost": lost, "duplicate_ids": dup_ids, "listed_twice": listed_dups,
        "stray": stray, "missing_from_list": missing, "list_read": listed is not None,
        "list_complete_after_s": round(time.time() - t_list, 1),
        "statuses": {st: sum(1 for s in mine if s.get("status") == st) for st in {s.get("status") for s in mine}},
    }
    print(json.dumps(report, indent=2, default=str))
    clean = listed is not None and not (lost or dup_ids or listed_dups or stray or missing)
    sys.exit(0 if clean else 1)


if __name__ == "__main__":
    main()
