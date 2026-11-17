#!/usr/bin/env python3
"""The numbers drills-local.sh judges by, from its evidence files. Each
command prints one JSON object.

  summarize.py storm FILE.jsonl               answers by outcome
  summarize.py fired FILE.jsonl T0            each alert and when it fired, from T0
  summarize.py firedline FILE.jsonl T0        the same as one line of text
  summarize.py dedup REGISTRY.jsonl REPO      per worker: GETs, and the most GETs of one path
  summarize.py backoff REGISTRY.jsonl REPO    per worker: registry attempts and the gaps between
  summarize.py routing RECEIVER.jsonl NAME=PATH ...
                                              which alerts reached which receiver path
"""
import json
import sys


def lines(path):
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                continue


def storm(path):
    rows = list(lines(path))
    by = {}
    for r in rows:
        by[r["class"]] = by.get(r["class"], 0) + 1
    ms = sorted(r["ms"] for r in rows) or [0]
    return {"creates": len(rows), "by_outcome": by, "p50_ms": ms[len(ms) // 2], "max_ms": ms[-1]}


def fired(path, t0):
    out = {}
    for e in lines(path):
        if "alert" in e and e.get("state") in ("firing", "inactive"):
            d = int(e["at"]) - int(t0)
            out[e["alert"]] = {"state": e["state"], "after": f"{d // 60}m{d % 60:02d}s", "at": e["at"],
                               "activeAt": e.get("activeAt")}
    return out


def dedup(path, repo):
    gets, same = {}, {}
    for e in lines(path):
        if e.get("method") != "GET" or f"/{repo}/" not in e.get("path", ""):
            continue
        gets[e["client"]] = gets.get(e["client"], 0) + 1
        k = (e["client"], e["path"])
        same[k] = same.get(k, 0) + 1
    return {"workers": len(gets), "gets_per_worker": gets, "max_same_path": max(same.values(), default=0)}


def backoff(path, repo):
    # One attempt is the burst of requests one pull makes; a new one starts
    # after 5 s of quiet from that worker.
    hits = {}
    for e in lines(path):
        if f"/{repo}/manifests/" in e.get("path", ""):
            hits.setdefault(e["client"], []).append(e["t"])
    attempts = {}
    for c, ts in hits.items():
        ts.sort()
        starts = [ts[0]]
        for a, b in zip(ts, ts[1:]):
            if b - a > 5:
                starts.append(b)
        attempts[c] = starts
    gaps = sorted(b - a for s in attempts.values() for a, b in zip(s, s[1:]))
    return {"workers": len(attempts), "attempts": sum(map(len, attempts.values())),
            "requests": sum(map(len, hits.values())),
            "min_gap_s": round(gaps[0], 1) if gaps else None,
            "median_gap_s": round(gaps[len(gaps) // 2], 1) if gaps else None}


def routing(path, want):
    got = {}
    for e in lines(path):
        if e.get("alertname") in want:
            got.setdefault(e["alertname"], set()).add((e["path"], e["status"]))
    return {"firing": sorted(a for a, p in want.items() if (p, "firing") in got.get(a, set())),
            "resolved": sorted(a for a, p in want.items() if (p, "resolved") in got.get(a, set())),
            "wrong_route": {a: sorted(v) for a, v in got.items() if any(x[0] != want[a] for x in v)}}


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "storm":
        out = storm(args[0])
    elif cmd == "fired":
        out = fired(args[0], args[1])
    elif cmd == "firedline":
        # The same, as "Name +XmYYs, ..." in the order they happened.
        f = fired(args[0], args[1])
        print(", ".join(f"{k} +{v['after']}" for k, v in sorted(f.items(), key=lambda kv: kv[1]["at"])))
        return
    elif cmd == "dedup":
        out = dedup(args[0], args[1])
    elif cmd == "backoff":
        out = backoff(args[0], args[1])
    elif cmd == "routing":
        out = routing(args[0], dict(a.split("=", 1) for a in args[1:]))
    else:
        sys.exit(f"summarize.py: unknown command {cmd}")
    print(json.dumps(out))


if __name__ == "__main__":
    main()
