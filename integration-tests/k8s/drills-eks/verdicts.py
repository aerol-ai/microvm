#!/usr/bin/env python3
"""The EKS drills' verdicts (drills-eks.sh), kept apart from the steps so
the offline safety tests can hold each one to its rule. Each prints one
JSON object, {"verdict": PASS|FAIL|INCONCLUSIVE, "detail": ...}.

  verdicts.py quiet <fired.jsonl> <history.jsonl> <prom-at-start> <prom-at-end>
      thresholds-quiet. FAIL when Prometheus did not answer at the start or
      the end of the window (prom-at-* is 1 when it did), or when any
      drilled alert fired: a "firing" line from `prom.py wait`, or a firing
      sample in the window from `prom.py history`. A wait that times out
      says nothing: it waits for all of them.
  verdicts.py ecr <storm.jsonl> <creates-wanted> <rate-limited> <after-ok>
      ecr-storm. rate-limited is increase(aerolvm_image_pull_errors_total
      {key="rate_limited"}) over the storm, or "error" when Prometheus did
      not answer. A throttled answer is a create that failed (not 2xx) with
      an error naming the registry's throttling (toomanyrequests, too many
      requests, 429); nothing else in a row counts (ids, image names and
      timestamps hold digits), and never a create AerolVM itself answered
      429 (its own reserve limit). PASS needs both: ECR throttled pulls and
      the creates said so.
  verdicts.py shard <dir> <gateway>...
      shard-routes, over <dir>/routes.jsonl and <dir>/caddy-<gateway>.json.
  verdicts.py admit <can-admit.txt> <query-exit> <workers>
      large-layers' "every worker still admits": the query answered, with
      one series per worker, none 0.
"""
import collections
import json
import os
import re
import sys

THROTTLED = re.compile(r"toomanyrequests|too many requests|\b429\b", re.I)


def out(verdict, detail):
    print(json.dumps({"verdict": verdict, "detail": detail}))


def lines(path):
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                continue


def quiet(fired, history, start_ok, end_ok):
    if start_ok != "1" or end_ok != "1":
        return out("FAIL", "Prometheus did not answer at the %s of the window: nothing can be said" %
                   ("start" if start_ok != "1" else "end"))
    firing = sorted({e["alert"] for e in lines(fired) if e.get("state") == "firing" and "alert" in e} |
                    {e["alert"] for e in lines(history) if e.get("state") == "firing" and "alert" in e})
    if firing:
        return out("FAIL", "fired under healthy traffic: " + ", ".join(firing))
    return out("PASS", "none fired")


def ecr(storm, wanted, rate_limited, after_ok):
    rows = list(lines(storm))
    failed = [r for r in rows if not 200 <= int(r.get("code", 0)) < 300]
    # A create AerolVM itself answered 429 (its leader's reserve limit) is
    # not the registry throttling, whatever its error says.
    named = [r for r in failed if int(r.get("code", 0)) != 429 and THROTTLED.search(str(r.get("error", "")))]
    detail = {"creates": len(rows), "wanted": int(wanted), "failed": len(failed), "throttled_answers": len(named),
              "rate_limited_pulls": rate_limited, "after_ok": after_ok == "1"}
    if len(rows) != int(wanted) or after_ok != "1":
        return out("FAIL", detail)
    if rate_limited == "error":
        return out("FAIL", dict(detail, why="Prometheus did not answer for the pull errors"))
    rl = float(rate_limited)
    if rl > 0 and named:
        return out("PASS", detail)
    if rl > 0 and failed:
        return out("FAIL", dict(detail, why="ECR throttled pulls, and creates failed without saying so"))
    if rl > 0:
        return out("INCONCLUSIVE", dict(detail, why="ECR throttled pulls, but no create failed"))
    if named:
        return out("INCONCLUSIVE", dict(detail, why="creates named throttling, the pull counter shows none"))
    return out("INCONCLUSIVE", dict(detail, why="ECR did not throttle"))


def shard(d, gws):
    routes, rings, bad = {}, set(), []
    for e in lines(os.path.join(d, "routes.jsonl")):
        b = e.get("body") or {}
        if e.get("code") != 200:
            bad.append("answer %s" % e.get("code"))
            continue
        owners = [o["node_id"] for o in b.get("owners", [])]
        routes[b["sandbox_id"]] = owners
        rings.add(b.get("ring_version"))
        if len(owners) != 2 or any(o not in gws for o in owners):
            bad.append("%s: owners %s" % (b["sandbox_id"], owners))
    cover = collections.Counter(o for ow in routes.values() for o in ow)
    caddy = {}
    for g in gws:
        p = os.path.join(d, "caddy-%s.json" % g)
        caddy[g] = open(p).read() if os.path.exists(p) else ""
    checked, wrong, nowhere = 0, [], 0
    for sid, owners in list(routes.items())[:6]:
        has = {g for g in gws if sid in caddy[g]}
        if not has:
            nowhere += 1
            continue
        checked += 1
        if has != set(owners):
            wrong.append("%s: in %s, owners %s" % (sid, sorted(has), sorted(owners)))
    detail = {"sandboxes": len(routes), "gateways": len(gws), "rings": sorted(map(str, rings)),
              "owned_per_gateway": dict(cover), "unowned": [g for g in gws if g not in cover], "bad": bad[:5],
              "caddy_checked": checked, "caddy_wrong": wrong, "caddy_route_nowhere": nowhere}
    ok = (routes and not bad and len(rings) == 1 and all(g in cover for g in gws) and not wrong
          and checked > 0 and nowhere == 0)
    return out("PASS" if ok else "FAIL", detail)


def admit(path, query_exit, workers):
    if query_exit != "0":
        return out("FAIL", "Prometheus did not answer the can_admit query")
    vals = []
    with open(path) as fh:
        for line in fh:
            parts = line.split()
            if parts:
                vals.append(float(parts[-1]))
    if len(vals) != int(workers):
        return out("FAIL", "%d can_admit series for %s workers" % (len(vals), workers))
    if any(v == 0 for v in vals):
        return out("FAIL", "a worker stopped admitting: %s" % vals)
    return out("PASS", "%d workers admit" % len(vals))


def main(argv):
    cmd, args = argv[1], argv[2:]
    if cmd == "quiet":
        return quiet(*args)
    if cmd == "ecr":
        return ecr(*args)
    if cmd == "shard":
        return shard(args[0], args[1:])
    if cmd == "admit":
        return admit(*args)
    sys.exit("verdicts.py: unknown command " + cmd)


if __name__ == "__main__":
    main(sys.argv)
