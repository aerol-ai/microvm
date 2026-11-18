#!/usr/bin/env python3
"""The fillers a drill needs to take every worker's free CPU (drills-lib.sh's
slo-breach, eks-bank.sh's scale step), sized from the cluster as it is:

  fillplan.py <members.json> <policy.yaml> [--past N]

members.json is GET /v1/cluster/members' body, or the drills' {"code",
"body"} wrapper of it. policy.yaml is the create policy (the
<cluster>-create-policy ConfigMap's policy.yaml); empty or missing means no
limit. Prints one JSON line:

  workers    the worker members
  admitting  those that can admit (capacity.can_admit: a 1-CPU probe)
  free_cpu   their free CPU summed (capacity.available_cpu)
  max_cpu    the policy's limits.max_cpu (0: no limit)
  cpu        one filler's CPU: the policy's limit, no more than the largest
             free CPU on one worker, in whole CPUs, at least 1
  count      fillers of that size the workers' free CPU takes, each worker
             counted on its own, and --past N more (so the cell needs
             another worker)
  topup_cpu  one more filler's CPU that any admitting worker can still take:
             the policy's limit, no more than the smallest free CPU among
             them, in whole CPUs, at least 1

The fifth EKS run filled with fixed sizes (8, 4, 2, then 1 CPU, 14 of each
at most): the policy refused 8 and 4, and 82 CPUs were far short of six
workers of 18. Exits 1 when the answer holds no worker.
"""
import json
import math
import re
import sys


def load_members(path):
    with open(path) as fh:
        raw = fh.read().strip()
    d = json.loads(raw) if raw else {}
    if isinstance(d, dict) and "body" in d and "code" in d:
        d = d["body"] or {}
    return [m for m in d.get("members", []) if "worker" in (m.get("role") or "")]


def max_cpu(path):
    try:
        with open(path) as fh:
            text = fh.read()
    except OSError:
        return 0.0
    m = re.search(r"\bmax_cpu:\s*([0-9.]+)", text)
    return float(m.group(1)) if m else 0.0


def whole(x, limit):
    """x in whole CPUs, no more than the policy's limit (0: none), at least 1
    (a limit under 1 CPU is the size itself)."""
    if 0 < limit < 1:
        return limit
    if limit > 0:
        x = min(x, limit)
    return max(1, int(math.floor(x)))


def plan(workers, limit, past):
    free = [float((m.get("capacity") or {}).get("available_cpu") or 0) for m in workers]
    admitting = [f for m, f in zip(workers, free) if (m.get("capacity") or {}).get("can_admit")]
    cpu = whole(max(free) if free else 1, limit)
    count = sum(int(f // cpu) for f in free) + past
    return {
        "workers": len(workers),
        "admitting": len(admitting),
        "free_cpu": round(sum(free), 2),
        "max_cpu": limit,
        "cpu": cpu,
        "count": count,
        "topup_cpu": whole(min(admitting) if admitting else 1, limit),
    }


def main(argv):
    args = argv[1:]
    past = 0
    if "--past" in args:
        i = args.index("--past")
        past = int(args[i + 1])
        del args[i:i + 2]
    if len(args) != 2:
        sys.exit("usage: fillplan.py <members.json> <policy.yaml> [--past N]")
    workers = load_members(args[0])
    if not workers:
        print(json.dumps({"error": "no worker in the members answer"}))
        sys.exit(1)
    print(json.dumps(plan(workers, max_cpu(args[1]), past)))


if __name__ == "__main__":
    main(sys.argv)
