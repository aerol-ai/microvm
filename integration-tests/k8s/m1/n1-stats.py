#!/usr/bin/env python3
"""n1-stats.py: N1's verdict from n1-bench.sh output.

    python3 -I n1-stats.py <bench log> [--warm-budget 1] [--cold-budget 3] [--seed 1]

For each phase: p50, p90, p99 of each side (the worker's create;dur from
Server-Timing, and the client's whole round trip), and the median of the
per-round differences split - single with a bootstrap 95% interval (10,000
resamples of the rounds, fixed seed). The budget (plan §3.7) is on the
worker's create p50: +1 ms warm, +3 ms cold.

Two tests per phase, and a phase passes only when both do:
  p50 gap         split's p50 minus single's p50, the budget's own terms:
                  INSIDE (at or under the budget) or OVER
  paired median   the median per-round difference and its interval:
    MEETS          the interval's top is at or under the budget
    LIKELY MEETS   the median difference is at or under it, the interval is not
    OVER           the interval's bottom is over the budget
    UNCLEAR        otherwise: run more rounds
The paired median alone graded run m1d-2's warm phase LIKELY MEETS (+0.80
ms) while its p50 gap was +1.30 ms, over the +1 ms budget.
Warm rounds where either side missed the pool are left out (reported), so
a miss never reads as split's cost. A miss is what the worker's
Server-Timing says (pool=miss on the N1 line); a log without that field
(older than m1d-3) falls back to "either side took over 100 ms".
"""
import argparse
import random
import re
import statistics
import sys

LINE = re.compile(r"^N1 (\S+) (\S+) (split|single) client_ms=(-?\d+) create_ms=(-?[\d.]+) code=(\d+) id=(\S+)(?: pool=(\S+))?")


def pct(xs, p):
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = max(0, min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1)))))
    return xs[k]


def is_warm(phase):
    # warm (containerd pool), wasm-warm and wasm-busy (part B): +1 ms.
    return "warm" in phase or "busy" in phase


def boot(diffs, seed, n=10000):
    rnd = random.Random(seed)
    meds = []
    for _ in range(n):
        s = [diffs[rnd.randrange(len(diffs))] for _ in diffs]
        meds.append(statistics.median(s))
    meds.sort()
    return meds[int(0.025 * n)], meds[int(0.975 * n) - 1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--warm-budget", type=float, default=1.0)
    ap.add_argument("--cold-budget", type=float, default=3.0)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    rows = {}
    bad = 0
    with open(a.log) as fh:
        for ln in fh:
            m = LINE.match(ln.strip())
            if not m:
                continue
            phase, rnd, mode, cms, wms, code, _, pool = m.groups()
            if code not in ("200", "201") or float(wms) < 0:
                bad += 1
                continue
            rows.setdefault(phase, {}).setdefault(rnd, {})[mode] = (float(wms), int(cms), pool)
    if not rows:
        print("n1-stats: no N1 lines")
        return 2
    print(f"failed or untimed creates left out: {bad}")
    verdicts = {}
    for phase in sorted(rows):
        warm = is_warm(phase)
        budget = a.warm_budget if warm else a.cold_budget
        pairs = [(r["split"], r["single"]) for k, r in rows[phase].items() if "split" in r and "single" in r and k != "prime"]
        misses = 0
        if warm:
            if any(p[0][2] in ("hit", "miss") or p[1][2] in ("hit", "miss") for p in pairs):
                kept = [p for p in pairs if p[0][2] == "hit" and p[1][2] == "hit"]
            else:
                kept = [p for p in pairs if p[0][0] <= 100 and p[1][0] <= 100]
            misses = len(pairs) - len(kept)
            pairs = kept
        p50 = {}
        for side, i in (("split", 0), ("single", 1)):
            w = [p[i][0] for p in pairs]
            p50[side] = pct(w, 50)
            c = [p[i][1] for p in pairs]
            if w:
                print(f"{phase:<6} {side:<6} n={len(w):<4} worker create ms p50 {pct(w, 50):8.2f} p90 {pct(w, 90):8.2f} p99 {pct(w, 99):8.2f}"
                      f" | client ms p50 {pct(c, 50):7.0f} p99 {pct(c, 99):7.0f}")
        # A burst runs one side, then the other: not paired, no verdict.
        if len(pairs) < 2 or phase == "burst":
            continue
        diffs = [p[0][0] - p[1][0] for p in pairs]
        med = statistics.median(diffs)
        lo, hi = boot(diffs, a.seed)
        if hi <= budget:
            v = "MEETS"
        elif lo > budget:
            v = "OVER"
        elif med <= budget:
            v = "LIKELY MEETS"
        else:
            v = "UNCLEAR"
        gap = p50["split"] - p50["single"]
        g = "INSIDE" if gap <= budget else "OVER"
        verdicts[phase] = (v, g)
        extra = f"; {misses} pool-miss rounds left out" if warm else ""
        print(f"{phase:<6} split-single median {med:+.2f} ms (95% {lo:+.2f} to {hi:+.2f}), budget +{budget:g}: {v}{extra}")
        print(f"{phase:<6} split-single p50 gap {gap:+.2f} ms ({p50['split']:.2f} - {p50['single']:.2f}), budget +{budget:g}: {g}")
    return 0 if all(v in ("MEETS", "LIKELY MEETS") and g == "INSIDE" for v, g in verdicts.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
