#!/usr/bin/env python3
"""verdict.py: SP-A's go or no-go from one run's folder (spa.sh writes it).

    python3 -I verdict.py integration-tests/k8s/.state/<run>

Reads each leg's console lines (<leg>.txt). A bench leg prints its own
verdicts ("SPA VERDICT ..."); a move leg (fckind's proof) passes when the
sandbox answers after the move with the boot ID it had before and its
counter kept counting. Plan §4.2's go: warm create under 100 ms p50, no
pause/resume cycle lost, the move passes. Exit 0 on go, 1 otherwise.
"""
import glob
import os
import re
import sys


def bench(lines):
    out = [l[len("SPA VERDICT "):] for l in lines if l.startswith("SPA VERDICT ")]
    return out, bool(out) and all(l.endswith("PASS") for l in out) and len(out) >= 2


def move(lines):
    before = after = None
    for l in lines:
        m = re.search(r"boot-([0-9a-f]{8}) counter-(\d+)", l)
        if not m:
            continue
        if l.startswith("FCK before:"):
            before = (m.group(1), int(m.group(2)))
        elif l.startswith("FCK after (try"):
            after = (m.group(1), int(m.group(2)))
    if not before or not after:
        return ["move: no before/after lines (the proof did not finish)"], False
    ok = before[0] == after[0] and after[1] > before[1]
    return ["move: boot %s counter %d -> boot %s counter %d -> %s" % (before + after + ("PASS" if ok else "FAIL",))], ok


def main(argv):
    d = argv[1]
    go = True
    files = sorted(glob.glob(os.path.join(d, "*.txt")))
    legs = [f for f in files if os.path.basename(f) not in ("report.txt", "cost.txt")]
    if not legs:
        print("verdict: no leg output in %s" % d)
        return 1
    for f in legs:
        leg = os.path.basename(f)[:-4]
        lines = [l.rstrip("\n") for l in open(f, errors="replace")]
        notes, ok = (move(lines) if leg.startswith("move-") else bench(lines))
        if not any(l.endswith("DONE") for l in lines):
            notes.append("no DONE line: the leg did not finish")
            ok = False
        for n in notes or ["no verdict lines"]:
            print("VERDICT %s: %s" % (leg, n))
        print("VERDICT %s: %s" % (leg, "go" if ok else "NO GO"))
        go = go and ok
    print("VERDICT SP-A: %s" % ("go" if go else "NO GO"))
    return 0 if go else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
