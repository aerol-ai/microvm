#!/usr/bin/env python3
"""cost.py: the M1 EKS drill's cost table, planned and worst case.

    python3 -I cost.py [--ceiling 8] [--ttl-hours 5] [--json out.json]
    python3 -I cost.py --vm-only --vm-type m7i.xlarge --vm-ttl-min 170 --ceiling 2

Makes nothing and calls nothing. On-demand prices, us-east-1, read from
AWS's price list on 2026-11-24 (aws pricing get-products); each can be
overridden with M1_PRICE_<NAME>. Exits 3 when the worst case passes the
ceiling, so m1-eks.sh up refuses before anything is made.
"""
import argparse
import json
import os
import sys

P = {
    "EKS": 0.10,            # EKS control plane, per hour (standard support)
    "M7I_LARGE": 0.1008,    # system machines
    "M7I_XLARGE": 0.2016,   # worker machines, and the VM of part B
    "C5_METAL": 4.08,       # only for the Firecracker metal row (not run)
    "IPV4": 0.005,          # each public IPv4 address, per hour
    "GP3_GB_MONTH": 0.08,
}
for k in list(P):
    P[k] = float(os.environ.get("M1_PRICE_" + k, P[k]))
GP3_H = P["GP3_GB_MONTH"] / 730

SYSTEM, WORKERS = 2, 3
# Disks: workers 60 GiB, system 20 GiB (EKS default), servers 3 x 10 GiB.
DISK_GB = WORKERS * 60 + SYSTEM * 20 + 3 * 10
CELL_H = (P["EKS"] + SYSTEM * P["M7I_LARGE"] + WORKERS * P["M7I_XLARGE"]
          + (SYSTEM + WORKERS) * P["IPV4"] + DISK_GB * GP3_H)

# Part A, step by step, in run order (minutes).
STEPS = [
    ("up", 20, "cluster.sh up: EKS, 2 system + 3 worker machines, ECR, teardown timer"),
    ("setup", 3, "br_netfilter DaemonSet on the workers (F2 stand-in)"),
    ("build", 20, "source to S3; images built in the cluster, pushed to ECR"),
    ("install", 12, "cert-manager, gp3 class, chart in single mode (T1)"),
    ("kernel", 3, "uname on every worker machine (6.12 wanted); verify (all single)"),
    ("switch1", 10, "privilegeMode=split; worker 1 decommissioned and made split; verify (mixed)"),
    ("shape", 6, "split pod shape, helper signed; image user split vs single (6.12)"),
    ("n1", 15, "N1 paired creates: cold, warm pool, burst; split vs single"),
    ("switch2", 10, "worker 2 made split; verify (mixed)"),
    ("moves", 12, "gVisor sandbox moved split to split through both helpers"),
    ("switch3", 14, "last single worker made split: cross-mode move refused; verify (all split)"),
    ("s2", 18, "OV-E2 mount + sandboxes; rollout T1->T2 in place; helper hot swap; helper restart"),
    ("variants", 10, "unsigned, other-key and older helpers refused in place"),
    ("f10", 8, "memory pressure on a split worker"),
    ("f8", 6, "split worker pod force-deleted with sandboxes; machine checked"),
    ("final", 3, "verify; evidence"),
    ("down", 20, "chart off, cluster.sh down, leak check"),
]
MARGIN = 1.25          # waits, a retried step
ALLOWANCE_A = 0.50     # ECR and S3 storage, Lambda, logs, cross-zone bytes

# Part B: one m7i.xlarge VM (WASM N1, ABAB); 40 GiB gp3; one public IPv4.
# 1.5 h: V8 warm creates ride in each of the four blocks too.
B_HOURS, B_TTL = 1.5, 3.0
B_H = P["M7I_XLARGE"] + P["IPV4"] + 40 * GP3_H
# Part B's machine types with a price here. Any other needs M1_PRICE_VM
# (its on-demand price per hour), or --vm-only refuses it.
VM_PRICES = {"m7i.xlarge": P["M7I_XLARGE"], "m7i.large": P["M7I_LARGE"], "c5.metal": P["C5_METAL"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ceiling", type=float, default=8.0)
    ap.add_argument("--ttl-hours", type=float, default=5.0)
    ap.add_argument("--json")
    ap.add_argument("--running", action="store_true", help="the run's spend so far and its projection")
    ap.add_argument("--cell-start", type=float, default=0, help="epoch the cluster's up began (0: not up)")
    ap.add_argument("--cell-end", type=float, default=0, help="epoch the cluster was down (0: still up)")
    ap.add_argument("--done", default="", help="part A steps finished, comma-separated")
    ap.add_argument("--vm-start", type=float, default=0)
    ap.add_argument("--vm-end", type=float, default=0)
    ap.add_argument("--limit", type=float, default=6.15)
    ap.add_argument("--vm-hours", type=float, default=B_HOURS, help="part B's planned hours (0: no VM this run)")
    ap.add_argument("--vm-hourly", type=float, default=0, help="part B's machine's cost per hour (0: m7i.xlarge's)")
    ap.add_argument("--vm-only", action="store_true", help="part B alone (vm-n1.sh): its cost against --ceiling")
    ap.add_argument("--vm-type", default="m7i.xlarge")
    ap.add_argument("--vm-ttl-min", type=float, default=170, help="minutes until the VM powers itself off")
    ap.add_argument("--hourly-out", help="--vm-only: write the VM's cost per hour here")
    a = ap.parse_args()
    if a.running:
        return running(a)
    if a.vm_only:
        return vm_only(a)

    print(f"Part A cell: ${CELL_H:.3f}/h = EKS {P['EKS']:.2f} + {SYSTEM} x m7i.large {P['M7I_LARGE']:.4f}"
          f" + {WORKERS} x m7i.xlarge {P['M7I_XLARGE']:.4f} + {SYSTEM + WORKERS} IPv4 x {P['IPV4']:.3f}"
          f" + {DISK_GB} GB gp3")
    print(f"{'step':<10}{'min':>5}{'USD':>8}  what")
    tot_min = 0
    for s, m, what in STEPS:
        tot_min += m
        print(f"{s:<10}{m:>5}{CELL_H * m / 60:>8.2f}  {what}")
    a_h = tot_min / 60
    a_planned = CELL_H * a_h + ALLOWANCE_A
    a_margin = CELL_H * a_h * MARGIN + ALLOWANCE_A
    # Worst: nothing torn down by hand; AWS's teardown timer ends the
    # machines at the TTL and the control plane up to an hour later.
    a_worst = CELL_H * a_ttl(a) + P["EKS"] * 1.0 + ALLOWANCE_A
    print(f"{'allowance':<10}{'':>5}{ALLOWANCE_A:>8.2f}  ECR/S3 storage, Lambda, logs, cross-zone traffic")
    print(f"Part A: {tot_min} min = {a_h:.2f} h -> planned ${a_planned:.2f}; with {MARGIN:g}x time ${a_margin:.2f};"
          f" worst (teardown timer at {a_ttl(a):g} h) ${a_worst:.2f}")
    b_planned = B_H * B_HOURS
    b_worst = B_H * B_TTL
    print(f"Part B VM: ${B_H:.3f}/h x {B_HOURS:g} h -> planned ${b_planned:.2f}; worst (self-terminates at {B_TTL:g} h) ${b_worst:.2f}")
    fc_nested = B_H * 0.75
    fc_metal = (P["C5_METAL"] + P["IPV4"]) * (0.75 + 0.25)
    print(f"Not run: Firecracker on the same nested-virtualization VM +${fc_nested:.2f};"
          f" a c5.metal comparison ${fc_metal:.2f} (45 min + 15 min to terminate)")
    planned = a_margin + b_planned
    worst = a_worst + b_worst
    print(f"TOTAL planned ${a_planned + b_planned:.2f} (with time margin ${planned:.2f}); worst case ${worst:.2f};"
          f" ceiling ${a.ceiling:.2f}")
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"cell_per_hour": round(CELL_H, 4), "a_planned": round(a_planned, 2), "a_margin": round(a_margin, 2),
                       "a_worst": round(a_worst, 2), "b_planned": round(b_planned, 2), "b_worst": round(b_worst, 2),
                       "planned": round(planned, 2), "worst": round(worst, 2), "ceiling": a.ceiling}, fh)
            fh.write("\n")
    if worst > a.ceiling:
        print(f"REFUSED: the worst case ${worst:.2f} passes the ceiling ${a.ceiling:.2f}")
        return 3
    return 0


def vm_only(a):
    """Part B's guard, before vm-n1.sh makes anything: the worst case is the
    machine running until it powers itself off (--vm-ttl-min) plus 10
    minutes to end. Exit 3 past the ceiling, or for a type with no price."""
    price = os.environ.get("M1_PRICE_VM")
    if price is None:
        if a.vm_type not in VM_PRICES:
            print(f"REFUSED: no price for {a.vm_type}; set M1_PRICE_VM to its on-demand price per hour")
            return 3
        price = VM_PRICES[a.vm_type]
    hourly = float(price) + P["IPV4"] + 40 * GP3_H
    worst_h = (a.vm_ttl_min + 10) / 60
    planned, worst = hourly * min(B_HOURS, worst_h), hourly * worst_h
    print(f"Part B VM {a.vm_type}: ${hourly:.3f}/h -> planned ${planned:.2f} ({min(B_HOURS, worst_h):g} h);"
          f" worst ${worst:.2f} (powers itself off after {a.vm_ttl_min:g} min, plus 10 to end); ceiling ${a.ceiling:.2f}")
    if a.hourly_out:
        with open(a.hourly_out, "w") as fh:
            fh.write(f"{hourly:.4f}\n")
    if worst > a.ceiling:
        print(f"REFUSED: the worst case ${worst:.2f} passes the ceiling ${a.ceiling:.2f}")
        return 3
    return 0


def running(a):
    """Spend so far (time x rate) and the projection: what is spent plus
    the planned minutes of the steps not done yet, plus each part's
    allowance. Exit 4 when the projection passes the limit: the run stops
    and tears down."""
    import time
    now = time.time()
    done = {x for x in a.done.split(",") if x}
    a_h = ((a.cell_end or now) - a.cell_start) / 3600 if a.cell_start else 0.0
    a_spent = CELL_H * a_h
    left_min = sum(m for s, m, _ in STEPS if s not in done) if not a.cell_end else 0
    a_proj = a_spent + CELL_H * left_min / 60 + (ALLOWANCE_A if a.cell_start else 0)
    b_rate = a.vm_hourly or B_H
    b_h = ((a.vm_end or now) - a.vm_start) / 3600 if a.vm_start else 0.0
    b_spent = b_rate * b_h
    b_proj = b_rate * (b_h if a.vm_end else max(b_h, a.vm_hours)) if a.vm_start else b_rate * a.vm_hours
    total_spent, total_proj = a_spent + b_spent, a_proj + b_proj
    print(f"COST spent ${total_spent:.2f} (cluster {a_h:.2f} h ${a_spent:.2f}; VM {b_h:.2f} h ${b_spent:.2f}); "
          f"projected ${total_proj:.2f} (cluster ${a_proj:.2f} with {left_min} planned min left; VM ${b_proj:.2f}); limit ${a.limit:.2f}")
    if total_proj > a.limit:
        print(f"COST STOP: the projection ${total_proj:.2f} passes the limit ${a.limit:.2f}")
        return 4
    return 0


def a_ttl(a):
    return a.ttl_hours


if __name__ == "__main__":
    sys.exit(main())
