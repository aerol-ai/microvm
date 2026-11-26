#!/usr/bin/env python3
"""cost.py: what an M2 spike run (spa.sh, spb.sh) costs, before it starts.

    python3 -I cost.py --ceiling 10 --leg <name>:<type>:<planned min>:<ttl min>:<disk GB> ...

Planned is the run as expected. Worst is every machine running until it
powers itself off (its ttl) plus 10 minutes to end. Each machine also pays
one public IPv4 address and its gp3 disk. Makes nothing and calls nothing.

Prices are on-demand, us-east-1, per hour. m7i.xlarge and c5.metal are from
AWS's price list on 2026-11-24 (k8s/m1/cost.py). The m8i prices are list
prices that were not read from the price list: check them before a run.
Override any price with M2_PRICE_<TYPE>, the type in capitals with dots
and dashes as underscores (M2_PRICE_M8I_XLARGE=0.22). A type with no price
is refused.

Exit 0 when the worst case is inside the ceiling, 3 when it passes it or a
type has no price, 2 on a bad argument.
"""
import argparse
import json
import os
import sys

PRICES = {
    "m7i.xlarge": 0.2016,
    "c5.metal": 4.08,
    "m8i.xlarge": 0.21168,
    "m8i.2xlarge": 0.42336,
    "m8i.4xlarge": 0.84672,
}
IPV4 = 0.005
GP3_GB_MONTH = 0.08
END_MIN = 10


def price(itype):
    env = "M2_PRICE_" + itype.upper().replace(".", "_").replace("-", "_")
    if env in os.environ:
        return float(os.environ[env])
    return PRICES.get(itype)


def parse_leg(text):
    parts = text.split(":")
    if len(parts) != 5:
        raise ValueError("leg %r: want name:type:planned_min:ttl_min:disk_gb" % text)
    name, itype = parts[0], parts[1]
    planned, ttl, disk = (float(p) for p in parts[2:])
    if planned <= 0 or ttl <= 0 or disk <= 0 or planned > ttl:
        raise ValueError("leg %r: minutes and disk must be positive, planned at most ttl" % text)
    return name, itype, planned, ttl, disk


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--leg", action="append", default=[], required=True)
    ap.add_argument("--ceiling", type=float, required=True)
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    try:
        legs = [parse_leg(x) for x in a.leg]
    except ValueError as e:
        print("cost.py: %s" % e)
        return 2
    rows, refused = [], []
    for name, itype, planned, ttl, disk in legs:
        p = price(itype)
        if p is None:
            refused.append(itype)
            continue
        hourly = p + IPV4 + disk * GP3_GB_MONTH / 730
        rows.append({"leg": name, "type": itype, "hourly": round(hourly, 4),
                     "planned_min": planned, "planned": round(hourly * planned / 60, 2),
                     "worst_min": ttl + END_MIN, "worst": round(hourly * (ttl + END_MIN) / 60, 2)})
    if refused:
        print("REFUSED: no price for %s; set M2_PRICE_<TYPE> to its on-demand price per hour" % ", ".join(sorted(set(refused))))
        return 3
    print("%-18s %-12s %9s %8s %8s %8s %8s" % ("leg", "type", "USD/h", "plan min", "plan $", "worst min", "worst $"))
    for r in rows:
        print("%-18s %-12s %9.4f %8g %8.2f %8g %8.2f" % (r["leg"], r["type"], r["hourly"], r["planned_min"],
                                                      r["planned"], r["worst_min"], r["worst"]))
    planned = round(sum(r["planned"] for r in rows), 2)
    worst = round(sum(r["worst"] for r in rows), 2)
    print("COST planned $%.2f; worst $%.2f (every machine to its ttl, plus %d min to end); ceiling $%.2f"
          % (planned, worst, END_MIN, a.ceiling))
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"legs": rows, "planned": planned, "worst": worst, "ceiling": a.ceiling}, fh)
            fh.write("\n")
    if worst > a.ceiling:
        print("REFUSED: the worst case $%.2f passes the ceiling $%.2f" % (worst, a.ceiling))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
