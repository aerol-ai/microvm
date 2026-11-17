#!/usr/bin/env python3
"""eks-bank.sh's enterprise guard: a chart render (helm template) must give
every node template enterprise mode and the audit store, or the run is
refused before Terraform makes anything (the bank run exists to test
enterprise mode; a commit without it would spend the budget on nothing).

  chart_guard.py <rendered.yaml> NAME=VALUE...

Each NAME=VALUE is an agent setting every one of the server, gateway and
worker templates in the pod-templates ConfigMap must carry; a VALUE of "*"
asks only that it be set and not empty. Prints what is missing and exits 1,
or exits 0. Reads the chart's own env lines (`- { name: X, value: "Y" }`);
a render it cannot read is refused too.
"""
import re
import sys

ENV = re.compile(r'-\s*\{\s*name:\s*([A-Z0-9_]+),\s*value:\s*"?([^"}]*?)"?\s*\}')
ROLES = ("server", "gateway", "worker")


def templates(text):
    """The pod-templates ConfigMap's role blocks: {role: text}."""
    for doc in re.split(r"^---\s*$", text, flags=re.M):
        if not re.search(r"^kind:\s*ConfigMap\s*$", doc, re.M) or not re.search(r"^\s+name:\s*\S+-pod-templates\s*$", doc, re.M):
            continue
        blocks, role = {}, None
        for line in doc.splitlines():
            m = re.match(r"^  (server|gateway|worker): \|\s*$", line)
            if m:
                role = m.group(1)
                blocks[role] = []
                continue
            if role and re.match(r"^  \S", line):
                role = None
            if role:
                blocks[role].append(line)
        return {r: "\n".join(v) for r, v in blocks.items()}
    return {}


def main(argv):
    text = open(argv[1]).read()
    want = [a.split("=", 1) for a in argv[2:]]
    blocks = templates(text)
    missing = []
    for role in ROLES:
        if role not in blocks:
            missing.append("%s: no template in the pod-templates ConfigMap" % role)
            continue
        env = {}
        for k, v in ENV.findall(blocks[role]):
            env.setdefault(k, v.strip())
        for k, v in want:
            got = env.get(k)
            if got is None or got == "" or (v != "*" and got != v):
                missing.append("%s: %s=%s (has %r)" % (role, k, v, got))
    if missing:
        print("\n".join(missing))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
