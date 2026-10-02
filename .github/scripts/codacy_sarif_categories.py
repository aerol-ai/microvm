#!/usr/bin/env python3
"""Give each Codacy tool one SARIF run and a unique code-scanning category.

Codacy's SARIF formatter emits one run per tool invocation. The same tool
(same driver name and version) runs once per language, and none of those
runs set automationDetails.id. GitHub code scanning treats that as multiple
runs of the same tool and category and rejects the upload:

https://github.blog/changelog/2025-07-21-code-scanning-will-stop-combining-multiple-sarif-runs-uploaded-in-the-same-sarif-file/

This writes a new SARIF file: runs that share a driver name and version
are merged (rules and artifact indexes remapped), and each remaining run
gets a distinct automationDetails.id. upload-sarif leaves an existing id
alone, so the id is the category GitHub records.

The Codacy CLI runs in Docker and leaves results.sarif owned by root, so
the output path must be a different file the runner user can create.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any


def sanitize_category(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")
    return cleaned or "tool"


def _driver(run: dict[str, Any]) -> dict[str, Any]:
    return run.setdefault("tool", {}).setdefault("driver", {})


def _run_key(run: dict[str, Any]) -> tuple[str, str]:
    driver = run.get("tool", {}).get("driver", {})
    return (str(driver.get("name") or ""), str(driver.get("version") or ""))


def _remap_locations(result: dict[str, Any], artifacts: list[dict[str, Any]], index_by_uri: dict[str, int]) -> None:
    for loc in result.get("locations") or []:
        phys = loc.get("physicalLocation") or {}
        aloc = phys.get("artifactLocation")
        if not isinstance(aloc, dict):
            continue
        uri = aloc.get("uri")
        if not isinstance(uri, str) or uri == "":
            continue
        if uri not in index_by_uri:
            index_by_uri[uri] = len(artifacts)
            artifacts.append({"location": {"uri": uri}})
        aloc["index"] = index_by_uri[uri]


def _remap_results(
    results: list[Any],
    src_rules: list[Any],
    rules: list[dict[str, Any]],
    rule_index: dict[str, int],
    artifacts: list[dict[str, Any]],
    index_by_uri: dict[str, int],
) -> list[dict[str, Any]]:
    src_ids = [r.get("id") if isinstance(r, dict) else None for r in src_rules]
    out: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        old_idx = result.get("ruleIndex")
        rid = result.get("ruleId")
        if not isinstance(rid, str) and isinstance(old_idx, int) and 0 <= old_idx < len(src_ids):
            rid = src_ids[old_idx]
        if isinstance(rid, str) and rid in rule_index:
            result["ruleId"] = rid
            result["ruleIndex"] = rule_index[rid]
        elif isinstance(old_idx, int) and old_idx < 0:
            # Codacy uses -1 when the pattern is missing from the rule list.
            # The SARIF spec does not allow a negative ruleIndex.
            result.pop("ruleIndex", None)
        _remap_locations(result, artifacts, index_by_uri)
        out.append(result)
    return out


def _absorb_rules(src_rules: list[Any], rules: list[dict[str, Any]], rule_index: dict[str, int]) -> None:
    for rule in src_rules:
        if not isinstance(rule, dict):
            continue
        rid = rule.get("id")
        if not isinstance(rid, str) or rid in rule_index:
            continue
        rule_index[rid] = len(rules)
        rules.append(rule)


def merge_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge runs that share a tool identity into the first run."""
    base = runs[0]
    driver = _driver(base)
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    artifacts: list[dict[str, Any]] = []
    index_by_uri: dict[str, int] = {}

    merged_results: list[dict[str, Any]] = []
    for run in runs:
        src_driver = run.get("tool", {}).get("driver", {})
        src_rules = src_driver.get("rules") or []
        _absorb_rules(src_rules, rules, rule_index)
        merged_results.extend(
            _remap_results(
                list(run.get("results") or []),
                src_rules,
                rules,
                rule_index,
                artifacts,
                index_by_uri,
            )
        )

    driver["rules"] = rules
    base["results"] = merged_results
    base["artifacts"] = artifacts
    return base


def assign_categories(doc: dict[str, Any]) -> tuple[int, int]:
    runs = doc.get("runs")
    if not isinstance(runs, list):
        doc["runs"] = []
        return 0, 0

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str, str]] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        key = _run_key(run)
        if key not in grouped:
            order.append(key)
            grouped[key] = []
        grouped[key].append(run)

    used: set[str] = set()
    merged: list[dict[str, Any]] = []
    for key in order:
        run = merge_runs(grouped[key])
        name = key[0] or "tool"
        category = "codacy-" + sanitize_category(name)
        candidate = category
        n = 2
        while candidate in used:
            candidate = f"{category}-{n}"
            n += 1
        used.add(candidate)
        # upload-sarif only fills automationDetails when it is absent, so this
        # id is the category GitHub stores for the run.
        run["automationDetails"] = {"id": candidate}
        merged.append(run)

    before = len(runs)
    doc["runs"] = merged
    return before, len(merged)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} results.sarif results.categorized.sarif", file=sys.stderr)
        return 2
    src, dst = argv[1], argv[2]
    if os.path.abspath(src) == os.path.abspath(dst):
        print(f"{dst}: refusing to overwrite the Codacy output; pass a new path", file=sys.stderr)
        return 2
    with open(src, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        print(f"{src}: SARIF root must be an object", file=sys.stderr)
        return 1
    before, after = assign_categories(doc)
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, separators=(",", ":"))
        fh.write("\n")
    print(f"codacy sarif: {before} runs -> {after} runs with unique categories ({dst})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
