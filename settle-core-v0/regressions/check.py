#!/usr/bin/env python3
"""Regression inputs from horizon-shield#49 (differential fuzzer, 2026-10-23).

The folders are inputs only and are copied verbatim from
`tools/fuzz/settle_core/findings_49` on branch `fuzz/settle-core-49` (commit
f3ef1fb2), together with the SHA256SUMS they arrived with. The expectations
below are the readings the report and the reference agreed on; they are what
this implementation had wrong in `97fed5d` and got wrong differently after the
first round of fixes.
"""
from __future__ import annotations

import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import settle_core_v0 as matter  # noqa: E402


def run(prefix: str):
    (path,) = glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), prefix + "_*"))
    contract, events, view, nenrin, parent = matter.load_vector(path)
    return matter.settle(contract, events, view, nenrin, parent)


def values(out, prefix):
    return {sha: d for sha, d in out["dispositions"].items() if sha.startswith(prefix)}


def case(letter, name, ok, out):
    print(("PASS  " if ok else "FAIL  ") + f"{letter}  {name}")
    if not ok:
        print("      reasons:", out["underspecified_reasons"])
        print("      deviations:", out["deviation_codes"])
        print("      dispositions:", {k[:8]: v for k, v in out["dispositions"].items()})
    return ok


def main() -> int:
    results = []

    out = run("B")
    results.append(case("B", "child failing 4.1 still adds parent_narrowing_failed",
                        "parent_narrowing_failed" in out["underspecified_reasons"], out))

    out = run("D")
    results.append(case("D", "revoked_by != principal is ignored before the anchors",
                        list(values(out, "31345af5").values()) == ["ignored"], out))

    out = run("E")
    results.append(case("E", "forged approval on a revoked execution is still classified",
                        "forged_approval" in out["deviation_codes"], out))

    out = run("F", )
    results.append(case("F", "witness-only nonconforming execution is rejected, not charged",
                        list(values(out, "05fa5c4b").values()) == ["rejected"], out))

    out = run("G")
    vals = set(out["dispositions"].values())
    results.append(case("G", "6.4 runs before 6.5 (duplicate_dropped, not ignored)",
                        {"duplicate_dropped", "ignored"} <= vals, out))

    out = run("H")
    results.append(case("H", "digest with a trailing newline is inconsistent, not foreign",
                        list(values(out, "d17ba054").values()) == ["inconsistent"], out))

    print(f"\n{sum(results)}/{len(results)} agreements")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
