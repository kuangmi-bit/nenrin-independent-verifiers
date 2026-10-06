#!/usr/bin/env python3
"""Run a verifier over one interop corpus and diff against expected.json.

usage: run_corpus.py <corpus_dir> [verifier_module]
  corpus_dir holds expected.json and fixtures/<name>.json
  verifier_module defaults to verify_interop (verify(bundle) -> Report)
"""
import importlib
import json
import sys
from pathlib import Path


def load(mod_name):
    mod = importlib.import_module(mod_name)
    return mod.verify


def main():
    corpus = Path(sys.argv[1]).resolve()
    mod_name = sys.argv[2] if len(sys.argv) > 2 else "verify_interop"
    verify = load(mod_name)
    expected = json.loads((corpus / "expected.json").read_text())["cases"]
    ok = 0
    fails = []
    for name, case in expected.items():
        bundle = json.loads((corpus / "fixtures" / f"{name}.json").read_text())
        want = case["expect"]
        want_sig = {
            "verdict": want["verdict"],
            "refusals": sorted(want["refusals"]),
            "findings": sorted(want["findings"]),
        }
        try:
            got = verify(bundle).signature()
        except Exception as exc:  # noqa: BLE001 - report crashes as mismatches
            got = {"verdict": f"CRASH:{type(exc).__name__}", "refusals": [],
                   "findings": []}
            got["error"] = str(exc)[:160]
        match = got == want_sig
        ok += match
        if not match:
            fails.append((name, got, want_sig))
    print(f"{corpus.name}: {ok}/{len(expected)} verdict signatures reproduced")
    for name, got, want in fails:
        print(f"\n  FAIL {name}")
        print(f"    got      {json.dumps(got, sort_keys=True)}")
        print(f"    expected {json.dumps(want, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
