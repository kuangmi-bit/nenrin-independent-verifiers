#!/usr/bin/env python3
"""Run the independent Python verifier over the interop-v0.2/edge corpus.

    python3 python/run_edge.py [corpus_dir]

Exits non-zero on any verdict-signature mismatch. Requires Python 3.10+ and
`cryptography` (Ed25519 through OpenSSL, as VERIFIER.md section 5 pins).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verifiers"))
from nenrin_verify_v02_edge import verify  # noqa: E402


def main():
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 \
        else Path(__file__).resolve().parent.parent
    expected = json.loads((root / "expected.json").read_text())["cases"]
    ok = 0
    for name, case in expected.items():
        bundle = json.loads((root / "fixtures" / f"{name}.json").read_text())
        want = case["expect"]
        want_sig = {"verdict": want["verdict"],
                    "refusals": sorted(want["refusals"]),
                    "findings": sorted(want["findings"])}
        rep = verify(bundle)
        got = rep.signature()
        if got == want_sig:
            ok += 1
            continue
        print(f"FAIL {name}")
        print(f"    got      {json.dumps(got, sort_keys=True)}")
        print(f"    expected {json.dumps(want_sig, sort_keys=True)}")
        print(f"    reasons  {rep.reasons}")
    print(f"{ok}/{len(expected)} verdict signatures reproduced")
    return 0 if ok == len(expected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
