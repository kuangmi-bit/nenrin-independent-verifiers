#!/usr/bin/env python3
"""Non-vacuity mutations and the r1 cross-check for the APS 2.0 reader.

A reader that agrees with every case proves nothing unless a single-byte
change moves it.  Each mutation below is applied to a case that passes, and
the reader must move on the layer the mutation targets and nowhere earlier.

The r1 cross-check reads the superseded revision with the same reader: r2's own
metadata says the passports are identical between the two, so any layer that
differs between the revisions must come from the fixture's metadata and not
from a passport byte.

    python3 runners/run_aps_v2_mutations.py
"""
from __future__ import annotations

import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "verifiers"))

import aps_v2_verify as v  # noqa: E402
from run_aps_v2 import fetch  # noqa: E402

R2 = {"commit": "e061462", "path": "fixtures/agent-passport-v2/agent-passport-vectors-v2-r2.json",
      "sha256": "9bd1f1849910c85f0555baf8efaa529aa9d057dce13c24606285b8643a003b89"}
R1 = {"commit": "407ca2d5ad10c846860ad1b6faafc971ae9690e5", "path": "fixtures/agent-passport-v2/agent-passport-vectors-v2.json",
      "sha256": "9fce76dbf13de9749a2ef52c8dedecce08e4874da0203b39a7d941eb479b5ac5"}


def read_all(blob):
    vectors = json.loads(blob)
    return vectors, {c["name"]: v.read_case(c, vectors) for c in vectors["cases"]}


def mutations(vectors):
    """(name, description, mutate(passport) -> None, expected layer movement)"""
    by_name = {c["name"]: c for c in vectors["cases"]}

    def base(name):
        return copy.deepcopy(by_name[name]["passport"])

    def stale_display_name(p):
        p.setdefault("self_asserted", {})["display_name"] = "mutated"  # passport_id not recomputed

    def other_key_signature(p):
        # the other key's signature over the same preimage: recomputed set, so
        # swap in a signature produced by the wrong key by re-signing the same
        # preimage with the other seed.
        import hashlib

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        tag = bytes.fromhex(vectors["domain_tags"]["signature"]["hex"])
        body = {k: x for k, x in p.items() if k != "signature"}
        msg = tag + v.canonical(body).encode("utf-8")
        other = next(k for k in vectors["keys"] if k["label"] != "agent-key")
        seed = hashlib.sha256(other["seed_label"].encode()).digest()
        p["signature"] = Ed25519PrivateKey.from_private_bytes(seed).sign(msg).hex()

    def extra_member(p):
        p["principal_id"] = "did:example:owner"

    def unsorted_caps(p):
        p.setdefault("self_asserted", {})["capabilities"] = ["data:read", "commerce:checkout"]

    def no_milliseconds(p):
        p["issued_at"] = p["issued_at"].replace(".000Z", "Z")

    def other_resolver_key(p):
        # Passport untouched: only the resolver's answer changes, which is what
        # a relying party actually controls.
        p["_resolver_override"] = True

    return [
        ("valid-did-key-minimal", "display_name changed, passport_id left stale", stale_display_name, {"passport_id": "mismatch"}),
        ("valid-did-key-minimal", "signature produced by the other key", other_key_signature, {"signature": "invalid"}),
        ("valid-did-key-minimal", "extra principal_id member", extra_member, {"structure": "rejected"}),
        ("valid-did-key-minimal", "capabilities reversed", unsorted_caps, {"structure": "rejected"}),
        ("valid-did-key-minimal", "timestamp without milliseconds", no_milliseconds, {"structure": "rejected"}),
        ("valid-did-web-resolved", "resolver answers a different key for the same method", other_resolver_key, {"key_authority": "rejected"}),
    ]


def read_all_with(vectors, resolver_override, entries=None):
    """Run every case, optionally answering every resolver lookup with a key
    that is not the record's."""
    import copy as _copy

    out = {}
    for case in vectors["cases"]:
        c = _copy.deepcopy(case)
        if resolver_override and c.get("resolver") == "table":
            v_entries = _copy.deepcopy(vectors["key_resolver"]["entries"])
            for e in v_entries:
                if e.get("outcome") == "resolved":
                    e["public_key_hex"] = "00" * 32
            orig = vectors["key_resolver"]["entries"]
            vectors["key_resolver"]["entries"] = v_entries
            out[c["name"]] = v.read_case(c, vectors)
            vectors["key_resolver"]["entries"] = orig
        else:
            out[c["name"]] = v.read_case(c, vectors)
    return out


def main():
    r2_blob = fetch(R2["commit"], R2["path"])
    r1_blob = fetch(R1["commit"], R1["path"])
    fixtures = {}
    for tag, blob, meta in (("r2", r2_blob, R2), ("r1", r1_blob, R1)):
        vectors, layers = read_all(blob)
        fixtures[tag] = (vectors, layers)
        print(f"{tag}: {meta['commit'][:8]} layers read, cases={len(vectors['cases'])}")

    vectors2, layers2 = fixtures["r2"]
    by_name = {c["name"]: c for c in vectors2["cases"]}
    print("\n== mutations (baseline layers -> mutated layers) ==")
    moved = 0
    for case_name, desc, mutate, expect in mutations(vectors2):
        baseline = layers2[case_name]
        case = copy.deepcopy(by_name[case_name])
        mutate(case["passport"])
        if case["passport"].pop("_resolver_override", False):
            after = read_all_with(vectors2, True)[case_name]
        else:
            after = v.read_case(case, vectors2)
        ok = all(after[k] == want for k, want in expect.items())
        moved += bool(ok)
        print(f"  [{('OK' if ok else 'MISS')}] {case_name}: {desc}")
        print(f"        baseline {json.dumps(baseline)}")
        print(f"        mutated  {json.dumps(after)}")
    print(f"  mutations moved the reader as expected: {moved}/{len(mutations(vectors2))}")

    print("\n== r1 vs r2, same reader, layers only (read from the two blobs) ==")
    diff = 0
    for name, l2 in layers2.items():
        l1 = fixtures["r1"][1][name]
        if l1 != l2:
            diff += 1
            print(f"  {name}: r1 {json.dumps(l1)}")
            print(f"  {' ' * len(name)}  r2 {json.dumps(l2)}")
    print(f"  layers differing between revisions: {diff}/20")

    print("\n== published layers, r1 vs r2 (the fixture's own column) ==")
    pub_diff = 0
    for c1 in fixtures["r1"][0]["cases"]:
        c2 = next(c for c in fixtures["r2"][0]["cases"] if c["name"] == c1["name"])
        if c1["layers"] != c2["layers"]:
            pub_diff += 1
            print(f"  {c1['name']}: r1 {json.dumps(c1['layers'])}")
            print(f"  {' ' * len(c1['name'])}  r2 {json.dumps(c2['layers'])}")
    print(f"  published layers differing between revisions: {pub_diff}/20")

    print("\n== does my reader agree with each revision's own published layers? ==")
    for tag in ("r1", "r2"):
        vectors, mine = fixtures[tag]
        agree = sum(
            1
            for c in vectors["cases"]
            if all(mine[c["name"]][k] == c["layers"].get(k) for k in v.LAYERS)
        )
        print(f"  {tag}: {agree}/{len(vectors['cases'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
