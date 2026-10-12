#!/usr/bin/env python3
"""Run the independent APS 2.0 reader over a pinned vector file.

    python3 runners/run_aps_v2.py --out results/aps-v2-r2.json

Fetches the vectors at the commit named in the fixture's own metadata (or at
--commit), refuses to run unless the file's sha256 is the expected one, proves
the local canonicalizer against the file's published preimages, then reads all
cases and writes a per-case result file.  Exit code 1 on any anchor or
preimage miss — a reader that cannot reproduce the published preimage bytes has
nothing to say about the outcomes.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "verifiers"))

import aps_v2_verify as v  # noqa: E402

SOURCE_REPO = "agent-passport-system/agent-passport-system"
SOURCE_PATH = "fixtures/agent-passport-v2/agent-passport-vectors-v2-r2.json"
EXPECTED_SHA256 = "9bd1f1849910c85f0555baf8efaa529aa9d057dce13c24606285b8643a003b89"
EXPECTED_COMMIT = "e061462"


def fetch(commit, path=SOURCE_PATH, repo=SOURCE_REPO):
    """Contents API raw bytes; gh when present, urllib otherwise."""
    if os.environ.get("APS_VECTORS_FILE"):
        with open(os.environ["APS_VECTORS_FILE"], "rb") as fh:
            return fh.read()
    if _which("gh"):
        out = subprocess.run(
            ["gh", "api", f"repos/{repo}/contents/{path}?ref={commit}",
             "-H", "Accept: application/vnd.github.raw"],
            capture_output=True,
        )
        if out.returncode == 0 and out.stdout:
            return out.stdout
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/contents/{path}?ref={commit}",
        headers={"Accept": "application/vnd.github.raw", "User-Agent": "aps-v2-reader"},
    )
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed host
        return resp.read()


def _which(name):
    from shutil import which

    return which(name)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def preimage_checks(vectors):
    """Prove the local canonicalizer on the published preimages."""
    rows = []
    tag_pid = bytes.fromhex(vectors["domain_tags"]["passport_id"]["hex"])
    tag_sig = bytes.fromhex(vectors["domain_tags"]["signature"]["hex"])
    by_name = {c["name"]: c for c in vectors["cases"]}
    for name, published in vectors["valid_cases_preimages"].items():
        passport = by_name[name]["passport"]
        got_pid = v.passport_id_preimage(passport, tag_pid).hex()
        got_sig = v.signature_preimage(passport, tag_sig).hex()
        rows.append(
            {
                "case": name,
                "passport_id_preimage_published": published.get("passport_id_preimage_hex"),
                "passport_id_preimage_ours": got_pid,
                "passport_id_preimage_match": got_pid == published.get("passport_id_preimage_hex"),
                "signature_preimage_published": published.get("signature_preimage_hex"),
                "signature_preimage_ours": got_sig,
                "signature_preimage_match": got_sig == published.get("signature_preimage_hex"),
            }
        )
    return rows


def key_checks(vectors):
    rows = []
    for entry in vectors["keys"]:
        seed_hex, pub_hex = v.derive_public_key(entry["seed_label"])
        rows.append(
            {
                "label": entry["label"],
                "seed_from_label_matches": seed_hex == entry["private_key_hex"],
                "public_from_seed_matches": pub_hex == entry["public_key_hex"],
                "multibase_decodes_to_seed_key": v.multibase_key_hex(entry["public_key_multibase"]) == pub_hex,
                "did_key_commits_to_multibase": entry["did_key"] == "did:key:" + entry["public_key_multibase"],
            }
        )
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--commit", default=EXPECTED_COMMIT)
    ap.add_argument("--expected-sha256", default=EXPECTED_SHA256)
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "aps-v2-r2.json"))
    args = ap.parse_args()

    raw = fetch(args.commit)
    anchor = sha256_bytes(raw)
    print(f"source {SOURCE_REPO}@{args.commit} {SOURCE_PATH}")
    print(f"sha256 {anchor}  expected {args.expected_sha256}  match={anchor == args.expected_sha256}")
    if anchor != args.expected_sha256:
        print("ANCHOR MISMATCH — refusing to run", file=sys.stderr)
        return 1

    vectors = json.loads(raw)
    keys = key_checks(vectors)
    preims = preimage_checks(vectors)
    preimage_ok = all(p["passport_id_preimage_match"] and p["signature_preimage_match"] for p in preims)
    print(f"key derivation {sum(all(kk for kk in k.values() if isinstance(kk, bool)) for k in keys)}/{len(keys)} all-true")
    print(f"published preimages reproduced {sum(1 for p in preims if p['passport_id_preimage_match'] and p['signature_preimage_match'])}/{len(preims)}")
    if not preimage_ok:
        print("PREIMAGE MISMATCH — the local canonicalizer differs from the corpus", file=sys.stderr)
        return 1

    cases = []
    agree_layers = 0
    agree_state = 0
    for case in vectors["cases"]:
        ours = v.read_case(case, vectors)
        theirs = case["layers"]
        ours_state = v.outcome_from_layers(ours)
        their_state = case["verification"]["state"]
        layers_agree = all(ours[k] == theirs.get(k) for k in v.LAYERS)
        agree_layers += layers_agree
        agree_state += ours_state == their_state
        cases.append(
            {
                "name": case["name"],
                "resolver": case["resolver"],
                "ours": ours,
                "fixture_layers": {k: theirs.get(k) for k in v.LAYERS},
                "layers_agree": layers_agree,
                "ours_state": ours_state,
                "fixture_state": their_state,
                "fixture_code": case["verification"]["code"],
                "state_agrees": ours_state == their_state,
            }
        )

    result = {
        "reader": {
            "file": "verifiers/aps_v2_verify.py",
            "sha256": sha256_bytes(open(os.path.join(ROOT, "verifiers", "aps_v2_verify.py"), "rb").read()),
            "canonicalizer": "verifiers/nenrin_verify_v0.py canonical() (musubi-canonical-v0)",
            "sdk_imported": False,
        },
        "source": {
            "repository": SOURCE_REPO,
            "commit_fetched": args.commit,
            "path": SOURCE_PATH,
            "sha256": anchor,
            "expected_sha256": args.expected_sha256,
            "anchor_match": True,
            "fixture_metadata": {
                "family": vectors.get("family"),
                "version": vectors.get("version"),
                "family_revision": vectors.get("family_revision"),
                "generated_at": vectors.get("generated_at"),
                "supersedes_sha256": (vectors.get("supersedes") or {}).get("sha256"),
                "sdk_reference_commit": (vectors.get("sdk_reference") or {}).get("commit"),
            },
        },
        "key_derivation": keys,
        "preimages": preims,
        "summary": {
            "cases": len(cases),
            "layers_agree": agree_layers,
            "state_agrees": agree_state,
        },
        "cases": cases,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(result, fh, indent=1, sort_keys=False)
        fh.write("\n")
    print(f"\nlayers agree with the fixture: {agree_layers}/{len(cases)}")
    print(f"outcome agrees with the fixture's verification.state: {agree_state}/{len(cases)}")
    for c in cases:
        if not c["layers_agree"] or not c["state_agrees"]:
            print(
                f"  {c['name']:34s} ours={c['ours_state']:13s} fixture={c['fixture_state']:13s} "
                f"{c['fixture_code']:32s} layers_agree={c['layers_agree']}"
            )
    print(f"\nwrote {args.out} sha256 {sha256_bytes(open(args.out, 'rb').read())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
