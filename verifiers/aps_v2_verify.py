#!/usr/bin/env python3
"""Independent reader for the `aps.agent-passport` 2.0 frozen vectors.

Nothing here is taken from agent-passport-system: every rule is implemented
from the fixture family's own published legend (``layers_legend``,
``domain_tags``, ``key_resolver``) and from the vector bytes.  No SDK is
imported and no SDK string is reproduced.

The canonicalizer is this repository's own musubi-canonical-v0
(``nenrin_verify_v0.canonical``); it is validated byte-for-byte against the
vectors' published preimages before any outcome is reported
(``runners/run_aps_v2.py`` does that step and fails loudly if it misses).

Layer vocabulary follows the fixture's own schema:
    structure          ok | unsupported | rejected
    passport_id        ok | mismatch | not_checked
    signature          ok | invalid | not_checked
    validity_window    ok | not_current | not_checked
    proof_of_possession  true exactly when the signature verified
    key_authority      verified | rejected | unresolved | not_checked
"""
from __future__ import annotations

import hashlib
import os
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nenrin_verify_v0 import b58decode, canonical  # noqa: E402

RECORD_TYPE = "aps.agent-passport"
VERSION = "2.0"

TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
DID_RE = re.compile(r"^did:(?:key|web):[A-Za-z0-9._:%-]+$")
MB_RE = re.compile(r"^z[1-9A-HJ-NP-Za-km-z]+$")

# Closed wire shape of section 3.1, read off the vector set: the members that
# ever appear in a valid passport, and the one that must not appear.
MEMBERS = frozenset(
    {
        "record_type",
        "version",
        "agent_id",
        "verification_method",
        "public_key_multibase",
        "issued_at",
        "expires_at",
        "nonce",
        "self_asserted",
        "passport_id",
        "signature",
    }
)
REQUIRED = MEMBERS - {"self_asserted"}
SELF_ASSERTED_MEMBERS = frozenset({"display_name", "capabilities"})

LAYERS = (
    "structure",
    "passport_id",
    "signature",
    "validity_window",
    "proof_of_possession",
    "key_authority",
)


# --------------------------------------------------------------- primitives

def multibase_key_hex(value):
    """'z' + base58btc(0xed01 || 32-byte key) -> key hex, or None."""
    if not isinstance(value, str) or not MB_RE.match(value):
        return None
    raw = b58decode(value[1:])
    if len(raw) != 34 or raw[:2] != b"\xed\x01":
        return None
    return raw[2:].hex()


def derive_public_key(seed_label):
    """The vectors' key derivation: sha256(utf8(label)) IS the Ed25519 seed."""
    seed = hashlib.sha256(seed_label.encode("utf-8")).digest()
    return seed.hex(), Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex()


def _is_str(p, *keys):
    return all(isinstance(p.get(k), str) for k in keys)


# ------------------------------------------------------------------ layers

def structure_layer(passport):
    if not isinstance(passport, dict):
        return "rejected"

    rt = passport.get("record_type")
    ver = passport.get("version")
    # The two named unsupported conditions, judged before anything else and
    # only when the member is a string.
    if isinstance(rt, str) and rt != RECORD_TYPE:
        return "unsupported"
    if rt == RECORD_TYPE and isinstance(ver, str) and ver != VERSION:
        return "unsupported"
    if rt != RECORD_TYPE or ver != VERSION:
        return "rejected"

    if set(passport) - MEMBERS or not REQUIRED <= set(passport):
        return "rejected"

    if not _is_str(
        passport,
        "agent_id",
        "verification_method",
        "public_key_multibase",
        "issued_at",
        "expires_at",
        "nonce",
        "passport_id",
        "signature",
    ):
        return "rejected"

    if not DID_RE.match(passport["agent_id"]):
        return "rejected"
    if not passport["verification_method"].startswith(passport["agent_id"] + "#"):
        return "rejected"
    if multibase_key_hex(passport["public_key_multibase"]) is None:
        return "rejected"
    if not TS_RE.match(passport["issued_at"]) or not TS_RE.match(passport["expires_at"]):
        return "rejected"
    if not HEX32_RE.match(passport["nonce"]):
        return "rejected"
    if not HEX64_RE.match(passport["passport_id"]):
        return "rejected"
    if not HEX128_RE.match(passport["signature"]):
        return "rejected"

    if "self_asserted" in passport:
        sa = passport["self_asserted"]
        if not isinstance(sa, dict) or set(sa) - SELF_ASSERTED_MEMBERS:
            return "rejected"
        if "display_name" in sa and not isinstance(sa["display_name"], str):
            return "rejected"
        caps = sa.get("capabilities", [])
        if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
            return "rejected"
        if caps != sorted(set(caps)):
            return "rejected"
    return "ok"


def passport_id_preimage(passport, tag_bytes):
    body = {k: v for k, v in passport.items() if k not in ("passport_id", "signature")}
    return tag_bytes + canonical(body).encode("utf-8")


def signature_preimage(passport, tag_bytes):
    body = {k: v for k, v in passport.items() if k != "signature"}
    return tag_bytes + canonical(body).encode("utf-8")


def passport_id_layer(passport, tag_bytes):
    computed = hashlib.sha256(passport_id_preimage(passport, tag_bytes)).hexdigest()
    return ("ok" if computed == passport["passport_id"] else "mismatch"), computed


def signature_layer(passport, tag_bytes):
    key_hex = multibase_key_hex(passport["public_key_multibase"])
    if key_hex is None:
        return False
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
    try:
        key.verify(bytes.fromhex(passport["signature"]), signature_preimage(passport, tag_bytes))
        return True
    except (InvalidSignature, ValueError):
        return False


def key_authority_layer(passport, entries, resolver_supplied):
    """verified | rejected | unresolved, per the fixture's key_resolver text."""
    record_key = multibase_key_hex(passport["public_key_multibase"])
    agent_id = passport["agent_id"]

    if agent_id.startswith("did:key:"):
        committed = multibase_key_hex(agent_id[len("did:key:"):])
        if committed is None:
            return "unresolved"
        return "verified" if committed == record_key else "rejected"

    if not resolver_supplied:
        return "unresolved"
    method = passport["verification_method"]
    entry = next(
        (e for e in entries if e.get("controller") == agent_id and e.get("verification_method") == method),
        None,
    )
    if entry is None:
        return "unresolved"
    if entry.get("outcome") != "resolved":
        return "unresolved"
    return "verified" if bytes.fromhex(entry["public_key_hex"]).hex() == record_key else "rejected"


def read_case(case, vectors):
    """The six layers for one case, computed in the fixture's order."""
    passport = case["passport"]
    tag_pid = bytes.fromhex(vectors["domain_tags"]["passport_id"]["hex"])
    tag_sig = bytes.fromhex(vectors["domain_tags"]["signature"]["hex"])
    out = {
        "structure": "not_checked",
        "passport_id": "not_checked",
        "signature": "not_checked",
        "validity_window": "not_checked",
        "proof_of_possession": False,
        "key_authority": "not_checked",
    }

    out["structure"] = structure_layer(passport)
    if out["structure"] != "ok":
        return out

    state, _computed = passport_id_layer(passport, tag_pid)
    out["passport_id"] = state
    if state != "ok":
        return out

    verified = signature_layer(passport, tag_sig)
    out["signature"] = "ok" if verified else "invalid"
    out["proof_of_possession"] = verified
    if not verified:
        return out

    window = "ok" if passport["issued_at"] <= case["now"] < passport["expires_at"] else "not_current"
    out["validity_window"] = window
    if window != "ok":
        return out

    entries = vectors["key_resolver"]["entries"]
    out["key_authority"] = key_authority_layer(passport, entries, case.get("resolver") == "table")
    return out


def outcome_from_layers(layers):
    """This reader's own admission outcome, in the fixture's vocabulary."""
    if layers["structure"] == "unsupported":
        return "unsupported"
    if layers["structure"] != "ok":
        return "invalid"
    if layers["passport_id"] != "ok" or layers["signature"] != "ok" or layers["validity_window"] != "ok":
        return "invalid"
    if layers["key_authority"] == "unresolved":
        return "indeterminate"
    if layers["key_authority"] == "rejected":
        return "invalid"
    return "valid"
