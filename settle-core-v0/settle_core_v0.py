#!/usr/bin/env python3
"""settle_core_v0.py -- an independent implementation of MUSUBI settle core v0.

Written from SETTLE_CORE_v0.md (revision 0.5) and the vectors only; the reference
implementation (settle_v1_16.py and what it imports) was not read.

    python3 settle_core_v0.py <vector_dir> [<vector_dir> ...]
    python3 settle_core_v0.py --check <vectors_root>

Returns the eight core fields of section 9.1.
"""
import base64
import binascii
import copy
import hashlib
import json
import os
import re
import sys

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    HAVE_CRYPTO = True
except ImportError:  # a stdlib-only runner: the pure verifier below is used instead
    HAVE_CRYPTO = False

MAX_INT = 2 ** 53 - 1
MAX_DEPTH = 512
MAX_INT_DIGITS = 4300
SCHEMAS = ("a2a-execution-v0", "a2a-revocation-v0", "a2a-revocation-ack-v0")
CONTEXT = {"a2a-execution-v0": b"a2a-execution-v0\n",
           "a2a-revocation-v0": b"a2a-revocation-v0\n",
           "a2a-revocation-ack-v0": b"a2a-revocation-ack-v0\n"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
ACTION = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
APPROVER_PROPS = {"name", "public_key_ed25519_b64", "actions"}
GRANT_KEYS = {"authorized_actions", "prohibited_actions", "conditional", "delegation",
              "data_access", "max_hops", "privacy", "revocation", "finality", "witnesses",
              "expiry_height", "ordering", "approval_policy", "limits"}
ACTION_TOP = {"schema", "contract_ref", "performed_actions", "approvals", "delegated_to",
              "nenrin_ref", "outcomes", "anchor", "signatures"}
REVOCATION_TOP = {"schema", "contract_ref", "revoked_by", "anchor", "signatures"}
ACK_TOP = {"schema", "contract_ref", "revocation_sha256", "acked_by", "anchor", "signatures"}
TOP_FIELDS = {"a2a-execution-v0": ACTION_TOP, "a2a-revocation-v0": REVOCATION_TOP,
              "a2a-revocation-ack-v0": ACK_TOP}
BATCH_SCHEMAS = ("nenrin-agreement-batch-v1", "nenrin-witness-batch-v1", "nenrin-trace-pin-batch-v0")
ESTABLISHES_BANNED = [r"\bperformed\b", r"\bdeliver(ed|y)\b", r"\bmoney (moved|was sent)\b",
                      r"\bfunds? (moved|were sent|were transferred)\b", r"\bpaid\b(?!\s+for\s+(this|the)\s+record)",
                      r"\bpayment (was|has been) (made|completed|settled|received)\b", r"\bcontract\b",
                      r"\bbinding\b", r"\bguarantee", r"\bescrow\b", r"\bcustody\b", r"\bsolvent\b",
                      r"\blawful\b", r"\bfair\b", r"\bcertified\b"]


# ---------------------------------------------------------------- JSON reading (2.2)
class ParseError(Exception):
    pass


def _pairs(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ParseError("duplicate key %r" % k)
        seen[k] = v
    return seen


def _int(text):
    if len(text.lstrip("-")) > MAX_INT_DIGITS:
        raise ParseError("integer token too long")
    return int(text)


def depth_ok(text):
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif ch in "]}":
            depth -= 1
    return True


def read_json(raw):
    """raw bytes -> value, or raise ParseError."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError(str(exc))
    if not depth_ok(text):
        raise ParseError("too deep")
    return json.loads(text, object_pairs_hook=_pairs, parse_int=_int)


# ---------------------------------------------------------------- canonical JSON (3.1)
def _string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append({8: "\\b", 12: "\\f", 10: "\\n", 13: "\\r", 9: "\\t"}.get(o, "\\u%04x" % o))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canon(v):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v != v:
            return "NaN"
        if v == float("inf"):
            return "Infinity"
        if v == float("-inf"):
            return "-Infinity"
        return repr(v)
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, dict):
        return "{" + ",".join(_string(k) + ":" + canon(v[k]) for k in sorted(v)) + "}"
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    raise TypeError(type(v))


def canon_bytes(v):
    return canon(v).encode("utf-8")


# ---------------------------------------------------------------- strictness (6.0)
def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def strict(v, depth=0):
    if depth > MAX_DEPTH:
        return False
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str) or not k.isascii() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in k):
                return False
            if not strict(x, depth + 1):
                return False
        return True
    if isinstance(v, list):
        return all(strict(x, depth + 1) for x in v)
    if isinstance(v, str):
        return not any(ord(c) < 0x20 or ord(c) == 0x7F for c in v)
    if isinstance(v, bool) or v is None:
        return True
    if isinstance(v, int):
        return -MAX_INT <= v <= MAX_INT
    return False  # floats, NaN, infinities


# ---------------------------------------------------------------- Ed25519 (3.2, 3.4)
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRTM1 = pow(2, (P - 1) // 4, P)


def _xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * SQRTM1) % P
    if (x * x - xx) % P != 0:
        return None
    return x


def decode_point(b):
    """32 bytes -> (x, y) or None if not a canonical encoding of a point on edwards25519."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    if y >= P:
        return None
    x = _xrecover(y)
    if x is None:
        return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = (P - x) % P
    return (x, y)


def _add(a, b):
    x1, y1 = a
    x2, y2 = b
    den = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + den, P - 2, P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - den, P - 2, P)
    return (x3 % P, y3 % P)


def _mul(pt, n):
    acc = (0, 1)
    base = pt
    while n > 0:
        if n & 1:
            acc = _add(acc, base)
        base = _add(base, base)
        n >>= 1
    return acc


_PRIME_CACHE = {}


def _prime_order(pt):
    if pt == (0, 1):
        return False  # identity
    if pt in _PRIME_CACHE:
        return _PRIME_CACHE[pt]
    res = _mul(pt, L) == (0, 1)
    _PRIME_CACHE[pt] = res
    return res


_KEY_CACHE = {}


def key_unusable(b):
    if b in _KEY_CACHE:
        return _KEY_CACHE[b]
    if len(b) != 32:
        res = True
    else:
        pt = decode_point(b)
        res = pt is None or not _prime_order(pt)
    _KEY_CACHE[b] = res
    return res


def b64_canonical(text, length):
    if not isinstance(text, str):
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != length:
        return None
    if base64.b64encode(raw).decode() != text:
        return None
    return raw


BASE_Y = (4 * pow(5, P - 2, P)) % P
_base_x = _xrecover(BASE_Y)
if _base_x & 1:  # RFC 8032: the base point has an even x
    _base_x = P - _base_x
BASE = (_base_x, BASE_Y)


def _ed25519_pure(pub, sig, message):
    """RFC 8032 verification with the group arithmetic above (stdlib only)."""
    import hashlib as _h
    if len(sig) != 64:
        return False
    r_pt = decode_point(sig[:32])
    a_pt = decode_point(pub)
    if r_pt is None or a_pt is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(_h.sha512(sig[:32] + pub + message).digest(), "little") % L
    return _mul(BASE, s) == _add(r_pt, _mul(a_pt, k))


_VERIFY_CACHE = {}


def verify(pub_b64, sig_b64, message):
    """True / False / 'unusable' (3.4)."""
    key = (pub_b64, sig_b64, message)
    if key in _VERIFY_CACHE:
        return _VERIFY_CACHE[key]
    pub = b64_canonical(pub_b64, 32)
    sig = b64_canonical(sig_b64, 64)
    if pub is None or sig is None or key_unusable(pub):
        res = "unusable"
    elif HAVE_CRYPTO:
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
            res = True
        except (InvalidSignature, ValueError):
            res = False
    else:
        res = _ed25519_pure(pub, sig, message)
    _VERIFY_CACHE[key] = res
    return res


_SIG_CACHE = {}


def sig_strict(sig_b64):
    if sig_b64 in _SIG_CACHE:
        return _SIG_CACHE[sig_b64]
    res = _sig_strict(sig_b64)
    _SIG_CACHE[sig_b64] = res
    return res


def _sig_strict(sig_b64):
    sig = b64_canonical(sig_b64, 64)
    if sig is None:
        return False
    r = decode_point(sig[:32])
    if r is None or not _prime_order(r):
        return False
    s = int.from_bytes(sig[32:], "little")
    return s < L


def strictly_verifies(pub_b64, sig_b64, message):
    return sig_strict(sig_b64) and verify(pub_b64, sig_b64, message) is True


# ---------------------------------------------------------------- digests (3.3)
def contract_sha256(contract):
    body = {k: v for k, v in contract.items() if k != "signatures"}
    return hashlib.sha256(b"a2a-contract-v0\n" + canon_bytes(body)).hexdigest()


def record_sha256(record):
    return hashlib.sha256(canon_bytes(record)).hexdigest()


def body_digest(record):
    body = {k: v for k, v in record.items() if k != "anchor"}
    return hashlib.sha256(canon_bytes(body)).digest()


def signing_bytes(record):
    body = {k: v for k, v in record.items() if k not in ("signatures", "anchor")}
    return CONTEXT[record["schema"]] + canon_bytes(body)


def signing_key(record):
    body = {k: v for k, v in record.items() if k not in ("signatures", "anchor")}
    return hashlib.sha256(CONTEXT[record["schema"]] + canon_bytes(body)).digest()


# ---------------------------------------------------------------- targets (5.2)
def target_from_bits(bits):
    exp = bits >> 24
    mant = bits & 0x007FFFFF
    if bits & 0x00800000 or mant == 0:
        return None
    if exp >= 3:
        return mant << (8 * (exp - 3))
    return mant >> (8 * (3 - exp))


def header_hash(hexstr):
    raw = bytes.fromhex(hexstr)
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


# ---------------------------------------------------------------- helpers
def normalize_domain(text):
    if not isinstance(text, str):
        return None
    d = text.strip().lower()
    while d.endswith("."):
        d = d[:-1]
    if any(c in d for c in "/@: ") or not d:
        return None
    labels = d.split(".")
    if len(labels) < 2 or not all(LABEL.match(l) for l in labels):
        return None
    return d


def party(contract, role):
    for p in contract.get("parties", []):
        if isinstance(p, dict) and p.get("role") == role:
            return p
    return None


def is_nonempty_str_list(v):
    return isinstance(v, list) and all(isinstance(x, str) and x for x in v)


# ---------------------------------------------------------------- 4.1 the door
def door(contract, parent=None):
    """Returns True when the contract is accepted (4.1)."""
    if not isinstance(contract, dict):
        return False
    if contract.get("schema") != "a2a-contract-v0":
        return False
    for k in ("contract_id", "nonce"):
        v = contract.get(k)
        if not isinstance(v, str) or not HEX32.match(v):
            return False
    parties = contract.get("parties")
    if not isinstance(parties, list) or len(parties) != 2:
        return False
    if not all(isinstance(p, dict) for p in parties):
        return False
    roles = sorted(p.get("role") for p in parties)
    if roles != ["contractor", "principal"]:
        return False
    doms = {}
    for p in parties:
        d = normalize_domain(p.get("domain"))
        if d is None:
            return False
        doms[p["role"]] = d
        ku = p.get("key_url")
        if not isinstance(ku, str) or not ku.startswith("https://"):
            return False
        if b64_canonical(p.get("public_key_ed25519_b64"), 32) is None:
            return False
    if doms["principal"] == doms["contractor"]:
        return False
    task = contract.get("task")
    if not isinstance(task, dict) or not isinstance(task.get("purpose"), str) or not task["purpose"]:
        return False
    pdg = task.get("payload_digest")
    if pdg is not None and not (isinstance(pdg, str) and HEX64.match(pdg)):
        return False
    grant = contract.get("grant")
    if not isinstance(grant, dict):
        return False
    if set(grant) - GRANT_KEYS:
        return False
    aa, pa = grant.get("authorized_actions"), grant.get("prohibited_actions")
    if not is_nonempty_str_list(aa) or not is_nonempty_str_list(pa):
        return False
    if set(aa) & set(pa):
        return False
    # rule 10 typed keys
    if grant.get("data_access") is not None and not is_nonempty_str_list(grant["data_access"]):
        return False
    for k in ("max_hops", "expiry_height"):
        if grant.get(k) is not None and not (is_int(grant[k]) and grant[k] >= 0):
            return False
    if grant.get("delegation") is not None:
        d = grant["delegation"]
        if not isinstance(d, dict) or set(d) != {"allowed"} or not is_nonempty_str_list(d["allowed"]):
            return False
    if grant.get("conditional") is not None:
        cond = grant["conditional"]
        if not isinstance(cond, list):
            return False
        seen = set()
        for c in cond:
            if not isinstance(c, dict) or not isinstance(c.get("action"), str) or not c["action"]:
                return False
            if c["action"] in seen:
                return False
            seen.add(c["action"])
            if "requires" in c and not isinstance(c["requires"], str):
                return False
    if grant.get("finality") is not None:
        fin = grant["finality"]
        if not isinstance(fin, dict) or set(fin) - {"depth", "max_target_bits"}:
            return False
        if "depth" in fin and not (is_int(fin["depth"]) and fin["depth"] >= 1):
            return False
        if "max_target_bits" in fin:
            b = fin["max_target_bits"]
            if not (isinstance(b, str) and re.match(r"^[0-9a-f]{8}$", b)):
                return False
            if target_from_bits(int(b, 16)) is None or target_from_bits(int(b, 16)) <= 0:
                return False
    if grant.get("witnesses") is not None:
        ws = grant["witnesses"]
        if not isinstance(ws, list):
            return False
        for w in ws:
            if not isinstance(w, dict) or not isinstance(w.get("name"), str) or not w["name"]:
                return False
            if b64_canonical(w.get("public_key_ed25519_b64"), 32) is None:
                return False
    if grant.get("privacy") is not None and not (isinstance(grant["privacy"], str) and grant["privacy"]):
        return False
    if grant.get("ordering") is not None:
        o = grant["ordering"]
        if not isinstance(o, dict) or set(o) - {"same_height"}:
            return False
        if "same_height" in o and not (o["same_height"] is None or isinstance(o["same_height"], str)):
            return False
    if grant.get("approval_policy") is not None:
        ap = grant["approval_policy"]
        if not isinstance(ap, dict) or set(ap) - {"allow_unscoped", "approvers"}:
            return False
        if "allow_unscoped" in ap and not isinstance(ap["allow_unscoped"], bool):
            return False
        if "approvers" in ap:
            appr = ap["approvers"]
            if not isinstance(appr, list) or not (1 <= len(appr) <= 16):
                return False
            names, keys = set(), set()
            cond_actions = {c["action"] for c in (grant.get("conditional") or []) if isinstance(c, dict)}
            for a in appr:
                if not isinstance(a, dict) or set(a) - APPROVER_PROPS:
                    return False
                if not isinstance(a.get("name"), str) or not a["name"] or a["name"] in names:
                    return False
                names.add(a["name"])
                kb = b64_canonical(a.get("public_key_ed25519_b64"), 32)
                if kb is None or kb in keys:
                    return False
                keys.add(kb)
                acts = a.get("actions")
                if not (isinstance(acts, list) and acts and all(isinstance(x, str) and x for x in acts)):
                    return False
                if len(set(acts)) != len(acts) or any(x not in cond_actions for x in acts):
                    return False
    if grant.get("revocation") is not None:
        r = grant["revocation"]
        if not isinstance(r, dict) or set(r) - {"effective_at", "ack_window"}:
            return False
        if r.get("effective_at") not in ("anchor", "delivery_ack"):
            return False
        if "ack_window" in r and not (is_int(r["ack_window"]) and r["ack_window"] >= 1):
            return False
    # rule 11: every number in the contract is an integer within range
    for v in walk_values(contract):
        if isinstance(v, float):
            return False
        if is_int(v) and not (-MAX_INT <= v <= MAX_INT):
            return False
    # rule 12: keys printable ASCII
    for k in walk_keys(contract):
        if not isinstance(k, str) or any(not (0x20 <= ord(c) <= 0x7E) for c in k):
            return False
    # rule 13 / 14
    est = contract.get("establishes")
    if not (isinstance(est, list) and est):
        return False
    for s in est:
        if not isinstance(s, str):
            return False
        for pat in ESTABLISHES_BANNED:
            if re.search(pat, s, re.I):
                return False
    dne = contract.get("does_not_establish")
    if not (isinstance(dne, list) and dne) or not all(isinstance(s, str) for s in dne):
        return False
    blob = " ".join(dne).lower()
    groups = (("runtime", "enforce"), ("judge", "liability", "fault"), ("deviat",), ("legal",))
    if not all(any(g in blob for g in grp) for grp in groups):
        return False
    # rule 15 / 16
    sigs = contract.get("signatures")
    if not isinstance(sigs, list):
        return False
    signing = b"a2a-contract-v0\n" + canon_bytes({k: v for k, v in contract.items() if k != "signatures"})
    good = {"principal": 0, "contractor": 0}
    by_domain = {doms["principal"]: "principal", doms["contractor"]: "contractor"}
    for s in sigs:
        if not isinstance(s, dict):
            return False
        d = normalize_domain(s.get("domain"))
        role = by_domain.get(d)
        if role is None:
            return False
        res = verify(party(contract, role).get("public_key_ed25519_b64"), s.get("signature"), signing)
        if res is not True:
            return False
        good[role] += 1
    if good["principal"] < 1 or good["contractor"] < 1:
        return False
    return True


def walk_values(v, depth=0):
    if depth > MAX_DEPTH:
        return
    if isinstance(v, dict):
        for x in v.values():
            yield from walk_values(x, depth + 1)
    elif isinstance(v, list):
        for x in v:
            yield from walk_values(x, depth + 1)
    else:
        yield v


def walk_keys(v, depth=0):
    if depth > MAX_DEPTH:
        return
    if isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from walk_keys(x, depth + 1)
    elif isinstance(v, list):
        for x in v:
            yield from walk_keys(x, depth + 1)


# ---------------------------------------------------------------- 4.3.1 grant subset
def g(v, k, default=None):
    return (v or {}).get(k, default) if isinstance(v, dict) else default


def grant_subset(c, p):
    c = c or {}
    p = p or {}
    c_aa, p_aa = set(c.get("authorized_actions") or []), set(p.get("authorized_actions") or [])
    if not c_aa <= p_aa:
        return False
    if not set(p.get("prohibited_actions") or []) <= set(c.get("prohibited_actions") or []):
        return False
    if not set(c.get("data_access") or []) <= set(p.get("data_access") or []):
        return False
    if is_int(p.get("max_hops")):
        if not is_int(c.get("max_hops")) or c["max_hops"] > p["max_hops"] - 1:
            return False
    if not set(g(g(c, "delegation"), "allowed", []) or []) <= set(g(g(p, "delegation"), "allowed", []) or []):
        return False
    c_cond = {x["action"]: x.get("requires") for x in (c.get("conditional") or []) if isinstance(x, dict)}
    for e in p.get("conditional") or []:
        a, r = e.get("action"), e.get("requires")
        if a in set(c.get("prohibited_actions") or []):
            continue
        if a not in set(c.get("authorized_actions") or []) and a not in c_cond:
            continue
        if a not in c_cond or c_cond[a] != r:
            return False
    for a in c_cond:
        if a not in set(p.get("authorized_actions") or []) and a not in {e.get("action") for e in (p.get("conditional") or [])}:
            return False
    if is_int(p.get("expiry_height")):
        if not is_int(c.get("expiry_height")) or c["expiry_height"] > p["expiry_height"]:
            return False
    if isinstance(p.get("revocation"), dict):
        m = p["revocation"].get("effective_at")
        cr = c.get("revocation")
        if not isinstance(cr, dict) or cr.get("effective_at") not in ("anchor", "delivery_ack"):
            return False
        if m == "anchor" and cr.get("effective_at") != "anchor":
            return False
        if m == "delivery_ack":
            if cr.get("effective_at") == "delivery_ack" and is_int(p["revocation"].get("ack_window")):
                w = p["revocation"]["ack_window"]
                if not is_int(cr.get("ack_window")) or cr["ack_window"] > w:
                    return False
        elif m not in ("anchor", "delivery_ack"):
            return False
    if isinstance(p.get("finality"), dict):
        cf = c.get("finality")
        if not isinstance(cf, dict):
            return False
        if is_int(p["finality"].get("depth")):
            if not is_int(cf.get("depth")) or cf["depth"] < p["finality"]["depth"]:
                return False
        if p["finality"].get("max_target_bits"):
            pt = target_from_bits(int(p["finality"]["max_target_bits"], 16))
            if pt is not None:
                cb = cf.get("max_target_bits")
                if not cb:
                    return False
                ct = target_from_bits(int(cb, 16))
                if ct is None or ct > pt:
                    return False
    p_wit = [w["public_key_ed25519_b64"] for w in (p.get("witnesses") or []) if isinstance(w.get("public_key_ed25519_b64"), str)]
    if p_wit:
        c_wit = {w.get("public_key_ed25519_b64") for w in (c.get("witnesses") or [])}
        if not c_wit or any(k not in c_wit for k in p_wit):
            return False
    for key in ("privacy", "ordering"):
        if p.get(key) is not None:
            if canon(c.get(key)) != canon(p.get(key)):
                return False
    if g(g(c, "approval_policy"), "allow_unscoped") is True and g(g(p, "approval_policy"), "allow_unscoped") is not True:
        return False
    p_appr = canon(sorted(canon(a) for a in (g(g(p, "approval_policy"), "approvers") or [])))
    c_appr = canon(sorted(canon(a) for a in (g(g(c, "approval_policy"), "approvers") or [])))
    if p_appr != c_appr:
        return False
    return True


# ---------------------------------------------------------------- 5.1 the view
def check_view(view, contract):
    """Returns (ok, extra_reasons) for 5.1 rules 1 to 9."""
    reasons = set()
    ok = True
    grant = (contract or {}).get("grant") if isinstance(contract, dict) else None
    fin = grant.get("finality") if isinstance(grant, dict) else None
    floor = None
    bits = fin.get("max_target_bits") if isinstance(fin, dict) else None
    if isinstance(bits, str) and re.match(r"^[0-9a-f]{8}$", bits):
        floor = target_from_bits(int(bits, 16))
    if floor is None or floor <= 0:
        ok = False
    lb = contract.get("lower_bound") if isinstance(contract, dict) else None
    if not (isinstance(lb, dict) and is_int(lb.get("height")) and isinstance(lb.get("hash"), str) and HEX64.match(lb["hash"])):
        ok = False
        height_lb = None
    else:
        height_lb = lb["height"]
    headers = view.get("headers") if isinstance(view, dict) else None
    if not isinstance(headers, list) or not headers:
        ok = False
        headers = []
    parsed = []
    prev_hash = None
    for i, h in enumerate(headers):
        if not isinstance(h, dict) or not is_int(h.get("height")) or h["height"] < 0:
            ok = False
            break
        hx = h.get("hex")
        if not isinstance(hx, str) or not re.match(r"^[0-9a-f]{160}\n?$", hx):
            ok = False
            break
        body = hx[:160]
        parsed.append((h["height"], body))
    if len(parsed) == len(headers) and parsed:
        for i in range(1, len(parsed)):
            if parsed[i][0] != parsed[i - 1][0] + 1:
                ok = False
                break
            if bytes.fromhex(parsed[i][1])[4:36][::-1].hex() != header_hash(parsed[i - 1][1]):
                ok = False
                break
        if ok:
            for height, body in parsed:
                raw = bytes.fromhex(body)
                tgt = target_from_bits(int.from_bytes(raw[72:76], "little"))
                if tgt is None or tgt > floor:
                    ok = False
                    break
                hh = int.from_bytes(bytes.fromhex(header_hash(body)), "big")
                if hh > tgt:
                    ok = False
                    break
            if ok and height_lb is not None:
                if not any(hh == height_lb and header_hash(b) == lb["hash"] for hh, b in parsed):
                    ok = False
    # rule 9
    if isinstance(view, dict) and isinstance(view.get("headers"), list):
        bad = False
        for h in view["headers"]:
            if not (isinstance(h, dict) and is_int(h.get("height"))
                    and isinstance(h.get("hex"), str) and re.match(r"^[0-9a-f]{160}$", h["hex"])):
                bad = True
                break
        if not bad and not strict(view):
            bad = True
        if bad:
            reasons.add("view_not_strict")
    if ok and len(parsed) > 200000:
        return "too_large", reasons
    return ok, reasons


# ---------------------------------------------------------------- 7.5 proof
def merkle_root(body_hex):
    raw = bytes.fromhex(body_hex)
    return raw[36:68]


def apply_proof(digest, proof):
    cur = digest
    for op in proof:
        if not isinstance(op, dict):
            return None
        name = op.get("op")
        if name == "sha256":
            cur = hashlib.sha256(cur).digest()
        elif name == "hexlify":
            cur = cur.hex().encode()
        elif name in ("append", "prepend"):
            x = op.get("hex")
            if not isinstance(x, str) or not re.match(r"^(?:[0-9a-f]{2})*$", x):
                return None
            b = bytes.fromhex(x)
            if len(b) > 4096:
                return None
            cur = cur + b if name == "append" else b + cur
        else:
            return None
        if len(cur) > 65536:
            return None
    return cur


def batch_leg(proof, digest_hex, record_schema):
    """7.6: returns (ok, code)."""
    hex_idx = [i for i, op in enumerate(proof) if isinstance(op, dict) and op.get("op") == "hexlify"]
    if not hex_idx:
        return True, None
    if len(hex_idx) > 1 or hex_idx[0] != 0:
        return False, "hexlify_not_leading"
    prepends, appends, saw_sha = [], [], False
    for op in proof[1:]:
        if not isinstance(op, dict):
            return False, "batch_leg_malformed"
        if op.get("op") == "sha256":
            saw_sha = True
            break
        if op.get("op") not in ("append", "prepend"):
            return False, "batch_leg_malformed"
        x = op.get("hex")
        if not isinstance(x, str) or not re.match(r"^(?:[0-9a-f]{2})*$", x):
            return False, "batch_leg_malformed"
        (prepends if op["op"] == "prepend" else appends).append(bytes.fromhex(x))
    if not saw_sha:
        return False, "batch_leg_malformed"
    batch = b"".join(reversed(prepends)) + digest_hex.encode() + b"".join(appends)
    try:
        text = batch.decode("utf-8")
        batch_doc = json.loads(text, object_pairs_hook=_pairs, parse_int=_int)
    except (UnicodeDecodeError, ValueError, ParseError):
        return False, "batch_not_json"
    if not isinstance(batch_doc, dict) or batch_doc.get("schema") not in BATCH_SCHEMAS:
        return False, "batch_schema_unknown"
    records = batch_doc.get("records")
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        return False, "batch_schema_unknown"
    if "count" in batch_doc and batch_doc["count"] != len(records):
        return False, "batch_count_mismatch"
    hits = [i for i, r in enumerate(records) if r.get("sha") == digest_hex]
    if not hits:
        return False, "record_not_listed_in_batch"
    if len(hits) > 1:
        return False, "record_listed_twice"
    hit = records[hits[0]]
    if batch_doc["schema"] == "nenrin-agreement-batch-v1":
        kinds = {"a2a-execution-v0": "execution"}
        kind = kinds.get(record_schema)
        if kind is None:
            return False, "record_kind_unknown"
        if hit.get("kind") != kind:
            return False, "record_kind_mismatch"
        if "schema" in hit and hit["schema"] != record_schema:
            return False, "record_schema_mismatch"
    raw_offset = sum(len(x) for x in prepends)
    pos = text.find('"' + digest_hex + '"')
    if pos < 0 or len(text[:pos].encode()) != raw_offset + 0:
        # the sha value must start at byte offset raw_offset
        pass
    # precise byte check: the 64 hex chars themselves start at raw_offset
    idx = text.find(digest_hex)
    if idx < 0 or len(text[:idx].encode("utf-8")) != raw_offset:
        return False, "batch_leg_splice_not_at_listing"
    return True, None


# ---------------------------------------------------------------- 6.0 triage
def record_flags(record, contract, grant, csha):
    """(strictly_signed, body_ok, anchor_ok) for a bound record."""
    schema = record.get("schema")
    sigs = record.get("signatures")
    strictly = False
    lax_seen = False
    body_value_strict = strict({k: v for k, v in record.items() if k not in ("signatures", "anchor")})
    if isinstance(sigs, list) and sigs:
        msg = signing_bytes(record)
        for entry in sigs:
            if not isinstance(entry, dict):
                continue
            role = entry.get("role")
            key = None
            if schema == "a2a-execution-v0":
                if role == "contractor":
                    key = party(contract, "contractor").get("public_key_ed25519_b64")
                elif role == "witness":
                    name = entry.get("witness_name")
                    for w in grant.get("witnesses") or []:
                        if isinstance(w, dict) and w.get("name") == name:
                            key = w.get("public_key_ed25519_b64")
                            break
            elif schema == "a2a-revocation-v0" and role == "principal":
                key = party(contract, "principal").get("public_key_ed25519_b64")
            elif schema == "a2a-revocation-ack-v0" and role == "contractor":
                key = party(contract, "contractor").get("public_key_ed25519_b64")
            if key is None:
                continue
            sig = entry.get("sig_b64")
            res = verify(key, sig, msg)
            if res is True:
                if sig_strict(sig) and strict(entry):
                    strictly = True
                else:
                    lax_seen = True
    body_ok = strict({k: v for k, v in record.items() if k not in ("signatures", "anchor")})
    if body_ok:
        if "nenrin_ref" in record and record["nenrin_ref"] is not None:
            if not (isinstance(record["nenrin_ref"], str) and HEX64.match(record["nenrin_ref"])):
                body_ok = False
        ref = record.get("contract_ref")
        if isinstance(ref, dict):
            for k in ("contract_sha256", "payload_digest"):
                if k in ref and ref[k] is not None and not (isinstance(ref[k], str) and HEX64.match(ref[k])):
                    body_ok = False
        if schema == "a2a-execution-v0":
            for k in ("performed_actions", "delegated_to"):
                if k in record and not (isinstance(record[k], list) and all(isinstance(x, str) for x in record[k])):
                    body_ok = False
            if "approvals" in record:
                if not (isinstance(record["approvals"], list) and all(isinstance(a, dict) for a in record["approvals"])):
                    body_ok = False
                else:
                    for a in record["approvals"]:
                        for k in ("sig_b64", "signature"):
                            if k in a:
                                v = a[k]
                                if isinstance(v, str) and b64_canonical(v, 64) is not None and not sig_strict(v):
                                    body_ok = False
    anchor_ok = True
    if "anchor" in record:
        a = record["anchor"]
        if not strict(a):
            anchor_ok = False
        elif isinstance(a, dict):
            if "block_hash" in a and not (isinstance(a["block_hash"], str) and HEX64.match(a["block_hash"])):
                anchor_ok = False
            proof = a.get("proof")
            if isinstance(proof, list):
                for op in proof:
                    if isinstance(op, dict) and "hex" in op:
                        x = op["hex"]
                        if not (isinstance(x, str) and re.match(r"^(?:[0-9a-f]{2})*$", x)):
                            anchor_ok = False
    return strictly, body_ok, anchor_ok, lax_seen


def anchors_validly(record, view_heights, view_hashes=None):
    """view_heights: height -> raw 80-byte header hex."""
    a = record.get("anchor")
    if not isinstance(a, dict):
        return False
    h = a.get("height")
    if not is_int(h) or h < 0 or h not in view_heights:
        return False
    if a.get("block_hash") != header_hash(view_heights[h]):
        return False
    proof = a.get("proof")
    if not (isinstance(proof, list) and 1 <= len(proof) <= 512):
        return False
    final = apply_proof(body_digest(record), proof)
    if final is None or final != merkle_root(view_heights[h]):
        return False
    ok, _ = batch_leg(proof, body_digest(record).hex(), record.get("schema"))
    return ok


def conformance_problem(record):
    schema = record.get("schema")
    allowed = TOP_FIELDS.get(schema, set())
    if set(record) - allowed:
        return True
    if schema == "a2a-execution-v0":
        pa = record.get("performed_actions")
        if not (isinstance(pa, list) and all(isinstance(x, str) for x in pa)):
            return True
        if "outcomes" in record and record["outcomes"] is not None:
            oc = record["outcomes"]
            if not isinstance(oc, dict):
                return True
            for k, v in oc.items():
                if k not in pa or v not in ("ok", "error", "timeout", "partial"):
                    return True
        if len(pa) > 256:
            return True
        for a in pa:
            if not ACTION.match(a):
                return True
        for ap in record.get("approvals") or []:
            act = ap.get("action") if isinstance(ap, dict) else None
            if not (isinstance(act, str) and ACTION.match(act)):
                return True
    return False


# ---------------------------------------------------------------- 10.x grant walk
def classify_approval(ap, pk, csha, contract):
    if not isinstance(ap, dict):
        return "forged"
    action = ap.get("action")
    vuh = ap.get("valid_until_height")
    nonce = ap.get("nonce")
    single = ap.get("single_use")
    csha_ap = ap.get("contract_sha256")
    sig = ap.get("sig_b64")
    if is_int(vuh) and vuh >= 0 and isinstance(nonce, str) and HEX32.match(nonce) \
            and isinstance(single, bool) and isinstance(csha_ap, str) and HEX64.match(csha_ap):
        msg = b"a2a-approval-v2\n" + canon_bytes({"contract_sha256": csha_ap, "action": action,
                                                  "valid_until_height": vuh, "nonce": nonce, "single_use": single})
        if verify(pk, sig, msg) is True:
            return "counted" if csha_ap == csha else "other_terms"
    task = contract.get("task") or {}
    fields = {"contract_id": contract.get("contract_id"),
              "payload_digest": task.get("payload_digest") if isinstance(task, dict) else None,
              "action": action, "valid_until_height": vuh, "nonce": nonce, "single_use": single}
    if is_int(vuh) and vuh >= 0 and isinstance(nonce, str) and HEX32.match(nonce) and isinstance(single, bool):
        if verify(pk, sig, b"a2a-approval-v1\n" + canon_bytes(fields)) is True:
            return "label_bound"
    if verify(pk, sig, b"a2a-approval-v0\n" + canon_bytes({"contract_id": contract.get("contract_id"),
                                                            "payload_digest": fields["payload_digest"],
                                                            "action": action})) is True:
        return "label_bound"
    return "forged"


def walk(event_set, records_by_sha, contract, csha, deviations, reasons):
    grant = contract["grant"]
    pk = party(contract, "principal").get("public_key_ed25519_b64")
    rev_policy = grant.get("revocation") if isinstance(grant.get("revocation"), dict) else None

    # 10.1 revocation effective heights
    rev_effective = {}
    if rev_policy:
        revs = [r for r in event_set if r["schema"] == "a2a-revocation-v0"]
        acks = [r for r in event_set if r["schema"] == "a2a-revocation-ack-v0"]
        for r in revs:
            h = r["_height"]
            mode = rev_policy.get("effective_at")
            if mode == "anchor":
                rev_effective[r["_sha"]] = h
            else:
                w = rev_policy.get("ack_window")
                cands = [a["_height"] for a in acks if a.get("revocation_sha256") in
                         (r["_body_hex"], r["_sha"])]
                E = h + w if is_int(w) else None
                if cands:
                    E = min(cands) if E is None else min(E, min(cands))
                rev_effective[r["_sha"]] = E if E is not None else h
        rev_sorted = sorted(rev_effective.items(), key=lambda kv: (kv[1], kv[0]))

    for rec in event_set:
        if rec["schema"] != "a2a-execution-v0":
            continue
        h = rec["_height"]
        if rev_policy:
            if any(E <= h for _, E in rev_sorted):
                for a in rec.get("performed_actions") or []:
                    deviations.add("revoked")
                continue
        expiry = grant.get("expiry_height")
        if expiry is not None and is_int(expiry) and h > expiry:
            for a in rec.get("performed_actions") or []:
                if isinstance(a, str):
                    deviations.add("after_expiry")
        cond = {c["action"]: c for c in (grant.get("conditional") or []) if isinstance(c, dict)}
        consumed = set()
        # approvals are consumed in event-set order across records: handled in the caller loop
        walk._consumed = getattr(walk, "_consumed", consumed)
        for a in rec.get("performed_actions") or []:
            if a in set(grant.get("prohibited_actions") or []):
                deviations.add("prohibited")
                continue
            if a in cond:
                ok = False
                for ap in rec.get("approvals") or []:
                    pass
                approved = False
                for other in event_set:
                    if other["_height"] > h:
                        continue
                    if other["_height"] == h and other["_sha"] != rec["_sha"]:
                        continue
                    for ap in other.get("approvals") or []:
                        cls = classify_approval(ap, pk, csha, contract)
                        if cls != "counted":
                            continue
                        if ap.get("action") != a:
                            continue
                        if h > (ap.get("valid_until_height") or 0):
                            continue
                        nonce = ap.get("nonce")
                        if ap.get("single_use") is True and nonce in walk._consumed:
                            continue
                        if ap.get("single_use") is True:
                            walk._consumed.add(nonce)
                        approved = True
                        break
                    if approved:
                        break
                if not approved:
                    deviations.add("conditional")
            elif a not in set(grant.get("authorized_actions") or []):
                deviations.add("unauthorized")
        allowed_del = set((grant.get("delegation") or {}).get("allowed") or []) if isinstance(grant.get("delegation"), dict) else set()
        for d in rec.get("delegated_to") or []:
            if d not in allowed_del:
                deviations.add("delegation")
        for ap in rec.get("approvals") or []:
            if classify_approval(ap, pk, csha, contract) == "forged":
                deviations.add("forged_approval")


# ---------------------------------------------------------------- main
def settle(contract, events, view, nenrin_records=None, parent=None):
    reasons, deviations, dispositions = set(), set(), {}
    if not isinstance(contract, dict):
        return {"contract_sha256": None, "verdict": "underspecified", "status": "undetermined",
                "bond_outcome": "n/a", "deviation_codes": [], "underspecified_reasons": ["contract_not_verified"],
                "event_set": [], "dispositions": {}}
    csha = contract_sha256(contract)
    if not isinstance(events, list):
        return {"contract_sha256": csha, "verdict": "underspecified", "status": "undetermined",
                "bond_outcome": bond_outcome(contract, "underspecified", "undetermined"),
                "deviation_codes": [], "underspecified_reasons": ["input_not_settleable"],
                "event_set": [], "dispositions": {}}

    grant = contract.get("grant") if isinstance(contract.get("grant"), dict) else {}
    door_ok = door(contract)
    if not door_ok:
        reasons.add("contract_not_verified")

    # 4.2
    if door_ok:
        if not isinstance(grant.get("authorized_actions"), list):
            reasons.add("authorized_actions_missing")
        names = []
        for key in ("authorized_actions", "prohibited_actions"):
            if isinstance(grant.get(key), list):
                names += grant[key]
        for c in grant.get("conditional") or []:
            if isinstance(c, dict) and isinstance(c.get("action"), str):
                names.append(c["action"])
        if any(isinstance(n, str) and not ACTION.match(n) for n in names):
            reasons.add("grant_action_name_invalid")
        wit = grant.get("witnesses") or []
        names = [w.get("name") for w in wit if isinstance(w, dict)]
        keys = [b64_canonical(v.get("public_key_ed25519_b64"), 32) for v in (contract.get("parties") or []) if isinstance(v, dict)]
        keys += [b64_canonical(w.get("public_key_ed25519_b64"), 32) for w in wit if isinstance(w, dict)]
        if len(set(names)) != len(names) or (None not in keys and len(set(keys)) != len(keys)):
            reasons.add("key_conflict")
        if len(wit) > 32:
            reasons.add("too_many_witnesses")
        if any(b64_canonical(w.get("public_key_ed25519_b64"), 32) is None for w in wit):
            reasons.add("witness_key_invalid")
        if grant.get("ordering") is not None and grant["ordering"].get("same_height") not in (None, "conservative"):
            reasons.add("tie_policy_refused")
        rev = grant.get("revocation")
        if isinstance(rev, dict) and rev.get("effective_at") == "delivery_ack" and not (is_int(rev.get("ack_window")) and rev.get("ack_window") >= 1):
            reasons.add("ack_window_missing")
        fin = grant.get("finality")
        if not (isinstance(fin, dict) and is_int(fin.get("depth")) and fin["depth"] >= 1):
            reasons.add("finality_policy_missing")
        if grant.get("approval_policy") is not None and grant["approval_policy"].get("allow_unscoped") is True:
            reasons.add("unscoped_approvals_refused")

    # 4.3 strict terms
    for s in contract.get("signatures") or []:
        if isinstance(s, dict):
            sig = s.get("signature")
            if not (isinstance(sig, str) and b64_canonical(sig, 64) is not None) or not sig_strict(sig):
                reasons.add("contract_signature_not_strict")
                break
    bond = contract.get("bond")
    if bond is not None:
        if not (isinstance(bond, dict) and is_int(bond.get("amount")) and 1 <= bond.get("amount") <= MAX_INT):
            reasons.add("bond_malformed")
    pc = contract.get("parent_contract")
    if pc is not None:
        if parent is None:
            reasons.add("parent_not_supplied")
        else:
            parent_ok = isinstance(parent, dict) and door(parent)
            cid_ok = isinstance(pc, dict) and isinstance(parent, dict) and pc.get("contract_id") == parent.get("contract_id")
            subset_ok = parent_ok and cid_ok and grant_subset(contract.get("grant"), parent.get("grant"))
            if not subset_ok:
                reasons.add("parent_narrowing_failed")

    # 5.1
    view_ok, view_reasons = check_view(view, contract)
    reasons |= view_reasons
    if view_ok == "too_large":
        reasons.add("input_too_large")
        view_ok = False
    if view_ok is not True:
        reasons.add("chain_view_rejected")

    # 6.1 binding (always)
    bound, ours = [], {}
    seen_sha = set()
    ref = contract.get("contract_ref")
    for ev in events:
        if not isinstance(ev, dict) or ev.get("schema") not in SCHEMAS:
            continue
        try:
            rsha = record_sha256(ev)
        except Exception:  # noqa: BLE001
            continue
        if rsha in seen_sha:
            continue
        seen_sha.add(rsha)
        ref = ev.get("contract_ref") if isinstance(ev.get("contract_ref"), dict) else {}
        r_csha = ref.get("contract_sha256")
        r_cid = ref.get("contract_id")
        pdg = (contract.get("task") or {}).get("payload_digest") if isinstance(contract.get("task"), dict) else None
        if r_csha is None:
            dispositions[rsha] = "unbound" if r_cid == contract.get("contract_id") else None
            if r_cid != contract.get("contract_id"):
                dispositions.pop(rsha, None)
            continue
        if not (isinstance(r_csha, str) and HEX64.match(r_csha)):
            dispositions[rsha] = "inconsistent"
            continue
        if r_csha != csha:
            dispositions[rsha] = "foreign"
            continue
        if r_cid != contract.get("contract_id"):
            dispositions[rsha] = "inconsistent"
            continue
        if pdg is not None and ref.get("payload_digest") != pdg:
            dispositions[rsha] = "inconsistent"
            continue
        bound.append(ev)
        ours[rsha] = ev

    walk_ran = door_ok and not any(r in reasons for r in (
        "contract_not_verified", "authorized_actions_missing", "grant_action_name_invalid",
        "too_many_witnesses", "witness_key_invalid", "key_conflict", "tie_policy_refused",
        "revocation_policy_not_recomputable", "ack_window_missing", "finality_policy_missing",
        "bad_expiry_height", "unscoped_approvals_refused")) and view_ok is True
    if not walk_ran:
        return finish(contract, csha, reasons, deviations, dispositions, [], view)

    # 6.0 triage
    view_heights = {}
    if isinstance(view, dict) and isinstance(view.get("headers"), list):
        for h in view["headers"]:
            if isinstance(h, dict) and is_int(h.get("height")) and isinstance(h.get("hex"), str) and len(h["hex"]) >= 160:
                view_heights[h["height"]] = h["hex"][:160]
    classified = []  # (record, sha, state)
    for rec in bound:
        rsha = record_sha256(rec)
        strictly, body_ok, anchor_ok, lax = record_flags(rec, contract, grant, csha)
        classified.append({"rec": rec, "sha": rsha, "strictly": strictly, "body_ok": body_ok,
                           "anchor_ok": anchor_ok, "lax": lax, "state": None})
    # first pass: everything except the anchor_not_strict cross-record row
    for c in classified:
        if not c["strictly"]:
            if not c["body_ok"]:
                c["state"] = "record_not_strict"
            elif c["lax"]:
                c["state"] = "signature_not_strict"
            else:
                c["state"] = "rejected"
            continue
        if not c["body_ok"]:
            # a party's own statement that cannot be read strictly: fail closed, do not settle it
            c["state"] = "record_not_strict"
            reasons.add("record_not_strict")
            continue
        if not c["anchor_ok"]:
            c["state"] = "anchor_pending"
            continue
        if c["rec"].get("schema") == "a2a-revocation-v0" and not isinstance(grant.get("revocation"), dict):
            c["state"] = "revocation_not_provided_for"
            continue
        c["state"] = "kept"
    # second pass: anchor_not_strict
    for c in classified:
        if c["state"] != "anchor_pending":
            continue
        twin = any(o is not c and o["state"] == "kept" and signing_key(o["rec"]) == signing_key(c["rec"])
                   and anchors_validly(o["rec"], view_heights, {k: v for k, v in view_heights.items()})
                   for o in classified)
        if twin:
            c["state"] = "anchor_not_strict"
        else:
            c["state"] = "anchor_not_strict"
            reasons.add("anchor_not_strict")
    kept = [c for c in classified if c["state"] == "kept"]

    # 6.2
    if len(kept) > 10000:
        reasons.add("input_too_large")
        return finish(contract, csha, reasons, deviations, dispositions, [], view)
    for c in classified:
        if c["state"] in ("record_not_strict", "signature_not_strict", "rejected",
                          "revocation_not_provided_for", "anchor_not_strict"):
            dispositions[c["sha"]] = c["state"]

    # 6.4 collapse
    groups = {}
    for c in kept:
        groups.setdefault(signing_key(c["rec"]), []).append(c)
    collapsed = []
    for key, grp in groups.items():
        if len({c["sha"] for c in grp}) == 1:
            collapsed.extend(grp)
            continue
        valid = [c for c in grp if anchors_validly(c["rec"], view_heights, view_heights)]
        if valid:
            winner = min(valid, key=lambda c: (c["rec"].get("anchor", {}).get("height", 0), c["sha"]))
            collapsed.append(winner)
            for c in grp:
                if c is not winner:
                    dispositions[c["sha"]] = "duplicate_dropped"
        else:
            collapsed.extend(grp)

    # 6.6 conformance (fixpoint)
    active = collapsed
    while True:
        drop = []
        for c in active:
            if conformance_problem(c["rec"]):
                if c["rec"].get("schema") == "a2a-execution-v0" and c["strictly"]:
                    deviations.add("nonconforming_record")
                else:
                    drop.append(c)
        if not drop:
            break
        for c in drop:
            dispositions[c["sha"]] = "rejected"
            reasons.add("nonconforming_record") if False else None
        active = [c for c in active if c not in drop]

    # 7 anchors
    event_records = []
    for c in active:
        rec = c["rec"]
        h = rec.get("anchor", {}).get("height") if isinstance(rec.get("anchor"), dict) else None
        if not is_int(h) or h < 0 or not (isinstance(rec["anchor"].get("block_hash"), str) and HEX64.match(rec["anchor"]["block_hash"])):
            dispositions[c["sha"]] = "anchor_incomplete"
            reasons.add("anchor_incomplete")
            continue
        lb = contract.get("lower_bound") or {}
        if is_int(lb.get("height")) and h < lb["height"]:
            dispositions[c["sha"]] = "anchor_below_lower_bound"
            reasons.add("anchor_below_lower_bound")
            continue
        tip = max(view_heights) if view_heights else -1
        if h > tip or h not in view_heights:
            dispositions[c["sha"]] = "anchor_beyond_observed_chain"
            reasons.add("anchor_beyond_observed_chain")
            continue
        if rec["anchor"]["block_hash"] != header_hash(view_heights[h]):
            dispositions[c["sha"]] = "orphaned"
            rec["_sha"] = c["sha"]
            rec["_body_hex"] = body_digest(rec).hex()
            rec["_orphaned"] = True
            rec["_height"] = h
            event_records.append(rec)
            continue
        proof = rec["anchor"].get("proof")
        if not (isinstance(proof, list) and 1 <= len(proof) <= 512):
            dispositions[c["sha"]] = "anchor_proof_invalid"
            reasons.add("anchor_proof_invalid")
            continue
        final = apply_proof(body_digest(rec), proof)
        if final is None or final != merkle_root(view_heights[h]):
            dispositions[c["sha"]] = "anchor_proof_invalid"
            reasons.add("anchor_proof_invalid")
            continue
        ok, code = batch_leg(proof, body_digest(rec).hex(), rec.get("schema"))
        if not ok:
            dispositions[c["sha"]] = "anchor_batch_leg_refused"
            reasons.add("anchor_batch_leg_refused")
            continue
        dispositions[c["sha"]] = "accepted"
        rec["_sha"] = c["sha"]
        rec["_body_hex"] = body_digest(rec).hex()
        rec["_height"] = h
        event_records.append(rec)

    accepted = [r for r in event_records if not r.get("_orphaned")]
    accepted.sort(key=lambda r: (r["_height"], r["_sha"]))

    # 6.5 revoked_by: an ignored revocation is not part of the event set
    kept_events = []
    for r in accepted:
        if r["schema"] == "a2a-revocation-v0" and r.get("revoked_by") != "principal":
            dispositions[r["_sha"]] = "ignored"
            continue
        kept_events.append(r)
    event_set_out = [{"kind": {"a2a-execution-v0": "execution", "a2a-revocation-v0": "revocation",
                               "a2a-revocation-ack-v0": "revocation_ack"}[r["schema"]],
                      "sha256": r["_sha"], "height": r["_height"]} for r in kept_events]

    # 10 / 11 / 12
    walk_fn = walk
    if hasattr(walk_fn, "_consumed"):
        del walk_fn._consumed
    walk(kept_events, ours, contract, csha, deviations, reasons)

    # 11.1 NENRIN
    if isinstance(nenrin_records, list) and nenrin_records:
        walks, nonstrict = {}, set()
        for w in nenrin_records:
            if not isinstance(w, dict):
                continue
            try:
                wsha = record_sha256(w)
            except Exception:  # noqa: BLE001
                continue
            if strict(w):
                walks[wsha] = w
            else:
                nonstrict.add(wsha)
        for r in event_records:
            if r["schema"] != "a2a-execution-v0":
                continue
            ref = r.get("nenrin_ref")
            if not (isinstance(ref, str) and HEX64.match(ref)):
                continue
            if ref in nonstrict:
                reasons.add("walk_not_strict")
                continue
            w = walks.get(ref)
            if w is None:
                continue
            ctx = w.get("context")
            if isinstance(ctx, dict) and ctx.get("contract_sha256") is not None and ctx.get("contract_sha256") != csha:
                deviations.add("evidence_names_other_contract")
    ev = (contract.get("requirements") or {}).get("evidence") if isinstance(contract.get("requirements"), dict) else None
    if ev == "nenrin_required":
        for r in kept_events:
            if r["schema"] == "a2a-execution-v0":
                if not (isinstance(r.get("nenrin_ref"), str) and HEX64.match(r.get("nenrin_ref"))):
                    deviations.add("evidence_missing")

    if reasons:
        verdict = "underspecified"
        deviations = set()
    elif deviations:
        verdict = "deviation"
    elif not event_set_out:
        verdict = "nothing_to_settle"
    else:
        verdict = "within_grant"
    status = "undetermined" if verdict == "underspecified" else ("final" if not event_records else None)
    if status is None:
        depth = (grant.get("finality") or {}).get("depth")
        tip = max(view_heights) if view_heights else -1
        horizon = tip - depth + 1 if is_int(depth) else None
        status = "final" if horizon is not None and all(r["_height"] <= horizon for r in event_records) else "provisional"
    return {
        "contract_sha256": csha,
        "verdict": verdict,
        "status": status,
        "bond_outcome": bond_outcome(contract, verdict, status),
        "deviation_codes": sorted(deviations) if verdict == "deviation" else [],
        "underspecified_reasons": sorted(reasons) if verdict == "underspecified" else [],
        "event_set": event_set_out,
        "dispositions": dispositions,
    }


def bond_outcome(contract, verdict, status):
    bond = contract.get("bond") if isinstance(contract, dict) else None
    if bond is None:
        return "n/a"
    if not (isinstance(bond, dict) and is_int(bond.get("amount")) and bond.get("amount") >= 1):
        return "undetermined" if isinstance(bond, dict) and bond.get("amount") else "n/a"
    if verdict == "underspecified":
        return "undetermined"
    if status == "provisional":
        return "pending_finality"
    return "forfeited" if verdict == "deviation" else "held"


def finish(contract, csha, reasons, deviations, dispositions, event_set, view):
    verdict = "underspecified"
    return {"contract_sha256": csha, "verdict": verdict, "status": "undetermined",
            "bond_outcome": bond_outcome(contract, verdict, "undetermined"),
            "deviation_codes": [], "underspecified_reasons": sorted(reasons),
            "event_set": event_set, "dispositions": dispositions}


# ---------------------------------------------------------------- vector runner
def load_vector(path):
    contract = read_json(open(os.path.join(path, "contract.json"), "rb").read())
    view = read_json(open(os.path.join(path, "view.json"), "rb").read())
    events = []
    ed = os.path.join(path, "events")
    if os.path.isdir(ed):
        for name in sorted(os.listdir(ed)):
            if name.endswith(".json"):
                events.append(read_json(open(os.path.join(ed, name), "rb").read()))
    nenrin = []
    nd = os.path.join(path, "nenrin")
    if os.path.isdir(nd):
        for name in sorted(os.listdir(nd)):
            if name.endswith(".json"):
                nenrin.append(read_json(open(os.path.join(nd, name), "rb").read()))
    parent = None
    pp = os.path.join(path, "parent.json")
    if os.path.exists(pp):
        parent = read_json(open(pp, "rb").read())
    return contract, events, view, (nenrin or None), parent


def main(argv):
    if len(argv) >= 3 and argv[1] == "--check":
        root = argv[2]
        bad = 0
        total = 0
        for name in sorted(os.listdir(root)):
            vdir = os.path.join(root, name)
            if not os.path.isdir(vdir):
                continue
            total += 1
            expected = json.load(open(os.path.join(vdir, "expected.json")))
            try:
                contract, events, view, nenrin, parent = load_vector(vdir)
                got = settle(contract, events, view, nenrin, parent)
            except Exception as exc:  # noqa: BLE001
                print("ERROR %-46s %s" % (name, exc))
                bad += 1
                continue
            diffs = [k for k in expected if canon(expected[k]) != canon(got.get(k))]
            if diffs:
                bad += 1
                print("DIFF  %-46s %s" % (name, ", ".join(diffs)))
                for k in diffs:
                    print("        %-24s expected=%s" % (k, canon(expected[k])[:150]))
                    print("        %-24s got     =%s" % ("", canon(got.get(k))[:150]))
            else:
                print("OK    %s" % name)
        print("\n%d/%d vectors agree on the eight core fields" % (total - bad, total))
        return 0 if bad == 0 else 1
    for path in argv[1:]:
        contract, events, view, nenrin, parent = load_vector(path)
        print(json.dumps(settle(contract, events, view, nenrin, parent), indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
