#!/usr/bin/env python3
"""nenrin-provenance-verify-v0, implemented from VERIFIER.md (normative text).

Source of rules: workers/hs-ledger/nenrin/provenance-v0/VERIFIER.md @ 65ae7d0f,
written by ogasurfproject-jpg after the clean-room test of 2026-10-04.

Independence notes (this matters for the evidence value of the result):
  * the reference implementation (sdk/nenrin_verify.mjs) was NOT read;
  * canonicalization is re-implemented here from the musubi-canonical-v0 prose
    (integer-only numbers, printable-ASCII keys, no whitespace) and is
    cross-checked byte-for-byte against a2a-python's RFC 8785 canonicalizer
    on both corpora;
  * Ed25519 verification is OpenSSL via `cryptography` (same primitive family
    as the reference, which VERIFIER.md section 5 pins).
"""
import base64
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ------------------------------------------------------------------ vocabulary

TS_RE = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
                   r"(?:\.(\d+))?Z\Z")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
LINK_PREFIX = "nenrin-exec://"
EVIDENCE_KINDS = {"bitcoin_tx", "ledger_record", "document_sha256", "url_sha256"}
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MAX_INT = 2 ** 53 - 1

OBS_DERIVED = ("evidence_id", "witness_sig", "edge_sig", "consent")
GRANT_DERIVED = ("grant_ref", "caller_sig", "action_binding")
RECEIPT_DERIVED = ("receipt_id", "provider_sig", "action_binding")
INTENT_DERIVED = ("intent_id", "intent_sig", "action_binding")


class CanonicalRefusal(Exception):
    """A value that musubi-canonical-v0 refuses to serialize."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


# ------------------------------------------------------------------ primitives

def _canon_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o == 0x08:
            out.append("\\b")
        elif o == 0x0C:
            out.append("\\f")
        elif o == 0x0A:
            out.append("\\n")
        elif o == 0x0D:
            out.append("\\r")
        elif o == 0x09:
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u00%02x" % o)
        elif 0xD800 <= o <= 0xDBFF or 0xDC00 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)  # lone surrogate, lowercase hex
        else:
            out.append(ch)  # non-ASCII, U+007F, U+2028, U+2029 raw
    out.append('"')
    return "".join(out)


def canonical(value):
    """musubi-canonical-v0. Raises CanonicalRefusal for refused values."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _canon_string(value)
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise CanonicalRefusal("unsafe_number")
        return "0" if value == 0 else str(value)  # -0 impossible in python int
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise CanonicalRefusal("non_integer_number")
        if float(value).is_integer() and abs(value) <= MAX_INT:
            return str(int(value))  # 1.0 is the integer 1 (section 5 input)
        raise CanonicalRefusal("non_integer_number")
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = []
        for k in value:
            if not isinstance(k, str):
                raise CanonicalRefusal("non_printable_key")
            if not all(0x20 <= ord(c) <= 0x7E for c in k):
                raise CanonicalRefusal("key_not_printable_ascii")
            keys.append(k)
        keys.sort()
        return "{" + ",".join(
            _canon_string(k) + ":" + canonical(value[k]) for k in keys) + "}"
    raise CanonicalRefusal("unrepresentable_value")


def cbytes(value):
    return canonical(value).encode("utf-8")


def digest(value):
    return hashlib.sha256(cbytes(value)).hexdigest()


def without(obj, keys):
    return {k: v for k, v in obj.items() if k not in keys}


def b58decode(s):
    n = 0
    for ch in s:
        if ch not in _B58:
            raise ValueError("bad base58")
        n = n * 58 + _B58.index(ch)
    pad = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


# ---- Ed25519 point arithmetic, for the section 5 key rule -------------------
# A public key resolves only if it is the canonical encoding (y < p, and not
# x = 0 with the sign bit set) of a point P of the prime-order subgroup (P is
# not the identity and L * P is the identity).  OpenSSL alone accepts small-order
# and mixed-order keys, so the check cannot be delegated to it.
_P = 2 ** 255 - 19
_N = 2 ** 252 + 27742317777372353535851937790883648493  # the group order L
_DP = (-121665 * pow(121666, _P - 2, _P)) % _P           # curve constant d
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    """x of the point with this y, or None; refuses x = 0 with the sign bit set."""
    if y >= _P:
        return None
    xx = (y * y - 1) * pow(_DP * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - xx) % _P != 0:
        return None
    if x == 0 and sign:
        return None
    if x % 2 != sign:
        x = _P - x
    return x


def _ext(x, y):
    return (x, y, 1, x * y % _P)


def _add(A, B):
    X1, Y1, Z1, T1 = A
    X2, Y2, Z2, T2 = B
    a = (Y1 - X1) * (Y2 - X2) % _P
    b = (Y1 + X1) * (Y2 + X2) % _P
    c = 2 * T1 * T2 * _DP % _P
    d = 2 * Z1 * Z2 % _P
    return ((b - a) * (d - c) % _P, (d + c) * (b + a) % _P,
            (d - c) * (d + c) % _P, (b - a) * (b + a) % _P)


def _double(A):
    X1, Y1, Z1, _ = A
    a = X1 * X1 % _P
    b = Y1 * Y1 % _P
    c = 2 * Z1 * Z1 % _P
    d = (-a) % _P
    e = ((X1 + Y1) ** 2 - a - b) % _P
    g = (d + b) % _P
    f = (g - c) % _P
    h = (d - b) % _P
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _affine(A):
    X, Y, Z, _ = A
    if Z % _P == 0:
        return None
    zi = pow(Z, _P - 2, _P)
    return (X * zi % _P, Y * zi % _P)


def _mul(pt, n):
    R = (0, 1, 1, 0)
    Q = _ext(pt[0], pt[1])
    while n:
        if n & 1:
            R = _add(R, Q)
        Q = _double(Q)
        n >>= 1
    return _affine(R)


def key_is_prime_order(raw):
    """Section 5 key rule: canonical encoding of a non-identity prime-order point."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        return False
    v = int.from_bytes(raw, "little")
    sign = (v >> 255) & 1
    y = v & ((1 << 255) - 1)
    x = _recover_x(y, sign)          # also refuses y >= p
    if x is None:
        return False
    if (x, y) == (0, 1):             # the identity
        return False
    return _mul((x, y), _N) == (0, 1)


def resolve_key(ident):
    """did:key z<base58btc> with payload 0xed01 + exactly 32 bytes."""
    if not isinstance(ident, str) or not ident.startswith("did:key:z"):
        return None
    try:
        raw = b58decode(ident[len("did:key:z"):])
    except ValueError:
        return None
    if len(raw) != 34 or raw[:2] != b"\xed\x01":
        return None
    if not key_is_prime_order(raw[2:]):
        return None  # small-order, mixed-order or non-canonical: no key resolves
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def canonical_b64(sig_b64):
    """Canonical standard base64 only (VERIFIER.md section 5, strict in 0.4.1):
    RFC 4648 section 4 alphabet, padding present, no whitespace, and the unused
    trailing bits of the final quantum zero. Round-tripping the decoded bytes
    enforces all four at once. Returns raw bytes or None."""
    if not isinstance(sig_b64, str) or not sig_b64:
        return None
    try:
        raw = base64.b64decode(sig_b64, validate=True)
    except Exception:  # noqa: BLE001 - alphabet, padding, whitespace
        return None
    if base64.b64encode(raw).decode("ascii") != sig_b64:
        return None  # non-canonical trailing bits, or padding it did not need
    return raw


def sig_verifies(ident, sig_b64, message):
    """Canonical standard base64 of a 64-byte Ed25519 signature."""
    key = resolve_key(ident)
    if key is None:
        return False
    raw = canonical_b64(sig_b64)
    if raw is None:
        return False
    if len(raw) != 64:
        return False
    try:
        key.verify(raw, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def ts_parse(value):
    """Valid timestamp -> comparable tuple; anything else -> None."""
    if not isinstance(value, str):
        return None
    m = TS_RE.match(value)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7) or ""
    ms = int((frac + "000")[:3])  # millisecond precision, extra digits truncated
    if h > 23 or mi > 59 or s > 59:  # hour 24 and second 60 are impossible
        return None
    try:
        date(y, mo, d)  # impossible calendar dates are rejected
    except ValueError:
        return None
    return (y, mo, d, h, mi, s, ms)


def binding_reason(record, action_field):
    """action_binding rule from section 2. Returns None or a reason string."""
    if "action_binding" not in record:
        return None
    b = record["action_binding"]
    if not isinstance(b, dict):  # not an object, or an array
        return "action_binding_malformed"
    if b.get("type") != "canonical_request_digest":
        return "action_binding_malformed"
    d = b.get("digest")
    if not isinstance(d, dict) or d.get("alg") != "sha-256" \
            or not isinstance(d.get("value"), str):
        return "action_binding_malformed"
    if b.get("canonicalization") != "musubi-canonical-v0" \
            or b.get("preimage_profile") != "task-execution-bind-v0/action":
        return "action_binding_unknown_profile"
    if action_field not in record or record.get(action_field) is None:
        return "action_binding_mismatch"
    try:
        want = digest(record[action_field])
    except CanonicalRefusal:
        return "action_binding_mismatch"
    if d.get("value") != want:
        return "action_binding_mismatch"
    return None


def recomputes_id(record, derived, id_field):
    try:
        return digest(without(record, derived)) == record.get(id_field)
    except CanonicalRefusal:
        return False


# -------------------------------------------------------------------- verifier

class Report:
    def __init__(self):
        self.refusals = set()
        self.findings = set()
        self.reasons = []
        self.reconciled = None
        self.primary = None
        self.receipts = []
        self.receipt_set_nonempty = False
        self.observations_presented = False

    def refuse(self, code, reason=""):
        self.refusals.add(code)
        self.reasons.append(f"{code}:{reason}" if reason else code)

    def find(self, code):
        self.findings.add(code)

    def signature(self):
        return {
            "verdict": "refused" if self.refusals else "accepted",
            "refusals": sorted(self.refusals),
            "findings": sorted(self.findings),
        }


def bundle_value(bundle, key):
    """Section 5: null, false or absent means not presented."""
    if key not in bundle:
        return None
    v = bundle[key]
    if v is None or v is False:
        return None
    return v


def bundle_list(bundle, key):
    v = bundle_value(bundle, key)
    return v if isinstance(v, list) else []


def verify(bundle):
    rep = Report()
    task_id = bundle.get("task_id")
    require_sigs = bundle.get("require_signatures", True) is not False

    obs = bundle_list(bundle, "observations")
    grant = bundle_value(bundle, "grant")
    intent = bundle_value(bundle, "intent")
    # Section 5, "Malformed records": a record slot that is present but neither an
    # object nor null/false is malformed: one refusal in its own step, and in every
    # other respect it is not presented.
    grant_malformed = grant is not None and not isinstance(grant, dict)
    intent_malformed = intent is not None and not isinstance(intent, dict)
    raw_receipt = bundle_value(bundle, "receipt")
    receipt_malformed = raw_receipt is not None and not isinstance(raw_receipt, dict)
    bad_receipt_elems = sum(1 for r in bundle_list(bundle, "receipts")
                            if not isinstance(r, dict))
    if not isinstance(grant, dict):
        grant = None
    if not isinstance(intent, dict):
        intent = None

    recs = []
    if isinstance(bundle.get("receipt"), dict):
        recs.append(bundle["receipt"])
    for r in bundle_list(bundle, "receipts"):
        if isinstance(r, dict) and all(cbytes(r) != cbytes(p) for p in recs):
            recs.append(r)
    rep.receipts = recs
    rep.receipt_set_nonempty = bool(recs)
    rep.observations_presented = bool(obs)
    primary = bundle["receipt"] if isinstance(bundle.get("receipt"), dict) \
        else (recs[0] if recs else None)
    rep.primary = primary

    # ---- step 0, identity
    if not isinstance(task_id, str) or not task_id:
        rep.refuse("task_id_missing", "not a non-empty string")
    for rec in list(obs) + ([grant] if grant else []) + \
            ([intent] if intent else []) + recs:
        if not isinstance(rec, dict):
            continue  # not a record: handled by its own layer (proposal, v0.2)
        if rec.get("task_id") != task_id:
            rep.refuse("task_id_mismatch", "record carries a different task_id")

    # ---- step 1, delegation
    if not obs:
        rep.find("no_delegation_observations")
    else:
        for i, o in enumerate(obs):
            if not isinstance(o, dict):
                rep.refuse("delegation_observation_invalid",
                           f"obs[{i}] record_not_object")
                continue
            hop = o.get("hop") if isinstance(o.get("hop"), dict) else {}
            # R1 witness independence
            if o.get("witness_id") is not None and \
                    o.get("witness_id") in (hop.get("from"), hop.get("to")):
                rep.refuse("delegation_observation_invalid",
                           f"obs[{i}] witness_not_independent")
                continue
            # R2 evidence_id recompute
            if not recomputes_id(o, OBS_DERIVED, "evidence_id"):
                rep.refuse("delegation_observation_invalid",
                           f"obs[{i}] recompute_mismatch")
                continue
            if require_sigs:
                preimage = without(o, OBS_DERIVED)
                try:
                    pre = cbytes(preimage)
                except CanonicalRefusal as exc:
                    rep.refuse("delegation_observation_invalid",
                               f"obs[{i}] witness_sig_invalid:{exc.code}")
                    continue
                if not sig_verifies(o.get("witness_id"), o.get("witness_sig"), pre):
                    rep.refuse("delegation_observation_invalid",
                               f"obs[{i}] witness_sig_invalid")
                    continue
                # edge_sig signs canonical({task_id, hop})
                try:
                    edge_pre = cbytes({"task_id": o.get("task_id"),
                                       "hop": o.get("hop")})
                except CanonicalRefusal as exc:
                    rep.refuse("delegation_observation_invalid",
                               f"obs[{i}] edge_sig_invalid:{exc.code}")
                    continue
                if not sig_verifies(hop.get("from"), o.get("edge_sig"), edge_pre):
                    rep.refuse("delegation_observation_invalid",
                               f"obs[{i}] edge_sig_invalid")
                    continue
        # R3 chain continuity over the presented set
        def recomputed_evidence_id(o):
            try:
                return digest(without(o, OBS_DERIVED))
            except CanonicalRefusal:
                return None

        obj_obs = [o for o in obs if isinstance(o, dict)]
        int_seqs = [o["hop"]["seq"] for o in obj_obs
                    if isinstance(o.get("hop"), dict)
                    and isinstance(o["hop"].get("seq"), int)
                    and not isinstance(o["hop"].get("seq"), bool)]
        n_bad_seq = len(obj_obs) - len(int_seqs)
        seqs = sorted(set(int_seqs))  # section 3 R3: the distinct seqs
        if n_bad_seq or seqs != list(range(len(seqs))):
            rep.refuse("delegation_chain_broken", "seq_gap")
        for o in obs:
            if not isinstance(o, dict) or not isinstance(o.get("hop"), dict) \
                    or not isinstance(o["hop"].get("seq", None), int) \
                    or isinstance(o["hop"].get("seq"), bool):
                continue
            seq = o["hop"]["seq"]
            prev = o.get("prev_evidence_id")
            if seq == 0:
                # section 5: must be exactly null; absent fails here
                if "prev_evidence_id" not in o or prev is not None:
                    rep.refuse("delegation_chain_broken", "root_prev_not_null")
                continue
            target_ids = {recomputed_evidence_id(p) for p in obs
                          if isinstance(p, dict)
                          and isinstance(p.get("hop"), dict)
                          and p["hop"].get("seq") == seq - 1}
            target_ids.discard(None)
            if prev not in target_ids:
                rep.refuse("delegation_chain_broken", "broken_link")
        # R4 witness disagreement per seq, never refuses
        per_seq = {}
        for o in obs:
            if not isinstance(o, dict) or not isinstance(o.get("hop"), dict):
                continue
            seq = o["hop"].get("seq")
            try:
                key = seq if isinstance(seq, (int, str)) else json.dumps(seq)
            except TypeError:
                key = repr(seq)
            conduct = o.get("conduct") if isinstance(o.get("conduct"), dict) else {}
            if "verdict" in conduct:
                val = conduct["verdict"]
                per_seq.setdefault(key, set()).add(
                    val if isinstance(val, str) else json.dumps(val))
            else:
                per_seq.setdefault(key, set()).add("<missing>")
        if any(len(v) > 1 for v in per_seq.values()):
            rep.find("witness_disagreement")

    # ---- step 2, execution
    if receipt_malformed:
        rep.refuse("execution_invalid", "receipt slot record_not_object")
    for _ in range(bad_receipt_elems):
        rep.refuse("execution_invalid", "receipts element record_not_object")
    if grant_malformed:
        rep.refuse("execution_invalid", "grant slot record_not_object")
    if not grant and not recs:
        rep.find("no_execution_records")
    elif (grant and not recs) or (recs and not grant):
        rep.refuse("execution_incomplete_pair", "grant xor receipt set")
    else:
        def pair_check(g, r, findings):
            """Step 2a on one (grant, receipt). Returns True when it passes."""
            if not recomputes_id(g, GRANT_DERIVED, "grant_ref"):
                return False
            if not recomputes_id(r, RECEIPT_DERIVED, "receipt_id"):
                return False
            for rec, field in ((g, "action"), (r, "executed_action")):
                if binding_reason(rec, field) is not None:
                    return False
            if r.get("grant_ref") != g.get("grant_ref"):
                return False
            parsed = {"executed_at": ts_parse(r.get("executed_at")),
                      "not_before": ts_parse(g.get("not_before")),
                      "not_after": ts_parse(g.get("not_after"))}
            if parsed["executed_at"] is None:
                return False
            if g.get("not_before") is not None and parsed["not_before"] is None:
                return False
            if g.get("not_after") is not None and parsed["not_after"] is None:
                return False
            if g.get("provider_id") is not None \
                    and g.get("provider_id") != r.get("provider_id"):
                return False
            if parsed["not_before"] is not None \
                    and parsed["executed_at"] < parsed["not_before"]:
                return False
            if parsed["not_after"] is not None \
                    and parsed["executed_at"] > parsed["not_after"]:
                return False
            if findings:
                if g.get("provider_id") is None:
                    rep.find("open_grant")
                elif g.get("provider_id") == g.get("caller_id"):
                    rep.find("self_authorized")
            try:
                if cbytes(g.get("action") if "action" in g else None) \
                        != cbytes(r.get("executed_action")
                                  if "executed_action" in r else None):
                    return False  # action_diverged
            except CanonicalRefusal:
                return False
            return True

        if not pair_check(grant, primary, True):
            rep.refuse("execution_invalid", "pair check failed")
        if require_sigs:
            ok = sig_verifies(grant.get("caller_id"), grant.get("caller_sig"),
                              cbytes(without(grant, GRANT_DERIVED)))
            if ok:
                ok = sig_verifies(primary.get("provider_id"),
                                  primary.get("provider_sig"),
                                  cbytes(without(primary, RECEIPT_DERIVED)))
            if not ok:
                rep.refuse("execution_signature_invalid", "caller or primary")
        for r in recs:
            if r is primary:
                continue
            if require_sigs:
                caller_ok = sig_verifies(grant.get("caller_id"),
                                         grant.get("caller_sig"),
                                         cbytes(without(grant, GRANT_DERIVED)))
                own_ok = sig_verifies(r.get("provider_id"),
                                      r.get("provider_sig"),
                                      cbytes(without(r, RECEIPT_DERIVED)))
                if not (caller_ok and own_ok):
                    continue  # ignored here, no code
            if not pair_check(grant, r, False):
                rep.refuse("execution_invalid", "other receipt pair check")
        # 2d reconciliation
        if grant.get("provider_id") is None:
            rep.refuse("execution_unreconciled", "no provider named")
        else:
            authentic = set()
            for r in recs:
                if r.get("grant_ref") != grant.get("grant_ref"):
                    continue
                if r.get("provider_id") != grant.get("provider_id"):
                    continue
                if not recomputes_id(r, RECEIPT_DERIVED, "receipt_id"):
                    continue
                if require_sigs and not sig_verifies(
                        grant.get("provider_id"), r.get("provider_sig"),
                        cbytes(without(r, RECEIPT_DERIVED))):
                    continue
                authentic.add(r.get("receipt_id"))
            if not authentic:
                rep.refuse("execution_unreconciled", "no authentic receipt")
            elif len(authentic) > 1:
                rep.refuse("execution_equivocation", "several authentic receipts")
            else:
                rep.reconciled = next(
                    r for r in recs if r.get("receipt_id") in authentic)

    # ---- step 3, preflight
    if intent_malformed:
        rep.refuse("preflight_invalid", "intent slot record_not_object")
    if intent is not None:
        if not grant:
            rep.refuse("preflight_without_grant", "intent presented alone")
        else:
            failed = False
            if not recomputes_id(grant, GRANT_DERIVED, "grant_ref"):
                failed = True
            if not failed and not recomputes_id(intent, INTENT_DERIVED,
                                                "intent_id"):
                failed = True
            if not failed and binding_reason(intent, "proposed_action") is not None:
                failed = True
            if not failed and intent.get("grant_ref") != grant.get("grant_ref"):
                failed = True
            declared = ts_parse(intent.get("declared_at"))
            nb = ts_parse(grant.get("not_before"))
            na = ts_parse(grant.get("not_after"))
            if not failed:
                if declared is None:
                    failed = True
                elif grant.get("not_before") is not None and nb is None:
                    failed = True
                elif grant.get("not_after") is not None and na is None:
                    failed = True
            if not failed and grant.get("provider_id") is not None \
                    and grant.get("provider_id") != intent.get("provider_id"):
                failed = True
            if not failed and nb is not None and declared < nb:
                failed = True
            if not failed and na is not None and declared > na:
                failed = True
            if not failed:
                if grant.get("provider_id") is None:
                    rep.find("open_grant")
                elif grant.get("provider_id") == grant.get("caller_id"):
                    rep.find("self_authorized")
            if not failed:
                try:
                    if cbytes(grant.get("action") if "action" in grant else None) \
                            != cbytes(intent.get("proposed_action")
                                      if "proposed_action" in intent else None):
                        failed = True  # action_diverged
                except CanonicalRefusal:
                    failed = True
            if failed:
                rep.refuse("preflight_invalid", "preflight check failed")
            if require_sigs and not sig_verifies(
                    intent.get("provider_id"), intent.get("intent_sig"),
                    cbytes(without(intent, INTENT_DERIVED))):
                rep.refuse("preflight_signature_invalid", "intent_sig")
            if rep.reconciled is not None:
                try:
                    if cbytes(intent.get("proposed_action")
                              if "proposed_action" in intent else None) \
                            != cbytes(rep.reconciled.get("executed_action")
                                      if "executed_action" in rep.reconciled
                                      else None):
                        rep.find("declared_executed_divergence")
                except CanonicalRefusal:
                    rep.find("declared_executed_divergence")

    # ---- step 4, evidence (target: reconciled, else primary, else skip)
    target = rep.reconciled or primary
    if target is not None:
        outcome = target.get("outcome")
        if not isinstance(outcome, dict):
            rep.find("no_evidence_bound")
        else:
            has = "evidence" in outcome
            e = outcome.get("evidence")
            absent = (not has) or e is None or e is False or e == 0 or e == ""
            if absent:
                rep.find("no_evidence_bound")
            else:
                well_formed = (
                    isinstance(e, dict)
                    and e.get("kind") in EVIDENCE_KINDS
                    and isinstance(e.get("ref"), str)
                    and bool(HEX64_RE.match(e["ref"]))
                    and isinstance(e.get("system"), str)
                    and len(e["system"]) > 0
                )
                if not well_formed:
                    rep.refuse("evidence_invalid", "malformed evidence")
                else:
                    rep.find("evidence_bound_unchecked")  # no lookup injected

    # ---- step 5, linkage (needs observations presented AND reconciled)
    if rep.observations_presented and rep.reconciled is not None:
        links = []
        for o in obs:
            if not isinstance(o, dict):
                continue
            conduct = o.get("conduct") if isinstance(o.get("conduct"), dict) else {}
            ref = conduct.get("detail_ref")
            if isinstance(ref, str) and ref.startswith(LINK_PREFIX):
                links.append(ref)
        if not links:
            rep.find("no_digest_link")
        else:
            want = digest(without(rep.reconciled, RECEIPT_DERIVED))
            for ref in links:
                if ref[len(LINK_PREFIX):] != want:
                    rep.refuse("linkage_receipt_mismatch", "link names another id")
    return rep


# ------------------------------------------------------------------------ main

def main():
    here = Path(__file__).parent
    dirs = sys.argv[1:] or [str(here / "corpus0"), str(here / "corpus01")]
    total_ok = total = 0
    for d in dirs:
        corpus = Path(d).resolve()
        expected = json.loads((corpus / "expected.json").read_text())["cases"]
        ok = 0
        lines = []
        for name, case in expected.items():
            bundle = json.loads((corpus / "fixtures" / f"{name}.json").read_text())
            want = case["expect"]
            want_sig = {"verdict": want["verdict"],
                        "refusals": sorted(want["refusals"]),
                        "findings": sorted(want["findings"])}
            rep = verify(bundle)
            got = rep.signature()
            match = got == want_sig
            ok += match
            if not match:
                lines.append(f"  FAIL {name}\n"
                             f"    got      {json.dumps(got, sort_keys=True)}\n"
                             f"    expected {json.dumps(want_sig, sort_keys=True)}\n"
                             f"    reasons  {rep.reasons}")
        print(f"{corpus.name}: {ok}/{len(expected)} verdict signatures reproduced")
        for line in lines:
            print(line)
        total_ok += ok
        total += len(expected)
    print(f"\ntotal: {total_ok}/{total}")


if __name__ == "__main__":
    main()
