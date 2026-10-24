# settle core v0 — independent implementation

An implementation of **MUSUBI settle core v0** written from the specification and the vectors alone
(`SETTLE_CORE_v0.md`, revision 0.5, and `vectors/` as published in
`ogasurfproject-jpg/horizon-shield`). The reference implementation (`settle_v1_16.py` and what it
imports) was not read; where this file and the text could be read two ways, the vector decided and the
reading is recorded under *Ambiguities* below.

First implementation by another party: `aeoess/musubi-settle-core-check` (Issue #49).
This one is independent of that one as well — only the published text and vectors were used.

## Result

```
$ python3 settle_core_v0.py --check <vectors_root>
128/128 vectors agree on the eight core fields
```

- The eight core fields are those of §9.1: `contract_sha256`, `verdict`, `status`, `bond_outcome`,
  `deviation_codes`, `underspecified_reasons`, `event_set`, `dispositions`.
- Run on 2026-10-19, Python 3.11.16, on the 128 vector folders published at the commit named in
  `results/vectors-2026-10-19.txt`.
- `verdict`, `status`, `deviation_codes`, `underspecified_reasons`, `event_set` and `dispositions`
  matched exactly on every vector, including the two real-engagement vectors and the 25 `synth_parent_full_*`
  narrowing vectors.
- §15 step 2 was run as well: the published reference (`settle_v1_16.py`) also agrees with the expected
  values on this machine, 128/128 (`results/reference-2026-10-19.txt`), so the comparison is against a
  reference that demonstrably still produces these vectors here.

## Shape

- Standard library only at run time. Ed25519 verification uses `cryptography` (OpenSSL) when it is
  installed and a small RFC 8032 verifier built on the module's own group arithmetic otherwise; the
  vectors pass on both paths. The strict-signature test of §3.4 (canonical prime-order `R`, `S < L`)
  is implemented directly because libraries disagree on lax signatures.
- No network at run time: the settle function takes `contract`, `events`, `view`, `nenrin_records`
  and `parent` as values.
- JSON is read with §2.2's extra rules: duplicate keys and depth > 512 are errors, integers must fit
  ±(2^53−1), `NaN` / `Infinity` / `-Infinity` are read as non-integer numbers, and an integer token
  longer than 4300 digits stops the reader.

```
python3 settle_core_v0.py <vector_dir>            # one vector, core fields as JSON
python3 settle_core_v0.py --check <vectors_root>  # every vector, compared with expected.json
```

## What this does not establish

The same limits §14 gives: not that any record is true, not that no key was stolen, not that acts
nobody recorded did not happen, not full Bitcoin consensus, and not that the view is the heaviest
chain. It says that this implementation computes the same core fields as the vectors on the inputs
the vectors carry.

It is also not a security review of the reference, and the fallback verifier is straightforward
code, not constant-time code — it verifies public data, so timing is not part of its threat model.

## Ambiguities met while implementing

Each was resolved by the vectors, as §15 asks:

1. **§6.0 row 4 — "the record is a party's own statement".** The text names the reason
   `record_not_strict` but does not say whether the record stays in the event set. The vectors
   (`synth_nan_in_signed_body`, `synth_float_in_signed_body`, `synth_infinity_in_signed_body`,
   `synth_negative_infinity_in_signed_body`) expect it to be **set aside** (`dispositions` carries
   `record_not_strict`, `event_set` is empty) *and* the reason to appear in
   `underspecified_reasons`. Implemented that way.
2. **§6.0 row 1 — "not strictly signed, body not strict".** The disposition is `record_not_strict`
   but no reason is added (`synth_unsigned_float_beside_good`: reasons empty, `within_grant`).
   So the reason is added on row 4 only, not on row 1.
3. **"Strictly signed" does not require the body to be a strict value.** A signature can strictly
   verify over a body holding `NaN`; that record reaches row 4 rather than row 1. Requiring a strict
   body would make row 4 unreachable and disagrees with the four vectors above.
4. **§4.3 parent narrowing is not part of the §4.1 door.** The text says the contract "does not pass
   4.1 with the parent supplied", which reads like a door failure; the vectors expect
   `parent_narrowing_failed` alone (no `contract_not_verified`) and the walk still to run
   (`synth_parent_widened` and the other `synth_parent_full_*` vectors).
5. **§10.1 / §9.1 — an ignored revocation is not in the event set**
   (`synth_revocation_by_non_principal`: disposition `ignored`, event set without the revocation).
6. **§4.1 rule 2 — `contract_id` and `nonce` are 32 hex characters, not 64.** A reading error on my
   side, noted so the next implementer does not repeat it.

## Files

- `settle_core_v0.py` — the implementation and the vector runner.
- `results/vectors-2026-10-19.txt` — the full per-vector log of the run reported above.
- `run_check.sh` — clones nothing; points the checker at a local checkout of the vectors.

## Differential-fuzzer follow-ups (2026-10-24)

`ogasurfproject-jpg/horizon-shield#49` ran a differential fuzzer over this implementation,
the reference and `aeoess/musubi-settle-core-check`. Five of the eight separations it found
are defects here and are fixed in this commit; the public 128 vectors agreed before and after
(they do not distinguish the two readings):

| case | what was wrong | fix |
|---|---|---|
| B | `parent_narrowing_failed` was skipped when the child itself failed section 4.1; 4.3.1 makes passing "with the parent supplied" conditional on passing 4.1 on its own | the subset test now includes the child's own door |
| D | the `revoked_by != "principal"` rule of 6.5 ran after section 7, so a revocation with a bad anchor was reported as an anchor failure instead of `ignored` | applied in 6.0 triage, before anchors |
| E | approvals carried by a revoked execution were never classified; 10.4 says "revoked or not" | classified before the revocation branch returns |
| F | any strictly signed nonconforming execution was a charge; 6.6 asks for a *contractor* signature that verifies | the contractor signature is tracked separately from "strictly signed" |
| G | status was computed over records that 6.5 had ignored, so an ignored revocation above the horizon made it `provisional` | ignored records no longer reach the event set |

Case H did not reproduce: `contract_ref.contract_sha256` values that are not 64 lowercase hex are
classified `inconsistent` here, which is the order in 6.1.
