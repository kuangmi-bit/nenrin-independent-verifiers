# NENRIN half of the VATE S3 crosswalk, read by an independent verifier

Poke-nushi's [NENRIN–VATE S3 crosswalk example](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/main/reference/nenrin-s3-crosswalk-example)
compares NENRIN's verdicts on three cases (`match`, `target_mismatch`, `missing_receipt`) with VATE's
assessment of the same S3 write across eleven relationships. The crosswalk ships two NENRIN engines, both
written by its own authors (`nenrin-verify` 0.5.1 from npm, 0.5.3 from PyPI).

`run_swap.py` runs the **NENRIN half with a verifier the crosswalk's authors did not write** — the
`nenrin-provenance-verify-v0` reader in this repository, implemented from `VERIFIER.md` alone without
reading the reference implementation — and then lets the crosswalk's **own pinned comparison code**
(`compare_records.py` / `crosswalk_core.relationship_rows`, imported unchanged, Apache-2.0) compute the
eleven relationship rows from those verdicts.

## Result (2026-10-16, crosswalk pinned at `79a9f91a`)

| case | this verifier | shipped npm | shipped PyPI |
|---|---|---|---|
| `match` | `accepted` — findings `evidence_bound_unchecked`, `no_delegation_observations` | identical | identical |
| `target_mismatch` | `refused` — `execution_invalid` | identical code | identical code |
| `missing_receipt` | `refused` — `execution_incomplete_pair` | identical code | identical code |

* Verdicts, refusal **codes** and findings agree with both shipped implementations on all three cases (6/6).
* All **11 relationship rows in all 3 cases** match the pinned expectations of the board row
  `poke-nushi-vate-nenrin-s3-crosswalk` (`tools/tsunagi/expected/vate-nenrin-s3-crosswalk-v0.json`) — 33/33.
* `pins` and the VATE side are byte-identical to that expectation file.
* One honest difference: this verifier carries its **own refusal wording** (`pair check failed`,
  `grant xor receipt set`) where the shipped implementations report `action_diverged` and `null`. Codes are
  the crosswalk's vocabulary; the reason strings are not.

## What this is not

* **Not a crosswalk rerun.** The VATE assessor is not re-executed; the VATE side is read from the
  crosswalk's saved, hash-pinned reports. The NENRIN side is a fresh local run of this repository's verifier.
* **Not a route through the crosswalk's own `--npm-entry` / `--python` flags.** `replay_native.py` calls
  `installed_identity()`, which requires the npm package to be named `nenrin-verify` at version `0.5.1` and
  checks the PyPI distribution's source files against `NATIVE-PINS.json`. Any third-party verifier is
  refused there *before it runs*. Swapping the engine therefore means restating the comparison with the
  crosswalk's comparison code as a library, which is what this script does — and why it labels the NENRIN
  side `fresh_local_run` instead of `rerun`.
* **No protocol verdict, no signature attribution, no execution or retry authority** — the same limits the
  crosswalk itself states.

## Run it

```bash
python3 run_swap.py \
  --example    <checkout>/reference/nenrin-s3-crosswalk-example \
  --repository <checkout of Poke-nushi/Verifiable-Agent-Trust-Envelope at 79a9f91a> \
  --verifiers  <this repository>/verifiers \
  --out        live-report.json
```

`live-report.json` is written deterministically: two consecutive runs are byte-identical
(sha256 `b473974de293ef5100c451b32afa3ed3a764c9b94b3afe7da12082c5e141264b`, 284,541 bytes).
