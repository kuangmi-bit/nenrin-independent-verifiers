# nenrin-independent-verifiers

Two independent Python implementations of the NENRIN provenance verifier, plus the runners that
check them against the interop corpora published by
[ogasurfproject-jpg/horizon-shield](https://github.com/ogasurfproject-jpg/horizon-shield).

*Independent* here means written from the normative text (`VERIFIER.md`) alone, without reading the
reference implementation (`sdk/nenrin_verify.mjs`) or the JavaScript runner. Both implementations
reproduce every corpus verdict signature:

| corpus | fixtures | reproduced | rules in force |
|---|---|---|---|
| `interop-v0` | 5 | **5/5** | `VERIFIER.md` @ `65ae7d0f` |
| `interop-v0.1` | 13 | **13/13** | same text, after the wording fixes |
| `interop-v0.2/edge` | 36 | **36/36** | + the section 5 key rule, malformed-record rule |

The corpora are not vendored here. `fetch_corpus.sh` fetches them at a pinned commit and runs both
verifiers, so a run is reproducible from the published bytes rather than from a copy in this
repository.

## Provenance

- Written after the clean-room test of 2026-10-04; the findings are in
  [a2aproject/A2A discussion #1631](https://github.com/a2aproject/A2A/discussions/1631).
- `interop-v0.2/edge` was merged upstream as
  [PR #30](https://github.com/ogasurfproject-jpg/horizon-shield/pull/30) (2026-10-04). The verifier
  in this repository is the same file that was merged as
  `workers/hs-ledger/nenrin/interop-v0.2/edge/python/verify_edge.py` (git blob `eb5d1575`); the 36
  expectations in that corpus were cut with it, one broken rule per fixture.
- The corpus snapshot the results are checked against is DOI-registered:
  **10.5281/zenodo.23136978**.
- Upstream pin used by `fetch_corpus.sh`: horizon-shield commit `7546b106` (the merge commit of PR
  #30).

## What this establishes, and what it does not

Establishes: two readers written from the text alone agree with the published verdict signatures and
digests for three corpora, and those expectations are reproducible from the published bytes.

Does not establish: that the specification is correct, that its rules are complete, or anything
about the conduct of the agents whose evidence the corpora describe. A verdict signature is the
verifier's own output and nothing more. Neither implementation has been reviewed by the authors of
the text.

## Layout

```
verifiers/nenrin_verify_v0.py         rules as of VERIFIER.md 65ae7d0f (interop-v0, interop-v0.1)
verifiers/nenrin_verify_v02_edge.py   the same reader plus the section 5 key rule (interop-v0.2/edge)
runners/run_corpus.py                 runs a verifier over a corpus dir and diffs expected.json
runners/run_edge.py                   runs the v0.2 reader over the edge corpus
fetch_corpus.sh                       fetches the pinned corpora and reproduces all three
```

## Requirements

Python 3.10+ and `cryptography`. Ed25519 is verified through OpenSSL, as `VERIFIER.md` section 5
pins; canonicalization (`musubi-canonical-v0`) is re-implemented from the prose, not imported.

## Run

```bash
./fetch_corpus.sh                       # clone the pinned commit into .corpus/, then verify
./fetch_corpus.sh /path/to/existing     # reuse an existing checkout, no network
```

Against a corpus directory you already have:

```bash
PYTHONPATH=verifiers python3 runners/run_corpus.py <corpus_dir> nenrin_verify_v0
python3 runners/run_edge.py <corpus_dir>     # holds expected.json and fixtures/
```

Each runner prints `<n>/<total> verdict signatures reproduced` and exits non-zero on any mismatch.

## Two defects this text found in this code

Re-reading section 5 of the specification after the first passing run caught two real bugs here, both
now fixed and both with fixtures upstream:

- a substituted regex mode ending in `$` accepted a timestamp with a trailing newline; `\Z` is the
  rule the text states (`ts_trailing_newline`);
- `prev_evidence_id` was treated as absent when the key itself was absent, instead of only when it
  is `null` (`prev_absent_seq0`).

That is the point of writing a second reader: the text is the oracle, not the first implementation.

## License

MIT — see [LICENSE](LICENSE).
