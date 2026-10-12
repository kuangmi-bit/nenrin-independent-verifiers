# nenrin-independent-verifiers

Two independent Python implementations of the NENRIN provenance verifier, plus the runners that
check them against the interop corpora published by
[ogasurfproject-jpg/horizon-shield](https://github.com/ogasurfproject-jpg/horizon-shield).

*Independent* here means written from the normative text (`VERIFIER.md`) alone, without reading the
reference implementation (`sdk/nenrin_verify.mjs`) or the JavaScript runner. Both implementations
reproduce every corpus verdict signature:

A third reader, for the `aps.agent-passport` 2.0 vectors of Agent Passport System, was added on
2026-10-12 and is described in its own section below.

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
verifiers/aps_v2_verify.py            reader for the aps.agent-passport 2.0 vectors
runners/run_corpus.py                 runs a verifier over a corpus dir and diffs expected.json
runners/run_edge.py                   runs the v0.2 reader over the edge corpus
runners/run_aps_v2.py                 fetches a pinned APS revision, anchor-checks it, reads all cases
runners/run_aps_v2_mutations.py       non-vacuity mutations + the r1 cross-check
results/aps-v2-r2.json                per-case output for r2 (with the file's own column alongside)
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

## Three defects this text found in this code

Re-reading section 5 of the specification after the first passing run caught two real bugs here, both
now fixed and both with fixtures upstream:

- a substituted regex mode ending in `$` accepted a timestamp with a trailing newline; `\Z` is the
  rule the text states (`ts_trailing_newline`);
- `prev_evidence_id` was treated as absent when the key itself was absent, instead of only when it
  is `null` (`prev_absent_seq0`).

A third came from the conformance-v0 differential on 2026-10-09 (freshly signed bundles, not the frozen
corpora):

- an action compared equal to itself when both sides were degenerate: `null == null` and `0 == 0` were
  read as agreement, so two bundles that the reference refuses were accepted here. Section 5 says a
  missing, `null`, `false`, `0` or `""` action fails E1 (`action_diverged`) on its own — agreement is not
  the rule, a present action is. The same fix applies to the intent's `proposed_action` (preflight) and
  to the declared-versus-executed comparison;
- `findings` was collected into a set, so a bundle that earns `self_authorized` twice (once on the grant,
  once on the intent) reported it once; the verdict signature carries one entry per occurrence.

After both fixes: 45/45 verdict signatures agree with the reference on the extended differential set (the
40 bundles the adversary generates plus five degenerate-action cases, including the boundary where
`action: {}` is an empty object and is therefore *not* degenerate), and the three frozen corpora still
reproduce at 5/5, 13/13 and 36/36.

That is the point of writing a second reader: the text is the oracle, not the first implementation.

## The `aps.agent-passport` 2.0 vectors (Agent Passport System)

A third reader, for a separate fixture family: the frozen passport vectors published by
[agent-passport-system](https://github.com/agent-passport-system/agent-passport-system). Every rule
is implemented from that family's own published legend — `layers_legend`, `domain_tags`,
`key_resolver` — and from the vector bytes. The Agent Passport System SDK is neither imported nor run
here, and no string of it is reproduced: the layer vocabulary and the outcome vocabulary are the
fixture's own. The canonicalizer is this repository's `musubi-canonical-v0`, proved against the
vectors' published preimages before any outcome is read (the runner exits 1 if that check misses).

| revision | file sha256 | this reader vs the fixture's published layers |
|---|---|---|
| r2 `e061462` | `9bd1f184…3b89` | **20/20** |
| r1 `407ca2d5` (superseded) | `9fce76db…5ac5` | 18/20 |

Both revisions are read from their published bytes at the pinned commit; neither is edited here.

The two r1 disagreements are `version-changed` and `record-type-changed`, whose published
`layers.structure` reads `rejected` in r1 and `unsupported` in r2. The passports, preimages, keys and
resolver table are byte-identical between the revisions, so this reader's own layers are identical
across them (0/20 differences): the r1→r2 move changes nothing a reader computes from the passports,
and in r2 the published column agrees with an outside reading on all twenty.

Disclosure, because it bounds what this shows: the fixture publishes the SDK's per-case output and its
own layers, so the expected outcomes were known to me before the reader was written. This is a
reproduction by an implementation written independently of the SDK — the oracle being the published
legend and the bytes — not a blind prediction.

Non-vacuity: six single-change mutations of a passing case — a stale `passport_id`, a signature from
the other key, an extra `principal_id` member, a reversed capabilities array, a timestamp without
milliseconds, and a resolver answering a different key — each move the reader on the layer the
mutation targets, 6/6 (`runners/run_aps_v2_mutations.py`; output in `results/aps-v2-mutations.txt`).

```bash
python3 runners/run_aps_v2.py                 # fetch at the pin, verify sha256, read, write results/
python3 runners/run_aps_v2_mutations.py       # non-vacuity + the r1 cross-check
```

What this does not establish: which reading is correct on the outcomes draft-04 leaves open — the
fixture records that the SDK and at least one outside reader differ on three of them. It adds one more
independently written implementation's per-case output for the same pinned bytes.

## License

MIT — see [LICENSE](LICENSE).
