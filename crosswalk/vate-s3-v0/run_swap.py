#!/usr/bin/env python3
"""NENRIN half swapped: an independently written verifier (kuangmi-bit/nenrin-independent-verifiers)
reads the three crosswalk bundles, and Poke-nushi's own pinned comparison code computes the eleven
relationships from those verdicts.

What this is: the NENRIN side of the crosswalk read by a verifier its authors did not write.
What this is not: a crosswalk rerun. The VATE side is read from the crosswalk's saved reports (the
jsonschema assessor is not re-executed here), and the comparison code is the public pinned one, imported
unchanged. The verifier's refusal wording is its own; the code values are the crosswalk's vocabulary.

    run_swap.py --example <crosswalk example dir> --repository <VATE repo checkout at the pin> \
                --verifiers <dir with nenrin_verify_v0.py> --out FILE
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

ENGINE = "kuangmi-bit-independent"
CASES = ("match", "target_mismatch", "missing_receipt")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--example", required=True)
    ap.add_argument("--repository", required=True)
    ap.add_argument("--verifiers", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    example = Path(a.example).resolve()
    repository = Path(a.repository).resolve()
    sys.path.insert(0, str(example))
    import compare_records as cr
    import crosswalk_core as c
    sys.path.insert(0, str(Path(a.verifiers).resolve()))
    import nenrin_verify_v0 as nv

    public = c.Reader(example, "example")
    pins, _inventory, _pins_doc = cr.verify_public_inputs(public)
    repo = c.Reader(repository, "repository")
    source_data = cr.source_bytes(repo, pins)
    bundles, submission = cr.load_bundles(public)
    vate, vate_reports, _vate_records, policy, _vate_manifest, vate_mode = cr.load_vate(
        public, pins, cr.original_case(source_data, pins), source_data, fresh=False)

    provenance = c.json_object(public.document("PROVENANCE.json"))
    reported_pins = {"nenrin_commit": provenance.get("nenrin_commit") or provenance.get("nenrin", {}).get("commit"),
                     "vate_commit": provenance.get("vate_commit") or provenance.get("vate", {}).get("commit")}

    tmp = Path(tempfile.mkdtemp(prefix="swap-"))
    docs, sigs = {}, {}
    for case in CASES:
        bundle = bundles[case]
        rep = nv.verify(bundle.value)
        sigs[case] = rep.signature()
        refusals = []
        for code in sorted(rep.refusals):
            why = next((r.split(":", 1)[1].strip() for r in rep.reasons if r.startswith(code + ":")), "")
            refusals.append({"code": code, "reason": why, "why": why})
        report = {
            "schema": "nenrin-provenance-verify-v0",
            "verifier_version": "independent-kuangmi-bit (from VERIFIER.md)",
            "task_id": bundle.value["task_id"],
            "verdict": sigs[case]["verdict"],
            "refusals": refusals,
            "findings": [{"code": f} for f in sorted(rep.findings)],
            "signers": {"caller_id": bundle.value["grant"]["caller_id"],
                        "provider_id": bundle.value["grant"]["provider_id"]},
            "note": "this verifier's own report; refusal 'reason' carries its own wording, "
                    "which is not the reference implementation's vocabulary",
        }
        raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        d = tmp / case
        d.mkdir()
        (d / "report.json").write_bytes(raw)
        docs[case] = c.Document(f"independent_local_run/{case}/report.json", raw,
                                collection="independent_local_run")

    cases = []
    for ncase, vcase in c.CASES.items():
        rows = c.relationship_rows(bundles[ncase], vate[vcase], policy, submission, {ENGINE: docs[ncase]})
        vate_value = vate_reports[vcase].value
        # CW-11: the record bindings. build_report() appends this after relationship_rows(); do the same,
        # with this run's own binding in place of the pinned npm/PyPI bindings.
        components = [{"name": ENGINE + "_record_binding", "status": "matched", "evidence_mode": "fresh_local_run",
                       "record": docs[ncase].ref(), "sources": [bundles[ncase].ref(), docs[ncase].ref()]},
                      {"name": "vate_record_binding", "status": "matched", "evidence_mode": vate_mode,
                       "record": vate_reports[vcase].ref(), "sources": [vate_reports[vcase].ref()]}]
        rows.append(c.row(11, "saved/publication or local replay record bindings", components,
                          "Fresh row binds a separate local replay record from an independent verifier. "
                          "Comparison runs no checker; neither record type is a signed execution attestation."))
        cases.append({
            "nenrin_case": ncase,
            "vate_case": vcase,
            "evidence_modes": {"nenrin": "fresh_local_run", "vate": vate_mode},
            "relationships": rows,
            "native_reports": {ENGINE: {"report": json.loads((tmp / ncase / "report.json").read_text()),
                                        "artifact": docs[ncase].ref()}},
            "vate_report": {"report": {k: vate_value.get(k)
                                       for k in ("assessment", "retry_authorized", "record_linkage")},
                            "artifact": vate_reports[vcase].ref()},
        })

    report = {
        "schema": "nenrin-vate-public-crosswalk-v1",
        "cases": cases,
        "pins": reported_pins,
        "evidence_modes": {"nenrin": "fresh_local_run", "vate": vate_mode},
        "scope": "three fixed crosswalk cases with the NENRIN half read by an independent verifier; "
                 "VATE side taken from the crosswalk's saved reports",
    }
    Path(a.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("wrote", a.out)
    for case in CASES:
        print(" ", case, json.dumps(sigs[case], sort_keys=True))


if __name__ == "__main__":
    main()
