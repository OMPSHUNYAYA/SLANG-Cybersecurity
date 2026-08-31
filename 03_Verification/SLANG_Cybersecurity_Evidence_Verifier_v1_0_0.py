#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SLANG-Cybersecurity Evidence & Artifact Integrity Verifier v1.0.0.

Checks declared scientific-ledger fields and selected key scientific/code
artifact hashes. Editable documentation and licensing files are deliberately
outside the hash scope.

This verifier is an integrity check. It is not independent scientific
validation and does not prove historical pre-reveal chronology.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED_HASHES = {
    "01_Reference_Implementation/SLANG_Cybersecurity_Structural_Chronology_Score_v1_0_0.py": "0056b4a80bf3129448b141c575082aad5c145d4d4a28edbb117fffcb1c88c151",
    "02_Frozen_Evidence/SLANG_Cybersecurity_Evidence_Ledger_v1_0_0.json": "5e2ab8e968706e80cc293bb282fc0dcf5328d4cf428e2a148e7e6821466420b6",
    "04_Reproduction/SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py": "e5e91ccef0c27b5154e5629c8ce717bf633ecf0c69296ab0942f997c35d0b025",
    "04_Reproduction/SLANG_Cybersecurity_DARPA_TC_E3_Result_Reproduction_v1_0_0.py": "d55b91cd23d20a59f589d3d33b07e9644b8b495ab90b2fa03b43879f1f4d23d5",
    "04_Reproduction/SLANG_Cybersecurity_OpTC_Result_Reproduction_v1_0_0.py": "f73828023c853bce575197cc26d04c979603c6bf4bcf1f04cceddfec7d10a3c6"
}


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify():
    here = Path(__file__).resolve().parent
    root = here.parent
    ledger_path = root / "02_Frozen_Evidence" / "SLANG_Cybersecurity_Evidence_Ledger_v1_0_0.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))

    evidence = ledger["evidence"]
    claims = ledger["claim_boundary"]
    rights = ledger["rights_boundary"]
    audit = ledger["post_result_comparative_audit"]

    checks = {
        "scientific_status_recorded": ledger["scientific_status"] == "BOUNDED_PARAMETER_FREE_ATTACK_CHRONOLOGY_PREDICTIVE_TRANSFER_RESULT",
        "parameter_free_score": ledger["core_score"]["fitted_coefficients"] == 0,
        "optc_transfer_pass": evidence["optc"]["primary_transfer_pass"] is True,
        "optc_auc_recorded": abs(evidence["optc"]["roc_auc"] - 0.8683485573437727) < 1e-15,
        "optc_exact_p_recorded": evidence["optc"]["exact_one_sided_signflip_p"] == 0.00390625,
        "e3_replication_not_confirmed": evidence["darpa_tc_e3"]["unchanged_q_replication_pass"] is False,
        "e3_auc_recorded": abs(evidence["darpa_tc_e3"]["roc_auc"] - 0.7468489802154151) < 1e-15,
        "e3_exact_p_recorded": evidence["darpa_tc_e3"]["exact_one_sided_signflip_p"] == 0.40625,
        "comparative_audit_is_post_result": audit["primary_frozen_results_modified"] is False,
        "optc_recency_auc_recorded": abs(audit["optc"]["parameter_free_scores"]["recency"]["auc"] - 0.87915036) < 1e-12,
        "optc_q_not_superior_to_recency": audit["summary"]["optc_q_vs_recency_auc_delta"] < 0.0,
        "e3_q_exceeds_recency_auc": audit["summary"]["e3_q_vs_recency_auc_delta"] > 0.0,
        "e3_q_vs_recency_paired_p_recorded": audit["summary"]["e3_q_vs_recency_paired_block_p"] == 0.015625,
        "no_universal_claim": claims["universal_cyberattack_prediction_claimed"] is False,
        "no_probability_claim": claims["probability_forecasting_claimed"] is False,
        "no_deployment_claim": claims["deployment_readiness_claimed"] is False,
        "no_repeated_replication_claim": claims["repeated_cross_environment_replication_established"] is False,
        "independent_reproduction_open": claims["independent_third_party_reproduction_complete"] is False,
        "no_complete_third_party_objects": rights["complete_third_party_objects_embedded"] is False,
        "no_bulk_third_party_datasets": rights["bulk_third_party_datasets_embedded"] is False,
        "no_substantial_source_text": rights["substantial_third_party_source_text_embedded"] is False,
        "third_party_terms_not_overridden": rights["third_party_terms_overridden"] is False,
        "no_pdf_source_objects_present": not any(root.rglob("*.pdf")),
    }

    artifact_checks = []
    for rel, expected in EXPECTED_HASHES.items():
        path = root / rel
        ok = path.is_file() and sha256(path) == expected
        artifact_checks.append((rel, ok))
    checks["selected_scientific_artifact_integrity"] = all(ok for _, ok in artifact_checks)

    print("SLANG-Cybersecurity Evidence & Artifact Integrity Verifier v1.0.0")
    print("scope:scientific-ledger consistency + selected key-artifact integrity")
    print("editable_documentation_hashed:false")
    print("scientific_validation:false")
    print("independent_third_party_reproduction:false")
    for name, ok in checks.items():
        print("%s:%s" % (name, "PASS" if ok else "FAIL"))
    for rel, ok in artifact_checks:
        print("artifact:%s:%s" % (rel, "PASS" if ok else "FAIL"))
    passed = sum(bool(v) for v in checks.values())
    print("checks:%d/%d %s" % (passed, len(checks), "PASS" if all(checks.values()) else "FAIL"))
    print("current_scientific_status:" + ledger["scientific_status"])
    print("independent_third_party_reproduction:OPEN_NOT_YET_CONFIRMED")
    return 0 if all(checks.values()) else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true", required=True)
    parser.parse_args()
    raise SystemExit(verify())


if __name__ == "__main__":
    main()
