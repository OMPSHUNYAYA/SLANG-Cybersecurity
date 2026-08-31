SLANG-CYBERSECURITY — EMPIRICAL REPRODUCTION AND COMPARATIVE AUDIT v1.0.0

Programs
--------
SLANG_Cybersecurity_OpTC_Result_Reproduction_v1_0_0.py
SLANG_Cybersecurity_DARPA_TC_E3_Result_Reproduction_v1_0_0.py
SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py

Dependency
----------
python -m pip install pypdf==6.16.2

Self-tests
----------
python -B SLANG_Cybersecurity_OpTC_Result_Reproduction_v1_0_0.py --self-test
python -B SLANG_Cybersecurity_DARPA_TC_E3_Result_Reproduction_v1_0_0.py --self-test
python -B SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py --self-test

Primary-result reproduction
---------------------------
python -B SLANG_Cybersecurity_OpTC_Result_Reproduction_v1_0_0.py --reproduce --pdf OpTCRedTeamGroundTruth.pdf

python -B SLANG_Cybersecurity_DARPA_TC_E3_Result_Reproduction_v1_0_0.py --reproduce --pdf TC_Ground_Truth_Report_E3_Update.pdf

Post-result baseline and sensitivity audit
------------------------------------------
python -B SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py --audit --module SLANG_Cybersecurity_OpTC_Result_Reproduction_v1_0_0.py --pdf OpTCRedTeamGroundTruth.pdf --half-split 121 --json-out SLANG_Cybersecurity_OpTC_Baseline_and_Sensitivity_Result_v1_0_0.json

python -B SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py --audit --module SLANG_Cybersecurity_DARPA_TC_E3_Result_Reproduction_v1_0_0.py --pdf TC_Ground_Truth_Report_E3_Update.pdf --half-split 354 --json-out SLANG_Cybersecurity_DARPA_TC_E3_Baseline_and_Sensitivity_Result_v1_0_0.json

The programs verify expected source identities before calculation. Source PDFs
are obtained separately and are not included in this repository.

The JSON files named in the commands are generated outputs and are not required
to be retained in the repository. The comparative results used in the scientific
summary are recorded in the machine-readable evidence ledger.

The comparative audit is explicitly post-result. It does not modify the frozen
primary OpTC or E3 result paths.
