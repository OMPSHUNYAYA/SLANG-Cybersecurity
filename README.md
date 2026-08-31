# SLANG-Cybersecurity

## Parameter-free structural attack-chronology ranking

![Version](https://img.shields.io/badge/Version-v1.0.0-blue)
![Core](https://img.shields.io/badge/Core-Python%20standard%20library-blueviolet)
![Self-tests](https://img.shields.io/badge/Bundled%20Self--Tests-51%2F51%20PASS-brightgreen)
![Integrity](https://img.shields.io/badge/Ledger%20%26%20Artifact%20Integrity-24%2F24%20PASS-brightgreen)
![OpTC](https://img.shields.io/badge/OpTC-AUC%200.86835-brightgreen)
![E3](https://img.shields.io/badge/E3%20replication-NOT%20CONFIRMED-orange)
![Independent reproduction](https://img.shields.io/badge/Independent%20Third--Party%20Reproduction-OPEN%20%2F%20NOT%20YET-orange)
![Shunyaya](https://img.shields.io/badge/Part%20of-Shunyaya%20Framework-gold)

[![Verify](https://github.com/OMPSHUNYAYA/SLANG-Cybersecurity/actions/workflows/verify.yml/badge.svg?branch=main)](https://github.com/OMPSHUNYAYA/SLANG-Cybersecurity/actions/workflows/verify.yml)

---

**What the check badges mean**

- **Bundled Self-Tests 51/51 PASS** — synthetic and structural checks across the reference score, both reproduction programs, the comparative audit, and the concept demonstration.
- **Ledger & Artifact Integrity 24/24 PASS** — the scientific ledger, declared status fields, claim boundaries, and selected key scientific/code artifact hashes are internally consistent.
- **Verify workflow** — runs the bundled self-tests and integrity verifier on GitHub Actions without requiring the third-party source PDFs.
- **These checks are software/package-integrity checks. They are not independent scientific reproduction of the OpTC or DARPA TC E3 results.**

---

## What this is

SLANG-Cybersecurity studies whether prior attack-event chronology contains a bounded near-term ranking signal that can be represented without fitted coefficients.

The structural chronology score is:

```text
A(t) = (t - t_prev) * N_prior / (t - t_first)
Q(t) = 1 / (1 + A(t))
```

where:

- `t_first` is the first admitted attack event observed at or before the anchor;
- `t_prev` is the most recent admitted attack event observed at or before the anchor;
- `N_prior` is the number of admitted attack events observed at or before the anchor.

Higher `Q` is the declared near-term ranking orientation.

`Q` is dimensionless and uses zero fitted coefficients.

The project contribution is not a claim that attack burstiness or event recency is new. The contribution is a frozen, inspectable chronology score; a bounded blind-transfer result on one untouched red-team environment; an unchanged-score non-replication on a second environment; and a reproducible post-result audit against simpler chronology baselines.

See [Scientific Status](./SCIENTIFIC_STATUS.txt) and [Claim Boundaries](./CLAIM_BOUNDARIES.txt) for the exact scope.

---

## Structural flow

[![SLANG-Cybersecurity structural flow](https://raw.githubusercontent.com/OMPSHUNYAYA/SLANG-Cybersecurity/main/SLANG-Cybersecurity-Diagram.png)](https://github.com/OMPSHUNYAYA/SLANG-Cybersecurity/blob/main/SLANG-Cybersecurity-Diagram.png)

*Prior cyber attack chronology -> parameter-free structural score -> frozen bounded prediction test -> reproducible evidence.*

🔎 [**View full-size diagram**](https://github.com/OMPSHUNYAYA/SLANG-Cybersecurity/blob/main/SLANG-Cybersecurity-Diagram.png)

---

## Status at a glance

Current classification:

`BOUNDED_PARAMETER_FREE_ATTACK_CHRONOLOGY_PREDICTIVE_TRANSFER_RESULT`

The strongest positive result is the frozen OpTC test. The same score was later carried unchanged into DARPA Transparent Computing Engagement 3 (E3), where it did not satisfy the frozen replication criteria.

| Environment | Eligible anchors | Positives | ROC AUC | Half AUCs | Informative blocks | Exact one-sided sign-flip | Result |
|---|---:|---:|---:|---:|---:|---:|---|
| OpTC | 242 | 33 | **0.86835** | **0.88875 / 0.82540** | 8 | **1/256 = 0.00390625** | Bounded transfer confirmed |
| DARPA TC E3 | 708 | 19 | 0.74685 | 0.49006 / 0.64636 | 7 | 0.40625 | Unchanged-score replication not confirmed |

For OpTC, all **8 of 8 informative chronological block effects favored `Q`**. The predeclared exhaustive one-sided sign-flip test therefore reached its minimum attainable value for eight informative blocks: `1/256 = 0.00390625`.

The 242 OpTC anchors determine the reported AUC. The exact block-level inference is based on the eight informative chronological blocks.

---

## Post-result comparative audit

After both primary environments had been revealed, a separate audit compared `Q` with simpler chronology baselines on the **identical eligible anchors and targets**.

This audit is explicitly post-result. It does not modify, rescue, or retroactively extend either frozen primary test.

| Environment | Q | Recency | Previous 900 s | Recent count 900 s | Historical rate | Fixed EWMA (tau=900 s) |
|---|---:|---:|---:|---:|---:|---:|
| OpTC | 0.86835 | **0.87915** | 0.79745 | 0.80593 | 0.56981 | **0.87937** |
| DARPA TC E3 | **0.74685** | 0.71457 | 0.47097 | 0.47097 | 0.49110 | 0.71301 |

Key interpretation:

- OpTC contains a strong recency-related temporal clustering signal. Pure recency and the fixed 900-second EWMA slightly outperform `Q` in overall AUC.
- In E3, `Q` exceeds pure recency by `0.03227` AUC. Six of seven paired informative blocks favor `Q`; the paired exact one-sided sign-flip value is `0.015625`.
- The E3 primary replication remains **not confirmed**. The comparative audit does not convert E3 into a positive replication.
- The normalization in `Q` is therefore not simply identical to pure recency, but its incremental predictive value is environment-dependent and is not established as a general transfer property.

The audit also reports symmetric grid-coincidence and `-60/+60` second timestamp-sensitivity diagnostics for both environments.

In OpTC, 3 eligible anchors coincide exactly with admitted event timestamps. In E3, 20 do. The E3 `+60 s` diagnostic produces AUC `1.0` because those coincident events move mechanically from causal history into the future target window; this is recorded as a timestamp-boundary artifact and is **not** used as evidence.

See [Model and Evaluation Notes](./MODEL_AND_EVALUATION_NOTES.txt) and the [Baseline and Sensitivity Audit](./04_Reproduction/SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py).

---

## Frozen prediction contract

- horizon: 900 seconds
- cadence: 900 seconds
- minimum history: at least two admitted prior events and `t > t_first`
- target: `Y(t)=1` iff at least one admitted event occurs in `(t,t+900]`
- event exactly at `t`: history, not target
- event exactly at `t+900`: target positive
- primary ranking metric: ROC AUC
- temporal partition: 18 chronological superblocks
- exact inference: exhaustive one-sided sign-flip over informative block AUC effects

Frozen primary gates:

```text
eligible anchors >= 64
positive targets >= 8
negative targets >= 16
overall AUC >= 0.75
each chronological half AUC >= 0.65
informative superblocks >= 8
exact sign-flip p <= 0.05
all informative-block LOBO overall AUC > 0.5
```

The primary tests used no post-truth refitting, recalibration, score reversal, horizon change, cadence change, threshold rescue, or feature-family rescue.

---

## What is deliberately not claimed

This repository does **not** establish:

- universal cyberattack prediction;
- calibrated probability forecasting;
- deployment readiness;
- replacement of intrusion-detection, SIEM, SOC, or endpoint-security systems;
- superiority over existing cybersecurity systems;
- repeated cross-environment replication;
- general superiority of `Q` over simple recency or fixed-scale temporal-intensity baselines;
- universal or environment-invariant predictive transfer;
- independent third-party scientific reproduction.

The current independent third-party reproduction status is:

`OPEN / NOT YET CONFIRMED`

See the complete [Claim Boundaries](./CLAIM_BOUNDARIES.txt).

---

## Repository map

- [`01_Reference_Implementation/`](./01_Reference_Implementation/) — dependency-free structural chronology score
- [`02_Frozen_Evidence/`](./02_Frozen_Evidence/) — machine-readable scientific evidence ledger and compact evidence summary
- [`03_Verification/`](./03_Verification/) — ledger consistency and selected key-artifact integrity verification
- [`04_Reproduction/`](./04_Reproduction/) — OpTC/E3 result reproduction and post-result comparative audit
- [`05_Concept_Demonstration/`](./05_Concept_Demonstration/) — separate structural escalation demonstration
- [`.github/workflows/verify.yml`](./.github/workflows/verify.yml) — data-independent GitHub Actions verification workflow

## Active files

### Reference implementation

- [`SLANG_Cybersecurity_Structural_Chronology_Score_v1_0_0.py`](./01_Reference_Implementation/SLANG_Cybersecurity_Structural_Chronology_Score_v1_0_0.py) — parameter-free reference score
- [`01_Reference_Implementation/README.txt`](./01_Reference_Implementation/README.txt) — reference implementation notes

### Frozen evidence

- [`SLANG_Cybersecurity_Evidence_Ledger_v1_0_0.json`](./02_Frozen_Evidence/SLANG_Cybersecurity_Evidence_Ledger_v1_0_0.json) — machine-readable project evidence ledger
- [`EVIDENCE_SUMMARY.txt`](./02_Frozen_Evidence/EVIDENCE_SUMMARY.txt) — compact scientific evidence summary

### Verification

- [`SLANG_Cybersecurity_Evidence_Verifier_v1_0_0.py`](./03_Verification/SLANG_Cybersecurity_Evidence_Verifier_v1_0_0.py) — **ledger and selected-artifact integrity only**
- [`SCIENTIFIC_ARTIFACT_SHA256SUMS_v1_0_0.txt`](./03_Verification/SCIENTIFIC_ARTIFACT_SHA256SUMS_v1_0_0.txt) — selected key scientific/code artifact SHA-256 manifest
- [`VERIFICATION_RESULT.txt`](./03_Verification/VERIFICATION_RESULT.txt) — packaged verification record

Editable documentation and licensing files are deliberately outside the selected-artifact hash manifest.

### Reproduction and comparative audit

- [`SLANG_Cybersecurity_OpTC_Result_Reproduction_v1_0_0.py`](./04_Reproduction/SLANG_Cybersecurity_OpTC_Result_Reproduction_v1_0_0.py) — OpTC source-dependent result reproduction
- [`SLANG_Cybersecurity_DARPA_TC_E3_Result_Reproduction_v1_0_0.py`](./04_Reproduction/SLANG_Cybersecurity_DARPA_TC_E3_Result_Reproduction_v1_0_0.py) — DARPA TC E3 source-dependent result reproduction
- [`SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py`](./04_Reproduction/SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py) — post-result baseline and timestamp-sensitivity audit
- [`04_Reproduction/README.txt`](./04_Reproduction/README.txt) — reproduction commands and scope

### Concept demonstration

- [`SLANG_Cybersecurity_Structural_Escalation_Kernel_v1_0_0.py`](./05_Concept_Demonstration/SLANG_Cybersecurity_Structural_Escalation_Kernel_v1_0_0.py) — separate structural escalation concept demonstration
- [`05_Concept_Demonstration/README.txt`](./05_Concept_Demonstration/README.txt) — demonstration scope

### Scientific and rights notes

- [`SCIENTIFIC_STATUS.txt`](./SCIENTIFIC_STATUS.txt) — current bounded scientific status
- [`CLAIM_BOUNDARIES.txt`](./CLAIM_BOUNDARIES.txt) — supported and unsupported claims
- [`REPRODUCIBILITY_SCOPE.txt`](./REPRODUCIBILITY_SCOPE.txt) — what can and cannot be reproduced from the repository alone
- [`SCIENTIFIC_CHAIN.txt`](./SCIENTIFIC_CHAIN.txt) — compact chronology of the scientific result
- [`MODEL_AND_EVALUATION_NOTES.txt`](./MODEL_AND_EVALUATION_NOTES.txt) — score decomposition, evaluation, baselines, and timestamp notes
- [`SOURCE_DATA_GUIDE.txt`](./SOURCE_DATA_GUIDE.txt) — separately obtained source-input guidance
- [`THIRD_PARTY_NOTICES.txt`](./THIRD_PARTY_NOTICES.txt) — third-party source and rights notices
- [`COPYRIGHT_NOTICE.txt`](./COPYRIGHT_NOTICE.txt) — project copyright notice
- [`LICENSE`](./LICENSE) — project license map
- [`requirements.txt`](./requirements.txt) — source-reproduction dependency declaration

---

## Quick verification

From the repository root:

```text
python -B 01_Reference_Implementation/SLANG_Cybersecurity_Structural_Chronology_Score_v1_0_0.py --self-test
python -B 03_Verification/SLANG_Cybersecurity_Evidence_Verifier_v1_0_0.py --verify
python -B 04_Reproduction/SLANG_Cybersecurity_OpTC_Result_Reproduction_v1_0_0.py --self-test
python -B 04_Reproduction/SLANG_Cybersecurity_DARPA_TC_E3_Result_Reproduction_v1_0_0.py --self-test
python -B 04_Reproduction/SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py --self-test
python -B 05_Concept_Demonstration/SLANG_Cybersecurity_Structural_Escalation_Kernel_v1_0_0.py --self-test
```

Packaged results:

```text
Structural Chronology Score       12/12 PASS
Evidence & Artifact Integrity     24/24 PASS
OpTC Reproduction                 12/12 PASS
DARPA TC E3 Reproduction          11/11 PASS
Baseline & Sensitivity Audit      10/10 PASS
Structural Escalation Kernel       6/6 PASS
```

The same data-independent checks are defined in the [Verify workflow](./.github/workflows/verify.yml).

**None of these data-independent checks reproduces the source-dependent OpTC or E3 headline metrics.**

---

## Source-dependent reproduction

The repository does not redistribute the third-party source PDFs or bulk source datasets.

Install the declared reproduction dependency:

```text
python -m pip install -r requirements.txt
```

Obtain the identified source PDFs separately as described in the [Source Data Guide](./SOURCE_DATA_GUIDE.txt).

Reproduce OpTC:

```text
python -B 04_Reproduction/SLANG_Cybersecurity_OpTC_Result_Reproduction_v1_0_0.py --reproduce --pdf "<path-to>/OpTCRedTeamGroundTruth.pdf"
```

Reproduce DARPA TC E3:

```text
python -B 04_Reproduction/SLANG_Cybersecurity_DARPA_TC_E3_Result_Reproduction_v1_0_0.py --reproduce --pdf "<path-to>/TC_Ground_Truth_Report_E3_Update.pdf"
```

Run the OpTC comparative audit:

```text
python -B 04_Reproduction/SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py --audit --module 04_Reproduction/SLANG_Cybersecurity_OpTC_Result_Reproduction_v1_0_0.py --pdf "<path-to>/OpTCRedTeamGroundTruth.pdf" --half-split 121
```

Run the E3 comparative audit:

```text
python -B 04_Reproduction/SLANG_Cybersecurity_Baseline_and_Sensitivity_Audit_v1_0_0.py --audit --module 04_Reproduction/SLANG_Cybersecurity_DARPA_TC_E3_Result_Reproduction_v1_0_0.py --pdf "<path-to>/TC_Ground_Truth_Report_E3_Update.pdf" --half-split 354
```

The reproduction and audit programs verify the declared source identity before calculation.

Reproducing the revealed historical results does not recreate the original blind chronology. See [Reproducibility Scope](./REPRODUCIBILITY_SCOPE.txt).

---

## Source and rights boundary

No complete third-party source PDF or bulk source dataset is distributed by this repository.

The repository contains project-authored code, project-derived numerical evidence, source identifiers, cryptographic identities, minimal factual provenance, and rights notices needed for reproducibility.

Third-party materials remain subject to their respective rights and terms and are not relicensed by SLANG-Cybersecurity.

See the [Source Data Guide](./SOURCE_DATA_GUIDE.txt) and [Third-Party Notices](./THIRD_PARTY_NOTICES.txt).

---

## License

- Project-authored software and verification code: **[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)**
- Project-authored documentation: **[CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/)**
- Third-party materials remain subject to their respective terms.

See [`LICENSE`](./LICENSE), [`COPYRIGHT_NOTICE.txt`](./COPYRIGHT_NOTICE.txt), and [`THIRD_PARTY_NOTICES.txt`](./THIRD_PARTY_NOTICES.txt).

---

## Summary

SLANG-Cybersecurity v1.0.0 reports a **bounded parameter-free attack-chronology predictive-transfer result**.

The frozen structural chronology score reached **ROC AUC 0.86835** on the untouched OpTC red-team environment, with both chronological halves above the declared gate and all **8 of 8 informative chronological blocks** favoring the score (`p = 1/256` under the predeclared exact one-sided sign-flip test).

An unchanged-score replication on DARPA TC E3 did **not** satisfy the frozen replication criteria and is reported as a non-confirmation rather than tuned or rescued.

A separate post-result comparative audit shows that simple recency slightly outperforms `Q` on OpTC, while `Q` outperforms recency on E3. The incremental value of the normalization is therefore environment-dependent and is **not** claimed as a general property.

Universal cyberattack prediction, calibrated probability forecasting, deployment readiness, repeated cross-environment replication, and independent third-party reproduction remain **not established**.

*Part of the Shunyaya Framework.*
