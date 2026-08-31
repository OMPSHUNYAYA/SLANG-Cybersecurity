#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SLANG-Cybersecurity Baseline and Sensitivity Audit v1.0.0.

Performs a post-result comparative audit on the identical chronology, eligible
anchors, target definition, AUC estimator, chronological superblocks, and exact
one-sided sign-flip procedure used by an identified SLANG-Cybersecurity
reproduction module.

The audit is descriptive. It does not modify, replace, or retroactively extend
the frozen primary OpTC or DARPA TC E3 tests.

Primary parameter-free comparisons:
  Q                  1 / (1 + lag * N_prior / elapsed)
  recency            1 / (1 + lag)
  previous_900s      1 if at least one prior event is in [t-900, t], else 0
  recent_count_900s  number of prior events in [t-900, t]
  historical_rate    N_prior / elapsed

A fixed-scale EWMA comparator is reported separately:
  ewma_horizon       sum_i exp(-(t - t_i) / 900)

The EWMA decay scale is fixed to the already-declared 900-second prediction
horizon. No parameter search or fitting is performed.

Third-party source files are not distributed by this program.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import importlib.util
import json
import math
import os
import sys

HORIZON_SECONDS = 900
REQUIRED_MODULE_FUNCTIONS = (
    "extract_plain",
    "parse_events",
    "event_hash",
    "feature_rows",
    "target",
    "auc",
    "blocks",
    "signflip",
)
REQUIRED_MODULE_CONSTANTS = (
    "EXPECTED_PDF_SHA",
    "EXPECTED_PDF_BYTES",
    "EXPECTED_PAGES",
    "EXPECTED_TEXT_SHA",
    "EXPECTED_EVENT_HASH",
)


def load_module(path):
    name = os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load reproduction module: %s" % path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)

    for item in REQUIRED_MODULE_FUNCTIONS:
        if not hasattr(mod, item):
            raise RuntimeError("reproduction module does not expose %s" % item)
    for item in REQUIRED_MODULE_CONSTANTS:
        if not hasattr(mod, item):
            raise RuntimeError("reproduction module does not expose %s" % item)
    return mod


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def verify_source_identity(mod, pdf_path):
    if sha256_file(pdf_path) != mod.EXPECTED_PDF_SHA:
        raise ValueError("source PDF SHA256 mismatch")
    if os.path.getsize(pdf_path) != mod.EXPECTED_PDF_BYTES:
        raise ValueError("source PDF byte-count mismatch")

    reader, text = mod.extract_plain(pdf_path)
    if len(reader.pages) != mod.EXPECTED_PAGES:
        raise ValueError("source PDF page-count mismatch")
    if sha256_text(text) != mod.EXPECTED_TEXT_SHA:
        raise ValueError("extracted-text SHA256 mismatch")

    events = mod.parse_events(text)
    if mod.event_hash(events) != mod.EXPECTED_EVENT_HASH:
        raise ValueError("canonical-event SHA256 mismatch")

    return events


def build_rows(mod, events):
    rows = mod.feature_rows(events)
    times = [event["t"] for event in events]
    if not rows or not times:
        raise ValueError("empty chronology or eligible-anchor set")

    first = times[0]
    labels = [
        mod.target(row["anchor_epoch_second_utc_surrogate"], times)
        for row in rows
    ]

    for row in rows:
        anchor = row["anchor_epoch_second_utc_surrogate"]
        n_prior = bisect.bisect_right(times, anchor)
        if n_prior < 1:
            raise ValueError("eligible anchor has no prior event")

        previous = times[n_prior - 1]
        lag = anchor - previous
        elapsed = anchor - first
        left = bisect.bisect_left(times, anchor - HORIZON_SECONDS)
        recent_count = n_prior - left

        row["_lag"] = lag
        row["_elapsed"] = elapsed
        row["_n_prior"] = n_prior
        row["score_Q"] = row["risk_score_Q"]
        row["score_recency"] = 1.0 / (1.0 + lag)
        row["score_previous_900s"] = 1.0 if recent_count > 0 else 0.0
        row["score_recent_count_900s"] = float(recent_count)
        row["score_historical_rate"] = (
            n_prior / elapsed if elapsed > 0 else 0.0
        )

        hi = n_prior
        ewma = 0.0
        for i in range(hi):
            ewma += math.exp(
                -(anchor - times[i]) / float(HORIZON_SECONDS)
            )
        row["score_ewma_horizon"] = ewma

    return rows, labels, times


def rows_with_score(rows, score_key):
    return [
        {
            "risk_score_Q": row[score_key],
            "exact_superblock_id": row["exact_superblock_id"],
        }
        for row in rows
    ]


def evaluate(mod, rows, labels, score_key, half_split):
    scores = [row[score_key] for row in rows]
    overall = mod.auc(labels, scores)
    half_1 = mod.auc(labels[:half_split], scores[:half_split])
    half_2 = mod.auc(labels[half_split:], scores[half_split:])
    diagnostics, ids, effects = mod.blocks(
        rows_with_score(rows, score_key),
        labels,
    )
    p_value, assignments = mod.signflip(effects)
    positive_block_effects = sum(
        1 for effect in effects if effect > 0.0
    )
    negative_block_effects = sum(
        1 for effect in effects if effect < 0.0
    )
    zero_block_effects = sum(
        1 for effect in effects if effect == 0.0
    )
    return {
        "auc": overall,
        "half_1_auc": half_1,
        "half_2_auc": half_2,
        "informative_blocks": len(ids),
        "informative_block_ids": ids,
        "positive_block_effects": positive_block_effects,
        "negative_block_effects": negative_block_effects,
        "zero_block_effects": zero_block_effects,
        "exact_one_sided_signflip_p": p_value,
        "exact_signflip_assignments": assignments,
        "block_diagnostics": diagnostics,
        "block_effects": effects,
    }


def paired_block_signflip(mod, rows, labels, key_a, key_b):
    diag_a, _, _ = mod.blocks(rows_with_score(rows, key_a), labels)
    diag_b, _, _ = mod.blocks(rows_with_score(rows, key_b), labels)

    differences = []
    for a, b in zip(diag_a, diag_b):
        if a["auc"] is not None and b["auc"] is not None:
            differences.append(a["auc"] - b["auc"])

    p_value, assignments = mod.signflip(differences)
    return {
        "informative_blocks": len(differences),
        "exact_one_sided_signflip_p": p_value,
        "exact_signflip_assignments": assignments,
        "positive_block_differences": sum(
            1 for value in differences if value > 0.0
        ),
        "negative_block_differences": sum(
            1 for value in differences if value < 0.0
        ),
        "zero_block_differences": sum(
            1 for value in differences if value == 0.0
        ),
    }


def rank_concordance(a, b):
    concordant = 0
    discordant = 0

    for i in range(len(a)):
        for j in range(i + 1, len(a)):
            da = a[i] - a[j]
            db = b[i] - b[j]
            if da == 0.0 or db == 0.0:
                continue
            if (da > 0.0) == (db > 0.0):
                concordant += 1
            else:
                discordant += 1

    total = concordant + discordant
    return concordant / total if total else None


def grid_sensitivity(mod, rows, labels, times):
    scores = [row["score_Q"] for row in rows]
    event_set = set(times)
    coincident_rows = [
        row
        for row in rows
        if row["anchor_epoch_second_utc_surrogate"] in event_set
    ]

    official_positive = sum(
        mod.target(
            row["anchor_epoch_second_utc_surrogate"],
            times,
            0,
        )
        for row in coincident_rows
    )
    minus_60_labels = [
        mod.target(
            row["anchor_epoch_second_utc_surrogate"],
            times,
            -60,
        )
        for row in rows
    ]
    plus_60_labels = [
        mod.target(
            row["anchor_epoch_second_utc_surrogate"],
            times,
            60,
        )
        for row in rows
    ]
    plus_60_coincident_positive = sum(
        mod.target(
            row["anchor_epoch_second_utc_surrogate"],
            times,
            60,
        )
        for row in coincident_rows
    )

    return {
        "grid_coincident_anchor_count": len(coincident_rows),
        "grid_coincident_Q_equal_1_count": sum(
            1
            for row in coincident_rows
            if math.isclose(
                row["score_Q"],
                1.0,
                rel_tol=0.0,
                abs_tol=1e-15,
            )
        ),
        "official_positive_targets_among_coincident_anchors": official_positive,
        "plus_60_positive_targets_among_coincident_anchors": (
            plus_60_coincident_positive
        ),
        "official_auc_Q": mod.auc(labels, scores),
        "minus_60_seconds_auc_Q": mod.auc(minus_60_labels, scores),
        "plus_60_seconds_auc_Q": mod.auc(plus_60_labels, scores),
        "jitter_is_diagnostic_only": True,
    }


def audit(mod, events, half_split):
    rows, labels, times = build_rows(mod, events)

    if half_split <= 0 or half_split >= len(rows):
        raise ValueError("half split must divide the eligible-anchor sequence")

    scorer_keys = [
        ("Q", "score_Q"),
        ("recency", "score_recency"),
        ("previous_900s", "score_previous_900s"),
        ("recent_count_900s", "score_recent_count_900s"),
        ("historical_rate", "score_historical_rate"),
    ]

    results = {}
    for name, key in scorer_keys:
        results[name] = evaluate(
            mod,
            rows,
            labels,
            key,
            half_split,
        )

    fixed_scale = evaluate(
        mod,
        rows,
        labels,
        "score_ewma_horizon",
        half_split,
    )

    q_auc = results["Q"]["auc"]
    parameter_free_comparisons = {}
    for name, key in scorer_keys[1:]:
        parameter_free_comparisons[name] = {
            "delta_auc_Q_minus_baseline": (
                None
                if q_auc is None or results[name]["auc"] is None
                else q_auc - results[name]["auc"]
            ),
            "paired_block_test_Q_minus_baseline": paired_block_signflip(
                mod,
                rows,
                labels,
                "score_Q",
                key,
            ),
            "ranking_concordance_with_Q": rank_concordance(
                [row["score_Q"] for row in rows],
                [row[key] for row in rows],
            ),
        }

    return {
        "post_result_audit": True,
        "primary_frozen_result_modified": False,
        "eligible_anchors": len(rows),
        "positive_targets": sum(labels),
        "negative_targets": len(labels) - sum(labels),
        "half_split": half_split,
        "prediction_horizon_seconds": HORIZON_SECONDS,
        "parameter_free_scorers": results,
        "parameter_free_comparisons": parameter_free_comparisons,
        "fixed_scale_ewma_horizon": {
            "tau_seconds": HORIZON_SECONDS,
            "parameter_search_used": False,
            "result": fixed_scale,
            "delta_auc_Q_minus_ewma": (
                None
                if q_auc is None or fixed_scale["auc"] is None
                else q_auc - fixed_scale["auc"]
            ),
        },
        "grid_and_timestamp_sensitivity": grid_sensitivity(
            mod,
            rows,
            labels,
            times,
        ),
    }


def fmt(value):
    if value is None:
        return "n/a"
    return "%.8f" % value


def print_audit(result):
    print("SLANG-Cybersecurity Baseline and Sensitivity Audit v1.0.0")
    print("post_result_audit:true")
    print("primary_frozen_result_modified:false")
    print("eligible_anchors:%d" % result["eligible_anchors"])
    print(
        "target_balance:%d/%d"
        % (
            result["positive_targets"],
            result["negative_targets"],
        )
    )
    print("half_split:%d" % result["half_split"])
    print("prediction_horizon_seconds:%d" % HORIZON_SECONDS)

    print("")
    print("parameter_free_scores:")
    q_auc = result["parameter_free_scorers"]["Q"]["auc"]
    for name in (
        "Q",
        "recency",
        "previous_900s",
        "recent_count_900s",
        "historical_rate",
    ):
        row = result["parameter_free_scorers"][name]
        delta = (
            None if row["auc"] is None or q_auc is None
            else row["auc"] - q_auc
        )
        print(
            "%s:auc=%s half1=%s half2=%s informative_blocks=%d "
            "positive_block_effects=%d exact_p=%s delta_auc_vs_Q=%s"
            % (
                name,
                fmt(row["auc"]),
                fmt(row["half_1_auc"]),
                fmt(row["half_2_auc"]),
                row["informative_blocks"],
                row["positive_block_effects"],
                fmt(row["exact_one_sided_signflip_p"]),
                fmt(delta),
            )
        )

    print("")
    print("paired_parameter_free_comparisons:")
    for name in (
        "recency",
        "previous_900s",
        "recent_count_900s",
        "historical_rate",
    ):
        row = result["parameter_free_comparisons"][name]
        paired = row["paired_block_test_Q_minus_baseline"]
        print(
            "Q_vs_%s:delta_auc_Q_minus_baseline=%s "
            "ranking_concordance=%s paired_blocks=%d "
            "positive_block_differences=%d exact_p=%s"
            % (
                name,
                fmt(row["delta_auc_Q_minus_baseline"]),
                fmt(row["ranking_concordance_with_Q"]),
                paired["informative_blocks"],
                paired["positive_block_differences"],
                fmt(paired["exact_one_sided_signflip_p"]),
            )
        )

    ewma = result["fixed_scale_ewma_horizon"]
    ewma_result = ewma["result"]
    print("")
    print(
        "fixed_scale_ewma_horizon:tau_seconds=%d parameter_search_used=false "
        "auc=%s half1=%s half2=%s delta_auc_Q_minus_ewma=%s"
        % (
            ewma["tau_seconds"],
            fmt(ewma_result["auc"]),
            fmt(ewma_result["half_1_auc"]),
            fmt(ewma_result["half_2_auc"]),
            fmt(ewma["delta_auc_Q_minus_ewma"]),
        )
    )

    grid = result["grid_and_timestamp_sensitivity"]
    print("")
    print("grid_and_timestamp_sensitivity:%s" % json.dumps(
        grid,
        sort_keys=True,
        separators=(",", ":"),
    ))


def self_test():
    class SyntheticModule:
        EXPECTED_PDF_SHA = ""
        EXPECTED_PDF_BYTES = 0
        EXPECTED_PAGES = 0
        EXPECTED_TEXT_SHA = ""
        EXPECTED_EVENT_HASH = ""

        @staticmethod
        def feature_rows(events):
            times = [event["t"] for event in events]
            first = times[0]
            rows = []
            for anchor in range(first + 900, times[-1] + 7200, 900):
                n = bisect.bisect_right(times, anchor)
                if n >= 2 and anchor > first:
                    lag = anchor - times[n - 1]
                    elapsed = anchor - first
                    q = 1.0 / (1.0 + lag * n / elapsed)
                    rows.append({
                        "anchor_epoch_second_utc_surrogate": anchor,
                        "risk_score_Q": q,
                    })
            n_rows = len(rows)
            for i, row in enumerate(rows):
                row["exact_superblock_id"] = min(
                    17,
                    (18 * i) // n_rows,
                )
            return rows

        @staticmethod
        def target(anchor, times, shift=0):
            shifted = times if shift == 0 else [x + shift for x in times]
            lo = bisect.bisect_right(shifted, anchor)
            hi = bisect.bisect_right(
                shifted,
                anchor + HORIZON_SECONDS,
            )
            return 1 if hi > lo else 0

        @staticmethod
        def auc(labels, scores):
            positives = [
                float(score)
                for label, score in zip(labels, scores)
                if label == 1
            ]
            negatives = [
                float(score)
                for label, score in zip(labels, scores)
                if label == 0
            ]
            if not positives or not negatives:
                return None
            wins = 0.0
            for positive in positives:
                for negative in negatives:
                    if positive > negative:
                        wins += 1.0
                    elif positive == negative:
                        wins += 0.5
            return wins / (len(positives) * len(negatives))

        @classmethod
        def blocks(cls, rows, labels):
            diagnostics = []
            ids = []
            effects = []
            for block in range(18):
                ys = []
                scores = []
                for row, label in zip(rows, labels):
                    if row["exact_superblock_id"] == block:
                        ys.append(label)
                        scores.append(row["risk_score_Q"])
                value = cls.auc(ys, scores)
                if value is not None:
                    ids.append(block)
                    effects.append(value - 0.5)
                diagnostics.append({
                    "id": block,
                    "auc": value,
                })
            return diagnostics, ids, effects

        @staticmethod
        def signflip(effects):
            if not effects:
                return None, 0
            observed = sum(effects) / len(effects)
            total = 1 << len(effects)
            extreme = 0
            for mask in range(total):
                value = sum(
                    effect if (mask >> i) & 1 else -effect
                    for i, effect in enumerate(effects)
                ) / len(effects)
                if value >= observed - 1e-15:
                    extreme += 1
            return extreme / total, total

    times = [
        1000,
        1200,
        1500,
        6100,
        6300,
        6600,
        11200,
        11400,
        11700,
        16500,
        16800,
        17100,
        22000,
    ]
    events = [{"t": t} for t in times]
    result = audit(
        SyntheticModule,
        events,
        half_split=10,
    )

    checks = [
        result["post_result_audit"] is True,
        result["primary_frozen_result_modified"] is False,
        result["eligible_anchors"] > 10,
        result["positive_targets"] > 0,
        "recency" in result["parameter_free_scorers"],
        "recent_count_900s" in result["parameter_free_scorers"],
        result["fixed_scale_ewma_horizon"]["tau_seconds"] == 900,
        result["fixed_scale_ewma_horizon"]["parameter_search_used"] is False,
        0.0 <= result["parameter_free_comparisons"]["recency"][
            "ranking_concordance_with_Q"
        ] <= 1.0,
        result["grid_and_timestamp_sensitivity"][
            "jitter_is_diagnostic_only"
        ] is True,
    ]

    print("SLANG-Cybersecurity Baseline and Sensitivity Audit v1.0.0 self-test")
    print("TOTAL %d/%d PASS" % (sum(checks), len(checks)))
    return 0 if all(checks) else 1


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--audit", action="store_true")
    parser.add_argument(
        "--module",
        help="SLANG-Cybersecurity reproduction module",
    )
    parser.add_argument(
        "--pdf",
        help="identified source PDF",
    )
    parser.add_argument(
        "--half-split",
        type=int,
        help="predeclared chronological half split",
    )
    parser.add_argument(
        "--json-out",
        help="optional JSON audit output",
    )
    args = parser.parse_args()

    if args.self_test:
        raise SystemExit(self_test())

    if not args.module or not args.pdf or args.half_split is None:
        raise SystemExit(
            "--audit requires --module, --pdf, and --half-split"
        )

    module = load_module(args.module)
    events = verify_source_identity(module, args.pdf)
    result = audit(module, events, args.half_split)
    print_audit(result)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                result,
                handle,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            handle.write("\n")


if __name__ == "__main__":
    main()
