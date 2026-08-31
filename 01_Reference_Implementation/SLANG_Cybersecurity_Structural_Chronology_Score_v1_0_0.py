#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SLANG-Cybersecurity Structural Chronology Score v1.0.0.

Dependency-free reference implementation of the frozen parameter-free
attack-chronology ranking score.
"""
from __future__ import annotations
import argparse
import bisect
import math

FORMULA = "Q(t)=1/(1+((t-t_prev)*N_prior/(t-t_first)))"

def structural_chronology_score(anchor_second, admitted_event_times):
    times = sorted(int(x) for x in admitted_event_times)
    n_prior = bisect.bisect_right(times, int(anchor_second))
    if n_prior < 2:
        raise ValueError("at least two admitted events at or before the anchor are required")
    t_first = times[0]
    t_prev = times[n_prior - 1]
    elapsed = int(anchor_second) - t_first
    lag = int(anchor_second) - t_prev
    if elapsed <= 0:
        raise ValueError("anchor must be later than the first admitted event")
    if lag < 0:
        raise ValueError("future events cannot enter the score")
    A = lag * n_prior / elapsed
    Q = 1.0 / (1.0 + A)
    return {
        "t": int(anchor_second),
        "t_first": t_first,
        "t_prev": t_prev,
        "N_prior": n_prior,
        "A": A,
        "Q": Q,
    }

def self_test():
    checks=[]
    def add(name, ok): checks.append((name, bool(ok)))
    s=structural_chronology_score(200,[100,150])
    add("N_prior", s["N_prior"]==2)
    add("t_first", s["t_first"]==100)
    add("t_prev", s["t_prev"]==150)
    add("A", math.isclose(s["A"],1.0))
    add("Q", math.isclose(s["Q"],0.5))
    add("recent_higher_risk", structural_chronology_score(160,[100,150])["Q"] > structural_chronology_score(250,[100,150])["Q"])
    add("time_scale_invariant", math.isclose(structural_chronology_score(2000,[1000,1500])["Q"],0.5))
    add("event_at_anchor_is_history", math.isclose(structural_chronology_score(200,[100,150,200])["Q"],1.0))
    add("distinct_same_time_events_count", structural_chronology_score(200,[100,150,200,200])["N_prior"]==4)
    try:
        structural_chronology_score(120,[100,150])
        insufficient=False
    except ValueError:
        insufficient=True
    add("future_event_not_counted_as_history", insufficient)
    try:
        structural_chronology_score(100,[100,100])
        bad_elapsed=False
    except ValueError:
        bad_elapsed=True
    add("positive_history_span_required", bad_elapsed)
    add("bounded_range", 0.0 < s["Q"] <= 1.0)
    failed=[n for n,v in checks if not v]
    print("SLANG-Cybersecurity Structural Chronology Score v1.0.0 self-test")
    print("TOTAL %d/%d PASS" % (len(checks)-len(failed),len(checks)))
    if failed:
        for n in failed: print("FAIL:"+n)
        raise SystemExit(1)

def demo():
    events=[0,300,900,1800,3600]
    print("SLANG-Cybersecurity Structural Chronology Score v1.0.0")
    print("formula:"+FORMULA)
    for t in [600,1200,1800,2700,4500]:
        try:
            s=structural_chronology_score(t,events)
            print("t=%d N_prior=%d lag=%d A=%.12g Q=%.12g" % (t,s["N_prior"],t-s["t_prev"],s["A"],s["Q"]))
        except ValueError as exc:
            print("t=%d unavailable:%s" % (t,exc))

def main():
    ap=argparse.ArgumentParser()
    g=ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--self-test",action="store_true")
    g.add_argument("--demo",action="store_true")
    args=ap.parse_args()
    if args.self_test: self_test()
    else: demo()

if __name__=="__main__": main()
