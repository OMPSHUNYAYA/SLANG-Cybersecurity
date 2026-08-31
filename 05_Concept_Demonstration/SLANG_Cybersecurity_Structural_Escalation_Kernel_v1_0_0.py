#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SLANG-Cybersecurity Structural Escalation Kernel v1.0.0.

Minimal deterministic structural-resolution demonstration. This demonstration
is conceptually separate from the empirical attack-chronology transfer result.
"""
from __future__ import annotations
import argparse

RULES = [
    ("attack", "suspected", lambda s: s.get("failures", 0) > 50),
    ("bruteforce", "true", lambda s: s.get("attack") == "suspected" and s.get("pattern") == "repeated"),
    ("block", "yes", lambda s: s.get("bruteforce") == "true"),
]

def resolve(state, rules=RULES):
    state=dict(state)
    changed=True
    while changed:
        changed=False
        for key,value,condition in rules:
            if condition(state) and state.get(key)!=value:
                state[key]=value; changed=True
    return state

def self_test():
    a=resolve({"failures":75,"pattern":"repeated"})
    b=resolve({"failures":20,"pattern":"repeated"})
    c=resolve({"attack":"suspected"})
    d=resolve({"block":"yes"})
    e=resolve({"failures":75,"pattern":"repeated"},list(reversed(RULES)))
    checks=[a.get("block")=="yes",b.get("attack") is None,c.get("block") is None,d.get("block")=="yes",e==a,resolve(a)==a]
    print("SLANG-Cybersecurity Structural Escalation Kernel v1.0.0 self-test")
    print("TOTAL %d/%d PASS"%(sum(checks),len(checks)))
    return 0 if all(checks) else 1

def demo():
    state=resolve({"failures":75,"pattern":"repeated"})
    order=["failures","pattern","attack","bruteforce","block"]
    print({k:state[k] for k in order if k in state})

def main():
    ap=argparse.ArgumentParser(); g=ap.add_mutually_exclusive_group(required=True); g.add_argument("--self-test",action="store_true"); g.add_argument("--demo",action="store_true"); a=ap.parse_args()
    raise SystemExit(self_test() if a.self_test else (demo() or 0))
if __name__=="__main__": main()
