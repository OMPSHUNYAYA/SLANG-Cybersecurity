#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SLANG-Cybersecurity OpTC Result Reproduction v1.0.0.

Recomputes the declared OpTC result from the identified source PDF. This
reproduction verifies a revealed historical result; it does not recreate the
original blind chronology.
"""
from __future__ import annotations
import argparse,bisect,hashlib,json,math,re
from datetime import datetime,timedelta,timezone

EXPECTED_PDF_SHA="5986d23b81169221a491f7a8302fce140b12638ef4cf9b3a894ed3cb2fad9567"
EXPECTED_PDF_BYTES=453244
EXPECTED_PAGES=7
EXPECTED_TEXT_SHA="00bfe9f179c4cfc2b4106219e7973b896beadf40519282934d601ff6ff3efa1c"
EXPECTED_EVENT_HASH="b8f70f094535dcd344312e178953137133a55d9f5d9050c7ab68313e896737fa"
EVENT_RE=re.compile(r"^(?P<date>\d{2}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+--\s+(?P<action>.+?)\s*$")

def canonical_json(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False)
def sha256_text(value): return hashlib.sha256(value.encode("utf-8")).hexdigest()
def sha256_file(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()
def normalize_text(text):
    text=(text or "").replace("\x00","").replace("\r\n","\n").replace("\r","\n")
    text=re.sub(r"[ \t\f\v]+"," ",text)
    text=re.sub(r" *\n+ *","\n",text)
    return text.strip()
def import_pypdf_exact():
    try: import pypdf
    except Exception as exc: raise RuntimeError("pypdf==6.16.2 is required") from exc
    if str(getattr(pypdf,"__version__",""))!="6.16.2": raise RuntimeError("pypdf==6.16.2 is required")
    return pypdf
def extract_plain(pdf_path):
    pypdf=import_pypdf_exact(); reader=pypdf.PdfReader(pdf_path,strict=False)
    if bool(getattr(reader,"is_encrypted",False)): raise ValueError("encrypted PDF not admitted")
    pages=[]
    for page in reader.pages:
        pages.append(normalize_text(page.extract_text(extraction_mode="plain")))
    return reader, "\n\n".join(pages).strip()
def calendar_window(events):
    first=datetime.fromtimestamp(events[0]["t"],tz=timezone.utc); last=datetime.fromtimestamp(events[-1]["t"],tz=timezone.utc)
    start=datetime(first.year,first.month,first.day,tzinfo=timezone.utc)
    end=datetime(last.year,last.month,last.day,tzinfo=timezone.utc)+timedelta(days=1)
    return start,end
def anchors_for(events):
    start,end=calendar_window(events); t=int(start.timestamp()); stop=int(end.timestamp()); anchors=[]
    while t+900<=stop: anchors.append(t); t+=900
    return anchors
def feature_rows(events):
    times=[e["t"] for e in events]; first=times[0]; eligible=[]
    for anchor in anchors_for(events):
        n=bisect.bisect_right(times,anchor)
        if n>=2 and anchor>first:
            prev=times[n-1]; past_event_rate=n/(anchor-first); A=(anchor-prev)*past_event_rate; Q=1/(1+A)
            eligible.append({"anchor_epoch_second_utc_surrogate":anchor,"anchor_iso":datetime.fromtimestamp(anchor,tz=timezone.utc).isoformat().replace("+00:00","Z"),"risk_score_Q":Q})
    n=len(eligible)
    for i,row in enumerate(eligible):
        row["eligible_anchor_index"]=i; row["exact_superblock_id"]=min(17,(18*i)//n)
    return eligible
def target(anchor,times,shift=0):
    ts=times if shift==0 else [x+shift for x in times]
    lo=bisect.bisect_right(ts,anchor); hi=bisect.bisect_right(ts,anchor+900)
    return 1 if hi>lo else 0
def auc(labels,scores):
    p=[float(s) for y,s in zip(labels,scores) if y==1]; n=[float(s) for y,s in zip(labels,scores) if y==0]
    if not p or not n: return None
    wins=0.0
    for a in p:
        for b in n:
            wins += 1.0 if a>b else 0.5 if a==b else 0.0
    return wins/(len(p)*len(n))
def blocks(rows,labels):
    di=[]; ids=[]; effects=[]
    for block in range(18):
        ys=[]; ss=[]
        for r,y in zip(rows,labels):
            if r["exact_superblock_id"]==block: ys.append(y); ss.append(r["risk_score_Q"])
        a=auc(ys,ss); inf=a is not None
        if inf: ids.append(block); effects.append(a-0.5)
        di.append({"id":block,"n":len(ys),"positive":sum(ys),"negative":len(ys)-sum(ys),"auc":a})
    return di,ids,effects
def signflip(effects):
    m=len(effects)
    if not m: return None,0
    obs=sum(effects)/m; total=1<<m; extreme=0
    for mask in range(total):
        val=sum((e if (mask>>i)&1 else -e) for i,e in enumerate(effects))/m
        if val>=obs-1e-15: extreme+=1
    return extreme/total,total
def lobo(rows,labels,ids):
    vals=[]
    for omit in ids:
        ys=[]; ss=[]
        for r,y in zip(rows,labels):
            if r["exact_superblock_id"]==omit: continue
            ys.append(y); ss.append(r["risk_score_Q"])
        vals.append(auc(ys,ss))
    return vals
def score_events(events,half_split):
    rows=feature_rows(events); times=[e["t"] for e in events]; labels=[target(r["anchor_epoch_second_utc_surrogate"],times) for r in rows]; scores=[r["risk_score_Q"] for r in rows]
    di,ids,effects=blocks(rows,labels); p,assign=signflip(effects); lv=lobo(rows,labels,ids)
    h1=auc(labels[:half_split],scores[:half_split]); h2=auc(labels[half_split:],scores[half_split:])
    target_rows=[{"eligible_anchor_index":r["eligible_anchor_index"],"anchor_iso":r["anchor_iso"],"anchor_epoch_second_utc_surrogate":r["anchor_epoch_second_utc_surrogate"],"exact_superblock_id":r["exact_superblock_id"],"target_Y_next_900s":int(y)} for r,y in zip(rows,labels)]
    scored_rows=[{"eligible_anchor_index":r["eligible_anchor_index"],"anchor_iso":r["anchor_iso"],"exact_superblock_id":r["exact_superblock_id"],"risk_score_Q":float(r["risk_score_Q"]),"target_Y_next_900s":int(y)} for r,y in zip(rows,labels)]
    return {"rows":rows,"labels":labels,"n":len(rows),"positive":sum(labels),"negative":len(labels)-sum(labels),"auc":auc(labels,scores),"half1":h1,"half2":h2,"ids":ids,"p":p,"assign":assign,"lobo":lv,"minus60":auc([target(r["anchor_epoch_second_utc_surrogate"],times,-60) for r in rows],scores),"plus60":auc([target(r["anchor_epoch_second_utc_surrogate"],times,60) for r in rows],scores),"target_hash":sha256_text(canonical_json(target_rows)),"scored_hash":sha256_text(canonical_json(scored_rows))}

def parse_events(text):
    out=[]; current=None
    def flush():
        nonlocal current
        if current is not None:
            current["action"]=re.sub(r"\s+"," "," ".join(current.pop("parts"))).strip(); out.append(current); current=None
    for line_no,raw in enumerate(text.splitlines(),1):
        line=raw.strip(); m=EVENT_RE.match(line)
        if m:
            flush(); dt=datetime.strptime(m.group("date")+" "+m.group("time"),"%m/%d/%y %H:%M:%S").replace(tzinfo=timezone.utc)
            current={"t":int(dt.timestamp()),"timestamp_iso":dt.isoformat().replace("+00:00","Z"),"parts":[m.group("action")]}
        elif current is not None and line: current["parts"].append(line)
    flush(); unique={}
    for e in out: unique.setdefault((e["timestamp_iso"],e["action"]),e)
    events=sorted(unique.values(),key=lambda e:(e["t"],e["action"]))
    return events
def event_hash(events): return sha256_text(canonical_json([{"timestamp_iso":e["timestamp_iso"],"action":e["action"]} for e in events]))
def reproduce(pdf):
    if sha256_file(pdf)!=EXPECTED_PDF_SHA or __import__('os').path.getsize(pdf)!=EXPECTED_PDF_BYTES: raise ValueError("source PDF identity mismatch")
    reader,text=extract_plain(pdf)
    if len(reader.pages)!=EXPECTED_PAGES: raise ValueError("page count mismatch")
    if sha256_text(text)!=EXPECTED_TEXT_SHA: raise ValueError("extracted text identity mismatch")
    events=parse_events(text)
    if len(events)!=101 or event_hash(events)!=EXPECTED_EVENT_HASH: raise ValueError("canonical event chronology mismatch")
    r=score_events(events,121)
    expected={"n":242,"positive":33,"negative":209,"auc":0.8683485573437727,"half1":0.8887457044673539,"half2":0.8253968253968254,"ids":[0,1,6,7,8,13,14,15],"p":0.00390625,"assign":256,"target_hash":"206b71630776c8ea9314a9557a21b0d26ca95106d2d2d17f08342da116793c04","scored_hash":"4eac55eae2e06a0ba25091e86c649a7d8a99176b69eba01afc2671acf737d258"}
    checks={k:(r[k]==v if not isinstance(v,float) else math.isclose(r[k],v,rel_tol=0,abs_tol=1e-15)) for k,v in expected.items()}
    checks["all_lobo_gt_0_5"]=all(x is not None and x>0.5 for x in r["lobo"])
    print("SLANG-Cybersecurity OpTC Result Reproduction v1.0.0")
    print("canonical_event_count:%d"%len(events)); print("eligible_anchors:%d"%r["n"]); print("target_balance:%d/%d"%(r["positive"],r["negative"])); print("roc_auc:%s"%repr(r["auc"])); print("chronological_half_auc:%s/%s"%(repr(r["half1"]),repr(r["half2"]))); print("informative_superblocks:%s"%json.dumps(r["ids"])); print("exact_one_sided_signflip_p:%s"%repr(r["p"])); print("all_lobo_auc_gt_0_5:%s"%str(all(x>0.5 for x in r["lobo"])).lower()); print("minus_60_seconds_auc:%s"%repr(r["minus60"])); print("plus_60_seconds_auc:%s"%repr(r["plus60"])); print("target_rows_sha256:%s"%r["target_hash"]); print("scored_rows_sha256:%s"%r["scored_hash"]); print("reproduction_checks:%d/%d %s"%(sum(checks.values()),len(checks),"PASS" if all(checks.values()) else "FAIL"))
    return 0 if all(checks.values()) else 1
def self_test():
    sample="09/23/19 11:23:29 -- Alpha\ncontinued\n09/23/19 11:24:54 -- Beta\n"
    ev=parse_events(sample); r=feature_rows([{"t":0,"timestamp_iso":"x","action":"a"},{"t":300,"timestamp_iso":"y","action":"b"},{"t":900,"timestamp_iso":"z","action":"c"}])
    checks=[len(ev)==2,ev[0]["action"]=="Alpha continued",target(0,[0,900])==1,target(900,[900])==0,math.isclose(auc([0,1],[0.1,0.9]),1.0),len(r)>0,EVENT_RE.match("09/23/19 11:23:29 -- Action") is not None,EVENT_RE.match("callback at 10:00") is None,EXPECTED_PAGES==7,len(EXPECTED_PDF_SHA)==64,len(EXPECTED_TEXT_SHA)==64,len(EXPECTED_EVENT_HASH)==64]
    print("SLANG-Cybersecurity OpTC Result Reproduction v1.0.0 self-test"); print("TOTAL %d/%d PASS"%(sum(checks),len(checks))); return 0 if all(checks) else 1
def main():
    ap=argparse.ArgumentParser(); g=ap.add_mutually_exclusive_group(required=True); g.add_argument("--self-test",action="store_true"); g.add_argument("--reproduce",action="store_true"); ap.add_argument("--pdf"); a=ap.parse_args()
    if a.self_test: raise SystemExit(self_test())
    if not a.pdf: raise SystemExit("--pdf is required with --reproduce")
    raise SystemExit(reproduce(a.pdf))
if __name__=="__main__": main()
