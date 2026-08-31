#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SLANG-Cybersecurity DARPA TC E3 Result Reproduction v1.0.0.

Recomputes the declared unchanged-score E3 replication from the identified source
PDF. The primary E3 replication is retained as not confirmed.
"""
from __future__ import annotations
import argparse,bisect,hashlib,json,math,re,os
from datetime import datetime,timedelta,timezone
EXPECTED_PDF_SHA="021fc642e18544fdcc7bf0a79e2b5aae001f5717d3adbce16744b68934523599"
EXPECTED_PDF_BYTES=1258337
EXPECTED_PAGES=47
EXPECTED_TEXT_SHA="83b713d529231257cf40afe8165ac2888b8db1152f871b294c4d275edb081915"
EXPECTED_EVENT_HASH="c80bbc4312ea3c0a7ebfb70e672e86e62f70c5da3c02a8d2e8422a8ffb62d354"
ROW_RE=re.compile(r"^(?P<date>20\d{2}-\d{2}-\d{2})\s+(?P<hhmm>[0-2]\d[0-5]\d)\s+(?P<body>\S.*)$")

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
    out=[]
    for raw in text.splitlines():
        line=raw.strip(); m=ROW_RE.match(line)
        if not m: continue
        hhmm=m.group("hhmm"); dt=datetime.strptime(m.group("date"),"%Y-%m-%d").replace(hour=int(hhmm[:2]),minute=int(hhmm[2:]),second=0,tzinfo=timezone.utc)
        out.append({"t":int(dt.timestamp()),"timestamp_iso":dt.isoformat().replace("+00:00","Z"),"action":re.sub(r"\s+"," ",m.group("body")).strip()})
    unique={}
    for e in out: unique.setdefault((e["timestamp_iso"],e["action"]),e)
    return sorted(unique.values(),key=lambda e:(e["t"],e["action"]))
def event_hash(events): return sha256_text(canonical_json([{"timestamp_iso":e["timestamp_iso"],"action":e["action"]} for e in events]))
def reproduce(pdf):
    if sha256_file(pdf)!=EXPECTED_PDF_SHA or os.path.getsize(pdf)!=EXPECTED_PDF_BYTES: raise ValueError("source PDF identity mismatch")
    reader,text=extract_plain(pdf)
    if len(reader.pages)!=EXPECTED_PAGES: raise ValueError("page count mismatch")
    if sha256_text(text)!=EXPECTED_TEXT_SHA: raise ValueError("extracted text identity mismatch")
    events=parse_events(text)
    if len(events)!=26 or event_hash(events)!=EXPECTED_EVENT_HASH: raise ValueError("canonical event chronology mismatch")
    r=score_events(events,354)
    expected={"n":708,"positive":19,"negative":689,"auc":0.7468489802154151,"half1":0.4900568181818182,"half2":0.6463606213998953,"ids":[7,9,11,12,14,16,17],"p":0.40625,"assign":128,"target_hash":"a12ce82f69670339769f99034d6b27b9dbbada9d91eb339d842a5900cc7ed3db","scored_hash":"e0905bf30898874c1dff90b967fa1642d1528c4d7f377e66741491c8dfb68636"}
    checks={k:(r[k]==v if not isinstance(v,float) else math.isclose(r[k],v,rel_tol=0,abs_tol=1e-15)) for k,v in expected.items()}
    checks["all_lobo_gt_0_5"]=all(x is not None and x>0.5 for x in r["lobo"])
    times=[e["t"] for e in events]; coinc=[row for row in r["rows"] if row["anchor_epoch_second_utc_surrogate"] in set(times)]
    coinc_q1=sum(1 for row in coinc if math.isclose(row["risk_score_Q"],1.0,rel_tol=0,abs_tol=1e-15))
    plus_pos=sum(target(row["anchor_epoch_second_utc_surrogate"],times,60) for row in coinc)
    official_pos=sum(target(row["anchor_epoch_second_utc_surrogate"],times,0) for row in coinc)
    checks["coincidence_count"]=len(coinc)==20; checks["coincident_q1"]=coinc_q1==20; checks["official_coincident_positive"]=official_pos==0; checks["plus60_coincident_positive"]=plus_pos==20; checks["plus60_auc"]=math.isclose(r["plus60"],1.0,rel_tol=0,abs_tol=1e-15)
    print("SLANG-Cybersecurity DARPA TC E3 Result Reproduction v1.0.0")
    print("canonical_event_count:%d"%len(events)); print("eligible_anchors:%d"%r["n"]); print("target_balance:%d/%d"%(r["positive"],r["negative"])); print("roc_auc:%s"%repr(r["auc"])); print("chronological_half_auc:%s/%s"%(repr(r["half1"]),repr(r["half2"]))); print("informative_superblocks:%s"%json.dumps(r["ids"])); print("exact_one_sided_signflip_p:%s"%repr(r["p"])); print("all_lobo_auc_gt_0_5:%s"%str(all(x>0.5 for x in r["lobo"])).lower()); print("minus_60_seconds_auc:%s"%repr(r["minus60"])); print("plus_60_seconds_auc:%s"%repr(r["plus60"])); print("grid_coincident_anchors:%d"%len(coinc)); print("grid_coincident_q_equal_1:%d"%coinc_q1); print("primary_replication:NOT_CONFIRMED"); print("reproduction_checks:%d/%d %s"%(sum(checks.values()),len(checks),"PASS" if all(checks.values()) else "FAIL"))
    return 0 if all(checks.values()) else 1
def self_test():
    sample="2018-01-02 1000 HOST_A SYNTHETIC_ACTION_A\n• 10:22 SYNTHETIC_DIAGNOSTIC_LINE\n2018-01-02 1400 HOST_B SYNTHETIC_ACTION_B\n"
    ev=parse_events(sample)
    checks=[len(ev)==2,ev[0]["timestamp_iso"]=="2018-01-02T10:00:00Z",ROW_RE.match("2018-01-03 1500 HOST_C SYNTHETIC_ACTION_C") is not None,ROW_RE.match("• 15:17 SYNTHETIC_DIAGNOSTIC_LINE") is None,target(0,[0,900])==1,target(900,[900])==0,math.isclose(auc([0,1],[0.1,0.9]),1.0),EXPECTED_PAGES==47,len(EXPECTED_PDF_SHA)==64,len(EXPECTED_TEXT_SHA)==64,len(EXPECTED_EVENT_HASH)==64]
    print("SLANG-Cybersecurity DARPA TC E3 Result Reproduction v1.0.0 self-test"); print("TOTAL %d/%d PASS"%(sum(checks),len(checks))); return 0 if all(checks) else 1
def main():
    ap=argparse.ArgumentParser(); g=ap.add_mutually_exclusive_group(required=True); g.add_argument("--self-test",action="store_true"); g.add_argument("--reproduce",action="store_true"); ap.add_argument("--pdf"); a=ap.parse_args()
    if a.self_test: raise SystemExit(self_test())
    if not a.pdf: raise SystemExit("--pdf is required with --reproduce")
    raise SystemExit(reproduce(a.pdf))
if __name__=="__main__": main()
