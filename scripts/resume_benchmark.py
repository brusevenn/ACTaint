"""Resume only never-requested ACToolBench project groups; preserve prior paid attempts."""
from __future__ import annotations
import argparse,concurrent.futures,datetime,hashlib,json,os,signal,subprocess,sys,time,uuid
from pathlib import Path

TOOL="ACTaint";ROOT=Path(__file__).resolve().parents[1];RUN="llm-resume-20261027";OLD="comparison-20261027-deepseek-high";CACHE="cache-optimization-20261027"
PYTHON=sys.executable
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p):
 h=hashlib.sha256()
 with Path(p).open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
 return h.hexdigest()
def write(p,d):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);t=p.with_name(p.name+".tmp-"+uuid.uuid4().hex[:8]);t.write_text(json.dumps(d,sort_keys=True,indent=2,ensure_ascii=False)+"\n");os.replace(t,p)
def request_audit(root):
 starts=0;terminals=0;bad=[]
 for p in Path(root).rglob("requests.jsonl"):
  for n,line in enumerate(p.read_text(errors="replace").splitlines(),1):
   try:r=json.loads(line)
   except json.JSONDecodeError:bad.append(f"{p.name}:{n}");continue
   event=r.get("event")
   if event in ("request","request_started"):starts+=1
   elif event in ("response","error"):terminals+=1
 return starts,terminals,bad
def verify_seal(folder,name):
 p=folder/name
 if not p.is_file():raise ValueError("SEALED_ARCHIVE_MISSING:"+str(p))
 s=json.loads(p.read_text())
 unsigned={k:v for k,v in s.items() if k not in ("seal_sha256","files_sha256")}
 expected=s.get("seal_sha256")
 if expected:
  raw=json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
  if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError("SEAL_HASH_INVALID:"+str(p))
 files=s.get("files")
 if not isinstance(files,dict):raise ValueError("SEAL_INVENTORY_MISSING:"+str(p))
 actual={str(x.relative_to(folder)) for x in folder.rglob("*") if x.is_file() and x!=p and ".tmp-" not in x.name}
 # Some result formats enumerate only payload files; allow only explicitly documented excluded controller summary sidecars.
 if set(files)!=actual:raise ValueError("SEALED_PATH_SET_CHANGED:"+str(p))
 for rel,d in files.items():
  if sha(folder/rel)!=d:raise ValueError("SEALED_FILE_HASH_CHANGED:"+rel)
 return sha(p)
def manifest_data():
 mp=ROOT/"datasets/actoolbench-cleaned-154/full/manifest.json";ix=ROOT/"datasets/actoolbench-cleaned-154/tools"/TOOL.lower()/"input-index.json"
 m=json.loads(mp.read_text());i=json.loads(ix.read_text())
 if len(m["cases"])!=154 or len(i["cases"])!=154 or len(i["projects"])!=121 or i.get("case_labels_included") is not False:raise ValueError("INPUT_DENOMINATOR_OR_LABEL_BOUNDARY")
 byid={r["case_id"]:r for r in m["cases"]}
 if set(byid)!={r["case_id"] for r in i["cases"]}:raise ValueError("INPUT_CASE_IDS_MISMATCH")
 groups={}
 for case in i["cases"]:
  pid=case["project_id"];g=groups.setdefault(pid,{"project_id":pid,"case_ids":[],"file_hashes":set()});g["case_ids"].append(case["case_id"])
  mr=byid[case["case_id"]];expected={(f["path"],f["sha256"]) for f in mr["source_files"]}
  idx={(f.get("source_relative_path",Path(f["source_path"]).name),f["sha256"]) for f in i["files"] if f["project_id"]==pid}
  if expected!=idx:raise ValueError("INDEX_MANIFEST_SOURCE_MAPPING_MISMATCH:"+case["case_id"])
  for f in mr["source_files"]:
   path=ROOT/"datasets/actoolbench-cleaned-154/full"/mr["source_root"]/f["path"]
   if not path.is_file() or sha(path)!=f["sha256"]:raise ValueError("SOURCE_HASH_MISMATCH:"+case["case_id"])
   g["file_hashes"].add(f["sha256"])
  cfgs=i["projects"][[p["project_id"] for p in i["projects"]].index(pid)]["compile_config_paths"]
  for c in cfgs:
   cp=ROOT/c if c.startswith("datasets/") else ROOT/"datasets/actoolbench-cleaned-154/full"/c
   if not cp.is_file():raise ValueError("COMPILE_CONFIG_MISSING:"+pid)
 return mp,ix,m,i,groups,byid
def old_attempts(project_id):
 folder=ROOT/"experiments"/OLD/"actoolbench154"/"jobs"/project_id
 starts,terminals,bad=request_audit(folder)
 receipt=folder/"controller-result.json";row=json.loads(receipt.read_text()) if receipt.is_file() else None
 if row and row.get("project_id") not in (None,project_id):raise ValueError("OLD_RECEIPT_PROJECT_ID_MISMATCH")
 return folder,row,starts,terminals,bad
def cache_result(project_id):
 root=ROOT/"experiments"/CACHE
 for p in sorted(root.glob("round-*")):
  candidate=p/project_id/"native/project-result.json"
  if not candidate.is_file():continue
  # verify the diagnostic round's top-level hash inventory before reuse.
  verify_seal(p.parent,"diagnostic-seal.json")
  starts,terminals,bad=request_audit(p/project_id)
  if bad or starts<1 or terminals<1:raise ValueError("DIAGNOSTIC_REQUEST_AUDIT_INVALID:"+project_id)
  return p/project_id,json.loads(candidate.read_text()),starts,terminals
 return None
def build_plan():
 mp,ix,m,i,groups,byid=manifest_data();formal=ROOT/"experiments"/OLD/"actoolbench154";formal_seal=verify_seal(formal,"predictions-seal.json")
 jobs=[]
 for pid,g in sorted(groups.items()):
  old,row,starts,terminals,bad=old_attempts(pid)
  source_hashes=sorted(g["file_hashes"])
  cfg=i["projects"][[p["project_id"] for p in i["projects"]].index(pid)]["compile_config_paths"]
  cfgrel=byid[g["case_ids"][0]]["compile_config_path"]
  if any(byid[c]["compile_config_path"]!=cfgrel for c in g["case_ids"]):raise ValueError("CASE_COMPILE_CONFIG_MAPPING_MISMATCH")
  cfgpath=ROOT/"datasets/actoolbench-cleaned-154/full"/cfgrel
  input_files=[(f["path"],f["sha256"]) for f in byid[g["case_ids"][0]]["source_files"]]
  identity=hashlib.sha256(json.dumps({"source_files":input_files,"compile_config_sha256":sha(cfgpath)},sort_keys=True).encode()).hexdigest()
  if row and row.get("input_identity") not in (None,identity):raise ValueError("OLD_RECEIPT_INPUT_IDENTITY_MISMATCH:"+pid)
  artifact=None
  source_file_inventory=sorted([[f["source_relative_path"],f["sha256"]] for f in i["files"] if f["project_id"]==pid])
  if bad:disposition="UNCERTAIN_CORRUPT_REQUEST_AUDIT_NO_REPLAY";reason="At least one request log row is malformed; cannot establish zero paid attempts."
  elif starts or terminals:disposition="REUSE_PRIOR_PAID_NO_REPLAY";reason="Historical request-start or terminal event exists; project wrapper cannot isolate unfinished files safely."
  elif row and row.get("status")=="PROJECT_COMPLETED":disposition="REUSE_PRIOR_COMPLETED";reason="Already completed native analysis without model requests."
  else:
   diag=cache_result(pid)
   if diag:
    folder,native,nreq,nterm=diag;disposition="REUSE_CACHE_DIAGNOSTIC_NO_REPLAY";reason="Post-payment diagnostic already requested this source group."
    row={"status":native.get("status","DIAGNOSTIC_STATUS_UNKNOWN"),"phase":"cache-diagnostic","prompt_layout":"prefix_stable_v2","case_ids":g["case_ids"],"source_file_count":len(input_files),"input_identity":identity}
    artifact=str(folder.relative_to(ROOT))
   else:
    disposition="ELIGIBLE_ZERO_REQUEST_RESUME";reason="No request-start/response/error event in a valid historical ledger."
    artifact=None
  if disposition.startswith("REUSE_") and artifact is None:artifact="experiments/"+OLD+"/actoolbench154/jobs/"+pid
  jobs.append({"tool":TOOL,"project_id":pid,"case_ids":g["case_ids"],"source_hashes":source_hashes,
   "source_file_count":len(input_files),"source_file_inventory":source_file_inventory,"compile_config_paths":[cfgrel],"compile_config_sha256":sha(cfgpath),
   "input_identity":identity,"disposition":disposition,"prior_status":row.get("status","NOT_RUN") if row else "NOT_RUN",
   "prior_phase":row.get("phase") if row else None,"prior_prompt_layout":row.get("prompt_layout") if row else None,
   "prior_request_attempts":starts,"prior_terminal_events":terminals,"prior_artifact":artifact,
   "historical_prediction_seal_sha256":formal_seal,"reason":reason})
 cases=[]
 for j in jobs:
  for cid in j["case_ids"]:
   cases.append({"case_id":cid,"project_id":j["project_id"],"status":j["disposition"],
    "source_hashes":j["source_hashes"],"provenance_variant":"prefix_stable_v2" if j["prior_phase"]=="cache-diagnostic" else (j["prior_prompt_layout"] or "prefix_stable_v2"),
    "prior_status":j["prior_status"],"prior_phase":j["prior_phase"],"prior_artifact":j["prior_artifact"],
    "compile_config_paths":j["compile_config_paths"],"source_file_inventory":j["source_file_inventory"],"compile_config_sha256":j["compile_config_sha256"],
    "input_identity":j["input_identity"],"historical_prediction_seal_sha256":formal_seal})
 if len(cases)!=154 or len({x["case_id"] for x in cases})!=154:raise ValueError("RESUME_CASE_DENOMINATOR_INVALID")
 return {"schema":"NATIVE_LLM_RESUME_PLAN_V1","tool":TOOL,"dataset":"ACToolBench154",
  "code_sha":subprocess.check_output(["git","log","-1","--format=%H","--","scripts/benchmark.py","scripts/resume_benchmark.py"],cwd=ROOT,text=True).strip(),
  "manifest_sha256":sha(mp),"input_index_sha256":sha(ix),"case_count":154,"project_group_count":121,
  "created_utc":now(),"ground_truth_read":False,"labels_in_detector_input":False,"automatic_retries":0,
  "duplicate_samples_replayed":False,"execution_launched":False,"jobs":jobs,"case_records":cases,
  "disposition_counts":{s:sum(j["disposition"]==s for j in jobs) for s in sorted({j["disposition"] for j in jobs})}}
def _global_stop_path():
 value=os.environ.get("EXPERIMENT_GLOBAL_STOP_FILE")
 return Path(value) if value else None
def _mark_global_stop():
 path=_global_stop_path()
 if path is None:return
 path.parent.mkdir(parents=True,exist_ok=True)
 if not path.exists():
  write(path,{"status":"STOPPED_AUTH_OR_PAYMENT_ERROR","tool":TOOL,"timestamp_utc":now()})
def _stop_for_provider_error(job_dir):
 for log in Path(job_dir).rglob("requests.jsonl"):
  for line in log.read_text(errors="replace").splitlines():
   try:r=json.loads(line)
   except json.JSONDecodeError:return True
   if r.get("event")=="error":
    code=r.get("status_code",r.get("http_status"))
    try:code=int(code)
    except (TypeError,ValueError):code=None
    body=r.get("error_body",{})
    provider_code=body.get("error",{}).get("code") if isinstance(body,dict) else None
    if code in (401,402,403) or provider_code in ("insufficient_balance_error","insufficient_quota","payment_required","billing_hard_limit_reached"):return True
 return False

def _safe_text(path):
 raw=Path(path).read_bytes()
 clean=raw.replace(str(ROOT).encode(),b"[TOOL_ROOT]").replace(str(Path.home()).encode(),b"[HOME]").replace(str(ROOT.parent).encode(),b"[WORKSPACE]/")
 if clean!=raw:
  side={"original_sha256":hashlib.sha256(raw).hexdigest(),"saved_sha256":hashlib.sha256(clean).hexdigest(),"normalization":"runtime_personal_paths"}
  Path(str(path)+".path-normalization.json").write_text(json.dumps(side,sort_keys=True)+"\n")
  Path(path).write_bytes(clean)

def execute(plan):
 out=ROOT/"experiments"/RUN
 out.mkdir(parents=True,exist_ok=True)
 planfile=out/"resume-plan.json"
 if planfile.exists():
  prior=json.loads(planfile.read_text())
  for k in ("tool","code_sha","manifest_sha256","input_index_sha256","case_count","project_group_count","jobs"):
   if prior.get(k)!=plan.get(k):raise RuntimeError("PREPARED_RESUME_PLAN_IDENTITY_CHANGED:"+k)
  plan=prior
 else:write(planfile,plan)
 launch=out/"launch-receipt.json"
 if launch.exists():raise FileExistsError("RESUME_ALREADY_LAUNCHED_NO_REPLAY")
 jobs=plan["jobs"]; eligible=[j for j in jobs if j["disposition"]=="ELIGIBLE_ZERO_REQUEST_RESUME"]
 write(launch,{"tool":TOOL,"code_sha":plan["code_sha"],"started_utc":now(),"concurrency":2,
  "eligible_project_count":len(eligible),"eligible_case_ids":[c for j in eligible for c in j["case_ids"]],
  "fixed_protocol":{"model":"deepseek-flash","reasoning_effort":"high","thinking":"enabled","max_tokens":65536,"request_timeout_seconds":300,"case_timeout_seconds":1200,"retries":0},"prompt_layout":"prefix_stable_v2"})
 import threading
 stop=threading.Event()
 def save_receipt(j,row):
  row.update(tool=TOOL,dataset="ACToolBench154",project_id=j["project_id"],case_ids=j["case_ids"],
   source_hashes=j["source_hashes"],source_file_inventory=j["source_file_inventory"],
   input_identity=j["input_identity"],compile_config_sha256=j["compile_config_sha256"],
   prior_request_attempts=0,code_sha=plan["code_sha"],prompt_layout="prefix_stable_v2",ended_utc=now())
  write(out/"jobs"/j["project_id"]/"resume-result.json",row)
  return row
 def one(j):
  dest=out/"jobs"/j["project_id"];dest.mkdir(parents=True,exist_ok=True)
  started=dest/"started.json";receipt=dest/"resume-result.json"
  if receipt.exists():return json.loads(receipt.read_text())
  if started.exists():
   return save_receipt(j,{"status":"INTERRUPTED_NOT_RETRIED","reason":"previous start marker without terminal result; do not replay physical request"})
  global_stop=_global_stop_path()
  if stop.is_set() or (global_stop is not None and global_stop.exists()):
   return save_receipt(j,{"status":"NOT_RUN_PROVIDER_STOP"})
  write(started,{"tool":TOOL,"dataset":"ACToolBench154","project_id":j["project_id"],"case_ids":j["case_ids"],
   "input_identity":j["input_identity"],"source_hashes":j["source_hashes"],"compile_config_sha256":j["compile_config_sha256"],
   "code_sha":plan["code_sha"],"started_utc":now(),"prompt_layout":"prefix_stable_v2","max_tokens":65536,
   "reasoning_effort":"high","thinking":{"type":"enabled"},"request_timeout_seconds":300,"case_timeout_seconds":1200,
   "automatic_retries":0,"prior_request_attempts":0})
  cmd=[PYTHON,"-B","scripts/benchmark.py","--project-id",j["project_id"],"--output",str(dest/"native"),
       "--prompt-layout","prefix_stable_v2","--timeout-seconds","1200"]
  if TOOL=="ACTaint":
   compiler_map=os.environ.get("ACTAINT_COMPILER_MAP")
   if not compiler_map:raise RuntimeError("ACTAINT_COMPILER_MAP_REQUIRED")
   cmd += ["--compiler-map",compiler_map,"--code-sha",plan["code_sha"]]
  try:
   with (dest/"stdout.txt").open("xb") as so,(dest/"stderr.txt").open("xb") as se:
    proc=subprocess.Popen(cmd,cwd=ROOT,stdout=so,stderr=se,start_new_session=True,env=os.environ.copy())
    try:rc=proc.wait(timeout=1200);outer="COMPLETED" if rc==0 else "TOOL_ERROR"
    except subprocess.TimeoutExpired:
     os.killpg(proc.pid,signal.SIGTERM)
     try:proc.wait(timeout=3)
     except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
     rc=proc.returncode;outer="TIMEOUT"
   _safe_text(dest/"stdout.txt");_safe_text(dest/"stderr.txt")
   native=dest/"native/project-result.json";nr=json.loads(native.read_text()) if native.exists() else {}
   status=nr.get("status",outer)
   row=save_receipt(j,{"status":status,"exit_code":rc,"native_result_present":native.exists(),"native_output":"native/project-result.json" if native.exists() else None,"artifact":str(dest.relative_to(ROOT)),"native_execution_status":status})
   if _stop_for_provider_error(dest):
    stop.set();_mark_global_stop()
   return row
  except Exception as e:
   row=save_receipt(j,{"status":"CONTROLLER_ERROR","error_type":type(e).__name__,"error_message":str(e).replace(str(ROOT),"[TOOL_ROOT]")[:1200]})
   if _stop_for_provider_error(dest):
    stop.set();_mark_global_stop()
   return row
 # Per-job receipts are persisted as each future finishes; provider stop closes the queue.
 results=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
  pending={pool.submit(one,j):j for j in eligible}
  for f in concurrent.futures.as_completed(pending):
   try:r=f.result()
   except Exception as e:
    j=pending[f];r=save_receipt(j,{"status":"CONTROLLER_ERROR","error_type":type(e).__name__,"error_message":str(e)[:800]})
   results.append(r)
 # Reuse historical paid/completed/diagnostic evidence explicitly; not rerun.
 result_by={r["project_id"]:r for r in results}
 for j in jobs:
  if j["project_id"] in result_by:continue
  result_by[j["project_id"]]={**j,"tool":TOOL,"dataset":"ACToolBench154","status":j["disposition"],
   "prior_request_attempts":j["prior_request_attempts"],"code_sha":plan["code_sha"],
   "prompt_layout":j.get("prior_prompt_layout") or ("prefix_stable_v2" if j.get("prior_phase")=="cache-diagnostic" else "baseline")}
 records=[]
 for c in plan["case_records"]:
  r=result_by[c["project_id"]]
  records.append({**c,"status":r["status"],"provenance_variant":r.get("prompt_layout"),
   "execution_artifact":r.get("artifact") or r.get("prior_artifact"),"execution_code_sha":r.get("code_sha"),
   "new_attempted":r["project_id"] in {x["project_id"] for x in results}})
 assert len(records)==154 and len({x["case_id"] for x in records})==154
 write(out/"case-records.json",{"schema":"NATIVE_LLM_RESUME_CASE_RECORDS_V1","tool":TOOL,"dataset":"ACToolBench154","case_count":154,"records":records,"ground_truth_read":False,"scoring_performed":False})
 write(out/"execution-summary.json",{"tool":TOOL,"code_sha":plan["code_sha"],"case_count":154,"project_group_count":121,
  "resumed_project_count":len(results),"provider_stop":stop.is_set() or bool(_global_stop_path() and _global_stop_path().exists()),"status_counts":{st:sum(x["status"]==st for x in records) for st in sorted({x["status"] for x in records})},
  "finished_utc":now(),"scoring_performed":False})
 files={str(p.relative_to(out)):sha(p) for p in out.rglob("*") if p.is_file() and p.name!="resume-seal.json"}
 seal={"schema":"NATIVE_LLM_RESUME_SEAL_V1","tool":TOOL,"dataset":"ACToolBench154","code_sha":plan["code_sha"],"manifest_sha256":plan["manifest_sha256"],
  "case_count":154,"files":files,"finished_utc":now(),"ground_truth_read":False,"scoring_performed":False,"old_predictions_modified":False}
 seal["seal_sha256"]=hashlib.sha256(json.dumps(seal,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
 write(out/"resume-seal.json",seal)
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--prepare",action="store_true");ap.add_argument("--execute",action="store_true");args=ap.parse_args()
 plan=build_plan();o=ROOT/"experiments"/RUN;"resume-plan.json"
 if args.prepare:
  o.mkdir(parents=True,exist_ok=True);p=o/"resume-plan.json"
  if p.exists():raise FileExistsError("RESUME_PLAN_EXISTS_NO_OVERWRITE")
  write(p,plan);print(json.dumps({"tool":TOOL,"dispositions":plan["disposition_counts"],"launched":False},sort_keys=True));return 0
 if args.execute:return execute(plan)
 print(json.dumps({"tool":TOOL,"dispositions":plan["disposition_counts"],"launched":False},sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
