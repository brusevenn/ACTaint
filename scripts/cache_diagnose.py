import os,json,sys,time,subprocess,signal,hashlib,concurrent.futures,datetime
from pathlib import Path
ROOT=Path(os.environ["CACHE_WORKSPACE"]);CONTROL=Path(os.environ["CACHE_CONTROL_ROOT"])
PR=json.loads((CONTROL/"preregistration.json").read_text())
def write(p,v):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);t=p.with_suffix(p.suffix+".tmp");t.write_text(json.dumps(v,indent=2,sort_keys=True)+"\n");os.replace(t,p)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def stats(root):
 starts={};resp={};errors={}
 for p in root.rglob("requests.jsonl"):
  for l in p.read_text().splitlines():
   try:d=json.loads(l)
   except ValueError:continue
   cid=d.get("call_id")
   if not cid:continue
   if d.get("event") in ("request","request_started"):starts[cid]=d
   elif d.get("event")=="response":resp[cid]=d
   elif d.get("event")=="error":errors[cid]=d
 total={k:0 for k in ("prompt_tokens","prompt_cache_hit_tokens","prompt_cache_miss_tokens","completion_tokens")}
 missing=0
 for d in resp.values():
  u=d.get("usage") or d
  if all(isinstance(u.get(k),int) and not isinstance(u.get(k),bool) and u[k]>=0 for k in total) and u["prompt_cache_hit_tokens"]+u["prompt_cache_miss_tokens"]==u["prompt_tokens"]:
   for k in total:total[k]+=u[k]
  else:missing+=1
 missing+=len(set(starts)-set(resp))
 observed=total["prompt_cache_hit_tokens"]/total["prompt_tokens"] if total["prompt_tokens"] else None
 complete=bool(starts) and missing==0
 return {"physical_attempts":len(starts),"responses":len(resp),"error_count":len(errors),"missing_usage":missing,"known_usage_totals":total,"observed_cache_rate":observed,"exact_cache_rate":observed if complete else None,"target_met":complete and observed is not None and observed>=.95,"provider_stop":any(d.get("status_code",d.get("http_status")) in (401,402,403) for d in errors.values())}
def run(tool,pid,roundno):
 repo=ROOT/tool;out=repo/"experiments/cache-optimization-20261027"/("round-"+str(roundno))/pid
 receipt=out/"job.json";native=out/"native"
 if receipt.exists():return json.loads(receipt.read_text())
 if out.exists() and (out/"started.json").exists():raise RuntimeError("EXISTING_ATTEMPT_NOT_REPLAYED")
 out.mkdir(parents=True,exist_ok=True)
 python=os.environ["CACHE_"+tool.upper()+"_PYTHON"]
 code=subprocess.check_output(["git","-C",str(repo),"rev-parse","HEAD"],text=True).strip()
 cmd=[python,"-B","scripts/benchmark.py","--project-id",pid,"--output",str(native),"--prompt-layout","prefix_stable_v2"]
 if tool=="ACTaint":cmd+=["--compiler-map",os.environ["CACHE_COMPILER_MAP"],"--code-sha",code]
 write(out/"started.json",{"tool":tool,"project_id":pid,"round":roundno,"code_sha":code,"source_hashes":PR[tool]["sources"][pid],"started_utc":now(),"layout":"prefix_stable_v2","request_timeout":300,"job_timeout":1200,"retries":0})
 with (out/"stdout.txt").open("xb") as so,(out/"stderr.txt").open("xb") as se:
  child=subprocess.Popen(cmd,cwd=repo,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"),stdout=so,stderr=se,start_new_session=True)
  try:exitcode=child.wait(timeout=1200);status="FINISHED"
  except subprocess.TimeoutExpired:
   os.killpg(child.pid,signal.SIGTERM)
   try:child.wait(timeout=3)
   except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
   exitcode=child.returncode;status="TIMEOUT"
 d={"tool":tool,"project_id":pid,"round":roundno,"code_sha":code,"status":status,"exit_code":exitcode,"ended_utc":now(),"cache":stats(out)}
 write(receipt,d);return d
def main():
 lifecycle={"status":"DIAGNOSTICS_RUNNING_FULL_RUN_NOT_RESUMED","started_utc":now(),"tools":{}}
 write(CONTROL/"lifecycle.json",lifecycle)
 # Tools sequential; global max2. Round3 serial order is the last allowed scheduling optimization.
 for tool in ("GPTLens","ACTaint"):
  root=ROOT/tool/"experiments/cache-optimization-20261027";rounds=[]
  for no,ids in enumerate(PR[tool]["rounds"],1):
   with concurrent.futures.ThreadPoolExecutor(max_workers=1 if no==3 else 2) as pool:
    list(pool.map(lambda pid:run(tool,pid,no),ids))
   summary=stats(root/("round-"+str(no)));summary.update(round=no,project_ids=ids,concurrency=1 if no==3 else 2,round_finished_utc=now())
   write(root/("round-"+str(no)+"-cache.json"),summary);rounds.append(summary)
   if summary["target_met"] or summary["provider_stop"]:break
  lifecycle["tools"][tool]={"rounds":rounds,"status":"DIAGNOSTIC_COMPLETE","full_run_resumed":False}
  write(root/"cache-optimization-summary.json",lifecycle["tools"][tool])
  # Normalize only runtime paths in saved text, then seal all raw responses/logs.
  for p in root.rglob("*"):
   if p.is_file():
    raw=p.read_bytes();new=raw.replace(str(ROOT).encode(),b"[WORKSPACE]").replace(b"/home/shanzy/",b"[HOME]/")
    if new!=raw:p.write_bytes(new)
  files={str(p.relative_to(root)):sha(p) for p in root.rglob("*") if p.is_file() and p.name!="diagnostic-seal.json"}
  write(root/"diagnostic-seal.json",{"schema":"CACHE_OPTIMIZATION_DIAGNOSTIC_SEAL_V1","tool":tool,"files":files,"sealed_utc":now(),"full_run_resumed":False,"labels_read":False})
  write(CONTROL/"lifecycle.json",lifecycle)
 lifecycle["status"]="DIAGNOSTICS_FINISHED_REVIEW_REQUIRED_BEFORE_FULL_RUN";write(CONTROL/"lifecycle.json",lifecycle)
if __name__=="__main__":main()
