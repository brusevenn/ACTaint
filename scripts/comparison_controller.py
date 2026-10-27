"""Execute only native ACTaint/GPTLens/ASTRO, preserve all records, never score."""
from __future__ import annotations
from pathlib import Path
import concurrent.futures as futures
import datetime, hashlib, json, os, signal, subprocess, sys, threading, time, base64, uuid

ROOT = Path(os.environ["COMPARISON_WORKSPACE"]).resolve()
CONTROL = Path(os.environ["COMPARISON_CONTROL_ROOT"]).resolve()
RUN = "comparison-20261027-deepseek-high"
BRANCH = {"ACTaint":"main","GPTLens":"release","ASTRO":"main"}
PYTHON = {name:os.environ["COMPARISON_"+name.upper()+"_PYTHON"] for name in BRANCH}
LOCK = threading.Lock()
STOP = threading.Event()
TOKEN = None
USER = "x-access-token"

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha(p):
    h=hashlib.sha256()
    with Path(p).open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()

def write(p,value):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    t=p.with_name(p.name+".tmp-"+str(os.getpid())+"-"+uuid.uuid4().hex[:6])
    t.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    os.replace(t,p)

def git(repo,args,authenticated=False):
    env=dict(os.environ,GIT_TERMINAL_PROMPT="0")
    if authenticated:
        if not TOKEN:raise RuntimeError("GITHUB_CREDENTIAL_NOT_PRESENT")
        env.update(GIT_CONFIG_COUNT="1",GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                   GIT_CONFIG_VALUE_0="AUTHORIZATION: basic "+base64.b64encode((USER+":"+TOKEN).encode()).decode())
    r=subprocess.run(["git","-C",str(repo)]+args,env=env,text=True,capture_output=True,timeout=600)
    if r.returncode:
        msg=(r.stderr or r.stdout).replace(str(ROOT),"[WORKSPACE]")
        if TOKEN:msg=msg.replace(TOKEN,"[REDACTED]")
        raise RuntimeError("GIT_"+args[0]+"_FAILED:"+msg[:1000])
    return r.stdout.strip()

def jobs_for(tool,dataset):
    repo=ROOT/tool
    if dataset=="actoolbench154":
        manifest=repo/"datasets/actoolbench-cleaned-154/full/manifest.json"
        d=json.loads(manifest.read_text());groups={}
        for case in d["cases"]:
            group=groups.setdefault(case["project_id"],{"id":case["project_id"],"case_ids":[],"file_count":case["source_file_count"]})
            group["case_ids"].append(case["case_id"])
            hashes=[]
            source_root=manifest.parent/case["source_root"]
            for item in case["source_files"]:
                actual=sha(source_root/item["path"])
                if actual!=item["sha256"]:raise RuntimeError("INPUT_SOURCE_HASH_MISMATCH")
                hashes.append((item["path"],actual))
            config=manifest.parent/case["compile_config_path"]
            group["input_identity"]=hashlib.sha256(json.dumps({"source_files":hashes,"compile_config_sha256":sha(config)},sort_keys=True).encode()).hexdigest()
            group["manifest_sha256"]=sha(manifest)
        assert len(d["cases"])==154 and len(groups)==121
        return list(sorted(groups.values(),key=lambda x:x["id"])),manifest
    manifest=repo/"datasets/smartbugs-wild-actaint/subsets/actaint-usable-533-v1/input-manifest.json"
    d=json.loads(manifest.read_text())
    cases=d.get("cases",d.get("records",[]))
    assert len(cases)==533
    jobs=[]
    for c in cases:
        rel=c.get("source_path") or c.get("path") or c.get("source_file")
        if not isinstance(rel,str):raise RuntimeError("SMARTBUGS_SOURCE_PATH_MISSING")
        source=manifest.parent/rel
        if not source.is_file():source=manifest.parent/"sources"/Path(rel).name
        actual=sha(source)
        expected=c.get("source_sha256") or c.get("sha256")
        if expected and actual!=expected:raise RuntimeError("SMARTBUGS_SOURCE_HASH_MISMATCH")
        jobs.append({"id":c["case_id"],"case_ids":[c["case_id"]],"file_count":1,"input_identity":actual,"manifest_sha256":sha(manifest)})
    return jobs,manifest

def redact_file(p):
    # Preserve bytes unless a runtime-only personal workspace path occurs.
    try:raw=p.read_bytes()
    except OSError:return
    changed=raw
    for source,replacement in ((str(ROOT).encode(),b"[WORKSPACE]"),
                               (b"/home/shanzy/",b"[HOME]/")):
        changed=changed.replace(source,replacement)
    if changed!=raw:
        audit={"path":p.name,"original_sha256":hashlib.sha256(raw).hexdigest(),
               "saved_sha256":hashlib.sha256(changed).hexdigest(),"policy":"PERSONAL_RUNTIME_PATHS_REPLACED"}
        p.write_bytes(changed)
        write(p.with_name(p.name+".path-normalization.json"),audit)

def request_stats(directory):
    starts={};responses={};errors={};invalid=[];legacy=0
    for p in Path(directory).rglob("*.jsonl"):
        if "request" not in p.name.lower():continue
        for i,line in enumerate(p.read_text(errors="replace").splitlines(),1):
            try:r=json.loads(line)
            except json.JSONDecodeError:
                invalid.append(str(p.relative_to(directory))+":"+str(i));continue
            event=r.get("event",r.get("status"))
            cid=r.get("call_id") or r.get("attempt_id")
            if event in ("request","request_started"):
                cid=cid or str(p.relative_to(directory))+":"+str(i)
                starts[cid]=r
            elif event in ("response","complete","completed"):
                cid=cid or r.get("request_id") or str(p.relative_to(directory))+":"+str(i)
                responses[cid]=r
                if not r.get("call_id") and not r.get("attempt_id"):legacy+=1
            elif event in ("error","failed"):
                cid=cid or str(p.relative_to(directory))+":"+str(i)
                errors[cid]=r
            code=r.get("status_code",r.get("http_status"))
            if code in (401,402,403):STOP.set()
    totals={"prompt_tokens":0,"completion_tokens":0,"prompt_cache_hit_tokens":0,"prompt_cache_miss_tokens":0}
    missing=0
    for cid,r in responses.items():
        u=r.get("usage") or r
        raw=r.get("raw_response") or {}
        if not u.get("prompt_tokens") and isinstance(raw,dict):u=raw.get("usage") or u
        vals=[u.get(k) for k in totals]
        good=all(isinstance(v,int) and not isinstance(v,bool) and v>=0 for v in vals)
        if good and vals[2]+vals[3]==vals[0]:
            for k,v in zip(totals,vals):totals[k]+=v
        else:missing+=1
    unknown_starts=set(starts)-set(responses)-set(errors)
    missing+=len(errors)+len(unknown_starts)
    attempts=len(starts) if starts else len(responses)+len(errors)
    observed=totals["prompt_cache_hit_tokens"]/totals["prompt_tokens"] if totals["prompt_tokens"] else None
    complete=bool(attempts) and not(missing or invalid or legacy) and len(responses)==attempts
    return {"physical_attempts":attempts,"response_count":len(responses),"error_count":len(errors),
            "inflight_or_missing_terminal_count":len(unknown_starts),"missing_usage_attempts":missing,
            "invalid_log_rows":invalid,"legacy_missing_start_count":legacy,"known_usage_totals":totals,
            "observed_token_weighted_cache_hit_rate":observed,
            "complete_token_weighted_cache_hit_rate":observed if complete else None,
            "usage_complete":complete,"target_95_established":complete and observed is not None and observed>=.95}

def native_command(tool,dataset,job,target,layout):
    # Native wrappers and their exact CLI are reviewed/frozen in runtime-cli.json.
    cfg=json.loads((CONTROL/"runtime-cli.json").read_text())[tool]
    replace={"id":job["id"],"dataset":dataset,"output":str(target),"layout":layout,
             "compiler_map":str(CONTROL/"compiler-map.local.json"),"python":PYTHON[tool],"code_sha":git(ROOT/tool,["rev-parse","HEAD"])}
    return [part.format(**replace) for part in cfg["command"]]

def identity_for(tool,dataset,job,code_sha):
    return {"tool":tool,"dataset":dataset,"id":job["id"],"case_ids":job["case_ids"],"code_sha":code_sha,"input_identity":job.get("input_identity"),"manifest_sha256":job.get("manifest_sha256")}

def validate_receipt(tool,dataset,job,code_sha,row):
    if any(row.get(k)!=v for k,v in identity_for(tool,dataset,job,code_sha).items()):
        raise RuntimeError("PAID_RECEIPT_INPUT_IDENTITY_MISMATCH")

def validate_prereg(preg,jobs):
    flat=[key for ids in preg["rounds"] for key in ids]
    if len(preg["rounds"])>3 or len(flat)!=len(set(flat)) or not set(flat)<=set(j["id"] for j in jobs):
        raise RuntimeError("DIAGNOSTIC_PREREGISTRATION_NOT_DISTINCT_OR_INVALID")

def run_job(tool,dataset,job,layout,phase,code_sha):
    repo=ROOT/tool;out=repo/"experiments"/RUN/dataset
    target=out/"jobs"/job["id"];receipt=target/"controller-result.json"
    if receipt.exists():
        row=json.loads(receipt.read_text())
        expected={"tool":tool,"dataset":dataset,"id":job["id"],"case_ids":job["case_ids"],"code_sha":code_sha,"input_identity":job.get("input_identity"),"manifest_sha256":job.get("manifest_sha256"),"prompt_layout":layout}
        if any(row.get(k)!=v for k,v in expected.items()):raise RuntimeError("PAID_OUTPUT_IDENTITY_MISMATCH")
        return row
    target.mkdir(parents=True,exist_ok=True)
    marker=target/"controller-start.json"
    if marker.exists():
        prior=json.loads(marker.read_text())
        expected={"tool":tool,"dataset":dataset,"id":job["id"],"case_ids":job["case_ids"],"code_sha":code_sha,"input_identity":job.get("input_identity"),"manifest_sha256":job.get("manifest_sha256"),"prompt_layout":layout}
        if any(prior.get(k)!=v for k,v in expected.items()):raise RuntimeError("UNFINISHED_OUTPUT_IDENTITY_MISMATCH")
        row={**identity_for(tool,dataset,job,code_sha),"status":"INTERRUPTED_NOT_RETRIED","phase":phase,"prompt_layout":layout}
        write(receipt,row);return row
    if tool!="ASTRO" and STOP.is_set():
        row={**identity_for(tool,dataset,job,code_sha),"status":"NOT_RUN_PROVIDER_STOP","phase":phase,"prompt_layout":layout}
        write(receipt,row);return row
    command=native_command(tool,dataset,job,target,layout)
    write(marker,{"tool":tool,"dataset":dataset,"input_identity":job.get("input_identity"),"manifest_sha256":job.get("manifest_sha256"),"id":job["id"],"case_ids":job["case_ids"],"code_sha":code_sha,"phase":phase,"prompt_layout":layout,"started_utc":now(),"file_count":job["file_count"],"timeout_seconds":1200})
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
    start=time.monotonic()
    with (target/"controller.stdout.txt").open("xb") as stdout,(target/"controller.stderr.txt").open("xb") as stderr:
        p=subprocess.Popen(command,cwd=repo,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
        try:rc=p.wait(timeout=1200);status="COMPLETED" if rc==0 else "TOOL_ERROR"
        except subprocess.TimeoutExpired:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
            rc=p.returncode;status="TIMEOUT"
    for f in (target/"controller.stdout.txt",target/"controller.stderr.txt"):redact_file(f)
    native=target/"project-result.json"
    native_status=None
    if native.exists():
        n=json.loads(native.read_text());native_status=n.get("status")
        if native_status not in ("COMPLETED","complete","COMPLETE"):status=native_status or status
    row={"tool":tool,"dataset":dataset,"input_identity":job.get("input_identity"),"manifest_sha256":job.get("manifest_sha256"),"id":job["id"],"case_ids":job["case_ids"],"status":status,"native_status":native_status,
         "exit_code":rc,"code_sha":code_sha,"phase":phase,"prompt_layout":layout,"ended_utc":now(),
         "elapsed_seconds":round(time.monotonic()-start,3),"file_count":job["file_count"],
         "native_result_present":native.exists()}
    if tool!="ASTRO":row["request_accounting"]=request_stats(target)
    write(receipt,row)
    with LOCK:print(json.dumps({"tool":tool,"dataset":dataset,"id":job["id"],"status":status}),flush=True)
    return row

def run_set(tool,dataset,jobs,layout,phase,code_sha):
    with futures.ThreadPoolExecutor(max_workers=2) as pool:
        return list(pool.map(lambda j:run_job(tool,dataset,j,layout,phase,code_sha),jobs))

def seal_dataset(tool,dataset,jobs,manifest,code_sha):
    out=ROOT/tool/"experiments"/RUN/dataset
    frozen=out/"predictions-seal.json"
    if frozen.exists():
        value=json.loads(frozen.read_text())
        unsigned={k:v for k,v in value.items() if k!="seal_sha256"}
        actual=hashlib.sha256(json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
        if actual!=value["seal_sha256"]:raise RuntimeError("EXISTING_SEAL_INVALID")
        for rel,digest in value["files"].items():
            if not (out/rel).is_file() or sha(out/rel)!=digest:raise RuntimeError("SEALED_BYTES_CHANGED")
        if value.get("tool")!=tool or value.get("dataset")!=dataset or value.get("manifest_sha256")!=sha(manifest) or value.get("code_sha")!=code_sha:
            raise RuntimeError("EXISTING_SEAL_RUN_IDENTITY_MISMATCH")
        actual_paths={str(p.relative_to(out)) for p in out.rglob("*") if p.is_file() and p.name!="predictions-seal.json" and ".tmp-" not in p.name}
        if actual_paths!=set(value["files"]):raise RuntimeError("EXISTING_SEAL_EXTRA_OR_MISSING_PATHS")
        data=json.loads((out/"case-records.json").read_text())
        expected_ids=[cid for job in jobs for cid in job["case_ids"]]
        actual_ids=[r["case_id"] for r in data["records"]]
        if sorted(actual_ids)!=sorted(expected_ids) or len(actual_ids)!=len(set(actual_ids)):
            raise RuntimeError("EXISTING_SEAL_CASE_IDENTITY_MISMATCH")
        cache=json.loads((out/"cache-statistics.json").read_text())
        return {"dataset":dataset,"case_count":data["case_count"],"group_count":data["execution_group_count"],"cache":cache,"seal_reused_unchanged":True,"statuses":{st:sum(r["status"]==st for r in data["records"]) for st in sorted({r["status"] for r in data["records"]})}}
    records=[]
    for job in jobs:
        r=json.loads((out/"jobs"/job["id"]/"controller-result.json").read_text())
        validate_receipt(tool,dataset,job,code_sha,r)
        for cid in job["case_ids"]:
            records.append({"case_id":cid,"execution_group_id":job["id"],"status":r["status"],
                            "execution_artifact":"jobs/"+job["id"],"shared_project_case_ids":job["case_ids"],
                            "file_count":job["file_count"],"phase":r["phase"],"prompt_layout":r["prompt_layout"]})
    assert len(records)==(154 if dataset=="actoolbench154" else 533)
    assert len({r["case_id"] for r in records})==len(records)
    write(out/"case-records.json",{"tool":tool,"dataset":dataset,"case_count":len(records),"execution_group_count":len(jobs),"records":records,"scoring_performed":False})
    stats=request_stats(out/"jobs") if tool!="ASTRO" else {"llm_used":False,"physical_attempts":0}
    write(out/"cache-statistics.json",stats)
    inventory={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob("*")) if p.is_file() and p.name!="predictions-seal.json" and ".tmp-" not in p.name}
    seal={"schema":"NATIVE_COMPARISON_PREDICTION_SEAL_V1","tool":tool,"dataset":dataset,"code_sha":code_sha,
          "manifest_sha256":sha(manifest),"case_count":len(records),"group_count":len(jobs),"files":inventory,
          "sealed_utc":now(),"ground_truth_read":False,"scoring_performed":False}
    seal["seal_sha256"]=hashlib.sha256(json.dumps(seal,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    write(out/"predictions-seal.json",seal)
    return {"dataset":dataset,"case_count":len(records),"group_count":len(jobs),"cache":stats,"statuses":{s:sum(r["status"]==s for r in records) for s in sorted({r["status"] for r in records})}}

def execute_tool(tool):
    repo=ROOT/tool
    result_root=repo/"experiments"/RUN
    code_inventory=result_root/"execution-code-inventory.json"
    if code_inventory.exists():
        prior=json.loads(code_inventory.read_text())
        for rel,digest in prior["files"].items():
            if not (repo/rel).is_file() or sha(repo/rel)!=digest:raise RuntimeError("EXECUTION_CODE_BYTES_CHANGED")
        code_sha=prior["code_sha"]
    else:
        code_sha=git(repo,["rev-parse","HEAD"])
        excluded=("experiments/","datasets/","data/","dataset/","logs/","case_result/","experiment/","sol_name/")
        paths=[rel for rel in git(repo,["ls-files"]).splitlines() if not rel.startswith(excluded) and Path(rel).name!=".env"]
        write(code_inventory,{"code_sha":code_sha,"files":{rel:sha(repo/rel) for rel in paths if (repo/rel).is_file()},"created_utc":now()})
    datasets=("actoolbench154","smartbugs533") if tool=="ASTRO" else ("actoolbench154",)
    summaries=[]
    for dataset in datasets:
        jobs,manifest=jobs_for(tool,dataset)
        out=result_root/dataset;out.mkdir(parents=True,exist_ok=True)
        if (out/"predictions-seal.json").exists():
            summaries.append(seal_dataset(tool,dataset,jobs,manifest,code_sha))
            continue
        if (out/"run-plan.json").exists():
            prior=json.loads((out/"run-plan.json").read_text())
            if prior.get("code_sha")!=code_sha or prior.get("jobs")!=jobs or prior.get("manifest_sha256")!=sha(manifest):
                raise RuntimeError("EXISTING_RUN_PLAN_IDENTITY_MISMATCH")
        else:
            write(out/"run-plan.json",{"tool":tool,"dataset":dataset,"code_sha":code_sha,"case_count":sum(len(j["case_ids"]) for j in jobs),"jobs":jobs,"manifest_sha256":sha(manifest),"model_protocol":{"model":"deepseek-flash","reasoning_effort":"high","thinking":{"type":"enabled"},"max_tokens":65536,"request_timeout":300,"case_timeout":1200,"automatic_retries":0,"global_llm_concurrency":2},"started_utc":now()})
        if tool!="ASTRO":
            preg=json.loads((CONTROL/"diagnostic-preregistration.json").read_text())[tool]
            validate_prereg(preg,jobs)
            layout="baseline"
            for n,ids in enumerate(preg["rounds"],1):
                layout="baseline" if n==1 else "prefix_stable"
                selected=[j for key in ids for j in jobs if j["id"]==key]
                if len(selected)!=len(ids):raise RuntimeError("DIAGNOSTIC_IDENTITY_MISMATCH")
                run_set(tool,dataset,selected,layout,"diagnostic-round-"+str(n),code_sha)
                # Measure only the unique projects of this diagnostic round, not pooled tools/rounds.
                temporary=out/("diagnostic-round-"+str(n))
                temporary.mkdir(exist_ok=True)
                for j in selected:
                    source=out/"jobs"/j["id"]
                    link=temporary/j["id"]
                    if not link.exists():link.symlink_to(source,target_is_directory=True)
                # Path.rglob does not traverse linked dirs; concatenate all selected usage via audit adapter.
                individual=[request_stats(out/"jobs"/j["id"]) for j in selected]
                total={k:sum(s["known_usage_totals"][k] for s in individual) for k in individual[0]["known_usage_totals"]}
                observed=total["prompt_cache_hit_tokens"]/total["prompt_tokens"] if total["prompt_tokens"] else None
                complete=any(s["physical_attempts"] for s in individual) and all(s["usage_complete"] or s["physical_attempts"]==0 for s in individual)
                report={"round":n,"project_ids":ids,"prompt_layout":layout,"projects":individual,"known_usage_totals":total,"observed_token_weighted_cache_hit_rate":observed,"usage_complete":complete,"target_95_established":complete and observed is not None and observed>=.95,"distinct_samples":True}
                write(out/("cache-diagnostic-round-"+str(n)+".json"),report)
                for link in temporary.iterdir():link.unlink()
                temporary.rmdir()
                if report["target_95_established"] or STOP.is_set():break
            diag_ids=set()
            for job in jobs:
                existing=out/"jobs"/job["id"]/"controller-result.json"
                if existing.exists():
                    validate_receipt(tool,dataset,job,code_sha,json.loads(existing.read_text()))
                    diag_ids.add(job["id"])
            run_set(tool,dataset,[j for j in jobs if j["id"] not in diag_ids],layout,"formal",code_sha)
        else:run_set(tool,dataset,jobs,"not_applicable","formal",code_sha)
        summaries.append(seal_dataset(tool,dataset,jobs,manifest,code_sha))
    write(result_root/"execution-summary.json",{"tool":tool,"code_sha":code_sha,"datasets":summaries,"finished_utc":now(),"scoring_performed":False})
    return summaries

def abort_tool(tool, reason):
    summaries=[]
    datasets=("actoolbench154","smartbugs533") if tool=="ASTRO" else ("actoolbench154",)
    code_sha=git(ROOT/tool,["rev-parse","HEAD"])
    for dataset in datasets:
        jobs,manifest=jobs_for(tool,dataset)
        for job in jobs:
            target=ROOT/tool/"experiments"/RUN/dataset/"jobs"/job["id"]
            receipt=target/"controller-result.json"
            if not receipt.exists():
                write(receipt,{**identity_for(tool,dataset,job,code_sha),"status":"INTERRUPTED_NOT_RETRIED" if (target/"controller-start.json").exists() else "NOT_RUN_CONTROLLER_ERROR","phase":"controller_error","prompt_layout":"not_executed","reason":reason})
        summaries.append(seal_dataset(tool,dataset,jobs,manifest,code_sha))
    return summaries

def credential_scan(repo, paths):
    values=[]
    envfile=repo/".env"
    if envfile.is_file():
        for line in envfile.read_text().splitlines():
            if "=" not in line or line.lstrip().startswith("#"):continue
            k,v=line.split("=",1)
            if any(w in k.upper() for w in ("KEY","TOKEN","PASSWORD","SECRET")):
                v=v.strip().strip(chr(34)).strip(chr(39))
                if len(v)>=12:values.append(v.encode())
    if TOKEN:values.append(TOKEN.encode())
    hits=[]
    for p in paths:
        if p.is_file():
            raw=p.read_bytes()
            if any(v in raw for v in values):hits.append(str(p.relative_to(repo)))
    if hits:raise RuntimeError("CREDENTIAL_ECHO_DETECTED:"+",".join(hits[:10]))

def publish(tool):
    repo=ROOT/tool;out=repo/"experiments"/RUN
    if not TOKEN:return {"status":"PUSH_PENDING_NO_CREDENTIAL"}
    branch=BRANCH[tool]
    credential_scan(repo,list(out.rglob("*")))
    git(repo,["fetch","origin",branch],True)
    origin=git(repo,["rev-parse","origin/"+branch])
    head=git(repo,["rev-parse","HEAD"])
    if origin!=head:raise RuntimeError("REMOTE_CHANGED_PUSH_REQUIRES_INTEGRATION")
    # Only this exact result namespace can be staged by the unattended publisher.
    if git(repo,["diff","--cached","--name-only"]):raise RuntimeError("PREEXISTING_STAGED_CHANGES_NOT_PUBLISHED")
    git(repo,["add","--","experiments/"+RUN])
    staged=git(repo,["diff","--cached","--name-only"]).splitlines()
    if any(not path.startswith("experiments/"+RUN+"/") for path in staged):
        raise RuntimeError("UNRELATED_STAGED_PATH_REFUSED")
    if not git(repo,["diff","--cached","--name-only"]):return {"status":"NO_RESULT_DIFF"}
    git(repo,["commit","-m","Archive native "+tool+" comparison results with complete case accounting"])
    commit=git(repo,["rev-parse","HEAD"])
    git(repo,["push","origin","HEAD:"+branch],True)
    remote=git(repo,["ls-remote","origin","refs/heads/"+branch],True).split()[0]
    if remote!=commit:raise RuntimeError("REMOTE_HEAD_MISMATCH")
    # Fresh remote object fetch, never a clone referencing the local object store.
    fresh=CONTROL/"remote-readback"/(tool+"-"+commit[:12])
    if not fresh.exists():
        git(repo,["clone","--filter=blob:none","--no-checkout","--single-branch","--branch",branch,
                  "https://github.com/brusevenn/"+tool+".git",str(fresh)],True)
        git(fresh,["config","core.autocrlf","false"])
        git(fresh,["sparse-checkout","init","--cone"])
        git(fresh,["sparse-checkout","set","experiments/"+RUN])
        git(fresh,["checkout","--detach",commit],True)
    receipt=out/"remote-delivery-receipt.json"
    files=[p for p in out.rglob("*") if p.is_file() and p!=receipt and ".tmp-" not in p.name]
    missing=[];mismatch=[];size=0
    for local in files:
        rel=local.relative_to(repo);remote_file=fresh/rel
        if not remote_file.is_file():missing.append(str(rel))
        elif sha(remote_file)!=sha(local):mismatch.append(str(rel))
        size+=local.stat().st_size
    if missing or mismatch:raise RuntimeError("REMOTE_BYTE_READBACK_FAILED")
    write(receipt,{"schema":"NATIVE_COMPARISON_REMOTE_BYTE_READBACK_V1","tool":tool,"archived_commit":commit,
                   "verified_files":len(files),"verified_bytes":size,"missing_files":missing,
                   "mismatched_files":mismatch,"skipped_files":0,"verified_utc":now(),
                   "method":"FRESH_GITHUB_PARTIAL_CLONE_NO_LOCAL_REFERENCE","scoring_performed":False})
    if git(repo,["diff","--cached","--name-only"]):raise RuntimeError("STAGED_PATHS_PRESENT_BEFORE_RECEIPT")
    git(repo,["add","--",str(receipt.relative_to(repo))])
    git(repo,["commit","-m","Verify independent "+tool+" result byte readback"])
    final=git(repo,["rev-parse","HEAD"])
    git(repo,["push","origin","HEAD:"+branch],True)
    remote=git(repo,["ls-remote","origin","refs/heads/"+branch],True).split()[0]
    if remote!=final:raise RuntimeError("RECEIPT_REMOTE_HEAD_MISMATCH")
    return {"status":"PUSHED_AND_BYTE_VERIFIED","archived_commit":commit,"commit":final,"branch":branch,
            "verified_files":len(files),"verified_bytes":size}

def main():
    global TOKEN,USER
    auth=json.load(sys.stdin) if "--credential-stdin" in sys.argv else {}
    TOKEN=auth.get("password");USER=auth.get("username") or USER
    state={"schema":"THREE_TOOL_COMPARISON_LIFECYCLE_V1","scope":{"ACTaint_ACToolBench":154,"GPTLens_ACToolBench":154,"ASTRO_ACToolBench":154,"ASTRO_SmartBugs":533},"status":"RUNNING","started_utc":now(),"tools":{}}
    def work(tool):
        try:
            summary=execute_tool(tool)
            try:delivery=publish(tool)
            except Exception as delivery_error:
                message=str(delivery_error).replace(str(ROOT),"[WORKSPACE]")
                if TOKEN:message=message.replace(TOKEN,"[REDACTED]")
                delivery={"status":"PUSH_PENDING_ERROR","error_type":type(delivery_error).__name__,"reason":message[:1000]}
            row={"status":"SEALED","datasets":summary,"delivery":delivery}
        except Exception as e:
            error=str(e).replace(str(ROOT),"[WORKSPACE]")
            if TOKEN:error=error.replace(TOKEN,"[REDACTED]")
            row={"status":"ERROR","error_type":type(e).__name__,"reason":error[:2000]}
            try:
                row["datasets"]=abort_tool(tool,error[:1000])
            except Exception as audit_error:
                row["accounting_error_type"]=type(audit_error).__name__
        with LOCK:
            state["tools"][tool]=row;write(CONTROL/"lifecycle.json",state)
    write(CONTROL/"lifecycle.json",state)
    static=threading.Thread(target=work,args=("ASTRO",));static.start()
    # Two LLM projects max across both LLM tools: tools run sequentially.
    for tool in ("ACTaint","GPTLens"):work(tool)
    static.join()
    state["status"]="FINISHED_WITH_RECORDED_TOOL_DISPOSITIONS";state["finished_utc"]=now()
    write(CONTROL/"lifecycle.json",state)
    TOKEN=None
if __name__=="__main__":main()
