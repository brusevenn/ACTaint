import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
os.environ.setdefault("COMPARISON_WORKSPACE",str(Path(__file__).resolve().parents[2]))
os.environ.setdefault("COMPARISON_CONTROL_ROOT",str(Path(__file__).resolve().parent))
for name in ("ACTAINT","GPTLENS","ASTRO"):os.environ.setdefault("COMPARISON_"+name+"_PYTHON","python3")
candidate=Path(__file__).with_name("comparison_controller.py")
if not candidate.exists():candidate=Path(__file__).resolve().parents[1]/"scripts/comparison_controller.py"
spec=importlib.util.spec_from_file_location("comparison_controller",candidate)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class TestController(unittest.TestCase):
    def stats(self,rows):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"requests.jsonl";p.write_text("\n".join(json.dumps(r) for r in rows)+"\n")
            return m.request_stats(Path(td))
    def test_distinct_requests_true_token_rate(self):
        r=self.stats([{"event":"request","call_id":"one"},{"event":"response","call_id":"one","prompt_tokens":100,"completion_tokens":4,"prompt_cache_hit_tokens":96,"prompt_cache_miss_tokens":4}])
        self.assertEqual(r["physical_attempts"],1);self.assertEqual(r["complete_token_weighted_cache_hit_rate"],.96);self.assertTrue(r["target_95_established"])
    def test_inflight_attempt_keeps_whole_rate_unknown(self):
        r=self.stats([{"event":"request","call_id":"one"},{"event":"response","call_id":"one","usage":{"prompt_tokens":100,"completion_tokens":3,"prompt_cache_hit_tokens":96,"prompt_cache_miss_tokens":4}},{"event":"request","call_id":"two"}])
        self.assertEqual(r["physical_attempts"],2);self.assertIsNone(r["complete_token_weighted_cache_hit_rate"]);self.assertEqual(r["inflight_or_missing_terminal_count"],1)
    def test_error_is_not_no_findings_and_usage_unknown(self):
        r=self.stats([{"event":"request","call_id":"one"},{"event":"error","call_id":"one","status_code":500}])
        self.assertEqual(r["error_count"],1);self.assertFalse(r["usage_complete"])
    def test_invalid_usage_invariant(self):
        r=self.stats([{"event":"request","call_id":"one"},{"event":"response","call_id":"one","prompt_tokens":100,"completion_tokens":4,"prompt_cache_hit_tokens":99,"prompt_cache_miss_tokens":4}])
        self.assertEqual(r["missing_usage_attempts"],1);self.assertIsNone(r["complete_token_weighted_cache_hit_rate"])
    def test_no_calls_not_fake_100_percent(self):
        r=self.stats([]);self.assertFalse(r["target_95_established"]);self.assertIsNone(r["complete_token_weighted_cache_hit_rate"])
    def test_current_fixed_denominator_and_shared_groups(self):
        for tool in ("ACTaint","GPTLens","ASTRO"):
            jobs,manifest=m.jobs_for(tool,"actoolbench154")
            self.assertEqual(len(jobs),121);self.assertEqual(sum(len(j["case_ids"]) for j in jobs),154);self.assertEqual(sum(j["file_count"] for j in jobs),694)
        jobs,_=m.jobs_for("ASTRO","smartbugs533");self.assertEqual(len(jobs),533)
    def test_receipt_reuse_no_subprocess_no_retry(self):
        with tempfile.TemporaryDirectory() as td,patch.object(m,"ROOT",Path(td)):
            p=Path(td)/"ACTaint"/"experiments"/m.RUN/"actoolbench154"/"jobs"/"p"/"controller-result.json"
            p.parent.mkdir(parents=True);p.write_text(json.dumps({**m.identity_for("ACTaint","actoolbench154",{"id":"p","case_ids":["c"],"file_count":1},"frozen"),"prompt_layout":"baseline","status":"ERROR"}))
            with patch.object(m.subprocess,"Popen") as child:
                r=m.run_job("ACTaint","actoolbench154",{"id":"p","case_ids":["c"],"file_count":1},"baseline","formal","frozen")
                child.assert_not_called();self.assertEqual(r["status"],"ERROR")
    def test_unfinished_paid_group_not_replayed(self):
        with tempfile.TemporaryDirectory() as td,patch.object(m,"ROOT",Path(td)):
            p=Path(td)/"ACTaint"/"experiments"/m.RUN/"actoolbench154"/"jobs"/"p"/"controller-start.json"
            p.parent.mkdir(parents=True);p.write_text(json.dumps({**m.identity_for("ACTaint","actoolbench154",{"id":"p","case_ids":["c"],"file_count":1},"frozen"),"prompt_layout":"baseline"}))
            with patch.object(m.subprocess,"Popen") as child:
                r=m.run_job("ACTaint","actoolbench154",{"id":"p","case_ids":["c"],"file_count":1},"baseline","formal","frozen")
                child.assert_not_called();self.assertEqual(r["status"],"INTERRUPTED_NOT_RETRIED")
    def test_started_alias_remains_missing_attempt(self):
        r=self.stats([{"event":"request_started","call_id":"one"}])
        self.assertEqual(r["physical_attempts"],1);self.assertEqual(r["inflight_or_missing_terminal_count"],1);self.assertFalse(r["usage_complete"])
    def test_preregistered_project_repeats_refused(self):
        with self.assertRaisesRegex(RuntimeError,"NOT_DISTINCT"):
            m.validate_prereg({"rounds":[["p"],["p"]]},[{"id":"p"}])
    def test_changed_input_receipt_refused(self):
        job={"id":"p","case_ids":["c"],"file_count":1,"input_identity":"new"}
        stale={**m.identity_for("ACTaint","actoolbench154",job,"frozen"),"input_identity":"old"}
        with self.assertRaisesRegex(RuntimeError,"IDENTITY_MISMATCH"):m.validate_receipt("ACTaint","actoolbench154",job,"frozen",stale)
    def test_publisher_refuses_existing_staged_paths(self):
        with tempfile.TemporaryDirectory() as td,patch.object(m,"ROOT",Path(td)),patch.object(m,"TOKEN","sentinel"),patch.object(m,"credential_scan"):
            calls=[]
            def fake(repo,args,authenticated=False):
                calls.append(args)
                if args[:2]==["rev-parse","origin/main"] or args==["rev-parse","HEAD"]:return "same"
                if args==["diff","--cached","--name-only"]:return "unrelated.py"
                return ""
            with patch.object(m,"git",side_effect=fake):
                with self.assertRaisesRegex(RuntimeError,"PREEXISTING_STAGED"):m.publish("ACTaint")
            self.assertFalse(any(x[0] in ("add","commit","push") for x in calls))
    def test_publisher_does_not_stage_outside_results(self):
        with tempfile.TemporaryDirectory() as td,patch.object(m,"ROOT",Path(td)),patch.object(m,"TOKEN","sentinel"),patch.object(m,"credential_scan"):
            calls=[];index_calls=[0]
            def fake(repo,args,authenticated=False):
                calls.append(args)
                if args[:2]==["rev-parse","origin/main"] or args==["rev-parse","HEAD"]:return "same"
                if args==["diff","--cached","--name-only"]:
                    index_calls[0]+=1
                    return "" if index_calls[0]==1 else "src/changed.py"
                return ""
            with patch.object(m,"git",side_effect=fake):
                with self.assertRaisesRegex(RuntimeError,"UNRELATED_STAGED_PATH"):m.publish("ACTaint")
            self.assertFalse(any(x[0] in ("commit","push") for x in calls))
    def make_seal(self,td):
        root=Path(td);manifest=root/"manifest.json";manifest.write_text("{}")
        job={"id":"p","case_ids":["c"+str(i) for i in range(154)],"file_count":1,"input_identity":"input","manifest_sha256":m.sha(manifest)}
        out=root/"ACTaint"/"experiments"/m.RUN/"actoolbench154"/"jobs"/"p"
        out.mkdir(parents=True)
        row={**m.identity_for("ACTaint","actoolbench154",job,"frozen"),"status":"ERROR","phase":"formal","prompt_layout":"baseline"}
        (out/"controller-result.json").write_text(json.dumps(row))
        return manifest,job
    def test_existing_seal_reuse_never_rewrites_bytes(self):
        with tempfile.TemporaryDirectory() as td,patch.object(m,"ROOT",Path(td)):
            manifest,job=self.make_seal(td)
            m.seal_dataset("ACTaint","actoolbench154",[job],manifest,"frozen")
            out=Path(td)/"ACTaint"/"experiments"/m.RUN/"actoolbench154"
            before={str(p):m.sha(p) for p in out.rglob("*") if p.is_file()}
            m.seal_dataset("ACTaint","actoolbench154",[job],manifest,"frozen")
            self.assertEqual(before,{str(p):m.sha(p) for p in out.rglob("*") if p.is_file()})
    def test_extra_unsealed_file_refused(self):
        with tempfile.TemporaryDirectory() as td,patch.object(m,"ROOT",Path(td)):
            manifest,job=self.make_seal(td)
            m.seal_dataset("ACTaint","actoolbench154",[job],manifest,"frozen")
            out=Path(td)/"ACTaint"/"experiments"/m.RUN/"actoolbench154"
            (out/"extra.txt").write_text("unsealed")
            with self.assertRaisesRegex(RuntimeError,"EXTRA_OR_MISSING_PATHS"):m.seal_dataset("ACTaint","actoolbench154",[job],manifest,"frozen")
    def test_manifest_change_refuses_sealed_reuse(self):
        with tempfile.TemporaryDirectory() as td,patch.object(m,"ROOT",Path(td)):
            manifest,job=self.make_seal(td)
            m.seal_dataset("ACTaint","actoolbench154",[job],manifest,"frozen")
            manifest.write_text("changed")
            with self.assertRaisesRegex(RuntimeError,"RUN_IDENTITY"):m.seal_dataset("ACTaint","actoolbench154",[job],manifest,"frozen")
if __name__=="__main__":unittest.main()
