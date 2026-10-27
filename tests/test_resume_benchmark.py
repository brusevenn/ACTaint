import importlib.util, json, tempfile, unittest
from pathlib import Path

MODULE_PATH=Path(__file__).resolve().parents[1]/"scripts/resume_benchmark.py"
spec=importlib.util.spec_from_file_location("resume_benchmark",MODULE_PATH)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ResumePlanTests(unittest.TestCase):
 def test_denominators_sources_and_paid_no_replay(self):
  data=module.build_plan()
  self.assertEqual((data["case_count"],data["project_group_count"]),(154,121))
  self.assertFalse(data["ground_truth_read"]);self.assertFalse(data["labels_in_detector_input"])
  self.assertFalse(data["execution_launched"]);self.assertFalse(data["duplicate_samples_replayed"])
  self.assertEqual(len({r["case_id"] for r in data["case_records"]}),154)
  self.assertTrue(all(job["source_hashes"] for job in data["jobs"]))
  self.assertTrue(all(job["disposition"].startswith("REUSE_") for job in data["jobs"] if job["prior_request_attempts"]>0))
  self.assertTrue(all(job["disposition"]=="ELIGIBLE_ZERO_REQUEST_RESUME" or job["prior_request_attempts"]>0 or job["disposition"].startswith("REUSE_") for job in data["jobs"]))

 def test_auth_or_payment_error_stops_new_queue(self):
  with tempfile.TemporaryDirectory() as temp:
   log=Path(temp)/"requests.jsonl"
   log.write_text(json.dumps({"event":"error","status_code":402})+"\n")
   self.assertTrue(module._stop_for_provider_error(temp))
   log.write_text(json.dumps({"event":"error","status_code":"403"})+"\n")
   self.assertTrue(module._stop_for_provider_error(temp))

 def test_corrupt_new_request_ledger_fails_closed(self):
  with tempfile.TemporaryDirectory() as temp:
   (Path(temp)/"requests.jsonl").write_text("{bad json\n")
   self.assertTrue(module._stop_for_provider_error(temp))

 def test_path_normalization_preserves_hash_link(self):
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)/"stderr.txt"
   path.write_text(str(module.ROOT)+"\n")
   original=module.sha(path)
   module._safe_text(path)
   side=json.loads(Path(str(path)+".path-normalization.json").read_text())
   self.assertEqual(side["original_sha256"],original)
   self.assertEqual(side["saved_sha256"],module.sha(path))
   self.assertNotIn(str(module.ROOT),path.read_text())

if __name__=="__main__":unittest.main()
