import importlib.util,unittest
from pathlib import Path
p=Path(__file__).resolve().parents[1]/"scripts/resume_benchmark.py"
s=importlib.util.spec_from_file_location("resume_benchmark",p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class ResumePlanTests(unittest.TestCase):
 def test_denominators_sources_and_paid_no_replay(self):
  d=m.build_plan();self.assertEqual((d["case_count"],d["project_group_count"]),(154,121))
  self.assertFalse(d["ground_truth_read"]);self.assertFalse(d["labels_in_detector_input"]);self.assertFalse(d["execution_launched"]);self.assertFalse(d["duplicate_samples_replayed"])
  self.assertEqual(len({r["case_id"] for r in d["case_records"]}),154)
  self.assertTrue(all(j["source_hashes"] for j in d["jobs"]))
  self.assertTrue(all(j["disposition"].startswith("REUSE_") for j in d["jobs"] if j["prior_request_attempts"]>0))
  self.assertTrue(all(j["disposition"]=="ELIGIBLE_ZERO_REQUEST_RESUME" or j["prior_request_attempts"]>0 or j["disposition"].startswith("REUSE_") for j in d["jobs"]))
if __name__=="__main__":unittest.main()
