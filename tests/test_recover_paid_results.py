"""Offline recovery must preserve paid model evidence without classification or replay."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/recover_paid_results.py"
spec = importlib.util.spec_from_file_location("recover_paid_results", SCRIPT)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class PaidRecoveryTests(unittest.TestCase):
    def test_native_complete_positive_and_negative(self):
        p = "--Vulnerability--:\n{Function:transferOwnership,Taint Path:msg.sender,Description:Unsafe.}\n"
        self.assertEqual(recovery.extract_conclusion(p, "stop")["functions"], ["transferOwnership"])
        self.assertEqual(recovery.extract_conclusion(p, "stop")["status"], "FINDINGS")
        self.assertEqual(recovery.extract_conclusion("--Vulnerability--:\nno vulnerability\n", "stop")["status"],
                         "EXPLICIT_NEGATIVE")

    def test_incomplete_and_missing_marker_never_become_negative(self):
        p = "--Vulnerability--:\n{Function:a,Taint Path:x,Description:y}\n"
        self.assertEqual(recovery.extract_conclusion(p, "length")["status"], "INCOMPLETE_RESPONSE")
        self.assertEqual(recovery.extract_conclusion("Reasoning without a verdict", "stop")["status"],
                         "MISSING_MARKER")
        self.assertEqual(recovery.extract_conclusion(None, "stop")["status"], "MISSING_VISIBLE_OUTPUT")

    def test_calls_are_linked_by_id_not_merged_or_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "requests.jsonl"
            source = [
                {"event": "request", "call_id": "sink",
                 "request_body": {"messages": [{"role": "system",
                  "content": "You task is to identify all **Sink** operations."}]}},
                {"event": "response", "call_id": "sink", "visible_output": "--Sink--:...", "finish_reason": "stop"},
                {"event": "request", "call_id": "taint",
                 "request_body": {"messages": [{"role": "system",
                  "content": "Your task is to analyze whether untrusted inputs can reach any security-sensitive operations."}]}},
                {"event": "response", "call_id": "taint",
                 "visible_output": "--Vulnerability--:\n{Function:f,Taint Path:x,Description:y}",
                 "finish_reason": "stop", "response_complete": True},
                {"event": "error", "call_id": "taint", "error_type": "ValueError"},
            ]
            log.write_text("\n".join(json.dumps(x) for x in source) + "\n", encoding="utf-8")
            items = recovery.read_requests(log)["entries"]
            self.assertEqual([(x["call_id"], x["stage"]) for x in items],
                             [("sink", "SINK"), ("taint", "TAINT")])
            self.assertEqual(items[1]["status"], "FINDINGS")
            self.assertTrue(items[1]["has_error_event"])
            self.assertEqual(items[1]["functions"], ["f"])

    def test_project_recovery_is_read_only_and_keeps_original_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = root / "experiments" / "old" / "jobs" / "proj-test" / "native"
            native.mkdir(parents=True)
            file_dir = native / "files" / "f1"
            file_dir.mkdir(parents=True)
            log = file_dir / "requests.jsonl"
            log.write_text("\n".join(json.dumps(x) for x in [
                {"event": "request", "call_id": "t", "request_body": {"messages": [
                    {"content": "Your task is to analyze whether untrusted inputs can reach any security-sensitive operations."}]}},
                {"event": "response", "call_id": "t", "finish_reason": "stop", "response_complete": True,
                 "visible_output": "--Vulnerability--:\n{Function:f,Taint Path:x,Description:y}"}]) + "\n")
            result = {"project_id": "proj-test", "status": "PROJECT_WITH_ERRORS",
                      "file_results": [{"source_repo_path": "source.sol", "status": "ERROR",
                                       "request_log_path": "files/f1/requests.jsonl"}]}
            (native / "project-result.json").write_text(json.dumps(result))
            before = (native / "project-result.json").read_bytes(), log.read_bytes()
            with patch.object(recovery, "ROOT", root):
                recovered = recovery.recover_project("proj-test", "experiments/old/jobs/proj-test")
            self.assertEqual(recovered["original_project_status"], "PROJECT_WITH_ERRORS")
            self.assertEqual(recovered["files"][0]["request_evidence"]["entries"][0]["functions"], ["f"])
            self.assertEqual(before, ((native / "project-result.json").read_bytes(), log.read_bytes()))


if __name__ == "__main__":
    unittest.main()
