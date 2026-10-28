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
    def test_repository_case_ids_projects_and_sources_match_label_free_index(self):
        audit = recovery.validate_input_records(recovery.INPUT, recovery.INPUT_INDEX)
        self.assertEqual(audit["validation"]["case_count"], 154)
        self.assertEqual(audit["validation"]["project_count"], 121)
        self.assertEqual(audit["validation"]["source_file_count"], 694)
        self.assertTrue(audit["validation"]["case_ids_exact_match"])
        self.assertTrue(audit["validation"]["case_project_mappings_validated"])
        self.assertTrue(audit["validation"]["source_paths_and_sha256_validated"])
        self.assertTrue(audit["validation"]["compile_config_paths_and_sha256_validated"])
        self.assertFalse(audit["validation"]["case_labels_included"])

    def test_source_run_snapshots_preserve_original_bytes_and_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            specs = recovery.SOURCE_RUN_SPECS
            for run_name, spec in specs.items():
                run_root = root / "experiments" / run_name
                inventory_root = run_root if spec["inventory_root"] == "." else run_root / spec["inventory_root"]
                inventory_root.mkdir(parents=True)
                sample = inventory_root / "raw-evidence.txt"
                sample.write_text(f"raw evidence {run_name}\n", encoding="utf-8")
                seal_path = run_root / spec["seal_path"]
                seal_path.parent.mkdir(parents=True, exist_ok=True)
                seal = {"files": {"raw-evidence.txt": recovery.sha(sample)}, "schema": "FIXTURE"}
                if spec["self_hash"]:
                    seal["seal_sha256"] = recovery.canonical_sha256(seal)
                seal_path.write_text(json.dumps(seal), encoding="utf-8")
            output = root / "experiments" / "offline-recovery-20261028"
            with patch.object(recovery, "ROOT", root):
                manifest = recovery.snapshot_source_runs(output)
            self.assertEqual(len(manifest["files"]), 6)
            for item in manifest["files"]:
                source = root / item["source_path"]
                copied = output / item["snapshot_path"]
                self.assertTrue(source.is_file())
                self.assertTrue(copied.is_file())
                self.assertEqual(item["original_sha256"], recovery.sha(source))
                self.assertEqual(item["snapshot_sha256"], recovery.sha(copied))
                self.assertEqual(item["original_sha256"], item["snapshot_sha256"])

    def test_native_complete_positive_and_negative(self):
        p = "--Vulnerability--:\n{Function:transferOwnership,Taint Path:msg.sender,Description:Unsafe.}\n"
        self.assertEqual(recovery.extract_conclusion(p, "stop", True)["functions"], ["transferOwnership"])
        self.assertEqual(recovery.extract_conclusion(p, "stop", True)["status"], "FINDINGS")
        self.assertEqual(recovery.extract_conclusion("--Vulnerability--:\nno vulnerability\n", "stop", True)["status"],
                         "EXPLICIT_NEGATIVE")

    def test_function_signature_commas_are_not_truncated(self):
        output = (
            "--Vulnerability--:\n"
            "{Function:withdraw(uint256,address),Taint Path:msg.sender,"
            "Description:Unauthorized withdrawal.}\n"
        )
        parsed = recovery.extract_conclusion(output, "stop", True)
        self.assertEqual(parsed["functions"], ["withdraw(uint256,address)"])
        self.assertEqual(parsed["raw_findings"], [
            "{Function:withdraw(uint256,address),Taint Path:msg.sender,Description:Unauthorized withdrawal.}"
        ])

    def test_malformed_finding_is_preserved_with_format_warnings(self):
        finding = "{Function:f,Taint Path:a,Taint Path:b}"
        output = "--Vulnerability--:\n" + finding + "\n"
        parsed = recovery.extract_conclusion(output, "stop", True)
        self.assertEqual(parsed["raw_findings"], [finding])
        self.assertEqual(parsed["functions"], ["f"])
        self.assertIn("MISSING_DESCRIPTION_FIELD", parsed["format_warnings"])
        self.assertIn("DUPLICATE_TAINT_PATH_FIELD", parsed["format_warnings"])

    def test_response_complete_flag_gates_conclusion(self):
        output = "--Vulnerability--:\n{Function:f,Taint Path:x,Description:y}"
        self.assertEqual(recovery.extract_conclusion(output, "stop", True)["status"], "FINDINGS")
        self.assertEqual(recovery.extract_conclusion(output, "stop", False)["status"], "INCOMPLETE_RESPONSE")
        self.assertEqual(recovery.extract_conclusion(output, "stop", None)["status"], "COMPLETENESS_UNVERIFIED")

    def test_sink_stage_no_sinks_and_missing_taint_are_distinguished(self):
        no_sinks = [{
            "stage": "SINK", "status": "STAGE_RESPONSE", "response_complete": True,
            "finish_reason": "stop", "visible_output": "reasoning\n--Sink--:\nno sinks\n",
        }]
        self.assertEqual(recovery._classify_sink_evidence(no_sinks), "SINK_STAGE_EXPLICIT_NO_SINKS")
        candidate = [{
            "stage": "SINK", "status": "STAGE_RESPONSE", "response_complete": True,
            "finish_reason": "stop", "visible_output": "--Sink--:\n{Function:f,Sink:x}\n",
        }]
        self.assertEqual(recovery._classify_sink_evidence(candidate), "SINK_STAGE_RESPONSE_WITHOUT_EXPLICIT_NO_SINKS")
        self.assertEqual(recovery._classify_sink_evidence([]), "SINK_RESPONSE_NOT_AVAILABLE")

    def test_incomplete_and_missing_marker_never_become_negative(self):
        p = "--Vulnerability--:\n{Function:a,Taint Path:x,Description:y}\n"
        self.assertEqual(recovery.extract_conclusion(p, "length", True)["status"], "INCOMPLETE_RESPONSE")
        self.assertEqual(recovery.extract_conclusion("Reasoning without a verdict", "stop", True)["status"],
                         "MISSING_MARKER")
        self.assertEqual(recovery.extract_conclusion(None, "stop", True)["status"], "MISSING_VISIBLE_OUTPUT")

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

    def test_raw_call_request_response_cache_and_error_events_are_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "requests.jsonl"
            request = {
                "event": "request", "call_id": "call-x", "project_id": "proj-x",
                "case_id": "case-x", "case_ids": ["case-x"],
                "source_file": "projects/proj-x/source_code/C.sol",
                "model": "deepseek-flash", "request_body": {"messages": [{"role": "system", "content": "Your task is to analyze whether untrusted inputs can reach any security-sensitive operations."}]},
            }
            response = {
                "event": "response", "call_id": "call-x", "visible_output": "--Vulnerability--:\nno vulnerability\n",
                "raw_response": {"choices": [{"message": {"content": "raw"}}]},
                "finish_reason": "stop", "response_complete": True,
                "prompt_cache_hit_tokens": 17, "prompt_cache_miss_tokens": 29,
            }
            error = {"event": "error", "call_id": "call-x", "error_type": "ValueError", "error_body": {"message": "parser"}}
            log.write_text("\n".join(json.dumps(x) for x in (request, response, error)) + "\n", encoding="utf-8")
            entry = recovery.read_requests(log)["entries"][0]
            self.assertEqual(entry["request_event"], request)
            self.assertEqual(entry["response_event"], response)
            self.assertEqual(entry["error_events"], [error])
            self.assertEqual(entry["status"], "EXPLICIT_NEGATIVE")

    def test_project_recovery_is_read_only_and_keeps_original_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = "experiments/comparison-20261027-deepseek-high/actoolbench154/jobs/proj-test"
            native = root / artifact / "native"
            native.mkdir(parents=True)
            file_dir = native / "files" / "f1"
            file_dir.mkdir(parents=True)
            log = file_dir / "requests.jsonl"
            input_path = "projects/proj-test/source_code/source.sol"
            source_path = "datasets/actoolbench-cleaned-154/full/projects/proj-test/source_code/source.sol"
            source_hash = "a" * 64
            request = {
                "event": "request", "call_id": "t", "project_id": "proj-test",
                "case_id": "case-test", "case_ids": ["case-test"], "source_file": input_path,
                "request_body": {"messages": [{
                    "content": "Your task is to analyze whether untrusted inputs can reach any security-sensitive operations."
                }]},
            }
            response = {
                "event": "response", "call_id": "t", "finish_reason": "stop", "response_complete": True,
                "visible_output": "--Vulnerability--:\n{Function:f,Taint Path:x,Description:y}",
            }
            log.write_text("\n".join(json.dumps(x) for x in (request, response)) + "\n")
            result = {
                "project_id": "proj-test", "case_ids": ["case-test"], "status": "PROJECT_WITH_ERRORS",
                "file_results": [{
                    "tool_input_path": input_path, "source_repo_path": source_path,
                    "source_sha256": source_hash, "actual_source_sha256": source_hash,
                    "status": "ERROR", "request_log_path": "files/f1/requests.jsonl",
                }],
            }
            (native / "project-result.json").write_text(json.dumps(result))
            before = (native / "project-result.json").read_bytes(), log.read_bytes()
            project_files = {input_path: {"sha256": source_hash, "source_path": source_path}}
            with patch.object(recovery, "ROOT", root):
                with patch.dict(recovery.SOURCE_RUN_SPECS, {
                    "comparison-20261027-deepseek-high": {
                        "seal_path": "actoolbench154/predictions-seal.json",
                        "inventory_root": "actoolbench154", "self_hash": True,
                    }
                }, clear=True):
                    recovered, stages = recovery.validate_project_artifact(
                        "proj-test", artifact, ["case-test"], project_files
                    )
            self.assertEqual(recovered["original_project_status"], "PROJECT_WITH_ERRORS")
            self.assertEqual(recovered["files"][0]["request_evidence"]["entries"][0]["functions"], ["f"])
            self.assertEqual(stages, {"TAINT": 1})
            self.assertEqual(before, ((native / "project-result.json").read_bytes(), log.read_bytes()))


if __name__ == "__main__":
    unittest.main()
