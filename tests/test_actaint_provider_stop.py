import importlib.util
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/benchmark.py"
SPEC = importlib.util.spec_from_file_location("actaint_benchmark", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProviderStopTests(unittest.TestCase):
    def test_payment_error_stops_project_queue(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "requests.jsonl"
            log.write_text(json.dumps({"event": "error", "status_code": 402}) + "\n")
            self.assertTrue(MODULE._request_log_requires_provider_stop(log))

    def test_malformed_request_log_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "requests.jsonl"
            log.write_text("not-json\n")
            self.assertTrue(MODULE._request_log_requires_provider_stop(log))

    def test_payment_error_broadcasts_shared_stop_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "provider-stop.json"
            with patch.dict(os.environ, {"EXPERIMENT_GLOBAL_STOP_FILE": str(marker)}):
                MODULE._mark_global_provider_stop()
            self.assertEqual(json.loads(marker.read_text())["status"], "STOPPED_AUTH_OR_PAYMENT_ERROR")

    def test_non_auth_error_does_not_stop_queue(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "requests.jsonl"
            log.write_text(json.dumps({"event": "error", "status_code": 429}) + "\n")
            self.assertFalse(MODULE._request_log_requires_provider_stop(log))


if __name__ == "__main__":
    unittest.main()
