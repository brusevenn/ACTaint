"""Regression tests for ACTaint's native taint-stage report boundary."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from llm.taint_agent import TaintAgent


class TaintReportMarkerTests(unittest.TestCase):
    def run_with_response(self, response):
        agent = TaintAgent(
            "{Function:transferOwnership, Sink:_owner = newOwner}",
            "constructor()",
            "contract Example {}",
        )
        with patch("llm.taint_agent.call_chatgpt", return_value=response) as client:
            output = agent.process()
        client.assert_called_once()
        return output

    def test_native_vulnerability_marker_is_accepted_without_modification(self):
        response = (
            "Reasoning: caller-controlled ownership update.\n"
            "--Vulnerability--:\n"
            "{Function:transferOwnership,Taint Path:msg.sender,"
            "Description:Unauthorized ownership transfer.}\n"
        )
        self.assertEqual(self.run_with_response(response), response)

    def test_native_no_vulnerability_marker_is_accepted(self):
        response = "Reasoning: restricted path.\n--Vulnerability--: \nno vulnerability\n"
        self.assertEqual(self.run_with_response(response), response)

    def test_indented_case_insensitive_header_is_accepted(self):
        response = "Reasoning.\n\t--vulnerability--  :\nno vulnerability\n"
        self.assertEqual(self.run_with_response(response), response)

    def test_inline_marker_mention_is_not_a_report(self):
        with self.assertRaisesRegex(ValueError, "missing the --Vulnerability--: marker"):
            self.run_with_response("The response format should include --Vulnerability--: at the end.")

    def test_missing_marker_does_not_become_negative(self):
        with self.assertRaisesRegex(ValueError, "missing the --Vulnerability--: marker"):
            self.run_with_response("Reasoning without a conclusive report.")

    def test_escaped_regex_literal_is_not_a_header(self):
        with self.assertRaisesRegex(ValueError, "missing the --Vulnerability--: marker"):
            self.run_with_response(r"--Vulnerability--\\s*:")


if __name__ == "__main__":
    unittest.main()
