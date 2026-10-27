import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from httpx import MockTransport


REPO = Path(__file__).resolve().parents[1]


def load_call_gpt(config):
    path = REPO / "src" / "llm" / "call_gpt.py"
    spec = importlib.util.spec_from_file_location("actaint_call_gpt_test", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"config": config}):
        spec.loader.exec_module(module)
    return module


class DeepSeekClientTests(unittest.TestCase):
    def test_sends_fixed_deepseek_request_and_logs_cache_usage_without_secrets(self):
        config = SimpleNamespace(
            gpt_url="https://api.example.invalid",
            gpt_key="unit-test-secret",
            gpt_model="model-from-env-must-not-win",
            gpt_reasoning_effort="high",
            gpt_thinking_enabled=True,
            gpt_max_tokens=65536,
            gpt_request_timeout=300,
            gpt_max_retries=0,
            total_token=0,
        )
        response_payload = {
            "id": "chatcmpl-unit-test",
            "object": "chat.completion",
            "created": 1,
            "model": "deepseek-flash",
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": "SMOKE_OK",
                    "reasoning_content": "must-not-be-written-to-log",
                },
            }],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "total_tokens": 120,
                "prompt_cache_hit_tokens": 80,
                "prompt_cache_miss_tokens": 20,
                "prompt_tokens_details": {"cached_tokens": 80},
            },
        }
        captured = {"body": None, "http_options": None}

        def handler(request):
            captured["body"] = json.loads(request.content.decode("utf-8"))
            return httpx.Response(200, json=response_payload, request=request)

        module = load_call_gpt(config)
        real_client_class = httpx.Client

        def mock_http_client(**kwargs):
            captured["http_options"] = kwargs.copy()
            return real_client_class(transport=MockTransport(handler), **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "requests.jsonl"
            with patch.dict(os.environ, {"TOOL_REQUEST_LOG_FILE": str(log_path)}), \
                 patch.object(module, "httpx", types.SimpleNamespace(Client=mock_http_client, Timeout=httpx.Timeout)):
                result = module.call_chatgpt([{"role": "user", "content": "unique source prompt"}])

            self.assertEqual(result, "SMOKE_OK")
            self.assertEqual(config.total_token, 120)
            body = captured["body"]
            self.assertEqual(body["model"], "deepseek-flash")
            self.assertEqual(body["max_tokens"], 65536)
            self.assertEqual(body["reasoning_effort"], "high")
            self.assertEqual(body["thinking"], {"type": "enabled"})
            self.assertNotIn("temperature", body)
            self.assertNotIn("top_p", body)
            self.assertEqual(body["messages"], [{"role": "user", "content": "unique source prompt"}])
            self.assertEqual(captured["http_options"]["trust_env"], False)
            self.assertEqual(captured["http_options"]["timeout"].read, 300)

            entries = [json.loads(line) for line in log_path.read_text().splitlines()]
            self.assertEqual([entry["event"] for entry in entries], ["request", "response"])
            self.assertEqual(entries[0]["request_body"], body)
            self.assertEqual(entries[1]["request_id"], "chatcmpl-unit-test")
            self.assertEqual(entries[1]["prompt_cache_hit_tokens"], 80)
            self.assertEqual(entries[1]["prompt_cache_miss_tokens"], 20)
            self.assertEqual(entries[1]["visible_output"], "SMOKE_OK")
            serialized_log = log_path.read_text()
            self.assertNotIn("unit-test-secret", serialized_log)
            self.assertEqual(entries[1]["raw_response"]["choices"][0]["message"]["reasoning_content"], "must-not-be-written-to-log")

    def test_logs_failure_once_and_does_not_retry(self):
        config = SimpleNamespace(
            gpt_url="https://api.example.invalid",
            gpt_key="unit-test-secret",
            gpt_model="deepseek-flash",
            gpt_reasoning_effort="high",
            gpt_thinking_enabled=True,
            gpt_max_tokens=65536,
            gpt_request_timeout=300,
            gpt_max_retries=0,
            total_token=0,
        )
        calls = []

        def handler(request):
            calls.append(request)
            return httpx.Response(503, json={"error": {"message": "temporary"}}, request=request)

        module = load_call_gpt(config)
        real_client_class = httpx.Client

        def mock_http_client(**kwargs):
            return real_client_class(transport=MockTransport(handler), **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "requests.jsonl"
            with patch.dict(os.environ, {"TOOL_REQUEST_LOG_FILE": str(log_path)}), \
                 patch.object(module, "httpx", types.SimpleNamespace(Client=mock_http_client, Timeout=httpx.Timeout)):
                with self.assertRaises(Exception):
                    module.call_chatgpt([{"role": "user", "content": "request that fails"}])
            self.assertEqual(len(calls), 1)
            entries = [json.loads(line) for line in log_path.read_text().splitlines()]
            self.assertEqual(entries[-1]["event"], "error")
            self.assertEqual(entries[-1]["status_code"], 503)
            self.assertNotIn("unit-test-secret", log_path.read_text())


if __name__ == "__main__":
    unittest.main()