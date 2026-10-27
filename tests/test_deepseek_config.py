import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]


class DeepSeekConfigTests(unittest.TestCase):
    def test_config_fixes_model_and_protocol_ignoring_sampling_overrides(self):
        env = {
            "DEEPSEEK_API_KEY": "unit-test-secret",
            "DEEPSEEK_BASE_URL": "https://api.example.invalid",
            "DEEPSEEK_MODEL": "deepseek-v4-pro",
            "CADG_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "openai-unit-test-secret",
            "OPENAI_BASE_URL": "https://openai.example.invalid",
            "OPENAI_MODEL": "legacy-model",
            "LLM_TEMPERATURE": "0.4",
            "LLM_TOP_P": "0.7",
            "LLM_REASONING_EFFORT": "max",
            "LLM_THINKING_ENABLED": "false",
        }
        dotenv = types.ModuleType("dotenv")
        dotenv.load_dotenv = lambda *args, **kwargs: None
        with patch.dict(os.environ, env, clear=True), patch.dict(sys.modules, {"dotenv": dotenv}):
            spec = importlib.util.spec_from_file_location("actaint_config_test", REPO / "src" / "config.py")
            config = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(config)

        self.assertEqual(config.gpt_provider, "deepseek")
        self.assertEqual(config.gpt_url, env["DEEPSEEK_BASE_URL"])
        self.assertEqual(config.gpt_key, env["DEEPSEEK_API_KEY"])
        self.assertEqual(config.gpt_model, "deepseek-flash")
        self.assertEqual(config.gpt_reasoning_effort, "high")
        self.assertTrue(config.gpt_thinking_enabled)
        self.assertEqual(config.gpt_max_tokens, 65536)
        self.assertEqual(config.gpt_request_timeout, 300)
        self.assertEqual(config.gpt_max_retries, 0)
        self.assertFalse(hasattr(config, "gpt_temperature"))
        self.assertFalse(hasattr(config, "gpt_top_p"))
        self.assertEqual(config.DATASET_PATH, "datasets/clean_datasets/CVE/" if not env.get("ACTAINT_DATASET_PATH") else env["ACTAINT_DATASET_PATH"])

    def test_deepseek_url_defaults_to_official_endpoint(self):
        env = {"DEEPSEEK_API_KEY": "unit-test-secret"}
        dotenv = types.ModuleType("dotenv")
        dotenv.load_dotenv = lambda *args, **kwargs: None
        with patch.dict(os.environ, env, clear=True), patch.dict(sys.modules, {"dotenv": dotenv}):
            spec = importlib.util.spec_from_file_location("actaint_config_default_url_test", REPO / "src" / "config.py")
            config = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(config)
        self.assertEqual(config.gpt_url, "https://api.deepseek.com")
        self.assertEqual(config.gpt_model, "deepseek-flash")


if __name__ == "__main__":
    unittest.main()