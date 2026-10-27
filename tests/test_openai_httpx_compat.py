import unittest

from openai import OpenAI


class OpenAIHttpxCompatibilityTests(unittest.TestCase):
    def test_openai_client_constructs_without_network_access(self):
        client = OpenAI(
            api_key="sentinel-test-key",
            base_url="https://api.example.invalid",
        )
        try:
            self.assertEqual(str(client.base_url).rstrip("/"), "https://api.example.invalid")
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
