import tempfile
import unittest
from pathlib import Path

from utils.runtime_target import append_runtime_target_url, load_runtime_target_url


class RuntimeTargetUrlTests(unittest.TestCase):
    def test_append_runtime_target_url_when_prompt_has_no_url(self):
        result = append_runtime_target_url("Find the flag.", "http://127.0.0.1:8080")
        self.assertIn("Find the flag.", result)
        self.assertIn("Target URL: http://127.0.0.1:8080", result)

    def test_append_runtime_target_url_keeps_user_url_and_appends_runtime_url(self):
        prompt = "Find the flag at http://localhost:8080."
        result = append_runtime_target_url(prompt, "http://127.0.0.1:8080")
        self.assertIn(prompt, result)
        self.assertIn("Target URL: http://127.0.0.1:8080", result)

    def test_append_runtime_target_url_does_not_duplicate_same_runtime_url(self):
        prompt = "Find the flag.\n\nTarget URL: http://127.0.0.1:8080"
        result = append_runtime_target_url(prompt, "http://127.0.0.1:8080")
        self.assertEqual(result, prompt)

    def test_load_runtime_target_url_prefers_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "annotations" / "Benchmark" / ".runtime"
            runtime.mkdir(parents=True)
            (runtime / "last_target.json").write_text('{"target_url": "http://127.0.0.1:1234"}', encoding="utf-8")
            (runtime / "last_target.env").write_text("TARGET_URL=http://127.0.0.1:5678\n", encoding="utf-8")

            self.assertEqual(load_runtime_target_url(root), "http://127.0.0.1:1234")


if __name__ == "__main__":
    unittest.main()
