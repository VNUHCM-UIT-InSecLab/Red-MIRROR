import unittest

from prompts.prompt import DeepPentestPrompt
from prompts.tools_description import EXPLOITER_TOOLS


class PromptContractTests(unittest.TestCase):
    def test_exploiter_tools_describe_supported_curl_body_types(self):
        self.assertIn('ONLY: "none", "form", "json", "raw"', EXPLOITER_TOOLS)
        self.assertIn('DO NOT invent unsupported body_type values', EXPLOITER_TOOLS)
        self.assertIn('use UploadFileTool instead of CurlHttpRequestTool', EXPLOITER_TOOLS)

    def test_update_plan_prompt_forbids_unsupported_curl_body_types(self):
        prompt = DeepPentestPrompt.update_plan
        self.assertIn('Do NOT generate tasks that require body_type="multipart/form-data"', prompt)
        self.assertIn('If the action is a true multipart file upload, use UploadFileTool', prompt)
        self.assertIn('### Structured Failure Evidence', prompt)
        self.assertIn('Treat Structured Failure Evidence as authoritative execution state', prompt)
        self.assertIn('form_shape_recon_required=true', prompt)
        self.assertIn('full_form_shape_required=true', prompt)
        self.assertIn('full observed form field set', prompt)
        self.assertIn('encoding_strategy_required=true', prompt)
        self.assertIn('blocked_direct_localhost_access=true', prompt)


if __name__ == "__main__":
    unittest.main()
