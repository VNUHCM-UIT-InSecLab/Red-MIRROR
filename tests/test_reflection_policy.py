import unittest
from unittest.mock import AsyncMock, patch

from server.chat.reflection import intra_reflection


class ReflectionPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_malformed_request_returns_retry(self):
        with patch(
            "server.chat.reflection._ask_reflection_model",
            new=AsyncMock(return_value={
                "decision": "RETRY",
                "failure_class": "retryable_local_error",
                "reason": "Fix malformed JSON body.",
                "next_query": "curl -X POST http://target/api -d '{}'",
                "remaining_reflections": 2,
            }),
        ):
            result = await intra_reflection(
                recon_analyzer_output="",
                exploit_analyzer_output="tool error: malformed JSON body",
                tool_runtime_result="Traceback: malformed JSON body",
                original_task="POST the exploit payload",
                current_query="curl broken",
                remaining_reflections=3,
            )

        self.assertEqual(result["decision"], "RETRY")
        self.assertEqual(result["failure_class"], "retryable_local_error")
        self.assertEqual(result["remaining_reflections"], 2)

    async def test_repeated_valid_no_signal_returns_pivot(self):
        with patch(
            "server.chat.reflection._ask_reflection_model",
            new=AsyncMock(return_value={
                "decision": "PIVOT",
                "failure_class": "valid_attempt_no_signal",
                "reason": "Valid request reached the target but no exploit signal appeared.",
                "next_query": "",
                "remaining_reflections": 3,
            }),
        ):
            result = await intra_reflection(
                recon_analyzer_output="same endpoint, no progress",
                exploit_analyzer_output="valid attempt but no signal",
                tool_runtime_result="[CurlHttpRequestTool] HTTP/1.1 200 OK\nresponse body: unchanged profile page",
                original_task="Exploit the IDOR endpoint",
                current_query="curl http://target/profile?id=1",
                remaining_reflections=3,
            )

        self.assertEqual(result["decision"], "PIVOT")
        self.assertEqual(result["failure_class"], "valid_attempt_no_signal")
        self.assertEqual(result["next_query"], "")

    async def test_unchanged_query_or_no_budget_returns_stop(self):
        with patch(
            "server.chat.reflection._ask_reflection_model",
            new=AsyncMock(return_value={
                "decision": "RETRY",
                "failure_class": "partial_positive_signal",
                "reason": "Try again.",
                "next_query": "curl http://target/a",
                "remaining_reflections": 1,
            }),
        ):
            result = await intra_reflection(
                recon_analyzer_output="",
                exploit_analyzer_output="time-based behavior observed",
                tool_runtime_result="sleep 5 observed",
                original_task="Exploit command injection",
                current_query="curl http://target/a",
                remaining_reflections=2,
            )

        self.assertEqual(result["decision"], "STOP")

        result = await intra_reflection(
            recon_analyzer_output="",
            exploit_analyzer_output="",
            tool_runtime_result="HTTP/1.1 200 OK",
            original_task="Exploit command injection",
            current_query="curl http://target/a",
            remaining_reflections=0,
        )
        self.assertEqual(result["decision"], "STOP")

    async def test_success_evidence_returns_success(self):
        result = await intra_reflection(
            recon_analyzer_output="",
            exploit_analyzer_output="",
            tool_runtime_result="response body: flag{demo-success}",
            original_task="Read the flag",
            current_query="curl http://target/flag",
            remaining_reflections=3,
        )

        self.assertEqual(result["decision"], "SUCCESS")
        self.assertEqual(result["failure_class"], "success")

    async def test_non_retryable_non_jwt_forces_pivot(self):
        with patch(
            "server.chat.reflection._ask_reflection_model",
            new=AsyncMock(return_value={
                "decision": "RETRY",
                "failure_class": "wrong_artifact_class",
                "reason": "Try JWTTool again.",
                "next_query": "JWTTool(mode='decode', token='same')",
                "remaining_reflections": 2,
            }),
        ):
            result = await intra_reflection(
                recon_analyzer_output="",
                exploit_analyzer_output="",
                tool_runtime_result="JWTToolError: NON_RETRYABLE_NON_JWT\nReason: token is not a confirmed JWT candidate.",
                original_task="Decode the token",
                current_query="JWTTool(mode='decode', token='same')",
                remaining_reflections=3,
            )

        self.assertEqual(result["decision"], "PIVOT")
        self.assertEqual(result["failure_class"], "wrong_artifact_class")
        self.assertEqual(result["next_query"], "")

    async def test_flag_task_does_not_accept_success_without_flag_evidence(self):
        with patch(
            "server.chat.reflection._ask_reflection_model",
            new=AsyncMock(return_value={
                "decision": "SUCCESS",
                "failure_class": "success",
                "reason": "Profile page returned 200.",
                "next_query": "",
                "remaining_reflections": 3,
            }),
        ):
            result = await intra_reflection(
                recon_analyzer_output="",
                exploit_analyzer_output="",
                tool_runtime_result="HTTP/1.1 200 OK\nProfile page loaded, flag artifact not present.",
                original_task="GET /profile to retrieve the flag{} artifact from the page content.",
                current_query="curl http://target/profile",
                remaining_reflections=3,
            )

        self.assertEqual(result["decision"], "PIVOT")
        self.assertNotEqual(result["failure_class"], "success")

    async def test_login_task_requires_matching_identity_evidence(self):
        with patch(
            "server.chat.reflection._ask_reflection_model",
            new=AsyncMock(return_value={
                "decision": "SUCCESS",
                "failure_class": "success",
                "reason": "Login succeeded.",
                "next_query": "",
                "remaining_reflections": 3,
            }),
        ):
            result = await intra_reflection(
                recon_analyzer_output="",
                exploit_analyzer_output="",
                tool_runtime_result="LOGIN SUCCESS — Session established as testuser!\nHTTP/1.1 200 OK",
                original_task="Use CurlHttpRequestTool to POST to /login to authenticate as admin.",
                current_query="curl login",
                remaining_reflections=3,
            )

        self.assertEqual(result["decision"], "PIVOT")
        self.assertNotEqual(result["failure_class"], "success")

    async def test_login_task_accepts_matching_identity_evidence(self):
        result = await intra_reflection(
            recon_analyzer_output="",
            exploit_analyzer_output="",
            tool_runtime_result="LOGIN SUCCESS — Session established as admin!\nHTTP/1.1 200 OK",
            original_task="Use CurlHttpRequestTool to POST to /login to authenticate as admin.",
            current_query="curl login",
            remaining_reflections=3,
        )

        self.assertEqual(result["decision"], "SUCCESS")
        self.assertEqual(result["failure_class"], "success")

    async def test_known_form_fields_not_preserved_triggers_shape_retry(self):
        with patch(
            "server.chat.reflection._ask_reflection_model",
            new=AsyncMock(return_value={
                "decision": "RETRY",
                "failure_class": "retryable_local_error",
                "reason": "Maybe switch encoding.",
                "next_query": "retry with json",
                "remaining_reflections": 2,
            }),
        ):
            result = await intra_reflection(
                recon_analyzer_output="",
                exploit_analyzer_output=(
                    "Observed profile form fields:\n"
                    "- `first_name`: profile first name\n"
                    "- `last_name`: profile last name\n"
                    "- `email`: profile email\n"
                    "- `profile_picture_url`: SSRF field\n"
                ),
                tool_runtime_result="HTTP/1.1 400 BAD REQUEST\nBad Request",
                original_task="Test SSRF via the profile picture URL feature on /profile.",
                current_query=(
                    "Use CurlHttpRequestTool to send POST to http://target/profile "
                    'with body_type="form", form_body={"profile_picture_url": "http://127.0.0.1/internal"}'
                ),
                remaining_reflections=3,
            )

        self.assertEqual(result["decision"], "RETRY")
        self.assertEqual(result["failure_class"], "known_form_fields_not_preserved")
        self.assertIn("preserve the known form shape", result["next_query"])
        self.assertIn("first_name", result["next_query"])

    async def test_http_400_cannot_count_as_generic_success(self):
        with patch(
            "server.chat.reflection._ask_reflection_model",
            new=AsyncMock(return_value={
                "decision": "SUCCESS",
                "failure_class": "success",
                "reason": "We learned something from the response.",
                "next_query": "",
                "remaining_reflections": 3,
            }),
        ):
            result = await intra_reflection(
                recon_analyzer_output="",
                exploit_analyzer_output="",
                tool_runtime_result="HTTP/1.1 400 BAD REQUEST\nBad Request",
                original_task="Test SSRF via the profile picture URL feature on /profile.",
                current_query="curl profile",
                remaining_reflections=3,
            )

        self.assertNotEqual(result["decision"], "SUCCESS")

    async def test_localhost_only_403_forces_pivot_not_success(self):
        with patch(
            "server.chat.reflection._ask_reflection_model",
            new=AsyncMock(return_value={
                "decision": "SUCCESS",
                "failure_class": "success",
                "reason": "Observed a response from reset endpoint.",
                "next_query": "",
                "remaining_reflections": 3,
            }),
        ):
            result = await intra_reflection(
                recon_analyzer_output="",
                exploit_analyzer_output="",
                tool_runtime_result="HTTP/1.1 403 FORBIDDEN\nUnauthorized",
                original_task="Attempt localhost-restricted reset_password access and inspect the response.",
                current_query=(
                    "Use CurlHttpRequestTool to send GET to http://127.0.0.1:44622/reset_password?username=admin&newpassword=Hacked123 "
                    'with headers={"X-Forwarded-For": "127.0.0.1"}'
                ),
                remaining_reflections=3,
            )

        self.assertEqual(result["decision"], "PIVOT")
        self.assertEqual(result["failure_class"], "direct_localhost_access_blocked")

    async def test_localhost_only_403_forces_pivot_not_retry(self):
        with patch(
            "server.chat.reflection._ask_reflection_model",
            new=AsyncMock(return_value={
                "decision": "RETRY",
                "failure_class": "retryable_local_error",
                "reason": "Try another localhost header.",
                "next_query": 'headers={"X-Real-IP": "127.0.0.1"}',
                "remaining_reflections": 2,
            }),
        ):
            result = await intra_reflection(
                recon_analyzer_output="",
                exploit_analyzer_output="",
                tool_runtime_result="HTTP/1.1 403 FORBIDDEN\nUnauthorized",
                original_task="Attempt localhost-restricted reset_password access and inspect the response.",
                current_query=(
                    "Use CurlHttpRequestTool to send GET to http://127.0.0.1:44622/reset_password?username=admin&newpassword=Hacked123 "
                    'with headers={"Host": "127.0.0.1"}'
                ),
                remaining_reflections=3,
            )

        self.assertEqual(result["decision"], "PIVOT")
        self.assertEqual(result["failure_class"], "direct_localhost_access_blocked")


if __name__ == "__main__":
    unittest.main()
