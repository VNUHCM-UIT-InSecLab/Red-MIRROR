import unittest
from unittest.mock import patch

from tools.web_exploit_tool import JWTTool, check_login_success, assess_login_result


class JwtToolGuardTests(unittest.TestCase):
    def test_decode_rejects_non_jwt_session_artifact(self):
        result = JWTTool.invoke({
            "mode": "decode",
            "token": "eyJ1c2VybmFtZSI6InRlc3R1c2VyIn0.an64FQ.OCav23UfhWlyUhZUc46KVAxZ3dE",
        })
        self.assertIn("NON_RETRYABLE_NON_JWT", result)
        self.assertIn("Do not retry JWTTool on the same artifact.", result)

    def test_decode_accepts_real_jwt_candidate(self):
        result = JWTTool.invoke({
            "mode": "decode",
            "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoidGVzdCJ9.",
        })
        self.assertIsInstance(result, dict)
        self.assertEqual(result["payload"]["user"], "test")

    def test_login_success_requires_more_than_session_cookie_keyword(self):
        response = (
            "HTTP/1.1 200 OK\n"
            "Set-Cookie: session=opaquevalue; HttpOnly; Path=/\n"
            "\n"
            "<html>login failed</html>"
        )
        self.assertFalse(check_login_success(response))

    def test_login_success_rejects_principal_mismatch(self):
        response = (
            "HTTP/1.1 200 OK\n"
            "Set-Cookie: session=eyJ1c2VybmFtZSI6InRlc3R1c2VyIn0.sig.sig; HttpOnly; Path=/\n"
            "\n"
            "<html>portal</html>"
        )
        assessment = assess_login_result(response, expected_username="admin")
        self.assertFalse(assessment["success"])
        self.assertEqual(assessment["principal"], "testuser")
        self.assertIn("mismatch", assessment["reason"])

    def test_login_success_accepts_matching_principal(self):
        response = (
            "HTTP/1.1 200 OK\n"
            "Set-Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0.sig.sig; HttpOnly; Path=/\n"
            "\n"
            "<html>portal</html>"
        )
        assessment = assess_login_result(response, expected_username="admin")
        self.assertTrue(assessment["success"])
        self.assertEqual(assessment["principal"], "admin")

    def test_encode_does_not_persist_without_explicit_opt_in(self):
        result = JWTTool.invoke({
            "mode": "encode",
            "algorithm": "none",
            "payload": {"user": "test"},
            "target_url": "http://target/",
        })
        self.assertFalse(result["cookie_jar"]["saved"])
        self.assertIn("persist_cookie=False", result["cookie_jar"]["note"])

    def test_encode_refuses_implicit_session_overwrite(self):
        result = JWTTool.invoke({
            "mode": "encode",
            "algorithm": "none",
            "payload": {"user": "test"},
            "target_url": "http://target/",
            "persist_cookie": True,
            "cookie_name": "session",
        })
        self.assertFalse(result["cookie_jar"]["saved"])
        self.assertIn("Refusing to overwrite cookie named 'session'", result["cookie_jar"]["error"])

    def test_encode_persists_only_with_explicit_cookie_name_and_opt_in(self):
        with patch("tools.web_exploit_tool._persist_cookie_to_jar", return_value={"saved": True, "cookie_name": "auth"}):
            result = JWTTool.invoke({
                "mode": "encode",
                "algorithm": "none",
                "payload": {"user": "test"},
                "target_url": "http://target/",
                "persist_cookie": True,
                "cookie_name": "auth",
            })
        self.assertTrue(result["cookie_jar"]["saved"])
        self.assertEqual(result["cookie_jar"]["cookie_name"], "auth")


if __name__ == "__main__":
    unittest.main()
