import unittest

from actions.decision_state import (
    analyze_response,
    should_force_replan,
    summarize_hypothesis_state,
    update_hypothesis_state,
)


class DecisionStateTests(unittest.TestCase):
    def test_response_analysis_detects_request_shape_invalid(self):
        analysis = analyze_response(
            task_instruction="Send a POST request to http://target/profile",
            result_text="HTTP/1.1 400 BAD REQUEST\nBad Request",
            reflection_outcome=None,
        )

        self.assertTrue(analysis.execution_ok)
        self.assertTrue(analysis.request_shape_invalid)
        self.assertIn("request_shape_invalid", analysis.notes)

    def test_response_analysis_keeps_surface_signals_as_metadata_only(self):
        analysis = analyze_response(
            task_instruction="Authenticate as test",
            result_text="HTTP/1.1 302 FOUND\nSet-Cookie: session=abc\nLocation: /dashboard?username=test",
            reflection_outcome=None,
        )

        self.assertTrue(analysis.execution_ok)
        self.assertIn("session_observed", analysis.notes)
        self.assertFalse(analysis.request_shape_invalid)

    def test_hypothesis_state_does_not_reject_after_single_inconclusive_family_attempt(self):
        state = {}
        first = analyze_response(
            task_instruction="Send a GET request to http://target/orders?user_id=10033",
            result_text="HTTP/1.1 200 OK\nThe username parameter appears ignored; no IDOR signal was observed.",
            reflection_outcome={"failure_class": "valid_attempt_no_signal"},
        )
        state = update_hypothesis_state(
            state,
            task_instruction="Send a GET request to http://target/orders?user_id=10033",
            analysis=first,
            task_succeeded=False,
            reflection_outcome={"attempt_family": "idor-probe"},
        )
        self.assertFalse(should_force_replan(
            state,
            task_instruction="Send a GET request to http://target/orders?user_id=10033",
            analysis=first,
            reflection_outcome={"attempt_family": "idor-probe"},
        ))

    def test_hypothesis_state_caps_repeated_inconclusive_attempt_family(self):
        state = {}
        task = "Send a GET request to http://target/orders?user_id=10033"
        analysis = analyze_response(
            task_instruction=task,
            result_text="HTTP/1.1 200 OK\nThe username parameter appears ignored; no IDOR signal was observed.",
            reflection_outcome={"failure_class": "valid_attempt_no_signal"},
        )
        for _ in range(3):
            state = update_hypothesis_state(
                state,
                task_instruction=task,
                analysis=analysis,
                task_succeeded=False,
                reflection_outcome={"attempt_family": "idor-probe"},
            )

        self.assertTrue(should_force_replan(
            state,
            task_instruction=task,
            analysis=analysis,
            reflection_outcome={"attempt_family": "idor-probe"},
        ))
        summary = summarize_hypothesis_state(state, task_instruction=task)
        self.assertIn("hypothesis_last_family=idor-probe", summary)
        self.assertIn("attempt_family_attempts=3", summary)

    def test_hypothesis_state_tracks_request_shape_failures_per_family(self):
        state = {}
        task = "Send a POST request to http://target/profile with form body 'name=a'"
        analysis = analyze_response(
            task_instruction=task,
            result_text="HTTP/1.1 400 BAD REQUEST\nBad Request",
            reflection_outcome=None,
        )
        state = update_hypothesis_state(
            state,
            task_instruction=task,
            analysis=analysis,
            task_succeeded=False,
            reflection_outcome={"attempt_family": "form-submission"},
        )
        state = update_hypothesis_state(
            state,
            task_instruction=task,
            analysis=analysis,
            task_succeeded=False,
            reflection_outcome={"attempt_family": "form-submission"},
        )

        self.assertTrue(should_force_replan(
            state,
            task_instruction=task,
            analysis=analysis,
            reflection_outcome={"attempt_family": "form-submission"},
        ))
        self.assertIn("attempt_family_blocked=true", summarize_hypothesis_state(state, task_instruction=task))


if __name__ == "__main__":
    unittest.main()
