import unittest

from actions.write_plan import merge_tasks_from_json
from db.models.task_model import Task


class WritePlanMergeTests(unittest.TestCase):
    def test_new_tasks_do_not_inherit_success_by_numeric_id(self):
        old_tasks = [
            Task(plan_id="plan-1", sequence=0, action="Web", instruction="[Exploitation] Old step 1", is_finished=True, is_success=True),
            Task(plan_id="plan-1", sequence=1, action="Web", instruction="[Exploitation] Old step 2", is_finished=True, is_success=True),
        ]
        new_tasks_json = [
            {"id": "1", "dependent_task_ids": [], "instruction": "[Exploitation] New step 1", "action": "Web"},
            {"id": "2", "dependent_task_ids": ["1"], "instruction": "[Exploitation] New step 2", "action": "Web"},
        ]

        merged = merge_tasks_from_json("plan-1", new_tasks_json, old_tasks)

        self.assertEqual(len(merged), 2)
        self.assertFalse(merged[0].is_finished)
        self.assertFalse(merged[0].is_success)
        self.assertFalse(merged[1].is_finished)
        self.assertFalse(merged[1].is_success)
        self.assertEqual(merged[1].dependencies, [0])


    def test_preserve_completed_task_with_none_id_does_not_crash(self):
        old_tasks = [
            Task(
                plan_id="plan-1",
                sequence=0,
                action="Web",
                instruction="[Exploitation] Reuse same step",
                is_finished=True,
                is_success=True,
                result="flag path confirmed",
                code=["tool()"],
            )
        ]
        new_tasks_json = [
            {"id": "1", "dependent_task_ids": [], "instruction": "[Exploitation] Reuse same step", "action": "Web"}
        ]

        merged = merge_tasks_from_json("plan-1", new_tasks_json, old_tasks)

        self.assertEqual(len(merged), 1)
        self.assertIsNone(merged[0].id)
        self.assertTrue(merged[0].is_finished)
        self.assertTrue(merged[0].is_success)

    def test_preserves_success_only_when_normalized_instruction_matches(self):
        old_tasks = [
            Task(
                id="task-1",
                plan_id="plan-1",
                sequence=0,
                action="Web",
                instruction="[Exploit]   Confirm   admin   panel  ",
                is_finished=True,
                is_success=True,
                result="done",
                code=["curl ..."],
            )
        ]
        new_tasks_json = [
            {"id": "9", "dependent_task_ids": [], "instruction": "[Exploitation] Confirm admin panel", "action": "Web"}
        ]

        merged = merge_tasks_from_json("plan-1", new_tasks_json, old_tasks)

        self.assertEqual(len(merged), 1)
        self.assertTrue(merged[0].is_finished)
        self.assertTrue(merged[0].is_success)
        self.assertEqual(merged[0].result, "done")
        self.assertEqual(merged[0].code, ["curl ..."])


if __name__ == "__main__":
    unittest.main()
