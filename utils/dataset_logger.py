import json
import os
from datetime import datetime
from threading import Lock, Thread

class DataLogger:
    _instance = None
    _lock = Lock()

    def __new__(cls, log_file="finetune_dataset.jsonl"):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DataLogger, cls).__new__(cls)
                cls._instance.log_file = log_file
                cls._instance._ensure_file()
        return cls._instance

    def _ensure_file(self):
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", encoding="utf-8") as f:
                pass

    def _write_async(self, entry):
        """Internal method to write to file in a separate thread."""
        def write_op():
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except Exception as e:
                print(f"[DataLogger] Error logging data: {e}")
        
        Thread(target=write_op, daemon=True).start()

    def log_planner_io(self, shared_memory, task_description, generated_plan):
        """
        Log Planner Input/Output pair (Non-blocking).
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "instruction": "You are a senior penetration tester. Create a detailed execution plan based on the shared memory context.",
            "input": f"Task: {task_description}\n\nShared Memory:\n{shared_memory}",
            "output": json.dumps(generated_plan, ensure_ascii=False) if isinstance(generated_plan, (dict, list)) else str(generated_plan)
        }
        self._write_async(entry)

    def log_next_task_io(self, shared_memory, current_task, generated_details):
        """
        Log Next Task Details Input/Output pair (Non-blocking).
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "instruction": "Generate specific execution details for the next pentest task.",
            "input": f"Task: {current_task}\n\nShared Memory:\n{shared_memory}",
            "output": generated_details
        }
        self._write_async(entry)
