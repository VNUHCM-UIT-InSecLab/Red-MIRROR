from threading import Lock

class DataLogger:
    _instance = None
    _lock = Lock()

    def __new__(cls, log_file="finetune_dataset.jsonl"):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DataLogger, cls).__new__(cls)
        return cls._instance

    def _ensure_file(self):
        return None

    def _write_async(self, entry):
        return None

    def log_planner_io(self, shared_memory, task_description, generated_plan):
        """
        Log Planner Input/Output pair (Non-blocking).
        """
        return None

    def log_next_task_io(self, shared_memory, current_task, generated_details):
        """
        Log Next Task Details Input/Output pair (Non-blocking).
        """
        return None
