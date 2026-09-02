import json
import re
from typing import List, Dict, Optional

from pydantic import BaseModel

from config.config import Configs
from prompts.prompt import DeepPentestPrompt
from db.models.plan_model import Plan
from db.models.task_model import TaskModel, Task
from server.chat.chat import _chat
from utils.log_common import RoleType
from utils.log_common import build_logger

logger = build_logger()


def extract_json_payload(text: str) -> str:
    if not text:
        return text

    s = text.strip()

    # Preferred explicit wrappers
    start_tag = "<json>"
    end_tag = "</json>"
    if start_tag in s and end_tag in s:
        start = s.find(start_tag) + len(start_tag)
        end = s.rfind(end_tag)
        return s[start:end].strip()

    # Common markdown fences
    if "```json" in s:
        start = s.find("```json") + len("```json")
        end = s.find("```", start)
        if end != -1:
            return s[start:end].strip()
    if "```" in s:
        start = s.find("```") + len("```")
        end = s.find("```", start)
        if end != -1:
            fenced = s[start:end].strip()
            if fenced.startswith("[") or fenced.startswith("{"):
                return fenced

    # Fallback: find first balanced JSON array/object in prose
    start_idx = -1
    opener = ""
    for i, ch in enumerate(s):
        if ch in "[{":
            start_idx = i
            opener = ch
            break
    if start_idx == -1:
        return s

    closer = "]" if opener == "[" else "}"
    depth = 0
    in_string = False
    escape = False
    for i in range(start_idx, len(s)):
        ch = s[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return s[start_idx:i + 1].strip()

    return s[start_idx:].strip()

class WritePlan(BaseModel):
    plan_chat_id: str
    role_name: str = RoleType.EXPLOITER.value

    def _extract_json_block(self, rsp: str) -> str:
        return extract_json_payload(rsp)

    def run(self, init_description, shared_summary) -> str:
        prompt = DeepPentestPrompt.write_plan_exploiter

        if self.role_name == RoleType.COLLECTOR.value:
             prompt = DeepPentestPrompt.write_plan_collector

        formatted_prompt = prompt.format(shared_summary=shared_summary, init_description=init_description)

        plan_max_tokens = 256

        rsp = _chat(
            query=formatted_prompt,
            conversation_id=self.plan_chat_id,
            kb_query=init_description,
            summary=False,
            use_history=True,
            max_tokens_override=plan_max_tokens,
        )
        if isinstance(rsp, tuple):
            rsp = rsp[0]
        return self._extract_json_block(rsp)

    def update(self, completed_task: Task, success_task: List[str], fail_task: List[str],
               init_description: str, shared_summary: str) -> Optional[str]:
        """
        Update the plan based on a completed task.

        Args:
            completed_task: Task object (from DB) with instruction, code, result populated
            success_task: List of successful task instructions
            fail_task: List of failed task instructions
            init_description: Initial task description
            shared_summary: Summary from shared memory

        Returns:
            JSON string containing updated plan, or empty string if no update needed
        """
        # Format code and task lists for better prompt readability
        formatted_code = "\n".join(completed_task.code) if isinstance(completed_task.code, list) else str(completed_task.code)
        formatted_success_tasks = "\n".join(f"- {t}" for t in success_task) if success_task else "None"
        formatted_fail_tasks = "\n".join(f"- {t}" for t in fail_task) if fail_task else "None"

        # Choose prompt based on role
        if self.role_name == RoleType.COLLECTOR.value:
            prompt = DeepPentestPrompt.update_plan_collector
        else:
            prompt = DeepPentestPrompt.update_plan

        query = prompt.format(
            current_task=completed_task.instruction,
            init_description=init_description,
            current_code=formatted_code,
            task_result=completed_task.result,
            shared_summary=shared_summary,
            success_task=formatted_success_tasks,
            fail_task=formatted_fail_tasks
        )

        update_max_tokens = 256

        rsp = _chat(
            query=query,
            conversation_id=self.plan_chat_id,
            kb_query=completed_task.instruction,
            summary=False,
            use_history=True,
            max_tokens_override=update_max_tokens,
        )
        if isinstance(rsp, tuple):
            rsp = rsp[0]
        if rsp == "":
            return rsp
        return self._extract_json_block(rsp)


def parse_tasks(response: str, current_plan: Plan):
    # Handle None or empty response
    if not response:
        raise ValueError("parse_tasks received empty or None response from LLM. The plan generation failed.")

    # Strip and clean the response
    processed_response = response.strip()

    processed_response = extract_json_payload(processed_response)

    # Preprocess to handle escape sequences
    processed_response = preprocess_json_string(processed_response)

    # Validate we have something to parse
    if not processed_response:
        raise ValueError("parse_tasks: After cleaning, response is empty. Cannot parse tasks.")

    try:
        parsed_response = json.loads(processed_response)
    except json.JSONDecodeError as e:
        raise ValueError(f"parse_tasks: Failed to parse JSON. Error: {e}. Response preview: {processed_response[:200]}...")

    if isinstance(parsed_response, dict):
        parsed_response = [parsed_response]
    elif not isinstance(parsed_response, list):
        raise ValueError(f"parse_tasks: Expected JSON list or object, got {type(parsed_response).__name__}.")

    tasks = import_tasks_from_json(current_plan.id, parsed_response)

    current_plan.tasks = tasks

    return current_plan

def preprocess_json_string(json_str: str) -> str:
    """
    Robust JSON preprocessing using a character-by-character state machine.

    Handles:
    - Unescaped double/single quotes inside string values
    - Unterminated JSON strings (LLM output cut off mid-string)
    - Invalid escape sequences (\\@, \\!)
    - Truncated JSON arrays/objects (missing closing brackets)

    Falls back to the original string if the repair itself produces
    something unparseable and worse than the original.
    """
    # Fix obviously invalid escape sequences first (e.g. \@ \!)
    json_str = re.sub(r'\\([@!])', lambda m: '\\\\' + m.group(1), json_str)

    # Fast path: already valid
    try:
        json.loads(json_str)
        return json_str
    except json.JSONDecodeError:
        pass

    # ------------------------------------------------------------------ #
    # Character-by-character repair                                        #
    # ------------------------------------------------------------------ #
    out: list[str] = []
    i = 0
    n = len(json_str)

    # Track open braces/brackets so we can close them at the end
    depth_stack: list[str] = []  # '[' or '{'

    in_string = False
    escape_next = False

    while i < n:
        ch = json_str[i]

        if escape_next:
            out.append(ch)
            escape_next = False
            i += 1
            continue

        if in_string:
            if ch == '\\':
                # Peek ahead: is the next char a valid JSON escape?
                next_ch = json_str[i + 1] if i + 1 < n else ''
                valid_escapes = set('"\\bfnrtu/')
                if next_ch in valid_escapes:
                    out.append(ch)
                    escape_next = True
                else:
                    # Invalid escape — double the backslash
                    out.append('\\\\')
                i += 1
                continue

            if ch == '"':
                # This closes the current string
                in_string = False
                out.append(ch)
                i += 1
                continue

            if ch == '\n' or ch == '\r':
                # Bare newline inside a JSON string — escape it
                out.append('\\n' if ch == '\n' else '\\r')
                i += 1
                continue

            # Ordinary character inside a string
            out.append(ch)
            i += 1
            continue

        # ---- Outside a string ----
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch in ('{', '['):
            depth_stack.append(ch)
            out.append(ch)
            i += 1
            continue

        if ch in ('}', ']'):
            if depth_stack:
                depth_stack.pop()
            out.append(ch)
            i += 1
            continue

        out.append(ch)
        i += 1

    # If we ended while still inside a string, close it
    if in_string:
        out.append('"')

    # Close any unclosed brackets/braces
    closing = {'{': '}', '[': ']'}
    for opener in reversed(depth_stack):
        out.append(closing[opener])

    repaired = ''.join(out)

    try:
        json.loads(repaired)
        return repaired
    except json.JSONDecodeError:
        # Repair made things worse; return original so the caller gets
        # the original error message
        return json_str

def merge_tasks(response: str, current_plan: Plan):
    # Strip common JSON wrapper tags that LLMs add
    processed_response = response.strip()

    processed_response = extract_json_payload(processed_response)

    # Preprocess the input JSON string
    processed_response = preprocess_json_string(processed_response)

    response = json.loads(processed_response)
    if isinstance(response, dict):
        response = [response]
    elif not isinstance(response, list):
        raise ValueError(f"merge_tasks: Expected JSON list or object, got {type(response).__name__}.")

    tasks = merge_tasks_from_json(current_plan.id, response, current_plan.tasks)

    current_plan.tasks = tasks

    return current_plan


def get_first_task_instruction(response: str) -> Optional[str]:
    if not response:
        return None

    processed_response = extract_json_payload(response.strip())
    processed_response = preprocess_json_string(processed_response)
    if not processed_response:
        return None

    parsed_response = json.loads(processed_response)
    if isinstance(parsed_response, dict):
        parsed_response = [parsed_response]
    if not isinstance(parsed_response, list) or not parsed_response:
        return None

    first_task = _normalize_task_schema(parsed_response[0])
    instruction = first_task.get("instruction")
    if not instruction:
        return None
    return normalize_phase_tags(instruction)


def normalize_phase_tags(instruction: str) -> str:
    """
    Normalize phase tags to handle LLM hallucinations.
    [Reconnaissance] -> [Recon]
    [Scan] -> [Scanning]
    [Exploit] -> [Exploitation]
    ...
    """
    # Regex basic patterns
    instruction = re.sub(r'^\[Recon.*?\]', '[Recon]', instruction, flags=re.IGNORECASE)
    instruction = re.sub(r'^\[Scan.*?\]', '[Scanning]', instruction, flags=re.IGNORECASE)
    instruction = re.sub(r'^\[Exploit.*?\]', '[Exploitation]', instruction, flags=re.IGNORECASE)
    return instruction

def _normalize_task_schema(task_data: Dict) -> Dict:
    """
    Accept slight schema drift from the planner without crashing the run.
    Canonical schema:
      - id
      - dependent_task_ids
      - instruction
      - action
    """
    normalized = dict(task_data or {})

    if 'instruction' not in normalized and 'task' in normalized:
        normalized['instruction'] = normalized['task']

    if 'dependent_task_ids' not in normalized or normalized['dependent_task_ids'] is None:
        normalized['dependent_task_ids'] = []

    if 'action' not in normalized or not normalized['action']:
        tool_name = str(normalized.get('tool', '') or '').lower()
        normalized['action'] = 'Shell' if 'cmdexec' in tool_name or 'shell' in tool_name else 'Web'

    return normalized

def import_tasks_from_json(plan_id: str, tasks_json: List[Dict]) -> List[TaskModel]:
    tasks = []
    normalized_tasks = [_normalize_task_schema(task_data) for task_data in tasks_json]
    for idx, task_data in enumerate(normalized_tasks):
        instruction = normalize_phase_tags(task_data['instruction'])
        task = Task(
            plan_id=plan_id,
            sequence=idx,
            action=task_data['action'],
            instruction=instruction,
            dependencies=[i for i, t in enumerate(normalized_tasks)
                          if t['id'] in task_data['dependent_task_ids']]
        )

        tasks.append(task)
    return tasks


def merge_tasks_from_json(plan_id: str, new_tasks_json: List[Dict], old_tasks: List[Task]) -> List[Task]:
    normalized_new_tasks = [_normalize_task_schema(task_data) for task_data in new_tasks_json]
    completed_tasks_map = {
        task.instruction: task
        for task in old_tasks
        if task.is_finished and task.is_success
    }

    merged_tasks = []

    for instruction, completed_task in completed_tasks_map.items():
        found = False
        for task_data in normalized_new_tasks:
            norm_instruction = normalize_phase_tags(task_data['instruction'])
            if norm_instruction == instruction:
                found = True
                break
        if not found:
            completed_task.sequence = len(merged_tasks)
            completed_task.dependencies = []
            merged_tasks.append(completed_task)

    new_task_id_to_idx = {
        task_data.get('id'): idx+len(merged_tasks)
        for idx, task_data in enumerate(normalized_new_tasks)
    }
    for idx, task_data in enumerate(normalized_new_tasks):
        instruction = normalize_phase_tags(task_data['instruction'])
        sequence = len(merged_tasks)

        if instruction in completed_tasks_map:
            existing_task = completed_tasks_map[instruction]
            existing_task.sequence = sequence
            existing_task.dependencies = [
                new_task_id_to_idx[dep_id]
                for dep_id in task_data['dependent_task_ids']
                if dep_id in new_task_id_to_idx
            ]
            merged_tasks.append(existing_task)
        else:
            new_task = Task(
                plan_id=plan_id,
                sequence=sequence,
                action=task_data['action'],
                instruction=instruction,
                dependencies=[
                    new_task_id_to_idx[dep_id]
                    for dep_id in task_data['dependent_task_ids']
                    if dep_id in new_task_id_to_idx
                ],
            )
            merged_tasks.append(new_task)

    return merged_tasks
