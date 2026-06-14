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
class WritePlan(BaseModel):
    plan_chat_id: str
    role_name: str = RoleType.EXPLOITER.value

    def run(self, init_description, shared_summary) -> str:
        prompt = DeepPentestPrompt.write_plan_exploiter
        use_reasoner = False  # Reasoner disabled for faster planning
        
        if self.role_name == RoleType.COLLECTOR.value:
             prompt = DeepPentestPrompt.write_plan_collector
        
        rsp = _chat(
            query=prompt.format(shared_summary=shared_summary, init_description=init_description), 
            conversation_id=self.plan_chat_id, 
            kb_name=Configs.kb_config.kb_name, 
            kb_query=init_description,
            use_reasoner=use_reasoner
        )
        if isinstance(rsp, tuple):
            rsp = rsp[0]

        match = re.search(r'<json>(.*?)</json>', rsp, re.DOTALL)
        if match:
            code = match.group(1)
            return code
        else:
            # Fallback: return raw response and let parse_tasks handle it
            return rsp

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
        use_reasoner = False  # Reasoner disabled for faster planning
        
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
        
        
        # Generate plan (consistency check removed for performance)
        rsp = _chat(
            query=query,
            conversation_id=self.plan_chat_id,
            kb_name=Configs.kb_config.kb_name,
            kb_query=completed_task.instruction,
            use_reasoner=use_reasoner
        )
        if isinstance(rsp, tuple):
            rsp = rsp[0]
        if rsp == "":
            return rsp

        match = re.search(r'<json>(.*?)</json>', rsp, re.DOTALL)
        if match:
            return match.group(1)
        else:
            return rsp


def parse_tasks(response: str, current_plan: Plan):
    # Handle None or empty response
    if not response:
        raise ValueError("parse_tasks received empty or None response from LLM. The plan generation failed.")
    
    # Strip and clean the response
    processed_response = response.strip()
    
    # Remove <json> tags if present
    if processed_response.startswith('<json>'):
        processed_response = processed_response[6:]
    if processed_response.endswith('</json>'):
        processed_response = processed_response[:-7]
    
    # Remove ```json code blocks if present
    if processed_response.startswith('```json'):
        processed_response = processed_response[7:]
    if processed_response.startswith('```'):
        processed_response = processed_response[3:]
    if processed_response.endswith('```'):
        processed_response = processed_response[:-3]
    
    processed_response = processed_response.strip()
    
    # Preprocess to handle escape sequences
    processed_response = preprocess_json_string(processed_response)
    
    # Validate we have something to parse
    if not processed_response:
        raise ValueError("parse_tasks: After cleaning, response is empty. Cannot parse tasks.")
    
    try:
        parsed_response = json.loads(processed_response)
    except json.JSONDecodeError as e:
        raise ValueError(f"parse_tasks: Failed to parse JSON. Error: {e}. Response preview: {processed_response[:200]}...")

    tasks = import_tasks_from_json(current_plan.id, parsed_response)

    current_plan.tasks = tasks

    return current_plan

def preprocess_json_string(json_str):
    """
    Enhanced JSON preprocessing to handle malformed strings with unescaped quotes,
    wildcards, and special characters in instruction fields.
    """
    # Fix invalid escape sequences
    json_str = re.sub(r'\\([@!])', r'\\\\\1', json_str)
    
    # Strategy: Use a robust approach to fix unterminated strings
    # Look for instruction fields and ensure proper escaping
    
    try:
        # First attempt: try to parse as-is
        json.loads(json_str)
        return json_str
    except json.JSONDecodeError as e:
        # If parsing fails, attempt to fix common issues
        error_msg = str(e)
        
        if "Unterminated string" in error_msg:
            # Pattern to match instruction fields with potentially problematic content
            # This will match: "instruction": "content..."
            pattern = r'("instruction"\s*:\s*")([^"]*(?:[^\\"]|\\.)*)(")'
            
            def fix_quotes(match):
                prefix = match.group(1)  # "instruction": "
                content = match.group(2)  # the content
                suffix = match.group(3)   # closing "
                
                # Check if content has unescaped quotes
                # Replace unescaped quotes (but not already escaped ones)
                fixed_content = content
                
                # Temporarily replace escaped quotes with placeholder
                fixed_content = fixed_content.replace('\\"', '\x00ESCAPED\x00')
                # Escape any remaining quotes
                fixed_content = fixed_content.replace('"', '\\"')
                # Restore the placeholders
                fixed_content = fixed_content.replace('\x00ESCAPED\x00', '\\"')
                
                return f'{prefix}{fixed_content}{suffix}'
            
            # Apply the fix
            json_str = re.sub(pattern, fix_quotes, json_str, flags=re.DOTALL)
            
            # Try parsing again
            try:
                json.loads(json_str)
                return json_str
            except json.JSONDecodeError:
                # If still failing, return original (will fail with better error message)
                pass
        
        # If all else fails, return the original
        return json_str
    
    return json_str

def merge_tasks(response: str, current_plan: Plan):
    # Strip common JSON wrapper tags that LLMs add
    processed_response = response.strip()
    
    # Remove <json> tags
    if processed_response.startswith('<json>'):
        processed_response = processed_response[6:]
    if processed_response.endswith('</json>'):
        processed_response = processed_response[:-7]
    
    # Remove ```json code blocks
    if processed_response.startswith('```json'):
        processed_response = processed_response[7:]
    if processed_response.startswith('```'):
        processed_response = processed_response[3:]
    if processed_response.endswith('```'):
        processed_response = processed_response[:-3]
    
    processed_response = processed_response.strip()
    
    # Preprocess the input JSON string
    processed_response = preprocess_json_string(processed_response)

    response = json.loads(processed_response)

    tasks = merge_tasks_from_json(current_plan.id, response, current_plan.tasks)

    current_plan.tasks = tasks

    return current_plan


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

def import_tasks_from_json(plan_id: str, tasks_json: List[Dict]) -> List[TaskModel]:
    tasks = []
    for idx, task_data in enumerate(tasks_json):
        instruction = normalize_phase_tags(task_data['instruction'])
        task = Task(
            plan_id=plan_id,
            sequence=idx,
            action=task_data['action'],
            instruction=instruction,
            dependencies=[i for i, t in enumerate(tasks_json)
                          if t['id'] in task_data['dependent_task_ids']]
        )

        tasks.append(task)
    return tasks


def merge_tasks_from_json(plan_id: str, new_tasks_json: List[Dict], old_tasks: List[Task]) -> List[Task]:
    # 获取所有已完成且成功的任务
    completed_tasks_map = {
        task.instruction: task
        for task in old_tasks
        if task.is_finished and task.is_success
    }

    merged_tasks = []

    for instruction, completed_task in completed_tasks_map.items():
        found = False
        for task_data in new_tasks_json:
            # Normalize for comparison logic
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
        for idx, task_data in enumerate(new_tasks_json)
    }
    for idx, task_data in enumerate(new_tasks_json):
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