from typing import Optional
from pydantic import BaseModel, ConfigDict

from actions.write_plan import WritePlan, parse_tasks, merge_tasks, get_first_task_instruction
from db.models.task_model import Task
from db.models.task_result import TaskResult
from prompts.prompt import DeepPentestPrompt
from db.models.plan_model import Plan
from server.chat.chat import _chat
from config.config import Configs
from utils.log_common import build_logger
from server.utils.utils import safe_parse_json
from srmm.srmm_manage import SRMMManager
import json
from utils.log_common import RoleType
import re
import json

logger = build_logger()


class Planner(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    current_plan: Plan = None
    init_description: str = ""
    srmm: Optional[SRMMManager] = None
    use_reflection: bool = True
    role_name: str = RoleType.EXPLOITER.value
    flag_found: bool = False  # Track if flag was found during execution

    def _extract_authoritative_base_url(self) -> str:
        text = self.init_description or ""
        match = re.search(r'https?://[^\s)>\]]+', text, re.IGNORECASE)
        return match.group(0).rstrip('.,;') if match else ""

    def _normalize_task_targets(self) -> None:
        base_url = self._extract_authoritative_base_url()
        if not base_url or not self.current_plan or not self.current_plan.tasks:
            return

        placeholder_patterns = [
            r'https?://target\.local(?::\d+)?',
            r'https?://target\b(?::\d+)?',
            r'https?://localhost(?::\d+)?',
            r'https?://127\.0\.0\.1(?::\d+)?',
        ]

        changed = 0
        for task in self.current_plan.tasks:
            instruction = task.instruction or ""
            updated = instruction
            for pattern in placeholder_patterns:
                updated = re.sub(pattern, base_url, updated, flags=re.IGNORECASE)
            if updated != instruction:
                task.instruction = updated
                changed += 1

        if changed:
            logger.info(f"[PLANNER] Normalized target URL in {changed} task(s) using init_description base URL: {base_url}")

    def plan(self):
        """
        Generate or continue plan.
        """
        if self.current_plan.current_task:
            return self.next_task_details()
        
        shared_summary = ""
        if Configs.basic_config.enable_srmm:
            shared_memory = self.srmm.get_shared_memory() if self.srmm is not None else "There is no shared memory because this is the first step of the session penetration testing."
            shared_summary = _chat(
                query=DeepPentestPrompt.shared_summary.format(shared_memory=shared_memory),
                summary=False
            )
            if isinstance(shared_summary, tuple):
                shared_summary = shared_summary[0]
        else:
            shared_summary = "There is no shared memory because SRMM is disabled in the configuration."
        
        response = WritePlan(plan_chat_id=self.current_plan.plan_chat_id, role_name=self.role_name).run(self.init_description, shared_summary)
        logger.info(f"plan: {response}")

        try:
            self.current_plan = parse_tasks(response, self.current_plan)
            self._normalize_task_targets()
            logger.info(f"[PLANNER] Parsed {len(self.current_plan.tasks)} tasks.")
        except Exception as e:
            logger.error(f"[PLANNER] Failed to parse plan: {e}")
            logger.error(f"[PLANNER] Raw response was: {response[:500] if response else 'None'}...")
            import traceback
            logger.error(traceback.format_exc())
            return None
        return self.next_task_details()

    def update_plan(self, task_result_obj: TaskResult) -> Optional[str]:
        """
        Update plan after each agent finishes its task.
        Only READ from SRMM shared memory (no write).
        
        Args:
            task_result_obj: TaskResult object containing instruction, code (tool calls), and result (tool outputs)
        
        Returns:
            Next task details string, or None if no more tasks
        """
        shared_summary = ""
        
        # Extract result string for check_success (use task_result_obj.result which contains tool outputs)
        result_text = task_result_obj.result if hasattr(task_result_obj, 'result') else str(task_result_obj)
        yes_count = 0
        no_count = 0
        last_check_success_yes = None
        last_check_success_no = None
        check_success_rounds = 3 if Configs.basic_config.enable_reflection else 1

        for i in range(check_success_rounds):
            check_response = _chat(
                query=DeepPentestPrompt.check_success.format(result=result_text),
                conversation_id=self.current_plan.react_chat_id,
                summary=False,
                use_history=False,
            )
            is_yes = "yes" in check_response.lower()
            
            if is_yes:
                yes_count += 1
                last_check_success_yes = check_response
            else:
                no_count += 1
                last_check_success_no = check_response
        
        if yes_count > no_count:
            check_success = last_check_success_yes
        else:
            check_success = last_check_success_no
        
        logger.info(f"Check success ({check_success_rounds} round(s)): {check_success}")

        # Extract code from TaskResult for persistence
        code_to_save = task_result_obj.code if hasattr(task_result_obj, 'code') else []
        
        if "yes" in check_success.lower():
            updated_task = self.update_task_status(
                self.current_plan.id,
                self.current_plan.current_task_sequence,
                True, True, result_text, code_to_save
            )
        else:
            updated_task = self.update_task_status(
                self.current_plan.id,
                self.current_plan.current_task_sequence,
                True, False, result_text, code_to_save
            )
        
        # 🎯 EARLY TERMINATION: Check if FLAG was found
        result_lower = str(result_text).lower()
        flag_indicators = [
            "flag{",           # Standard CTF flag format
        ]
        
        if any(indicator in result_lower for indicator in flag_indicators):
            logger.info(f"🎯 FLAG FOUND! Result contains flag. Terminating early.")
            import re
            flag_match = re.search(r'FLAG\{[^}]*\}', result_text, re.IGNORECASE)
            if flag_match:
                logger.info(f"🎯 FLAG EXTRACTED: {flag_match.group(0)}")
            else:
                logger.info(f"FLAG detected but not cleanly extracted. Preview: {result_text[:1000]}")
            
            # Mark current task as successful (with code)
            code_to_save = task_result_obj.code if hasattr(task_result_obj, 'code') else []
            self.update_task_status(
                self.current_plan.id,
                self.current_plan.current_task_sequence,
                True, True, result_text, code_to_save
            )
            
            # Set flag_found to True so Role can check this state
            self.flag_found = True
            
            # Return None to stop the execution loop
            return None
        
        if Configs.basic_config.enable_srmm:
            if self.srmm is not None:
                try:
                    shared_memory = self.srmm.get_shared_memory()
                    shared_summary = _chat(
                        query=DeepPentestPrompt.shared_summary.format(shared_memory=shared_memory),
                        summary=False
                    )
                    if isinstance(shared_summary, tuple):
                        shared_summary = shared_summary[0]
                except Exception as e:
                    logger.warning(f"[SRMM_ERROR] Failed to get shared summary: {e}")
                    shared_summary = "Failed to retrieve shared memory"
            else:
                shared_summary = "SRMM is enabled but manager is not initialized"
        else:
            shared_summary = "There is no shared memory because SRMM is disabled in the configuration."
        
        if self.role_name == RoleType.COLLECTOR.value:
            total_tasks = len(self.current_plan.tasks)
            if total_tasks >=4:
                #logger.info(f"🛑 [COLLECTOR] Task limit reached ({total_tasks}/4). Stopping reconnaissance.")
                return None
        
        # Bước 5: Cập nhật plan với Task object (contains code and result from TaskResult)
        updated_response = (WritePlan(plan_chat_id=self.current_plan.react_chat_id, role_name=self.role_name)
                            .update(updated_task,  # Pass Task object with code and result populated
                                    self.current_plan.finished_success_tasks,
                                    self.current_plan.finished_fail_tasks,
                                    self.init_description, shared_summary))
        
        logger.info(f"updated_plan: {updated_response}")

        normalized_updated_response = (updated_response or "").strip() if isinstance(updated_response, str) else updated_response
        if self.role_name == RoleType.COLLECTOR.value and normalized_updated_response in ("", "[]", "<json>[]</json>"):
            logger.info("[PLANNER] Collector produced no follow-up tasks. Ending collector phase.")
            return None

        if not updated_response:
            return None

        immediate_next_task = get_first_task_instruction(updated_response)
        merge_tasks(updated_response, self.current_plan)
        self._normalize_task_targets()

        if immediate_next_task:
            matched_task = next(
                (task for task in self.current_plan.tasks if task.instruction == immediate_next_task and not task.is_finished),
                None
            )
            if matched_task is not None:
                self.current_plan.current_task_sequence = matched_task.sequence
            return immediate_next_task

        return self.next_task_details()

    def next_task_details(self):
        """
        Query next task details.
        """
        current_task = self.current_plan.current_task
        if current_task is None:
            fallback_task = next((task for task in self.current_plan.tasks if not getattr(task, "is_finished", False)), None)
            if fallback_task is None and self.current_plan.tasks:
                fallback_task = self.current_plan.tasks[0]
            if fallback_task is None:
                logger.warning("[PLANNER] No available task found after parsing/merge.")
                return None
            current_task = fallback_task

        self.current_plan.current_task_sequence = current_task.sequence
        return current_task.instruction

    def update_task_status(self, plan_id: str, task_sequence: int,
                           is_finished: bool, is_success: bool, 
                           result: Optional[str] = None,
                           code: Optional[list] = None) -> Task:
        """
        Update task status including code field.
        
        Args:
            plan_id: Plan ID
            task_sequence: Task sequence number
            is_finished: Whether task is finished
            is_success: Whether task succeeded
            result: Task execution result
            code: List of code/commands executed (from TaskResult)
        
        Returns:
            Updated Task object
        """
        task = next((
            t for t in self.current_plan.tasks
            if t.plan_id == plan_id and t.sequence == task_sequence
        ), None)

        if task:
            task.is_finished = is_finished
            task.is_success = is_success
            if result:
                task.result = result
            if code is not None:
                task.code = code

        return task
