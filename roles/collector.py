from typing import ClassVar, Optional
from prompts.collector_prompt import CollectorPrompt
from prompts.prompt import DeepPentestPrompt
from roles.role import Role
from utils.log_common import RoleType
from srmm.srmm_manage import SRMMManager
from server.chat.chat import _call_tool, _chat
from server.chat.reflection import intra_reflection
from config.config import Configs
from roles.exploiter import Exploiter
from utils.log_common import build_logger
logger = build_logger()
from tools.web_recon_tool import tools_description
class Collector(Role):
    name: str = RoleType.COLLECTOR.value
    allowed_prefixes: list[str] = []
    goal: str = "Perform a full scan of the target to identify all open ports and services."
    prompt: ClassVar[CollectorPrompt] = CollectorPrompt

    def __init__(self, console, max_interactions, srmm: Optional[SRMMManager] = None, llm=None, **kwargs):
        super().__init__(**kwargs)
        self.console = console
        self.max_interactions = max_interactions
        self.srmm = srmm
        self.llm = llm
            
    async def put_message(self, message):
        super().put_message(self)
        
        if message.current_role_name == RoleType.COLLECTOR.value:
            message.current_role_name = RoleType.EXPLOITER.value
            message.history_planner_ids.append(self.planner.current_plan.id)
            message.current_planner_id = ''
            await Exploiter(
                console=self.console,
                max_interactions=self.max_interactions,
                srmm=self.srmm,
                llm=self.llm
            ).run(message)

    async def _react(self, next_task):
        """
        Use Validator-Driven Agent Flow for reconnaissance.
        Passes SHORT query + role_guidance + context to _call_tool_with_reflection.
        """
        # Build context from shared memory (if enabled)
        context = ""
        if Configs.basic_config.enable_srmm and getattr(self, "srmm", None) is not None:
            try:
                # Only READ from SRMM, don't write task description
                shared_memory = self.srmm.get_shared_memory()
                context = str(shared_memory)[:2000]
                try:
                    self.console.log(f"[SRMM] Collector context loaded: {len(context)} chars")
                    logger.info(f"[SRMM DEBUG] Content preview: {context[:500]}...")
                except Exception:
                    pass
            except Exception as e:
                logger.warning(f"[SRMM] Collector SRMM get_shared_memory failed: {e}")
        
        query = next_task
        logger.info(f"[Collector] Query: {query}")

        remaining_reflections = 3
        task_result = None
        analyzer_result = ""

        while True:
            task_result, analyzer_result = await _call_tool(
                query=query,
                conversation_id=self.planner.current_plan.react_chat_id,
                llm_model=self.llm,
                type="collector",
                use_history=False,
            )

            if not Configs.basic_config.enable_reflection:
                break

            try:
                decision_obj = await intra_reflection(
                    recon_analyzer_output=analyzer_result,
                    exploit_analyzer_output="",
                    tool_runtime_result=getattr(task_result, "result", "") or "",
                    original_task=next_task,
                    current_query=query,
                    remaining_reflections=remaining_reflections,
                )
            except Exception as e:
                logger.warning(f"[Collector][Reflection] Failed: {e}")
                break

            decision = str(decision_obj.get("decision", "STOP")).upper()
            remaining_reflections = int(decision_obj.get("remaining_reflections", remaining_reflections))
            next_query = str(decision_obj.get("next_query", "") or "")

            if decision == "RETRY" and next_query.strip() and remaining_reflections >= 0:
                logger.info(f"[Collector][Reflection] RETRY: {decision_obj.get('reason','')}")
                query = next_query.strip()
                continue

            # STOP or SUCCESS
            logger.info(f"[Collector][Reflection] {decision}: {decision_obj.get('reason','')}")
            break
        
        if Configs.basic_config.enable_srmm and getattr(self, "srmm", None) is not None:
            try:
                # Use analyzer_result for SRMM (summarized text)
                res_text = self.srmm.encode_obs({"role": self.name, "result": analyzer_result})
                self.srmm.step("agent_collector", res_text)
                try:
                    self.console.log("[SRMM] Collector memory updated.")
                except Exception:
                    pass
            except Exception as e:
                try:
                    self.console.log(f"[SRMM_ERROR] {e}")
                except Exception:
                    pass
        
        # Pass TaskResult object to planner.update_plan
        return self.planner.update_plan(task_result)
