from typing import List, Optional
from pydantic import BaseModel, Field

from db.repository.plan_repository import get_planner_by_id
from prompts.prompt import DeepPentestPrompt
from server.chat.chat import _chat
from utils.log_common import build_logger
from utils.log_common import RoleType
from rag.red_mirror import RAGQueryContext, get_default_rag_service
from config.config import Configs

logger = build_logger()


from prompts.summary_prompt import SummaryPrompt

class PlannerSummary(BaseModel):
    history_planner_ids: List[str] = Field(default_factory=list)

    def get_summary(self):
        if len(self.history_planner_ids) == 0:
            return ""

        summary = "**Previous Phase**:\n"
        for index, planner_id in enumerate(self.history_planner_ids):
            plan = get_planner_by_id(planner_id)
            for task in plan.finished_tasks:
                summary += (f"**Instruction**: {task.instruction}\n, **Code**: {task.code}\n, **Result**: {task.result}\n"
                            f"------\n")
        if summary == "**Previous Phase**:\n":
            return ""
        response = _chat(query=DeepPentestPrompt.write_summary + str(summary), summary=False)
        if isinstance(response, tuple):
             response = response[0]

        logger.info(f"summary: {response}")

        return response

    def get_filtered_recon_summary(self):
        """
        Extracts and filters critical recon data for the exploiter.
        """
        if len(self.history_planner_ids) == 0:
            return "No previous reconnaissance data found."

        raw_results = ""
        for index, planner_id in enumerate(self.history_planner_ids):
            plan = get_planner_by_id(planner_id)
            if not plan:
                continue
            for task in plan.finished_tasks:
                # We care more about the result than the code itself for recon summary
                raw_results += (f"Task: {task.instruction}\nResult: {task.result}\n"
                                f"------\n")

        if not raw_results:
            return "No reconnaissance results available."

        # Use the specific filtering prompt
        response = _chat(
            query=SummaryPrompt.recon_summary_prompt.format(recon_results=raw_results),
            summary=False
        )
        if isinstance(response, tuple):
            response = response[0]

        if Configs.basic_config.enable_rag:
            try:
                rag_result = get_default_rag_service().retrieve(
                    RAGQueryContext(
                        current_task="Correlate reconnaissance findings with task-relevant external knowledge for exploitation planning.",
                        role=RoleType.EXPLOITER.value,
                        shared_summary=response,
                    )
                )
                rag_context = rag_result.format_for_prompt(max_snippets=4)
                if rag_context:
                    response = f"{response}\n\n### Prioritized Attack-Vector Context\n{rag_context}"
            except Exception as e:
                logger.warning(f"[RAG] Summarizer retrieval failed: {e}")

        logger.info(f"Filtered Recon Summary: {response}")
        return response
