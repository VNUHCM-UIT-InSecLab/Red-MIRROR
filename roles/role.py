import prompts.tools_description
from typing import Any, ClassVar, Optional, List
from pydantic import Field, BaseModel, ConfigDict
from actions.plan_summary import PlannerSummary
from actions.planner import Planner
from config.config import Configs
from db.models.plan_model import Plan
from db.repository.plan_repository import get_planner_by_id, add_plan_to_db
from db.repository.task_repository import add_task_to_plan
from prompts.prompt import DeepPentestPrompt
from server.chat.chat import _chat
from utils.log_common import RoleType, build_logger
from srmm.srmm_manage import SRMMManager
from srmm.srmm_core import SRMMCore

logger = build_logger()


class Role(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    name: str
    goal: str
    tools: str = ""
    prompt: ClassVar
    max_interactions: int = 5
    previous_summary: PlannerSummary = Field(default_factory=PlannerSummary)
    planner: Planner = Field(default_factory=Planner)
    chat_counter: int = 0
    plan_chat_id: str = ""
    react_chat_id: str = ""
    console: Any = None
    srmm: Optional[SRMMManager] = None
    llm: Any = None
    agent: Any = None
    allowed_prefixes: List[str] = []
    context: str = ""

    def get_summary(self, history_planner_ids):
        self.previous_summary = PlannerSummary(history_planner_ids=history_planner_ids)
        return self.previous_summary.get_summary()

    def get_filtered_summary(self, history_planner_ids):
        self.previous_summary = PlannerSummary(history_planner_ids=history_planner_ids)
        return self.previous_summary.get_filtered_recon_summary()

    def put_message(self, message):
        if self.planner.current_plan:
            add_task_to_plan(self.planner.current_plan.tasks)
        # To be implemented in each subclass
        pass

    def FindTargetURL(self, task_description):
        """
        Extract target URL from task description.
        """
        prompt = DeepPentestPrompt.FindTargetURL.format(task_description=task_description)
        response = _chat(query=prompt, summary=False)
        if isinstance(response, tuple):
            response = response[0]
        return response.strip()
    
    # _react method is implemented by subclasses (Collector, Exploiter)
    # Each subclass provides its own async implementation using _call_tool
    async def _react(self, next_task):
        """
        Base _react method - must be overridden by subclasses.
        Collector and Exploiter provide their own async implementations.
        """
        raise NotImplementedError("Subclasses must implement _react method")
            
    def _check_phase(self, instruction: str) -> bool:
        """Check if instruction matches the role's allowed phase prefixes."""
        if not self.allowed_prefixes:
            return True
        for prefix in self.allowed_prefixes:
            if prefix in instruction:
                return True
        return False

    def _plan(self, session):
        if Configs.basic_config.enable_srmm:
            if self.srmm is None:
                try:
                    self.srmm = SRMMManager(SRMMCore(hidden_size=512), num_agents=3, text_mode=True)
                except Exception:
                    self.srmm = SRMMManager(None, num_agents=3, text_mode=True)
        if session.current_planner_id != '':
            self.planner = Planner(current_plan=get_planner_by_id(session.current_planner_id), 
                                 init_description=session.init_description, 
                                 role_name=self.name,
                                 srmm=self.srmm)
        else:
            with self.console.status("[bold green] Initializing DeepPentest Sessions...") as status:
                try:
                    if self.name == RoleType.EXPLOITER.value:
                        self.tools = prompts.tools_description.EXPLOITER_TOOLS
                        self.context = self.get_filtered_summary(session.history_planner_ids)
                    else:
                        self.tools = prompts.tools_description.COLLECTOR_TOOLS
                        self.context = self.get_summary(session.history_planner_ids)

                    (text_0, self.plan_chat_id) = _chat(
                        query=self.prompt.init_plan_prompt.format(init_description=session.init_description,
                                                                  goal=self.goal,
                                                                  tools=self.tools,
                                                                  context=self.context)
                    )
                    (text_1, self.react_chat_id) = _chat(query=self.prompt.init_reasoning_prompt)
                except Exception as e:
                    self.console.print(f"Failed to initialize chat sessions: {e}", style="bold red")
                    return None
            plan = Plan(goal=self.goal, plan_chat_id=self.plan_chat_id, react_chat_id=self.react_chat_id, current_task_sequence=0)
            plan = add_plan_to_db(plan)
            self.console.print("Plan Initialized.", style="bold green")
            session.current_planner_id = plan.id
            self.planner = Planner(current_plan=plan, init_description=session.init_description, role_name=self.name, srmm=self.srmm)

        return self.planner.plan()
    
    async def run(self, session):
        """
        Run planning/react loop.
        """
        next_task = self._plan(session)
        print(f"[DEBUG]next_task for {self.name}: {next_task}")
        while self.chat_counter < self.max_interactions and next_task is not None:            
            next_task =  await self._react(next_task)

        # Only call put_message if collector didn't find a flag
        # Check planner.flag_found instead of relying on next_task being None
        if self.name == RoleType.COLLECTOR.value:
            if self.planner.flag_found:
                logger.info(f"🎯 [{self.name}] Flag found! Skipping put_message to Exploiter.")
            else:
                await self.put_message(session)
