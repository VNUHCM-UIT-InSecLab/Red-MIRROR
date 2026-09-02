from typing import List
from pydantic import BaseModel, Field


class TaskResult(BaseModel):
    """
    Standardized format for task execution results.
    Used to pass structured data to WritePlan.update() method.
    """
    instruction: str = Field(default="", description="The task instruction that was executed")
    code: List[str] = Field(default_factory=list, description="List of commands/code executed")
    result: str = Field(default="", description="The execution result/output")
    analysis: str = Field(default="", description="Analyzer output derived from the execution result")
    
    def format_code_for_prompt(self) -> str:
        """Format code list as readable string for LLM prompts"""
        if not self.code:
            return "No code executed"
        return "\n".join(self.code)
    
    class Config:
        from_attributes = True
