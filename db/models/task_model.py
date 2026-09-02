from typing import List, Optional

from sqlalchemy import Column, String, Boolean, Integer, JSON, ForeignKey, TEXT
from sqlalchemy.orm import relationship

from utils.session import Base
from pydantic import *

class TaskModel(Base):
    __tablename__ = "tasks"
    id = Column(String(32), primary_key=True)
    plan_id = Column(String(32), ForeignKey('plans.id'))
    sequence = Column(Integer, nullable=False)
    action = Column(String(255), nullable=True)
    instruction = Column(String(512), nullable=True)
    code = Column(JSON, nullable=True)
    result = Column(TEXT, nullable=True)
    is_success = Column(Boolean, default=False)
    is_finished = Column(Boolean, default=False)

    dependencies = Column(JSON, default=list)

    plan = relationship("PlanModel", back_populates="tasks")

class Task(BaseModel):
    id: Optional[str] = Field(default=None)
    plan_id: Optional[str] = Field(default=None)
    sequence: int = Field(...)
    action: Optional[str] = Field(default=None)
    instruction: Optional[str] = Field(default=None)
    code: List[str] = Field(default_factory=list)
    result: str = Field(default="")
    is_success: bool = False
    is_finished: bool = False

    dependencies: List[int] = Field(default_factory=list)

    class Config:
        from_attributes = True
