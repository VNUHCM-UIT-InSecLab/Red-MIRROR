from datetime import datetime
from typing import Optional
from pydantic import *
from langchain_core.documents import Document

from sqlalchemy import Column, Integer, String, DateTime, func

from utils.session import Base


class MatchDocument(Document):
    id: Optional[str] = None



class KnowledgeBaseModel(Base):

    __tablename__ = "knowledge_base"
    id = Column(Integer, primary_key=True, autoincrement=True, comment="Knowledge Base ID")
    kb_name = Column(String(50), comment="Knowledge Base Name")
    kb_info = Column(String(200), comment="KB Description (for Agent)")
    vs_type = Column(String(50), comment="Vector Store Type")
    embed_model = Column(String(50), comment="Embedding Model Name")
    file_count = Column(Integer, default=0, comment="File Count")
    create_time = Column(DateTime, default=func.now(), comment="Created Time")

    def __repr__(self):
        return f"<KnowledgeBase(id='{self.id}', kb_name='{self.kb_name}',kb_intro='{self.kb_info} vs_type='{self.vs_type}', embed_model='{self.embed_model}', file_count='{self.file_count}', create_time='{self.create_time}')>"



class KnowledgeBaseSchema(BaseModel):
    id: int = Field(..., description="Knowledge Base ID")
    kb_name: str = Field(..., description="Knowledge Base Name")
    kb_info: Optional[str] = Field(None, description="KB Description (for Agent)")
    vs_type: Optional[str] = Field(None, description="Vector Store Type")
    embed_model: Optional[str] = Field(None, description="Embedding Model Name")
    file_count: Optional[int] = Field(0, description="File Count")
    create_time: Optional[datetime] = Field(None, description="Created Time")


    class Config:
        from_attributes = True

