from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class RAGQueryContext:
    current_task: str
    role: str = ""
    challenge_id: str = ""
    init_description: str = ""
    shared_summary: str = ""
    failed_tasks: List[str] = field(default_factory=list)
    task_result: str = ""


@dataclass
class RAGSnippet:
    content: str
    source_type: str
    source: str
    title: str = ""
    url: str = ""
    trust_level: str = "unknown"
    knowledge_type: str = "reference"
    applicability: str = ""
    retrieval_reason: str = ""
    safety_notes: str = ""
    provenance: Dict[str, Any] = field(default_factory=dict)
    facets: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RAGResult:
    query: str
    task_context: str
    snippets: List[RAGSnippet] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "task_context": self.task_context,
            "snippets": [snippet.to_dict() for snippet in self.snippets],
        }

    def format_for_prompt(self, max_snippets: int = 5, max_chars: int = 5000) -> str:
        if not self.snippets:
            return ""

        lines = ["### External Knowledge From RAG"]
        for idx, snippet in enumerate(self.snippets[:max_snippets], start=1):
            lines.append(f"{idx}. [{snippet.trust_level}] {snippet.title or snippet.source}")
            lines.append(f"   Source: {snippet.source_type} | {snippet.source or snippet.url}")
            if snippet.knowledge_type:
                lines.append(f"   Knowledge type: {snippet.knowledge_type}")
            if snippet.applicability:
                lines.append(f"   Applicability: {snippet.applicability}")
            if snippet.retrieval_reason:
                lines.append(f"   Retrieval reason: {snippet.retrieval_reason}")
            if snippet.safety_notes:
                lines.append(f"   Safety notes: {snippet.safety_notes}")
            lines.append(f"   Content: {snippet.content}")

        rendered = "\n".join(lines)
        return rendered[:max_chars]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
