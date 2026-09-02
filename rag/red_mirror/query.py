from __future__ import annotations

from rag.red_mirror.schema import RAGQueryContext


class QueryBuilder:
    def build(self, context: RAGQueryContext) -> str:
        parts = [
            context.current_task,
            context.init_description,
            context.shared_summary,
            context.task_result,
            "\n".join(context.failed_tasks),
        ]
        query = " ".join(part.strip() for part in parts if part and part.strip())
        return " ".join(query.split())[:1200]

    def task_context(self, context: RAGQueryContext) -> str:
        parts = []
        if context.role:
            parts.append(f"role={context.role}")
        if context.current_task:
            parts.append(f"task={context.current_task}")
        if context.init_description:
            parts.append(f"objective={context.init_description}")
        if context.failed_tasks:
            parts.append("failed_tasks=" + " | ".join(context.failed_tasks[:3]))
        return "\n".join(parts)
