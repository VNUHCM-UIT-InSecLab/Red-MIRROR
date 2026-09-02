from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from rag.red_mirror.config import RAGRuntimeConfig
from rag.red_mirror.query import QueryBuilder
from rag.red_mirror.schema import RAGQueryContext, RAGSnippet
from rag.red_mirror.web_search import RAGWebSearchTool


@dataclass
class WebSearchDecision:
    need_web_search: bool = False
    reason: str = ""
    queries: list[str] = field(default_factory=list)
    expected_use: str = ""


class RAGMediator:
    def __init__(self, config: RAGRuntimeConfig, web_search_tool: RAGWebSearchTool | None = None):
        self.config = config
        self.web_search_tool = web_search_tool or RAGWebSearchTool(config)
        self.query_builder = QueryBuilder()
        self._state: dict[str, dict[str, object]] = {}

    def retrieve(self, context: RAGQueryContext, default_query: str) -> list[RAGSnippet]:
        decision = self.build_default_decision(context, default_query)
        return self.retrieve_from_decision(context, decision)

    def retrieve_from_decision(self, context: RAGQueryContext, decision: WebSearchDecision) -> list[RAGSnippet]:
        if not self._valid_decision(decision):
            return []

        challenge_id = self._challenge_id(context)
        state = self._state.setdefault(challenge_id, {"provider_calls_used": 0, "normalized_queries": set()})
        snippets: list[RAGSnippet] = []

        for query in decision.queries[: self.config.web_search_max_queries_per_decision]:
            normalized_query = self.normalize_query(query)
            if not normalized_query:
                continue

            cached = self._cache_get(normalized_query)
            if cached is not None:
                snippets.extend(cached)
                continue

            normalized_queries = state["normalized_queries"]
            if self.config.web_search_dedup_enabled and normalized_query in normalized_queries:
                continue

            if int(state["provider_calls_used"]) >= self.config.web_search_max_calls_per_challenge:
                break

            normalized_queries.add(normalized_query)
            state["provider_calls_used"] = int(state["provider_calls_used"]) + 1
            result = self.web_search_tool.retrieve(query)
            self._cache_set(normalized_query, result)
            snippets.extend(result)

        return snippets

    def build_default_decision(self, context: RAGQueryContext, default_query: str) -> WebSearchDecision:
        query = default_query or self.query_builder.build(context)
        if not query:
            return WebSearchDecision(need_web_search=False, reason="Empty RAG query.", queries=[])
        return WebSearchDecision(
            need_web_search=True,
            reason="Planner/Summarizer requested task-specific external knowledge.",
            queries=[query],
            expected_use="Use retrieved knowledge to refine planning or summarization context.",
        )

    def provider_calls_used(self, context: RAGQueryContext) -> int:
        return int(self._state.get(self._challenge_id(context), {}).get("provider_calls_used", 0))

    def _valid_decision(self, decision: WebSearchDecision) -> bool:
        if not decision.need_web_search:
            return False
        if not decision.reason.strip():
            return False
        if not decision.queries:
            return False
        return True

    def _challenge_id(self, context: RAGQueryContext) -> str:
        if context.challenge_id:
            return context.challenge_id
        material = self.query_builder.task_context(context) or context.current_task
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def normalize_query(query: str) -> str:
        return " ".join(query.lower().split())[:500]

    def _cache_path(self) -> Path:
        return Path(self.config.cache_dir) / "web_search_cache.json"

    def _cache_get(self, normalized_query: str) -> list[RAGSnippet] | None:
        if not self.config.web_search_cache_enabled:
            return None
        cache = self._read_cache()
        item = cache.get(normalized_query)
        if not item:
            return None
        ttl_seconds = int(self.config.web_search_cache_ttl_hours) * 3600
        if ttl_seconds > 0 and time.time() - float(item.get("cached_at", 0)) > ttl_seconds:
            return None
        return [RAGSnippet(**snippet) for snippet in item.get("snippets", [])]

    def _cache_set(self, normalized_query: str, snippets: list[RAGSnippet]) -> None:
        if not self.config.web_search_cache_enabled:
            return
        cache = self._read_cache()
        cache[normalized_query] = {
            "cached_at": time.time(),
            "snippets": [snippet.to_dict() for snippet in snippets],
        }
        path = self._cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache), encoding="utf-8")

    def _read_cache(self) -> dict[str, object]:
        path = self._cache_path()
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        return {}

