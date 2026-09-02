from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from urllib.parse import urlparse

from rag.red_mirror.config import RAGRuntimeConfig
from rag.red_mirror.schema import RAGSnippet, utc_now_iso

logger = logging.getLogger(__name__)


class RAGWebSearchTool:
    def __init__(self, config: RAGRuntimeConfig):
        self.config = config

    def retrieve(self, query: str) -> list[RAGSnippet]:
        provider = (self.config.web_search_provider or "").lower()
        if provider == "tavily":
            return self._retrieve_tavily(query)
        logger.warning("RAGWebSearchTool unsupported provider: %s", provider)
        return []

    def _retrieve_tavily(self, query: str) -> list[RAGSnippet]:
        if not self.config.web_search_api_key:
            return []

        endpoint = self.config.web_search_endpoint or "https://api.tavily.com/search"
        payload = {
            "api_key": self.config.web_search_api_key,
            "query": query,
            "search_depth": self.config.web_search_search_depth or "basic",
            "max_results": int(self.config.web_search_max_results),
            "include_answer": False,
            "include_raw_content": bool(self.config.web_search_include_raw_content),
        }

        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=int(self.config.web_search_timeout)) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            logger.warning("RAGWebSearchTool failed closed: %s", exc.__class__.__name__)
            return []

        snippets: list[RAGSnippet] = []
        for rank, item in enumerate((data.get("results") or [])[: self.config.web_search_max_snippets], start=1):
            url = item.get("url", "")
            content = item.get("content") or item.get("raw_content") or ""
            snippets.append(
                RAGSnippet(
                    content=content,
                    source_type="web_search",
                    source=self._source_from_url(url) or "tavily",
                    title=item.get("title", ""),
                    url=url,
                    trust_level="unknown",
                    knowledge_type="reference",
                    retrieval_reason=f"Web search matched task query: {query[:160]}",
                    provenance={
                        "retrieved_at": utc_now_iso(),
                        "retriever": "web",
                        "provider": "tavily",
                        "rank": rank,
                        "score": item.get("score"),
                    },
                )
            )
        return snippets

    @staticmethod
    def _source_from_url(url: str) -> str:
        try:
            return urlparse(url).netloc
        except Exception:
            return ""

