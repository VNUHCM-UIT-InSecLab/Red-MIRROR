from __future__ import annotations

from functools import lru_cache

from rag.red_mirror.config import RAGRuntimeConfig, load_rag_config
from rag.red_mirror.gate import RAGGate
from rag.red_mirror.local_corpus import LocalCorpusRetriever
from rag.red_mirror.mediator import RAGMediator
from rag.red_mirror.query import QueryBuilder
from rag.red_mirror.schema import RAGQueryContext, RAGResult


class RAGService:
    def __init__(self, config: RAGRuntimeConfig | None = None):
        self.config = config or load_rag_config()
        self.query_builder = QueryBuilder()
        self.local_retriever = LocalCorpusRetriever(self.config)
        self.mediator = RAGMediator(self.config)
        self.gate = RAGGate(self.config.trusted_domains)

    def retrieve(self, context: RAGQueryContext) -> RAGResult:
        if not self.config.enabled:
            return RAGResult(query="", task_context=self.query_builder.task_context(context), snippets=[])

        query = self.query_builder.build(context)
        task_context = self.query_builder.task_context(context)
        local_snippets = self.local_retriever.retrieve(query)
        web_snippets = self.mediator.retrieve(context, query)

        snippets = self.gate.filter_and_normalize(local_snippets + web_snippets, query)
        return RAGResult(query=query, task_context=task_context, snippets=snippets)


@lru_cache(maxsize=1)
def get_default_rag_service() -> RAGService:
    return RAGService()
