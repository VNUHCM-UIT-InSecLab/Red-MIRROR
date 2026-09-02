import unittest
from pathlib import Path

from rag.red_mirror.config import RAGRuntimeConfig
from rag.red_mirror.gate import RAGGate
from rag.red_mirror.local_corpus import LocalCorpusRetriever
from rag.red_mirror.mediator import RAGMediator, WebSearchDecision
from rag.red_mirror.schema import RAGQueryContext, RAGSnippet
from rag.red_mirror.service import RAGService
from rag.red_mirror.web_search import RAGWebSearchTool


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "rag/corpus/red_mirror_v1.jsonl"


class RedMirrorRAGTests(unittest.TestCase):
    def config(self):
        return RAGRuntimeConfig(
            enabled=True,
            corpus_path=str(CORPUS),
            local_top_k=4,
            local_min_score=0.01,
            web_search_api_key="",
            web_search_cache_enabled=False,
        )

    def test_schema_allows_non_security_facets(self):
        snippet = RAGSnippet(
            content="FastAPI path operation parameters are parsed from function parameters.",
            source_type="web_search",
            source="fastapi.tiangolo.com",
            trust_level="trusted_public",
            knowledge_type="reference",
            facets={"software": {"product": "FastAPI", "component": "routing"}},
        )
        data = snippet.to_dict()
        self.assertEqual(data["facets"]["software"]["product"], "FastAPI")
        self.assertNotIn("security", data["facets"])

    def test_local_retrieval_covers_ssti_payload_placement(self):
        retriever = LocalCorpusRetriever(self.config())
        retriever._embed_text = lambda _text: []
        snippets = retriever.retrieve("Jinja2 SSTI query parameter payload placement")
        self.assertTrue(snippets)
        joined = "\n".join(snippet.content + " " + str(snippet.facets) for snippet in snippets)
        self.assertIn("Jinja2", joined)
        self.assertIn("query_param", joined)

    def test_local_retrieval_covers_command_injection_filtering(self):
        retriever = LocalCorpusRetriever(self.config())
        retriever._embed_text = lambda _text: []
        snippets = retriever.retrieve("command injection semicolon filtering")
        joined = "\n".join(snippet.title for snippet in snippets)
        self.assertIn("Command injection", joined)

    def test_web_search_missing_config_fails_closed(self):
        tool = RAGWebSearchTool(RAGRuntimeConfig(web_search_api_key=""))
        self.assertEqual(tool.retrieve("OWASP XSS context"), [])

    def test_gate_marks_trusted_public_sources(self):
        gate = RAGGate(["portswigger.net"])
        snippets = [
            RAGSnippet(
                content="XSS context guidance",
                source_type="web_search",
                source="portswigger.net",
                title="XSS contexts",
                url="https://portswigger.net/web-security/cross-site-scripting/contexts",
            )
        ]
        normalized = gate.filter_and_normalize(snippets, "xss context")
        self.assertEqual(normalized[0].trust_level, "trusted_public")

    def test_service_returns_prompt_context(self):
        service = RAGService(self.config())
        service.local_retriever._embed_text = lambda _text: []
        result = service.retrieve(
            RAGQueryContext(
                current_task="Exploit suspected XSS where script tag is blocked",
                role="exploiter",
            )
        )
        rendered = result.format_for_prompt()
        self.assertIn("External Knowledge From RAG", rendered)
        self.assertIn("XSS", rendered)

    def test_service_disabled_by_config_returns_no_snippets(self):
        config = self.config()
        config.enabled = False
        service = RAGService(config)
        service.local_retriever.retrieve = lambda _query: self.fail("local retriever should not run when RAG is disabled")
        service.mediator.retrieve = lambda _context, _query: self.fail("web mediator should not run when RAG is disabled")

        result = service.retrieve(RAGQueryContext(current_task="Need external knowledge", role="planner"))

        self.assertEqual(result.snippets, [])
        self.assertEqual(result.query, "")

    def test_execution_agents_do_not_import_rag(self):
        collector = (ROOT / "roles/collector.py").read_text(encoding="utf-8")
        exploiter = (ROOT / "roles/exploiter.py").read_text(encoding="utf-8")
        self.assertNotIn("rag.red_mirror", collector)
        self.assertNotIn("rag.red_mirror", exploiter)
        self.assertNotIn("RAGWebSearchTool", collector)
        self.assertNotIn("RAGWebSearchTool", exploiter)

    def test_planning_path_does_not_use_legacy_kb_arguments(self):
        write_plan = (ROOT / "actions/write_plan.py").read_text(encoding="utf-8")
        self.assertNotIn("kb_name=", write_plan)
        self.assertNotIn("kb_query=", write_plan)

    def test_mediator_enforces_five_provider_calls_per_challenge(self):
        class FakeWebSearch:
            def __init__(self):
                self.calls = 0

            def retrieve(self, query):
                self.calls += 1
                return [
                    RAGSnippet(
                        content=f"result for {query}",
                        source_type="web_search",
                        source="example.com",
                        url=f"https://example.com/{self.calls}",
                    )
                ]

        config = self.config()
        config.web_search_max_calls_per_challenge = 5
        config.web_search_max_queries_per_decision = 1
        config.web_search_cache_enabled = False
        fake = FakeWebSearch()
        mediator = RAGMediator(config, fake)
        context = RAGQueryContext(current_task="test", challenge_id="challenge-1")

        for idx in range(8):
            mediator.retrieve_from_decision(
                context,
                WebSearchDecision(
                    need_web_search=True,
                    reason="test",
                    queries=[f"unique query {idx}"],
                ),
            )

        self.assertEqual(fake.calls, 5)
        self.assertEqual(mediator.provider_calls_used(context), 5)

    def test_mediator_dedup_does_not_consume_provider_calls(self):
        class FakeWebSearch:
            def __init__(self):
                self.calls = 0

            def retrieve(self, query):
                self.calls += 1
                return []

        config = self.config()
        config.web_search_cache_enabled = False
        fake = FakeWebSearch()
        mediator = RAGMediator(config, fake)
        context = RAGQueryContext(current_task="test", challenge_id="challenge-2")
        decision = WebSearchDecision(need_web_search=True, reason="test", queries=["Same Query"])

        mediator.retrieve_from_decision(context, decision)
        mediator.retrieve_from_decision(context, decision)

        self.assertEqual(fake.calls, 1)
        self.assertEqual(mediator.provider_calls_used(context), 1)


if __name__ == "__main__":
    unittest.main()
