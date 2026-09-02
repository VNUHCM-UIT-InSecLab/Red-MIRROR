from __future__ import annotations

from urllib.parse import urlparse

from rag.red_mirror.schema import RAGSnippet


class RAGGate:
    def __init__(self, trusted_domains: list[str]):
        self.trusted_domains = trusted_domains

    def trust_level_for_url(self, url: str) -> str:
        if not url:
            return "curated"
        parsed = urlparse(url)
        host_path = f"{parsed.netloc}{parsed.path}".lower()
        host = parsed.netloc.lower()
        for domain in self.trusted_domains:
            normalized = domain.lower().rstrip("/*")
            if "/" in normalized:
                if host_path.startswith(normalized):
                    return "trusted_public"
            elif host == normalized or host.endswith("." + normalized):
                return "trusted_public"
        return "unknown"

    def filter_and_normalize(self, snippets: list[RAGSnippet], query: str) -> list[RAGSnippet]:
        normalized = []
        seen = set()
        for rank, snippet in enumerate(snippets, start=1):
            key = snippet.url or f"{snippet.source}:{snippet.title}:{snippet.content[:80]}"
            if key in seen:
                continue
            seen.add(key)

            if snippet.source_type == "web_search":
                snippet.trust_level = self.trust_level_for_url(snippet.url)
                if snippet.trust_level == "unknown":
                    snippet.safety_notes = "Source is outside the trusted allowlist; use only as weak contextual signal."

            snippet.provenance.setdefault("rank", rank)
            snippet.retrieval_reason = snippet.retrieval_reason or f"Matched task query: {query[:160]}"
            snippet.content = " ".join(snippet.content.split())[:1200]
            normalized.append(snippet)
        return normalized
