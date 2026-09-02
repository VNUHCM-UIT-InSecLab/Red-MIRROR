from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, Iterable, List

from rag.red_mirror.config import RAGRuntimeConfig
from rag.red_mirror.schema import RAGSnippet, utc_now_iso


class LocalCorpusRetriever:
    def __init__(self, config: RAGRuntimeConfig):
        self.config = config
        self._records: list[dict[str, Any]] | None = None

    def retrieve(self, query: str) -> list[RAGSnippet]:
        records = self._load_records()
        if not records:
            return []

        query_vector = self._embed_text(query)
        scored = []
        for record in records:
            score = 0.0
            if query_vector:
                doc_vector = self._record_embedding(record)
                score = self._cosine(query_vector, doc_vector)
            if score <= 0:
                score = self._keyword_score(query, record)
            if score >= self.config.local_min_score:
                scored.append((score, record))

        scored.sort(key=lambda item: item[0], reverse=True)
        snippets = []
        for rank, (score, record) in enumerate(scored[: self.config.local_top_k], start=1):
            snippets.append(
                RAGSnippet(
                    content=record.get("content", ""),
                    source_type="local_corpus",
                    source=record.get("source", "curated_local"),
                    title=record.get("title", ""),
                    url=record.get("url", ""),
                    trust_level=record.get("trust_level", "curated"),
                    knowledge_type=record.get("knowledge_type", "reference"),
                    applicability=record.get("applicability", ""),
                    safety_notes=record.get("safety_notes", ""),
                    provenance={
                        "corpus_version": record.get("corpus_version", self.config.corpus_version),
                        "retrieved_at": utc_now_iso(),
                        "retriever": "local",
                        "rank": rank,
                        "score": round(float(score), 4),
                    },
                    facets=record.get("facets", {}),
                )
            )
        return snippets

    def _load_records(self) -> list[dict[str, Any]]:
        if self._records is not None:
            return self._records
        path = Path(self.config.corpus_path)
        if not path.exists():
            self._records = []
            return self._records
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            records.append(json.loads(line))
        self._records = records
        return records

    def _record_embedding(self, record: dict[str, Any]) -> list[float]:
        text = f"{record.get('title', '')}\n{record.get('content', '')}"
        key = hashlib.sha256(f"{self.config.embedding_model}:{text}".encode("utf-8")).hexdigest()
        cache_path = Path(self.config.cache_dir) / "embeddings.json"
        cache = self._read_cache(cache_path)
        if key in cache:
            return cache[key]
        vector = self._embed_text(text)
        if vector:
            cache[key] = vector
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(cache), encoding="utf-8")
        return vector

    def _embed_text(self, text: str) -> list[float]:
        try:
            from openai import OpenAI

            client = OpenAI(
                api_key=self.config.embedding_api_key or "dummy",
                base_url=self.config.embedding_base_url,
                timeout=30,
            )
            response = client.embeddings.create(model=self.config.embedding_model, input=text[:6000])
            return list(response.data[0].embedding)
        except Exception:
            return []

    @staticmethod
    def _read_cache(path: Path) -> dict[str, list[float]]:
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        return {}

    @staticmethod
    def _cosine(left: list[float], right: list[float]) -> float:
        if not left or not right or len(left) != len(right):
            return 0.0
        dot = sum(a * b for a, b in zip(left, right))
        norm_l = math.sqrt(sum(a * a for a in left))
        norm_r = math.sqrt(sum(b * b for b in right))
        if norm_l == 0 or norm_r == 0:
            return 0.0
        return dot / (norm_l * norm_r)

    @staticmethod
    def _keyword_score(query: str, record: dict[str, Any]) -> float:
        query_terms = set(LocalCorpusRetriever._tokens(query))
        haystack = " ".join(
            [
                record.get("title", ""),
                record.get("content", ""),
                json.dumps(record.get("facets", {})),
                record.get("knowledge_type", ""),
            ]
        )
        doc_terms = set(LocalCorpusRetriever._tokens(haystack))
        if not query_terms or not doc_terms:
            return 0.0
        overlap = len(query_terms & doc_terms)
        return overlap / max(6, len(query_terms))

    @staticmethod
    def _tokens(text: str) -> Iterable[str]:
        token = []
        for ch in text.lower():
            if ch.isalnum() or ch in {"_", "-", "."}:
                token.append(ch)
            else:
                if token:
                    yield "".join(token)
                    token = []
        if token:
            yield "".join(token)
