from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List


DEFAULT_TRUSTED_DOMAINS = [
    "owasp.org",
    "cheatsheetseries.owasp.org",
    "portswigger.net",
    "developer.mozilla.org",
    "cwe.mitre.org",
    "capec.mitre.org",
    "attack.mitre.org",
    "www.cisa.gov",
    "nvd.nist.gov",
    "github.com/OWASP",
    "github.com/PortSwigger",
    "github.com/swisskyrepo/PayloadsAllTheThings",
    "book.hacktricks.xyz",
    "www.hacktricks.wiki",
    "jinja.palletsprojects.com",
    "twig.symfony.com",
    "flask.palletsprojects.com",
    "fastapi.tiangolo.com",
    "docs.djangoproject.com",
    "expressjs.com",
    "nodejs.org",
    "spring.io",
    "docs.spring.io",
    "laravel.com",
    "symfony.com",
    "rubyonrails.org",
    "www.php.net",
    "docs.python.org",
    "docs.oracle.com",
    "dev.mysql.com",
    "www.postgresql.org",
    "sqlite.org",
    "mariadb.com",
    "httpd.apache.org",
    "nginx.org",
    "tomcat.apache.org",
    "jetty.org",
    "docs.docker.com",
    "kubernetes.io",
    "redis.io",
    "www.mongodb.com",
    "www.elastic.co",
]


@dataclass
class RAGRuntimeConfig:
    enabled: bool = False
    corpus_path: str = "rag/corpus/red_mirror_v1.jsonl"
    corpus_version: str = "red-mirror-rag-v1"
    embedding_base_url: str = "http://100.115.23.55:8317/v1"
    embedding_model: str = "Qwen3-Embedding-4B"
    embedding_api_key: str = "dummy"
    cache_dir: str = ".cache/rag"
    local_top_k: int = 4
    local_min_score: float = 0.12
    web_search_provider: str = "tavily"
    web_search_api_key: str = ""
    web_search_endpoint: str = ""
    web_search_search_depth: str = "basic"
    web_search_max_results: int = 5
    web_search_max_snippets: int = 4
    web_search_include_raw_content: bool = False
    web_search_timeout: int = 20
    web_search_decision_layer: bool = True
    web_search_max_queries_per_decision: int = 2
    web_search_max_calls_per_challenge: int = 5
    web_search_cache_enabled: bool = True
    web_search_dedup_enabled: bool = True
    web_search_cache_ttl_hours: int = 168
    trusted_domains: List[str] = field(default_factory=lambda: list(DEFAULT_TRUSTED_DOMAINS))


def load_rag_config() -> RAGRuntimeConfig:
    try:
        from config.config import Configs

        root = getattr(Configs, "PENTEST_ROOT", Path("."))
        llm_config = Configs.llm_config
        basic_config = Configs.basic_config
        embedding_url = getattr(llm_config, "embedding_url", "") or getattr(llm_config, "base_url", "")
        embedding_model = getattr(llm_config, "embedding_models", "") or "Qwen3-Embedding-4B"
        return RAGRuntimeConfig(
            enabled=bool(getattr(basic_config, "enable_rag", False)),
            corpus_path=str(Path(root) / "rag/corpus/red_mirror_v1.jsonl"),
            embedding_base_url=embedding_url,
            embedding_model=embedding_model,
            embedding_api_key=getattr(llm_config, "api_key_embedding", "") or getattr(llm_config, "api_key", "") or "dummy",
            web_search_provider=getattr(llm_config, "rag_web_search_provider", "tavily"),
            web_search_api_key=getattr(llm_config, "rag_web_search_api_key", ""),
            web_search_endpoint=getattr(llm_config, "rag_web_search_endpoint", ""),
            web_search_search_depth=getattr(llm_config, "rag_web_search_search_depth", "basic"),
            web_search_max_results=int(getattr(llm_config, "rag_web_search_max_results", 3)),
            web_search_max_snippets=int(getattr(llm_config, "rag_web_search_max_snippets", 2)),
            web_search_include_raw_content=bool(getattr(llm_config, "rag_web_search_include_raw_content", False)),
            web_search_timeout=int(getattr(llm_config, "rag_web_search_timeout", 20)),
            web_search_decision_layer=bool(getattr(llm_config, "rag_web_search_decision_layer", True)),
            web_search_max_queries_per_decision=int(getattr(llm_config, "rag_web_search_max_queries_per_decision", 1)),
            web_search_max_calls_per_challenge=int(getattr(llm_config, "rag_web_search_max_calls_per_challenge", 3)),
            web_search_cache_enabled=bool(getattr(llm_config, "rag_web_search_cache_enabled", True)),
            web_search_dedup_enabled=bool(getattr(llm_config, "rag_web_search_dedup_enabled", True)),
            web_search_cache_ttl_hours=int(getattr(llm_config, "rag_web_search_cache_ttl_hours", 168)),
        )
    except Exception:
        return RAGRuntimeConfig()
