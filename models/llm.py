# models/llm.py
from langchain_ollama import ChatOllama
from config.config import Configs
from langchain_openai import ChatOpenAI

LANGCHAIN_TOOL_CALL_TIMEOUT = 90
LANGCHAIN_TOOL_CALL_MAX_RETRIES = 2
LANGCHAIN_TOOL_CALL_MAX_TOKENS = 256


def _opencode_go_reasoning_kwargs(base_url: str | None = None):
    url = (base_url or Configs.llm_config.base_url or "").lower()
    if "opencode.ai" not in url:
        return {}
    return {
        "extra_body": {
            "thinking": {"type": "disabled"},
            "reasoning_effort": "none",
        }
    }


def _deepseek_reasoning_kwargs(base_url: str | None = None):
    url = (base_url or Configs.llm_config.base_url or "").lower()
    if "api.deepseek.com" not in url:
        return {}
    return {
        "model_kwargs": {
            "reasoning_effort": "none",
        },
        "extra_body": {
            "thinking": {"type": "disabled"},
        },
    }


def _chat_openai_kwargs(model_name: str | None = None):
    kwargs = dict(
        model=model_name or Configs.llm_config.llm_model_name,
        temperature=Configs.llm_config.temperature,
        top_p=Configs.llm_config.top_p,
        max_tokens=LANGCHAIN_TOOL_CALL_MAX_TOKENS,
        timeout=min(Configs.llm_config.timeout, LANGCHAIN_TOOL_CALL_TIMEOUT),
        max_retries=LANGCHAIN_TOOL_CALL_MAX_RETRIES,
        api_key=Configs.llm_config.api_key,
        base_url=Configs.llm_config.base_url,
    )
    kwargs.update(_opencode_go_reasoning_kwargs())
    kwargs.update(_deepseek_reasoning_kwargs())
    return kwargs


def build_chat_openai(model_name: str | None = None):
    return ChatOpenAI(**_chat_openai_kwargs(model_name))


if Configs.llm_config.llm_model == "ollama":
    llm = ChatOllama(
        model=Configs.llm_config.llm_model_name,
        base_url=Configs.llm_config.base_url,
        temperature=Configs.llm_config.temperature,
        top_p=Configs.llm_config.top_p,
    )
else:
    llm = build_chat_openai()
    llm_analyzer = llm
