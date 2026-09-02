from __future__ import annotations

"""Provider adapter layer for instantiating chat model clients."""

from dataclasses import dataclass
from typing import Any

from autopt.config.schema import AppConfig
from autopt.models.registry import ModelSpec


def _enabled_control(value: str) -> str | None:
    """Return an optional provider control only when it is explicitly enabled."""
    normalized = str(value or "").strip().lower()
    if normalized in {"", "none", "off", "false", "disabled"}:
        return None
    return str(value).strip()


@dataclass(frozen=True, slots=True)
class ProviderPayload:
    provider: str
    model_name: str
    temperature: float
    thinking: str = "none"
    reasoning_effort: str = "none"
    max_tokens: int = 256
    api_key: str = ""
    api_base: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_name": self.model_name,
            "temperature": self.temperature,
            "thinking": self.thinking,
            "reasoning_effort": self.reasoning_effort,
            "max_tokens": self.max_tokens,
            "api_key": self.api_key,
            "api_base": self.api_base,
        }


def build_provider_payload(provider: str, model_name: str, config: AppConfig) -> ProviderPayload:
    provider_name = provider or config.llm.default_provider
    provider_config = config.llm.get_provider(provider_name)

    if provider_name == "nvidia":
        return ProviderPayload(
            provider=provider_name,
            model_name=model_name,
            temperature=float(provider_config.temperature or 0.0),
            thinking=config.llm.thinking,
            reasoning_effort=config.llm.reasoning_effort,
            max_tokens=config.llm.max_tokens,
            api_key=provider_config.api_key,
        )
    if provider_name == "together":
        return ProviderPayload(
            provider=provider_name,
            model_name=model_name,
            temperature=float(provider_config.temperature or 0.0),
            thinking=config.llm.thinking,
            reasoning_effort=config.llm.reasoning_effort,
            max_tokens=config.llm.max_tokens,
            api_key=provider_config.api_key,
        )
    return ProviderPayload(
        provider="openai",
        model_name=model_name,
        temperature=float(provider_config.temperature or 0.0),
        thinking=config.llm.thinking,
        reasoning_effort=config.llm.reasoning_effort,
        max_tokens=config.llm.max_tokens,
        api_key=provider_config.api_key,
        api_base=provider_config.api_base,
    )


def build_chat_model(model: ModelSpec, config: AppConfig) -> Any:
    payload = build_provider_payload(model.provider, model.name, config)

    if payload.provider == "nvidia":
        try:
            from langchain_nvidia_ai_endpoints import ChatNVIDIA
        except ImportError as exc:
            raise RuntimeError(
                "langchain_nvidia_ai_endpoints is required for NVIDIA-backed models."
            ) from exc
        return ChatNVIDIA(
            temperature=payload.temperature,
            model=payload.model_name,
            api_key=payload.api_key,
        )

    if payload.provider == "together":
        try:
            from langchain_together import ChatTogether
        except ImportError as exc:
            raise RuntimeError(
                "langchain_together is required for Together-backed models."
            ) from exc
        return ChatTogether(
            model=payload.model_name,
            temperature=payload.temperature,
            api_key=payload.api_key,
        )

    # OpenCode is OpenAI-compatible on the wire, but its DeepSeek gateway has
    # provider-specific controls that the OpenAI SDK serializes incorrectly.
    # Use the direct HTTP adapter so the exact JSON body stays under our control.
    return DirectOpenCodeChatModel(payload=payload)
