"""AIProvider abstraction. The model proposes JSON actions; it is never the security boundary."""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.audit.redaction import redact_text
from app.config import Settings


class ProviderError(Exception):
    """The AI backend failed (network, auth, quota...). The task must FAIL SAFELY."""


class MalformedAction(Exception):
    """The model answered, but not with a valid action object."""


class ModelActionSchema(BaseModel):
    model_config = ConfigDict(extra="ignore")
    tool: str | None = Field(default=None, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(default="", max_length=600)
    final: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def _exactly_one(self) -> "ModelActionSchema":
        if (self.tool is None) == (self.final is None):
            raise ValueError("exactly one of 'tool' or 'final' is required")
        return self


@dataclass
class ModelAction:
    tool: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    final: str | None = None


def parse_model_json(text: str) -> ModelAction:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.I)
    try:
        obj = json.loads(cleaned)
    except ValueError:
        m = re.search(r"\{.*\}", cleaned, re.S)
        if not m:
            raise MalformedAction("response is not JSON") from None
        try:
            obj = json.loads(m.group(0))
        except ValueError:
            raise MalformedAction("response is not valid JSON") from None
    try:
        v = ModelActionSchema.model_validate(obj)
    except ValidationError as exc:
        raise MalformedAction(str(exc.errors()[0]["msg"])) from exc
    return ModelAction(v.tool, v.arguments, v.reason, v.final)


Message = dict[str, Any]


class AIProvider(ABC):
    name: str

    @abstractmethod
    def next_action(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelAction:
        """Return the next action. Raise ProviderError on backend failure, MalformedAction on bad output."""


def _http_error(prefix: str, exc: Exception) -> ProviderError:
    detail = ""
    if isinstance(exc, httpx.HTTPStatusError):
        detail = f" (HTTP {exc.response.status_code}: {redact_text(exc.response.text[:200], aggressive=True)})"
    return ProviderError(f"{prefix} request failed{detail}")


class OpenAICompatibleProvider(AIProvider):
    """Works with OpenAI and any server exposing /chat/completions (Azure-compatible gateways, vLLM, Ollama...)."""

    name = "openai"

    def __init__(self, s: Settings, transport: httpx.BaseTransport | None = None):
        if not s.ai_api_key:
            raise ProviderError("AI_API_KEY is not configured")
        self.base = (s.ai_base_url or "https://api.openai.com/v1").rstrip("/")
        self.model = s.ai_model or "gpt-4o-mini"
        self._key = s.ai_api_key
        self._client = httpx.Client(timeout=s.ai_timeout_seconds, transport=transport)

    def next_action(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelAction:
        body = {
            "model": self.model, "temperature": 0, "response_format": {"type": "json_object"},
            "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
        }
        try:
            r = self._client.post(f"{self.base}/chat/completions", json=body,
                                  headers={"Authorization": f"Bearer {self._key}"})
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise _http_error("OpenAI-compatible", exc) from None
        return parse_model_json(text or "")


class GeminiProvider(AIProvider):
    name = "gemini"

    def __init__(self, s: Settings, transport: httpx.BaseTransport | None = None):
        if not s.ai_api_key:
            raise ProviderError("AI_API_KEY is not configured")
        self.base = (s.ai_base_url or "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
        self.model = s.ai_model or "gemini-2.0-flash"
        self._key = s.ai_api_key
        self._client = httpx.Client(timeout=s.ai_timeout_seconds, transport=transport)

    def next_action(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelAction:
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        contents = [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
                    for m in messages if m["role"] != "system"]
        body = {"systemInstruction": {"parts": [{"text": system}]}, "contents": contents,
                "generationConfig": {"temperature": 0, "responseMimeType": "application/json"}}
        try:  # key goes in a header, not the URL, so it cannot leak through URL logging
            r = self._client.post(f"{self.base}/models/{self.model}:generateContent", json=body,
                                  headers={"x-goog-api-key": self._key})
            r.raise_for_status()
            text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise _http_error("Gemini", exc) from None
        return parse_model_json(text or "")


def build_provider(s: Settings) -> AIProvider:
    kind = s.ai_provider.lower()
    if kind == "openai":
        return OpenAICompatibleProvider(s)
    if kind == "gemini":
        return GeminiProvider(s)
    if kind == "scripted":
        from app.agent.scripted import ScriptedProvider

        return ScriptedProvider()
    raise ProviderError(f"unknown AI_PROVIDER {s.ai_provider!r}")
