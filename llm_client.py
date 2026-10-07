from __future__ import annotations

import json
import os
import re
from typing import Any, Protocol


class LLMError(Exception):
    pass


class ChatJSONClient(Protocol):
    def chat_json(self, system: str, user: str) -> dict[str, Any]: ...
    def describe(self) -> dict[str, Any]: ...


def describe_client(client: ChatJSONClient) -> dict[str, Any]:
    return client.describe()


def _clean_json_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    t = text.strip()
    t = re.sub(r"<think>.*?</think>", "", t, flags=re.DOTALL).strip()
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", t, flags=re.IGNORECASE)
    if fence_match:
        t = fence_match.group(1).strip()
    if not (t.startswith("{") and t.endswith("}")):
        start = t.find("{")
        end = t.rfind("}")
        if start != -1 and end != -1 and end > start:
            t = t[start : end + 1]
    return t.strip()


def _parse_json_object(text: Any) -> dict[str, Any]:
    if text is None or not isinstance(text, str) or not text.strip():
        raise LLMError("Model JSON response was empty or not text")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, TypeError):
        pass

    cleaned = _clean_json_text(text)
    try:
        obj = json.loads(cleaned)
    except (json.JSONDecodeError, TypeError) as exc:
        raise LLMError(f"Model did not return valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise LLMError("Model JSON response was not a JSON object")
    return obj


class MockChatClient:

    def describe(self) -> dict[str, Any]:
        return {"provider": "mock", "model": "deterministic_mock", "local": True}

    def chat_json(self, system: str, user: str) -> dict[str, Any]:
        raise LLMError("mock mode does not call an LLM")


class OllamaClient:

    def __init__(
        self,
        url: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
    ) -> None:
        self.url = (url or os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
        self.timeout = int(timeout or os.getenv("OLLAMA_TIMEOUT", "600"))

    def describe(self) -> dict[str, Any]:
        return {"provider": "ollama", "model": self.model, "endpoint": self.url, "local": True}

    def chat_json(self, system: str, user: str) -> dict[str, Any]:
        import requests

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "format": "json",
            "stream": False,
            "keep_alive": "1h"
        }
        try:
            resp = requests.post(f"{self.url}/api/chat", json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc

        content = (data.get("message") or {}).get("content", "")
        if not content:
            raise LLMError("Ollama response had no message content")
        return _parse_json_object(content)


class OpenAICompatibleClient:

    def __init__(
        self,
        url: str,
        model: str,
        api_key: str | None = None,
        timeout: int = 120,
        json_mode: bool = True,
        extra_headers: dict[str, str] | None = None,
        provider: str = "openai_compatible",
    ) -> None:
        if not url or not model:
            raise LLMError("OpenAICompatibleClient requires both an API URL and a model name")
        clean_url = url.rstrip("/")
        if clean_url.endswith("/v1"):
            clean_url += "/chat/completions"
        self.url = clean_url
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.json_mode = json_mode
        self.extra_headers = extra_headers or {}
        self.provider = provider

    def describe(self) -> dict[str, Any]:
        return {"provider": self.provider, "model": self.model, "endpoint": self.url, "local": False}

    def chat_json(self, system: str, user: str) -> dict[str, Any]:
        import requests

        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
        }
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            resp = requests.post(self.url, headers=headers, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            raise LLMError(f"{self.provider} request failed: {exc}") from exc

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"Unexpected response shape from {self.provider}: {exc}") from exc

        if not content or not isinstance(content, str):
            raise LLMError(f"{self.provider} returned empty or non-string message content")

        return _parse_json_object(content)


_ROLE_ENV = {"ad": "AD", "endpoint": "ENDPOINT", "network": "NETWORK", "web": "WEB"}

_PROVIDER_DEFAULT_URL = {
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "cerebras": "https://api.cerebras.ai/v1/chat/completions",
}


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    return value if value not in (None, "") else default


def _build_openai_compatible_for(prefix: str) -> OpenAICompatibleClient:
    provider = (_env(f"SOC_{prefix}_PROVIDER", "openai_compatible") or "openai_compatible").strip().lower()
    url = _env(f"SOC_{prefix}_API_URL") or _PROVIDER_DEFAULT_URL.get(provider)
    model = _env(f"SOC_{prefix}_MODEL")
    if not url or not model:
        raise LLMError(
            f"multi_api mode requires SOC_{prefix}_MODEL to be set in .env, and SOC_{prefix}_API_URL "
            f"unless SOC_{prefix}_PROVIDER is a known provider ({', '.join(_PROVIDER_DEFAULT_URL)})"
        )
    api_key = _env(f"SOC_{prefix}_API_KEY")
    timeout = int(_env(f"SOC_{prefix}_TIMEOUT", "120") or "120")
    json_mode = str(_env(f"SOC_{prefix}_JSON_MODE", "true")).lower() in {"1", "true", "yes"}
    headers_raw = _env(f"SOC_{prefix}_HEADERS_JSON")
    extra_headers: dict[str, str] = {}
    if headers_raw:
        try:
            extra_headers = json.loads(headers_raw)
        except json.JSONDecodeError as exc:
            raise LLMError(f"SOC_{prefix}_HEADERS_JSON is not valid JSON: {exc}") from exc
    return OpenAICompatibleClient(
        url=url, model=model, api_key=api_key, timeout=timeout,
        json_mode=json_mode, extra_headers=extra_headers, provider=provider,
    )


def build_client_for_role(role: str, mode: str = "ollama") -> ChatJSONClient:
    mode = (mode or "ollama").strip().lower()

    if mode == "mock":
        return MockChatClient()

    if mode == "ollama":
        return OllamaClient(
            url=_env("OLLAMA_URL"),
            model=_env("OLLAMA_MODEL"),
            timeout=int(_env("OLLAMA_TIMEOUT", "600") or "600"),
        )

    if mode == "multi_api":
        if role == "correlation":
            return OllamaClient(
                url=_env("CORRELATION_OLLAMA_URL"),
                model=_env("CORRELATION_OLLAMA_MODEL"),
                timeout=int(_env("CORRELATION_OLLAMA_TIMEOUT", "600") or "600"),
            )
        if role == "web" and not _env("SOC_WEB_API_URL") and not _env("SOC_WEB_PROVIDER") and not _env("SOC_WEB_MODEL"):
            return _build_openai_compatible_for("NETWORK")
        prefix = _ROLE_ENV.get(role)
        if not prefix:
            raise LLMError(f"Unknown role '{role}' for multi_api mode")
        return _build_openai_compatible_for(prefix)

    raise LLMError(f"Unknown mode '{mode}'")
