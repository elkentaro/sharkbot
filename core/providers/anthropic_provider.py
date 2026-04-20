from __future__ import annotations

import os
import time
from typing import Any, Dict, List

import requests

from .base import AIProvider, ProviderResult
from .rule_based import RuleBasedProvider


class AnthropicProvider(AIProvider):
    provider_id = "anthropic"
    display_name = "Claude"
    models = ["claude-sonnet-4-5", "claude-opus-4-1"]

    def __init__(self) -> None:
        self._fallback = RuleBasedProvider()
        self._base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        self._timeout = float(os.getenv("SMART_FILTER_PROVIDER_TIMEOUT", "45"))
        self._max_retries = int(os.getenv("SMART_FILTER_PROVIDER_RETRIES", "2"))
        self._retry_backoff_seconds = float(os.getenv("SMART_FILTER_PROVIDER_RETRY_BACKOFF_SECONDS", "1.0"))

    def available(self) -> bool:
        return bool(os.getenv("ANTHROPIC_API_KEY"))

    def explain_packet(self, context: Dict[str, Any], user_text: str, model: str | None = None) -> ProviderResult:
        if not self.available():
            return self._fallback.explain_packet(context, user_text, model)
        chosen_model = model or self.models[0]
        system_prompt = self.build_system_prompt()
        user_prompt = self.build_user_prompt(context, user_text)
        try:
            resp = self._request_with_retries(system_prompt, user_prompt, chosen_model)
            data = resp.json()
            text = self._extract_text(data)
            if not text:
                raise ValueError("Anthropic returned no text output")
            return ProviderResult(text=text, meta={"provider": self.provider_id, "model": chosen_model, "live": True})
        except Exception as exc:
            fallback = self._fallback.explain_packet(context, user_text, model)
            fallback.text = f"[Claude live call failed: {self._format_error(exc)}]\n\n" + fallback.text
            fallback.meta = {"provider": self.provider_id, "model": chosen_model, "live": False, "error": str(exc)}
            return fallback

    def suggest_actions(self, context: Dict[str, str]) -> List[Dict[str, str]]:
        return self._fallback.suggest_actions(context)

    def _request_with_retries(self, system_prompt: str, user_prompt: str, model: str) -> requests.Response:
        last_response: requests.Response | None = None
        for attempt in range(self._max_retries + 1):
            resp = requests.post(
                f"{self._base_url.rstrip('/')}/v1/messages",
                headers={
                    "x-api-key": os.getenv("ANTHROPIC_API_KEY", ""),
                    "anthropic-version": os.getenv("ANTHROPIC_VERSION", "2023-06-01"),
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 700,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                },
                timeout=self._timeout,
            )
            if resp.status_code != 529:
                resp.raise_for_status()
                return resp
            last_response = resp
            if attempt >= self._max_retries:
                break
            time.sleep(self._retry_backoff_seconds * (2 ** attempt))

        if last_response is not None:
            last_response.raise_for_status()
        raise RuntimeError("Anthropic request failed without a response")

    def _format_error(self, exc: Exception) -> str:
        if isinstance(exc, requests.HTTPError) and exc.response is not None:
            response = exc.response
            request_id = response.headers.get("request-id") or response.headers.get("x-request-id")
            if response.status_code == 529:
                if request_id:
                    return f"Claude is temporarily overloaded (HTTP 529, request id {request_id})"
                return "Claude is temporarily overloaded (HTTP 529)"
            if request_id:
                return f"HTTP {response.status_code} (request id {request_id})"
        return str(exc)

    def _extract_text(self, data: Dict[str, Any]) -> str:
        parts: List[str] = []
        for content in data.get("content", []) or []:
            if content.get("type") == "text" and content.get("text"):
                parts.append(content["text"])
        return "\n".join(p for p in parts if p).strip()
