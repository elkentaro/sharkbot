from __future__ import annotations

import os
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

    def available(self) -> bool:
        return bool(os.getenv("ANTHROPIC_API_KEY"))

    def explain_packet(self, context: Dict[str, Any], user_text: str, model: str | None = None) -> ProviderResult:
        if not self.available():
            return self._fallback.explain_packet(context, user_text, model)
        chosen_model = model or self.models[0]
        prompt = self.build_explanation_prompt(context, user_text)
        try:
            resp = requests.post(
                f"{self._base_url.rstrip('/')}/v1/messages",
                headers={
                    "x-api-key": os.getenv("ANTHROPIC_API_KEY", ""),
                    "anthropic-version": os.getenv("ANTHROPIC_VERSION", "2023-06-01"),
                    "content-type": "application/json",
                },
                json={
                    "model": chosen_model,
                    "max_tokens": 700,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            text = self._extract_text(data)
            if not text:
                raise ValueError("Anthropic returned no text output")
            return ProviderResult(text=text, meta={"provider": self.provider_id, "model": chosen_model, "live": True})
        except Exception as exc:
            fallback = self._fallback.explain_packet(context, user_text, model)
            fallback.text = f"[Claude live call failed: {exc}]\n\n" + fallback.text
            fallback.meta = {"provider": self.provider_id, "model": chosen_model, "live": False, "error": str(exc)}
            return fallback

    def suggest_actions(self, context: Dict[str, str]) -> List[Dict[str, str]]:
        return self._fallback.suggest_actions(context)

    def _extract_text(self, data: Dict[str, Any]) -> str:
        parts: List[str] = []
        for content in data.get("content", []) or []:
            if content.get("type") == "text" and content.get("text"):
                parts.append(content["text"])
        return "\n".join(p for p in parts if p).strip()
