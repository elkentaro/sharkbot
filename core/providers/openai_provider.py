from __future__ import annotations

import os
from typing import Any, Dict, List

import requests

from .base import AIProvider, ProviderResult
from .rule_based import RuleBasedProvider


class OpenAIProvider(AIProvider):
    provider_id = "openai"
    display_name = "OpenAI"
    models = ["gpt-5-mini", "gpt-5", "codex-mini-latest"]

    def __init__(self) -> None:
        self._fallback = RuleBasedProvider()
        self._base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self._timeout = float(os.getenv("SMART_FILTER_PROVIDER_TIMEOUT", "45"))

    def available(self) -> bool:
        return bool(os.getenv("OPENAI_API_KEY"))

    def explain_packet(self, context: Dict[str, Any], user_text: str, model: str | None = None) -> ProviderResult:
        if not self.available():
            return self._fallback.explain_packet(context, user_text, model)
        chosen_model = model or self.models[0]
        prompt = self.build_explanation_prompt(context, user_text)
        try:
            resp = requests.post(
                f"{self._base_url.rstrip('/')}/responses",
                headers={
                    "Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": chosen_model,
                    "input": prompt,
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            text = self._extract_text(data)
            if not text:
                raise ValueError("OpenAI returned no text output")
            return ProviderResult(text=text, meta={"provider": self.provider_id, "model": chosen_model, "live": True})
        except Exception as exc:
            fallback = self._fallback.explain_packet(context, user_text, model)
            fallback.text = f"[OpenAI live call failed: {exc}]\n\n" + fallback.text
            fallback.meta = {"provider": self.provider_id, "model": chosen_model, "live": False, "error": str(exc)}
            return fallback

    def suggest_actions(self, context: Dict[str, str]) -> List[Dict[str, str]]:
        return self._fallback.suggest_actions(context)

    def _extract_text(self, data: Dict[str, Any]) -> str:
        parts: List[str] = []
        for item in data.get("output", []) or []:
            if item.get("type") != "message":
                continue
            for content in item.get("content", []) or []:
                if content.get("type") in {"output_text", "text"} and content.get("text"):
                    parts.append(content["text"])
        return "\n".join(p for p in parts if p).strip()
