from __future__ import annotations

import os
from typing import Any, Dict, List

import requests

from .base import AIProvider, ProviderResult
from .rule_based import RuleBasedProvider


class GeminiProvider(AIProvider):
    provider_id = "gemini"
    display_name = "Gemini"
    models = ["gemini-2.5-flash", "gemini-2.5-pro"]

    def __init__(self) -> None:
        self._fallback = RuleBasedProvider()
        self._base_url = os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")
        self._timeout = float(os.getenv("SMART_FILTER_PROVIDER_TIMEOUT", "45"))

    def available(self) -> bool:
        return bool(os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY"))

    def explain_packet(self, context: Dict[str, Any], user_text: str, model: str | None = None) -> ProviderResult:
        if not self.available():
            return self._fallback.explain_packet(context, user_text, model)
        chosen_model = model or self.models[0]
        system_prompt = self.build_system_prompt()
        user_prompt = self.build_user_prompt(context, user_text)
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or ""
        try:
            resp = requests.post(
                f"{self._base_url.rstrip('/')}/models/{chosen_model}:generateContent",
                params={"key": api_key},
                headers={"Content-Type": "application/json"},
                json={
                    "systemInstruction": {"parts": [{"text": system_prompt}]},
                    "contents": [
                        {
                            "role": "user",
                            "parts": [{"text": user_prompt}],
                        }
                    ]
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            text = self._extract_text(data)
            if not text:
                raise ValueError("Gemini returned no text output")
            return ProviderResult(text=text, meta={"provider": self.provider_id, "model": chosen_model, "live": True})
        except Exception as exc:
            fallback = self._fallback.explain_packet(context, user_text, model)
            fallback.text = f"[Gemini live call failed: {exc}]\n\n" + fallback.text
            fallback.meta = {"provider": self.provider_id, "model": chosen_model, "live": False, "error": str(exc)}
            return fallback

    def suggest_actions(self, context: Dict[str, str]) -> List[Dict[str, str]]:
        return self._fallback.suggest_actions(context)

    def _extract_text(self, data: Dict[str, Any]) -> str:
        parts: List[str] = []
        for candidate in data.get("candidates", []) or []:
            content = candidate.get("content", {})
            for part in content.get("parts", []) or []:
                text = part.get("text")
                if text:
                    parts.append(text)
        return "\n".join(p for p in parts if p).strip()
