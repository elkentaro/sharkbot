from __future__ import annotations

import os
from typing import Any, Dict, List

import requests

from .base import AIProvider, ProviderResult
from .rule_based import RuleBasedProvider


class OllamaProvider(AIProvider):
    provider_id = "ollama"
    display_name = "Ollama"
    models = ["llama3.1", "qwen2.5", "mistral"]

    def __init__(self) -> None:
        self._fallback = RuleBasedProvider()
        self._base_url = os.getenv("OLLAMA_BASE_URL") or os.getenv("OLLAMA_HOST") or "http://127.0.0.1:11434"
        self._timeout = float(os.getenv("SMART_FILTER_PROVIDER_TIMEOUT", "60"))

    def available(self) -> bool:
        return bool(self._base_url)

    def explain_packet(self, context: Dict[str, Any], user_text: str, model: str | None = None) -> ProviderResult:
        chosen_model = model or self.models[0]
        system_prompt = self.build_system_prompt()
        user_prompt = self.build_user_prompt(context, user_text)
        try:
            resp = requests.post(
                f"{self._base_url.rstrip('/')}/api/chat",
                headers={"Content-Type": "application/json"},
                json={
                    "model": chosen_model,
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            text = ((data.get("message") or {}).get("content") or "").strip()
            if not text:
                raise ValueError("Ollama returned no text output")
            return ProviderResult(text=text, meta={"provider": self.provider_id, "model": chosen_model, "live": True})
        except Exception as exc:
            fallback = self._fallback.explain_packet(context, user_text, model)
            fallback.text = f"[Ollama live call failed: {exc}]\n\n" + fallback.text
            fallback.meta = {"provider": self.provider_id, "model": chosen_model, "live": False, "error": str(exc)}
            return fallback

    def suggest_actions(self, context: Dict[str, str]) -> List[Dict[str, str]]:
        return self._fallback.suggest_actions(context)
