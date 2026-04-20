from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

DEFAULT_CONFIG_PATH = "config.toml"


def _read_toml(path: Path) -> Dict[str, Any]:
    if not tomllib:
        raise RuntimeError("Python 3.11+ is required for TOML config support.")
    with path.open("rb") as f:
        return tomllib.load(f)


def _apply_provider_env(provider_cfg: Dict[str, Any]) -> None:
    openai = provider_cfg.get("openai", {})
    anthropic = provider_cfg.get("anthropic", {})
    gemini = provider_cfg.get("gemini", {})
    ollama = provider_cfg.get("ollama", {})

    if openai.get("api_key"):
        os.environ["OPENAI_API_KEY"] = str(openai["api_key"])
    if anthropic.get("api_key"):
        os.environ["ANTHROPIC_API_KEY"] = str(anthropic["api_key"])
    if gemini.get("api_key"):
        os.environ["GEMINI_API_KEY"] = str(gemini["api_key"])
        os.environ["GOOGLE_API_KEY"] = str(gemini["api_key"])
    if ollama.get("base_url"):
        os.environ["OLLAMA_BASE_URL"] = str(ollama["base_url"])


def load_config(config_path: str | None = None) -> Dict[str, Any]:
    chosen = config_path or os.getenv("SMART_FILTER_CONFIG") or DEFAULT_CONFIG_PATH
    path = Path(chosen)
    if not path.is_absolute():
        path = Path.cwd() / path

    config: Dict[str, Any] = {
        "config_path": str(path),
        "exists": False,
        "receiver": {},
        "defaults": {},
        "providers": {},
    }

    if not path.exists():
        return config

    raw = _read_toml(path)
    config["exists"] = True
    config["receiver"] = raw.get("receiver", {})
    config["defaults"] = raw.get("defaults", {})
    config["providers"] = raw.get("providers", {})

    receiver = config["receiver"]
    defaults = config["defaults"]
    provider_cfg = config["providers"]
    advanced = raw.get("advanced", {})
    config["advanced"] = advanced

    if receiver.get("host"):
        os.environ.setdefault("SMART_FILTER_HOST", str(receiver["host"]))
    if receiver.get("bind_host"):
        os.environ["SMART_FILTER_BIND_HOST"] = str(receiver["bind_host"])
    if receiver.get("port"):
        os.environ.setdefault("SMART_FILTER_PORT", str(receiver["port"]))
    if receiver.get("public_base_url"):
        os.environ["SMART_FILTER_PUBLIC_BASE_URL"] = str(receiver["public_base_url"]).rstrip("/")
    if defaults.get("provider"):
        os.environ["SMART_FILTER_PROVIDER"] = str(defaults["provider"])
    if defaults.get("model"):
        os.environ["SMART_FILTER_MODEL"] = str(defaults["model"])
    if advanced.get("timeout_seconds"):
        os.environ["SMART_FILTER_PROVIDER_TIMEOUT"] = str(advanced["timeout_seconds"])

    _apply_provider_env(provider_cfg)
    return config
