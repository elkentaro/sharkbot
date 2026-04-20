from .anthropic_provider import AnthropicProvider
from .gemini_provider import GeminiProvider
from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider
from .rule_based import RuleBasedProvider


def build_provider_registry():
    providers = {}
    for cls in [RuleBasedProvider, OllamaProvider, OpenAIProvider, AnthropicProvider, GeminiProvider]:
        instance = cls()
        providers[instance.provider_id] = instance
    return providers
