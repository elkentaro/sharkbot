from __future__ import annotations

import argparse
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template, request

from core.config import load_config

APP_CONFIG = load_config()

from core.providers import build_provider_registry


app = Flask(__name__, template_folder="templates", static_folder="static")
PROVIDERS = build_provider_registry()
DEFAULT_PROVIDER = os.getenv("SMART_FILTER_PROVIDER", APP_CONFIG.get("defaults", {}).get("provider", "rule_based"))
DEFAULT_MODEL = os.getenv("SMART_FILTER_MODEL", APP_CONFIG.get("defaults", {}).get("model", "builtin"))
BIND_HOST = os.getenv("SMART_FILTER_BIND_HOST") or os.getenv("SMART_FILTER_HOST", "127.0.0.1")
PUBLIC_BASE_URL = (os.getenv("SMART_FILTER_PUBLIC_BASE_URL") or "").rstrip("/")


@dataclass
class SessionState:
    session_id: str
    created_at: float
    context: Dict[str, Any]
    messages: List[Dict[str, Any]] = field(default_factory=list)
    pending: Optional[Dict[str, Any]] = None
    resolved: Dict[str, Any] = field(default_factory=dict)
    settings: Dict[str, str] = field(default_factory=dict)
    suggested_actions: List[Dict[str, str]] = field(default_factory=list)
    backend_confirmed: bool = False


SESSIONS: Dict[str, SessionState] = {}

COMMON_NOISE = {
    "mdns": "mdns",
    "arp": "arp",
    "ssdp": "ssdp",
    "broadcast": "eth.addr == ff:ff:ff:ff:ff:ff",
    "multicast": "eth.dst[0] & 1",
    "all_common": "mdns || arp || ssdp || eth.addr == ff:ff:ff:ff:ff:ff || eth.dst[0] & 1",
}

PROTOCOL_MAP = {
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ipv6",
    "dns": "dns",
    "http": "http",
    "tls": "tls",
    "tcp": "tcp",
    "udp": "udp",
    "arp": "arp",
    "icmp": "icmp",
    "dhcp": "dhcp || bootp",
    "mdns": "mdns",
    "ssdp": "ssdp",
}


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def provider_payload() -> List[Dict[str, Any]]:
    return [
        {
            "id": p.provider_id,
            "name": p.display_name,
            "label": p.display_name,
            "models": p.models,
            "available": p.available(),
        }
        for p in PROVIDERS.values()
    ]


def available_ai_provider_ids() -> List[str]:
    return [
        provider_id
        for provider_id, provider in PROVIDERS.items()
        if provider_id != "rule_based" and provider.available()
    ]


def provider_prompt_suffix(provider_id: str) -> str:
    return {
        "openai": "OpenAI",
        "anthropic": "Claude",
        "gemini": "Gemini",
        "ollama": "Ollama",
    }.get(provider_id, provider_id)


def infer_packet_protocol(context: Dict[str, Any]) -> str:
    candidates = [
        context.get("packet_protocol"),
        context.get("protocol_hint"),
        "dns" if context.get("dns_name") else None,
        "http" if context.get("http_host") else None,
        "tcp" if context.get("tcp_srcport") or context.get("tcp_dstport") else None,
        "udp" if context.get("udp_srcport") or context.get("udp_dstport") else None,
        "ip" if context.get("selected_ip") else None,
        "ipv6" if context.get("selected_ipv6") else None,
        "ethernet" if context.get("selected_mac") else None,
    ]
    for item in candidates:
        if item:
            return str(item)
    return "packet"


def summary_from_context(context: Dict[str, Any]) -> Dict[str, str]:
    proto = infer_packet_protocol(context).upper()
    src = context.get("ip_src") or context.get("ipv6_src") or context.get("eth_src") or context.get("selected_mac") or "(unknown)"
    dst = context.get("ip_dst") or context.get("ipv6_dst") or context.get("eth_dst") or "(unknown)"
    return {
        "frame": str(context.get("frame_number") or "(unknown)"),
        "protocol": proto,
        "source": str(src),
        "destination": str(dst),
        "selected_ip": str(context.get("selected_ip") or context.get("selected_ipv6") or "(none)"),
        "selected_mac": str(context.get("selected_mac") or "(none)"),
        "current_filter": str(context.get("current_filter") or ""),
    }


def backend_selection_required(state: SessionState) -> bool:
    return bool(available_ai_provider_ids()) and not state.backend_confirmed


def backend_usage_text(state: SessionState) -> str:
    configured = available_ai_provider_ids()
    suffixes = [f"+{provider_prompt_suffix(provider_id)}" for provider_id in configured]
    return (
        "Pick one of the configured AI backends in the browser card if you want model-assisted replies. "
        "Rule-based help stays on by default. Use +AI for the selected backend or "
        + ", ".join(suffixes)
        + " to force a specific backend for one reply."
    )


def initial_messages(state: SessionState) -> List[Dict[str, Any]]:
    summary = summary_from_context(state.context)
    settings = state.settings
    messages: List[Dict[str, Any]] = [{"type": "system_notice", "text": "Smart Filter Assistant is ready."}]
    if backend_selection_required(state):
        return messages
    if available_ai_provider_ids():
        messages.append({
            "type": "assistant_text",
            "text": f"AI backend ready: {PROVIDERS[settings['provider']].display_name} / {settings['model']}",
        })
        messages.append({
            "type": "assistant_text",
            "text": backend_usage_text(state),
        })
    else:
        messages.append({
            "type": "assistant_text",
            "text": (
                f"Selected packet looks like {summary['protocol']} from {summary['source']} to {summary['destination']}. "
                "Rule-based help is ready. No AI backends are configured yet."
            ),
        })
    messages.append({
        "type": "packet_summary",
        "summary": summary,
        "provider": settings["provider"],
        "model": settings["model"],
    })
    messages.append({
        "type": "suggested_actions",
        "title": "Based on this analysis",
        "items": state.suggested_actions,
    })
    return messages


def make_session(context: Dict[str, Any]) -> SessionState:
    sid = secrets.token_urlsafe(8)
    provider = DEFAULT_PROVIDER if DEFAULT_PROVIDER in PROVIDERS else "rule_based"
    if provider != "rule_based" and not PROVIDERS[provider].available():
        provider = "rule_based"
    model = DEFAULT_MODEL if DEFAULT_MODEL in PROVIDERS[provider].models else PROVIDERS[provider].models[0]
    context = dict(context)
    context["packet_protocol"] = infer_packet_protocol(context)
    state = SessionState(
        session_id=sid,
        created_at=time.time(),
        context=context,
        settings={"provider": provider, "model": model},
    )
    state.backend_confirmed = not bool(available_ai_provider_ids())
    state.suggested_actions = guided_next_steps(state)
    state.messages.extend(initial_messages(state))
    SESSIONS[sid] = state
    return state


def get_state(session_id: str) -> SessionState:
    state = SESSIONS.get(session_id)
    if not state:
        raise KeyError(session_id)
    return state


def session_missing_payload(session_id: str) -> Dict[str, str]:
    return {
        "error": "session_not_found",
        "session_id": session_id,
        "title": "Session not found",
        "message": "This packet session is no longer available. Go back to Wireshark and launch Smart Filter Assistant again from the packet menu.",
    }


def detect_protocols(text: str) -> List[str]:
    found = []
    for word, expr in PROTOCOL_MAP.items():
        if word in {"ip", "ipv4"} and re.search(r"\bthis ip\b", text):
            continue
        if re.search(rf"\b{re.escape(word)}\b", text):
            found.append(expr)
    return found


def wants_noise_exclusion(text: str) -> bool:
    return "noise" in text


def extract_noise(text: str) -> Optional[str]:
    if "all common" in text or "common noise" in text:
        return "all_common"
    for key in ["mdns", "arp", "ssdp", "broadcast", "multicast"]:
        if re.search(rf"\b{re.escape(key)}\b", text):
            return key
    return None


def has_host_reference(text: str) -> bool:
    return any(
        k in text
        for k in [
            "this host",
            "this device",
            "this mac",
            "this ip",
            "related to this",
            "involving this",
            "this source",
            "related traffic",
            "related conversation",
        ]
    )


def classify_direction(text: str) -> Optional[str]:
    if any(k in text for k in ["from this", "outgoing", "source"]):
        return "src"
    if any(k in text for k in ["to this", "incoming", "destination"]):
        return "dst"
    if any(k in text for k in ["related to", "involving", "either", "both directions", "this host"]):
        return "either"
    return None


def build_host_expr(state: SessionState) -> str:
    host_kind = state.resolved.get("host_kind", "ip")
    direction = state.resolved.get("direction", "either")
    ip = state.context.get("selected_ip") or state.context.get("selected_ipv6")
    mac = state.context.get("selected_mac")

    def addr_expr(kind: str, which: str) -> str:
        if kind == "ip" and ip:
            field = "ipv6" if ":" in str(ip) else "ip"
            if which == "src":
                return f"{field}.src == {ip}"
            if which == "dst":
                return f"{field}.dst == {ip}"
            return f"{field}.addr == {ip}"
        if kind == "mac" and mac:
            if which == "src":
                return f"eth.src == {mac}"
            if which == "dst":
                return f"eth.dst == {mac}"
            return f"eth.addr == {mac}"
        return ""

    if host_kind == "both":
        parts = []
        for kind in ["ip", "mac"]:
            expr = addr_expr(kind, direction)
            if expr:
                parts.append(expr)
        return "(" + " || ".join(parts) + ")" if parts else ""

    return addr_expr(host_kind, direction)




def guided_next_steps(state: SessionState) -> List[Dict[str, str]]:
    steps: List[Dict[str, str]] = []
    ctx = state.context
    proto = (ctx.get("packet_protocol") or ctx.get("protocol_hint") or "").lower()
    ip = ctx.get("selected_ip") or ctx.get("selected_ipv6")
    mac = ctx.get("selected_mac")
    current_filter = ctx.get("current_filter") or ""

    def add(label: str, prompt: str) -> None:
        steps.append({"id": label.lower().replace(" ", "_"), "label": label, "prompt": prompt})

    add("Explain this packet", "Explain this packet")
    if ip:
        add("Show related traffic", "Show all traffic involving this IP")
    elif mac:
        add("Show related traffic", "Show all traffic involving this MAC")
    else:
        add("Show related traffic", "Show traffic related to this host")
    if ip:
        add("Show all traffic involving this IP", "Show all traffic involving this IP")
    if mac:
        add("Show all traffic involving this MAC", "Show all traffic involving this MAC")

    if proto in ("http",):
        add("Show only HTTP traffic", "Show only HTTP traffic")
        add("Show this HTTP conversation", "Show the related HTTP conversation")
    elif proto in ("dns",):
        add("Show only DNS traffic", "Show only DNS traffic")
        add("Show DNS traffic except mDNS", "Show DNS traffic except mDNS")
    elif proto in ("arp",):
        add("Show only ARP traffic", "Show only ARP traffic")
        add("Hide ARP noise", "Exclude ARP from the current view")
    elif proto in ("tcp",):
        add("Show this TCP conversation", "Show the related TCP conversation")
        add("Show only TCP traffic", "Show only TCP traffic")
    elif proto in ("udp",):
        add("Show this UDP conversation", "Show the related UDP conversation")
        add("Show only UDP traffic", "Show only UDP traffic")
    elif proto:
        add(f"Show only {proto.upper()} traffic", f"Show only {proto.upper()} traffic")

    if current_filter:
        add("Explain the current filter and this packet together", "Explain this packet in the context of the current filter")

    steps.extend(ai_upgrade_suggestions(state.context, state.settings))

    deduped = []
    seen = set()
    for item in steps:
        key = item["prompt"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[:6]


def auto_ai_provider_for_failure(state: SessionState) -> Optional[str]:
    selected_provider = state.settings.get("provider", "rule_based")
    if selected_provider != "rule_based":
        provider = PROVIDERS.get(selected_provider)
        if provider and provider.available():
            return selected_provider
    configured = available_ai_provider_ids()
    return configured[0] if configured else None


def contextual_refinement_hint(state: SessionState, original_text: str) -> str:
    text = normalize(original_text)
    selected_ip = state.context.get("selected_ip") or state.context.get("selected_ipv6")
    selected_mac = state.context.get("selected_mac")
    current_filter = state.context.get("current_filter")

    if "related traffic" in text or "related conversation" in text:
        if selected_ip:
            return "Show all traffic involving this IP"
        if selected_mac:
            return "Show all traffic involving this MAC"
    if "only ipv6" in text:
        if selected_ip:
            return "Show all IPv6 traffic involving this IP"
        return "Show only IPv6 traffic"
    if "only ip" in text or "only ipv4" in text:
        if selected_ip:
            return "Show all IPv4 traffic involving this IP"
        return "Show only IP traffic"
    if "current filter" in text and current_filter:
        return "Explain this packet in the context of the current filter"
    if selected_ip:
        return "Show all traffic involving this IP"
    if selected_mac:
        return "Show all traffic involving this MAC"
    return ""


def resolve_ai_provider_for_text(state: SessionState, user_text: str) -> tuple[str, bool]:
    _, override_provider, explicit_ai = parse_ai_override(user_text)
    requested_provider = override_provider or state.settings.get("provider", "rule_based")
    if explicit_ai and override_provider is None and requested_provider == "rule_based":
        configured_ai = available_ai_provider_ids()
        if configured_ai:
            requested_provider = configured_ai[0]
    if requested_provider not in PROVIDERS:
        requested_provider = "rule_based"
    return requested_provider, explicit_ai


def chosen_model_for_provider(state: SessionState, provider_id: str) -> str:
    provider = PROVIDERS[provider_id]
    current_provider = state.settings.get("provider")
    current_model = state.settings.get("model")
    if provider_id == current_provider and current_model in provider.models:
        return current_model
    return provider.models[0]


def explain_filter_limit(state: SessionState, original_text: str, reason: str, technical: bool = False) -> Dict[str, Any]:
    selected_provider, explicit_ai = resolve_ai_provider_for_text(state, original_text)
    auto_provider = auto_ai_provider_for_failure(state)
    provider_id: Optional[str] = None

    if explicit_ai and selected_provider != "rule_based":
        provider = PROVIDERS.get(selected_provider)
        if provider and provider.available():
            provider_id = selected_provider
    elif auto_provider:
        provider_id = auto_provider

    if provider_id:
        cleaned_text, _, _ = parse_ai_override(original_text)
        provider = PROVIDERS[provider_id]
        chosen_model = chosen_model_for_provider(state, provider_id)
        guidance_prompt = (
            "The built-in Wireshark rule helper could not safely complete this request from deterministic logic alone. "
            "Try to fulfill the user's request directly using the provided packet context. "
            "If you can provide a safe explanation or Wireshark display filter, do that. "
            "If the request is still too ambiguous, explain exactly why and ask for the minimum additional context needed.\n\n"
            f"User request: {cleaned_text}\n"
            f"Reason: {reason}"
        )
        result = provider.explain_packet(state.context, guidance_prompt, chosen_model)
        response_source = "ai" if result.meta.get("live", False) else "fallback"
        mode = "explicitly requested" if explicit_ai else "automatically used"
        source_note = (
            f"Rule-based logic could not safely complete this request, so {provider.display_name} was {mode}."
            if response_source == "ai"
            else f"Rule-based logic could not safely complete this request, and {provider.display_name} did not complete the AI fallback."
        )
        fallback_text = (
            "I couldn't safely complete that request with built-in rules, and the AI fallback did not complete it either."
            f"\n\nWhy: {reason}"
        )
        refinement = contextual_refinement_hint(state, original_text)
        if refinement:
            fallback_text += f"\n\nTry this instead: {refinement}"
        if guided_next_steps(state):
            fallback_text += "\n\nUse one of the suggested actions below, or refine the request with a specific protocol, address, direction, port, or exclusion."
        return {
            "type": "explanation",
            "title": "AI fallback response" if response_source == "ai" else "Unable to complete request",
            "text": result.text if response_source == "ai" else fallback_text,
            "provider": result.meta.get("provider"),
            "model": result.meta.get("model"),
            "response_source": response_source,
            "source_note": source_note,
            "suggested_actions": guided_next_steps(state),
        }

    intro = (
        "I couldn't safely complete that request with built-in rules."
        if not technical
        else "I couldn't complete that request with the built-in filter logic."
    )
    body = f"{intro}\n\nWhy: {reason}"
    steps = guided_next_steps(state)
    refinement = contextual_refinement_hint(state, original_text)
    if refinement:
        body += f"\n\nTry this instead: {refinement}"
    if steps:
        body += "\n\nUse one of the suggested actions below, or refine the request with a specific protocol, address, direction, port, or exclusion."
    message = {
        "type": "explanation",
        "title": "Unable to complete request",
        "text": body,
        "provider": "rule_based",
        "model": "builtin",
        "response_source": "rule_based",
        "source_note": "No configured AI backend was available for automatic fallback.",
        "suggested_actions": steps,
    }
    return message


def build_filter(state: SessionState, original_text: str) -> Dict[str, Any]:
    text = normalize(original_text)
    clauses: List[str] = []
    protocols = detect_protocols(text)
    if protocols:
        clauses.append(protocols[0] if len(protocols) == 1 else "(" + " || ".join(protocols) + ")")
    if has_host_reference(text):
        host_expr = build_host_expr(state)
        if host_expr:
            clauses.append(host_expr)
    port_match = re.search(r"\bport\s+(\d{1,5})\b", text)
    if port_match:
        port = port_match.group(1)
        clauses.append(f"(tcp.port == {port} || udp.port == {port})")
    if "retransmission" in text or "retransmissions" in text:
        clauses.append("tcp.analysis.retransmission")
    if state.context.get("dns_name") and "this queried name" in text:
        clauses.append(f'dns.qry.name == "{state.context["dns_name"]}"')
    noise_key = state.resolved.get("noise_kind") or extract_noise(text)
    if noise_key:
        clauses.append(f"!({COMMON_NOISE[noise_key]})")
    if not clauses:
        reason = "The request did not map cleanly to a safe Wireshark display filter from the currently selected packet context."
        technical = False
        if has_host_reference(text) and not build_host_expr(state):
            reason = "You referred to 'this host', but the selected packet does not expose enough usable IP or MAC context for the rule-based filter builder to match it safely."
            technical = True
        elif "stream" in text and not (state.context.get("tcp_srcport") or state.context.get("udp_srcport")):
            reason = "You asked for stream-like traffic, but the selected packet does not expose a TCP or UDP conversation context the rule-based helper can safely reuse."
            technical = True
        elif not detect_protocols(text) and not has_host_reference(text) and not extract_noise(text):
            reason = "The request is still too open-ended for the rule-based filter builder. It needs at least one anchor such as a protocol, a host/device reference, a direction, a port, or an exclusion."
        return explain_filter_limit(state, original_text, reason, technical=technical)
    filt = " && ".join(clauses)
    explanation_bits = []
    if protocols:
        explanation_bits.append("matching the requested protocol(s)")
    if has_host_reference(text):
        hk = state.resolved.get("host_kind", "ip")
        explanation_bits.append(f"using the selected {hk.upper() if hk != 'both' else 'IP and MAC'} context")
    if noise_key:
        explanation_bits.append(f"excluding {noise_key.replace('_', ' ')} traffic")
    result = {
        "type": "filter_result",
        "filter": filt,
        "explanation": "Built by " + ", ".join(explanation_bits) + "." if explanation_bits else "Proposed Wireshark display filter.",
        "provider": "rule_based",
        "model": "builtin",
        "response_source": "rule_based",
        "upgrade_title": "Need more context or a deeper explanation?",
        "upgrade_suggestions": ai_upgrade_suggestions(state.context, state.settings),
    }
    return enrich_rule_based_response(result, state.context, state.settings)


def parse_ai_override(text: str) -> tuple[str, Optional[str], bool]:
    raw = text.strip()
    match = re.search(r"\+\s*(ai|openai|claude|anthropic|gemini|ollama|rule(?:-?based)?)\s*$", raw, flags=re.IGNORECASE)
    if not match:
        return raw, None, False
    suffix = match.group(1).lower()
    provider_map = {
        "ai": None,
        "openai": "openai",
        "claude": "anthropic",
        "anthropic": "anthropic",
        "gemini": "gemini",
        "ollama": "ollama",
        "rule": "rule_based",
        "rulebased": "rule_based",
        "rule-based": "rule_based",
    }
    provider = provider_map.get(suffix, None)
    cleaned = raw[:match.start()].rstrip()
    return cleaned or raw, provider, True


def ai_upgrade_suggestions(context: Dict[str, Any], settings: Dict[str, Any]) -> List[Dict[str, str]]:
    configured = available_ai_provider_ids()
    if not configured:
        return []

    suggestions: List[Dict[str, str]] = []
    selected_provider = settings.get("provider", "rule_based")
    if selected_provider != "rule_based" and selected_provider in configured:
        suggestions.append({
            "id": "upgrade_ai_selected",
            "label": "Explain this packet +AI",
            "prompt": "Explain this packet +AI",
        })
    else:
        suggestions.append({
            "id": "upgrade_ai_generic",
            "label": "Explain this packet +AI",
            "prompt": "Explain this packet +AI",
        })

    for provider_id in configured:
        suffix = provider_prompt_suffix(provider_id)
        suggestions.append({
            "id": f"upgrade_{provider_id}",
            "label": f"Explain this packet +{suffix}",
            "prompt": f"Explain this packet +{suffix}",
        })
    return suggestions


def enrich_rule_based_response(message: Dict[str, Any], context: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    message["response_source"] = message.get("response_source") or "rule_based"
    if message["type"] == "explanation":
        message["upgrade_title"] = "Want a deeper AI-assisted answer?"
        message["upgrade_suggestions"] = ai_upgrade_suggestions(context, settings)
        message["source_note"] = "This answer was generated by built-in rule-based logic to save tokens."
    elif message["type"] == "filter_result":
        message["source_note"] = "This filter was generated by built-in rule-based logic."
    return message


def maybe_make_clarification(state: SessionState, text: str) -> Optional[Dict[str, Any]]:
    normalized = normalize(text)
    if "this mac" in normalized:
        state.resolved["host_kind"] = "mac"
    elif "this ip" in normalized:
        state.resolved["host_kind"] = "ip"
    if has_host_reference(normalized) and not state.resolved.get("host_kind"):
        has_ip = bool(state.context.get("selected_ip") or state.context.get("selected_ipv6"))
        has_mac = bool(state.context.get("selected_mac"))
        options = []
        if has_ip:
            label = f"IP ({state.context.get('selected_ip') or state.context.get('selected_ipv6')})"
            options.append({"id": "ip", "label": label})
        if has_mac:
            options.append({"id": "mac", "label": f"MAC ({state.context.get('selected_mac')})"})
        if has_ip and has_mac:
            options.append({"id": "both", "label": "Both"})
        if len(options) >= 2:
            state.pending = {"kind": "host_kind", "original_text": text}
            return {"type": "clarification", "question": "What should 'this host' mean?", "options": options}
    if has_host_reference(normalized) and not state.resolved.get("direction"):
        inferred_direction = classify_direction(normalized)
        if inferred_direction:
            state.resolved["direction"] = inferred_direction
            return None
        state.pending = {"kind": "direction", "original_text": text}
        return {
            "type": "clarification",
            "question": "Should I match packets from this host, to this host, or either direction?",
            "options": [
                {"id": "src", "label": "From this host"},
                {"id": "dst", "label": "To this host"},
                {"id": "either", "label": "Either direction"},
            ],
        }
    if wants_noise_exclusion(normalized) and not state.resolved.get("noise_kind"):
        inferred_noise = extract_noise(normalized)
        if inferred_noise:
            state.resolved["noise_kind"] = inferred_noise
            return None
        state.pending = {"kind": "noise_kind", "original_text": text}
        return {
            "type": "clarification",
            "question": "What kind of noise should I exclude?",
            "options": [
                {"id": "all_common", "label": "All common noise"},
                {"id": "mdns", "label": "mDNS"},
                {"id": "arp", "label": "ARP"},
                {"id": "ssdp", "label": "SSDP"},
            ],
        }
    return None


def classify_user_text(text: str) -> str:
    t = normalize(text)
    if any(k in t for k in ["explain", "what is this packet", "what is this", "why is this", "summarize", "summary"]):
        return "explain"
    if any(k in t for k in ["show", "filter", "exclude", "only", "find", "traffic"]):
        return "filter"
    return "hybrid"


def explain_packet(state: SessionState, user_text: str) -> Dict[str, Any]:
    cleaned_text, _, _ = parse_ai_override(user_text)
    requested_provider, explicit_ai = resolve_ai_provider_for_text(state, user_text)
    provider_id = requested_provider if explicit_ai else "rule_based"

    provider = PROVIDERS[provider_id]
    chosen_model = chosen_model_for_provider(state, provider_id)
    result = provider.explain_packet(state.context, cleaned_text, chosen_model)

    response_source = "rule_based"
    if explicit_ai and result.meta.get("live", False):
        response_source = "ai"
    elif explicit_ai and not result.meta.get("live", False):
        response_source = "fallback"

    message = {
        "type": "explanation",
        "title": "Packet explanation",
        "text": result.text,
        "provider": result.meta.get("provider"),
        "model": result.meta.get("model"),
        "suggested_actions": guided_next_steps(state),
        "response_source": response_source,
        "source_note": "",
    }

    if response_source == "rule_based":
        message = enrich_rule_based_response(message, state.context, state.settings)
    elif response_source == "fallback":
        backend_name = PROVIDERS[provider_id].display_name
        message["upgrade_title"] = "AI did not complete. Try again with +AI or switch the selected backend."
        message["upgrade_suggestions"] = ai_upgrade_suggestions(state.context, state.settings)
        message["source_note"] = f"AI was explicitly requested, but the selected backend ({backend_name}) failed, so the assistant fell back to rule-based logic."
    else:
        backend_name = PROVIDERS[provider_id].display_name
        message["source_note"] = f"AI-assisted answer using {backend_name}. The next message will still default to rule-based unless you add +AI again."
    return message


def response_payload(state: SessionState) -> Dict[str, Any]:
    return {
        "session_id": state.session_id,
        "context": state.context,
        "messages": state.messages,
        "settings": state.settings,
        "providers": provider_payload(),
        "suggested_actions": state.suggested_actions,
        "backend_confirmed": state.backend_confirmed,
    }


def session_web_url(session_id: str) -> str:
    base_url = PUBLIC_BASE_URL or request.host_url.rstrip("/")
    return f"{base_url}/session/{session_id}"


@app.get("/")
def home():
    return "Smart Filter Receiver running"


@app.get("/health")
def health():
    return jsonify({"ok": True, "providers": provider_payload()})


@app.post("/api/session")
def api_create_session():
    payload = request.get_json(force=True, silent=True) or {}
    context = payload.get("context") or payload
    state = make_session(context)
    return jsonify({"session_id": state.session_id, "web_url": session_web_url(state.session_id)})


@app.get("/session/<session_id>")
def session_page(session_id: str):
    try:
        get_state(session_id)
    except KeyError:
        payload = session_missing_payload(session_id)
        return render_template("session_missing.html", **payload), 404
    return render_template("index.html", session_id=session_id)


@app.get("/api/session/<session_id>")
def api_session_state(session_id: str):
    try:
        return jsonify(response_payload(get_state(session_id)))
    except KeyError:
        return jsonify(session_missing_payload(session_id)), 404


@app.post("/api/session/<session_id>/message")
def api_session_message(session_id: str):
    state = get_state(session_id)
    payload = request.get_json(force=True, silent=True) or {}
    text = (payload.get("text") or "").strip()
    if not text:
        return jsonify(response_payload(state))
    if backend_selection_required(state):
        state.messages.append({"type": "error", "text": "Set the background AI backend first."})
        return jsonify(response_payload(state))
    state.messages.append({"type": "user_message", "text": text})

    clarification = maybe_make_clarification(state, text)
    if clarification:
        state.messages.append(clarification)
        return jsonify(response_payload(state))

    intent = classify_user_text(text)
    if intent == "explain":
        state.messages.append(explain_packet(state, text))
        return jsonify(response_payload(state))
    if intent == "hybrid" and any(k in normalize(text) for k in ["filter", "show", "exclude"]):
        state.messages.append(build_filter(state, text))
        return jsonify(response_payload(state))
    if intent == "hybrid":
        state.messages.append(explain_packet(state, text))
        return jsonify(response_payload(state))

    state.messages.append(build_filter(state, text))
    return jsonify(response_payload(state))


@app.post("/api/session/<session_id>/clarification")
def api_session_clarification(session_id: str):
    state = get_state(session_id)
    payload = request.get_json(force=True, silent=True) or {}
    option_id = payload.get("option_id")
    if not state.pending:
        state.messages.append({"type": "error", "text": "There is no pending clarification."})
        return jsonify(response_payload(state))
    pending = state.pending
    state.pending = None
    state.resolved[pending["kind"]] = option_id
    state.messages.append({"type": "user_choice", "text": option_id})

    original_text = pending.get("original_text", "")
    clarification = maybe_make_clarification(state, original_text)
    if clarification:
        state.messages.append(clarification)
        return jsonify(response_payload(state))

    intent = classify_user_text(original_text)
    if pending["kind"] == "host_kind" and not state.resolved.get("direction") and has_host_reference(normalize(original_text)):
        state.pending = {"kind": "direction", "original_text": original_text}
        state.messages.append({
            "type": "clarification",
            "question": "Should I match packets from this host, to this host, or either direction?",
            "options": [
                {"id": "src", "label": "From this host"},
                {"id": "dst", "label": "To this host"},
                {"id": "either", "label": "Either direction"},
            ],
        })
        return jsonify(response_payload(state))
    if intent == "explain":
        state.messages.append(explain_packet(state, original_text))
    else:
        state.messages.append(build_filter(state, original_text))
    return jsonify(response_payload(state))


@app.post("/api/session/<session_id>/clear")
def api_session_clear(session_id: str):
    state = get_state(session_id)
    state.messages = initial_messages(state)
    state.pending = None
    state.resolved = {}
    return jsonify(response_payload(state))


@app.get("/api/providers")
def api_providers():
    return jsonify({"providers": provider_payload(), "config": {"path": APP_CONFIG.get("config_path"), "exists": APP_CONFIG.get("exists", False)}})


@app.post("/api/session/<session_id>/settings")
def api_session_settings(session_id: str):
    state = get_state(session_id)
    payload = request.get_json(force=True, silent=True) or {}
    provider = payload.get("provider") or state.settings["provider"]
    if provider not in PROVIDERS:
        return jsonify({"error": "Unknown provider"}), 400
    if provider != "rule_based" and not PROVIDERS[provider].available():
        return jsonify({"error": f"{PROVIDERS[provider].display_name} is not configured"}), 400
    model = payload.get("model") or PROVIDERS[provider].models[0]
    if model not in PROVIDERS[provider].models:
        model = PROVIDERS[provider].models[0]
    state.settings = {"provider": provider, "model": model}
    state.backend_confirmed = True
    state.suggested_actions = guided_next_steps(state)
    state.messages = initial_messages(state)
    return jsonify(response_payload(state))


@app.post("/api/session/<session_id>/action")
def api_session_action(session_id: str):
    state = get_state(session_id)
    payload = request.get_json(force=True, silent=True) or {}
    prompt = (payload.get("prompt") or "").strip()
    if not prompt:
        return jsonify(response_payload(state))
    if backend_selection_required(state):
        state.messages.append({"type": "error", "text": "Set the background AI backend first."})
        return jsonify(response_payload(state))
    state.messages.append({"type": "user_choice", "text": prompt})
    clarification = maybe_make_clarification(state, prompt)
    if clarification:
        state.messages.append(clarification)
        return jsonify(response_payload(state))
    if classify_user_text(prompt) == "explain":
        state.messages.append(explain_packet(state, prompt))
    else:
        state.messages.append(build_filter(state, prompt))
    return jsonify(response_payload(state))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=BIND_HOST)
    parser.add_argument("--port", type=int, default=int(os.getenv("SMART_FILTER_PORT", "8765")))
    parser.add_argument("--debug", action="store_true", default=os.getenv("SMART_FILTER_DEBUG", "").lower() in {"1", "true", "yes", "on"})
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=args.debug)
