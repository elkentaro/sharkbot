from __future__ import annotations

import argparse
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask, Response, jsonify, render_template, request

from core.config import load_config
from core.playbooks import Playbook, load_playbook_registry

APP_CONFIG = load_config()

from core.providers import build_provider_registry


app = Flask(__name__, template_folder="templates", static_folder="static")
PROVIDERS = build_provider_registry()
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
PLAYBOOKS = load_playbook_registry(os.path.join(APP_ROOT, "playbooks"))
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
    playbook_id: Optional[str] = None
    applied_filters: List[Dict[str, str]] = field(default_factory=list)


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
    "wifi": "wlan",
    "wi-fi": "wlan",
    "wlan": "wlan",
    "802.11": "wlan",
    "ble": "btle",
    "btle": "btle",
    "bluetooth": "btle",
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


def playbook_payload() -> List[Dict[str, Any]]:
    return [playbook.payload() for playbook in sorted(PLAYBOOKS.values(), key=lambda item: (not item.built_in, item.name.lower()))]


def active_playbook(state: SessionState) -> Optional[Playbook]:
    if not state.playbook_id:
        return None
    return PLAYBOOKS.get(state.playbook_id)


def playbook_state_payload(state: SessionState) -> Optional[Dict[str, Any]]:
    playbook = active_playbook(state)
    return playbook.payload() if playbook else None


def recommended_playbook(state: SessionState) -> Optional[Playbook]:
    context = state.context
    proto = str(context.get("packet_protocol") or context.get("protocol_hint") or "").strip().lower()
    if context.get("tcp_srcport") or context.get("tcp_dstport") or "tcp" in proto:
        return PLAYBOOKS.get("tcp_issue")
    if "btle" in proto or "ble" in proto or "bluetooth" in proto:
        return PLAYBOOKS.get("btle_investigation")
    if proto in {"wlan", "wifi", "wi-fi", "802.11"} or "wlan" in proto or "wifi" in proto or "802.11" in proto:
        return PLAYBOOKS.get("wifi_investigation")
    return None


def recommended_playbook_payload(state: SessionState) -> Optional[Dict[str, Any]]:
    playbook = recommended_playbook(state)
    return playbook.payload() if playbook else None


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
        "Rule-based help stays on by default. Use +AI for the selected backend or "
        + ", ".join(suffixes)
        + " to force a specific backend for one reply."
    )


def generic_mode_text(state: SessionState) -> str:
    summary = summary_from_context(state.context)
    base = (
        f"Generic packet analysis is active for this {summary['protocol']} packet from {summary['source']} to {summary['destination']}. "
        "Start by explaining the packet, then scope the related host or device traffic, then narrow by protocol or conversation."
    )
    if not PLAYBOOKS:
        return base
    recommended = recommended_playbook(state)
    if recommended:
        return (
            f"{base} Playbooks are also available if you want guided analysis. "
            f"For this packet, the best guided starting point is {recommended.name}."
        )
    return f"{base} Playbooks are also available if you want guided analysis."


def playbook_guidance_summary(playbook: Playbook) -> str:
    focus = [item["label"] for item in playbook.suggested_actions[:3]]
    if not focus:
        return playbook.description
    if len(focus) == 1:
        return f"{playbook.description} For basic triage, start with {focus[0]}."
    if len(focus) == 2:
        joined = f"start with {focus[0]}, then {focus[1]}"
    else:
        joined = f"start with {focus[0]}, then {focus[1]}, then {focus[2]}"
    return f"{playbook.description} For basic triage, {joined}. Each step is meant to confirm scope before you assume intent or impact."


def playbook_stage_text(playbook: Playbook) -> str:
    if playbook.playbook_id == "tcp_issue":
        return "Why this sequence: first isolate the TCP conversation, then explain the packet role, then check retransmissions, duplicate ACKs, resets, or other stall indicators so you can tell which side is failing and whether the issue repeats."
    if playbook.playbook_id == "suspicious_traffic":
        return "Why this sequence: first explain why the packet stands out, then scope the host or device, then isolate expert-marked or repeated traffic so you can decide whether the activity looks routine, misconfigured, or worth escalation."
    if playbook.playbook_id == "wifi_investigation":
        return "Why this sequence: first identify the frame type and device roles, then scope one wireless device or exchange, then narrow into authentication, association, roaming, or retransmission behavior so you can tell whether the issue is one client, one AP, or wider RF noise."
    if playbook.playbook_id == "btle_investigation":
        return "Why this sequence: first identify the BLE packet purpose and device roles, then scope one device or exchange, then narrow into ATT/GATT or control behavior so you can tell whether the capture shows expected service traffic or a failed or suspicious BLE interaction."
    return "Why this sequence: start with the clearest narrowing pivot, then move deeper based on what the filtered traffic reveals."


def playbook_low_confidence_reason(
    state: SessionState,
    playbook: Optional[Playbook],
    filter_text: str = "",
) -> Optional[str]:
    if not playbook:
        return None
    context = state.context
    proto = normalize(str(context.get("packet_protocol") or context.get("protocol_hint") or ""))
    lower_filter = str(filter_text or "").lower()
    selected_mac = str(context.get("selected_mac") or "").lower()
    has_wlan_context = proto in {"wlan", "wifi", "wi-fi", "802.11"} or "wlan" in proto or "wifi" in proto or "802.11" in proto
    has_btle_context = "btle" in proto or "ble" in proto or "bluetooth" in proto

    if playbook.playbook_id == "wifi_investigation":
        if not has_wlan_context and "wlan" not in lower_filter:
            return "The active playbook is Wi-Fi-focused, but the current packet/filter does not expose native 802.11 fields or wireless frame context."
        if is_broadcast_or_multicast_mac(selected_mac):
            return "The current packet/filter is centered on the broadcast MAC address, which is usually too noisy to drive a reliable Wi-Fi next step from rules alone."
    if playbook.playbook_id == "btle_investigation":
        if not has_btle_context and "btle" not in lower_filter and "btatt" not in lower_filter and "btl2cap" not in lower_filter:
            return "The active playbook is BLE-focused, but the current packet/filter does not expose native BTLE fields or BLE exchange context."
    return None


def playbook_prompt_overlay(playbook: Optional[Playbook]) -> str:
    if not playbook:
        return ""
    lines = [
        f"Active playbook: {playbook.name}",
        f"Playbook description: {playbook.description}",
        "Playbook guidance:",
        playbook.system_guidance,
    ]
    if playbook.rule_hints:
        lines.append("Playbook rule hints: " + ", ".join(playbook.rule_hints))
    if playbook.prompt_hints:
        lines.append("Playbook investigation prompts: " + "; ".join(playbook.prompt_hints[:4]))
    return "\n".join(lines).strip()


def with_playbook_guidance(state: SessionState, user_text: str) -> str:
    playbook = active_playbook(state)
    overlay = playbook_prompt_overlay(playbook)
    if not overlay:
        return user_text
    return f"{user_text}\n\n{overlay}".strip()


def playbook_selector_action(label: str = "Use Playbook") -> Dict[str, str]:
    return {"id": "use_playbook", "label": label, "prompt": "", "kind": "playbook_open"}


def clear_playbook_action() -> Dict[str, str]:
    return {"id": "clear_playbook", "label": "Clear Playbook", "prompt": "", "kind": "playbook_clear"}


def filter_explain_action(filter_text: str) -> Dict[str, str]:
    return {"id": "explain_filter_ai", "label": "Explain filter +AI", "prompt": filter_text, "kind": "filter_explain_ai"}


def playbook_selector_message(state: SessionState) -> Dict[str, Any]:
    recommended = recommended_playbook_payload(state)
    active = playbook_state_payload(state)
    if active:
        title = f"Switch playbook from {active['name']}"
        text = "Choose a different playbook if you want SharkBot to guide the investigation with a different analysis style."
    elif recommended:
        title = f"Choose a playbook. Recommended: {recommended['name']}"
        text = "Playbooks can guide the next stage of the investigation. Pick one if you want SharkBot to shift from generic help into guided analysis."
    else:
        title = "Choose a playbook"
        text = "Playbooks can guide the next stage of the investigation. Pick one if you want SharkBot to shift from generic help into guided analysis."
    return {
        "type": "playbook_selector",
        "title": title,
        "text": text,
        "playbooks": playbook_payload(),
        "recommended_playbook": recommended,
        "active_playbook": active,
    }


def initial_messages(state: SessionState) -> List[Dict[str, Any]]:
    summary = summary_from_context(state.context)
    settings = state.settings
    playbook = active_playbook(state)
    messages: List[Dict[str, Any]] = [{"type": "system_notice", "text": "SharkBot is ready."}]
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
        "type": "assistant_text",
        "text": playbook_guidance_summary(playbook) if playbook else generic_mode_text(state),
        "message_kind": "mode_intro",
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
        "message": "This packet session is no longer available. Go back to Wireshark and launch SharkBot again from the packet menu.",
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
    if any(k in text for k in ["related to", "involving", "either", "both directions", "this host"]):
        return "either"
    if any(k in text for k in ["from this", "outgoing", "source"]):
        return "src"
    if any(k in text for k in ["to this", "incoming", "destination"]):
        return "dst"
    return None


def is_broadcast_or_multicast_mac(value: Optional[str]) -> bool:
    mac = str(value or "").strip().lower()
    if not mac:
        return False
    if mac == "ff:ff:ff:ff:ff:ff":
        return True
    first_octet = mac.split(":", 1)[0]
    try:
        return bool(int(first_octet, 16) & 1)
    except ValueError:
        return False


def has_wireless_mac_context(context: Dict[str, Any]) -> bool:
    proto = normalize(str(context.get("packet_protocol") or context.get("protocol_hint") or ""))
    return (
        proto in {"wlan", "wifi", "wi-fi", "802.11"}
        or "wlan" in proto
        or "wifi" in proto
        or "802.11" in proto
        or any(context.get(key) for key in ["wlan_sa", "wlan_ta", "wlan_da", "wlan_ra", "wlan_bssid"])
    )


def has_btle_mac_context(context: Dict[str, Any]) -> bool:
    proto = normalize(str(context.get("packet_protocol") or context.get("protocol_hint") or ""))
    return (
        "btle" in proto
        or "ble" in proto
        or "bluetooth" in proto
        or bool(context.get("btcommon_addr"))
    )


def preferred_device_mac(context: Dict[str, Any]) -> Optional[str]:
    selected = str(context.get("selected_mac") or "").strip().lower()
    if selected and not is_broadcast_or_multicast_mac(selected):
        return selected
    candidate_keys = (
        ["wlan_sa", "wlan_ta", "wlan_da", "wlan_ra", "eth_src", "eth_dst"]
        if has_wireless_mac_context(context)
        else ["eth_src", "eth_dst", "wlan_sa", "wlan_ta", "wlan_da", "wlan_ra"]
    )
    for key in candidate_keys:
        value = str(context.get(key) or "").strip().lower()
        if value and not is_broadcast_or_multicast_mac(value):
            return value
    return selected or None


def build_host_expr(state: SessionState) -> str:
    host_kind = state.resolved.get("host_kind", "ip")
    direction = state.resolved.get("direction", "either")
    ip = state.context.get("selected_ip") or state.context.get("selected_ipv6")
    mac = preferred_device_mac(state.context)
    wireless_mac = has_wireless_mac_context(state.context)
    btle_mac = has_btle_mac_context(state.context)

    def addr_expr(kind: str, which: str) -> str:
        if kind == "ip" and ip:
            field = "ipv6" if ":" in str(ip) else "ip"
            if which == "src":
                return f"{field}.src == {ip}"
            if which == "dst":
                return f"{field}.dst == {ip}"
            return f"{field}.addr == {ip}"
        if kind == "mac" and mac:
            if btle_mac:
                return f"btcommon.addr == {mac}"
            if wireless_mac:
                if which == "src":
                    return f"wlan.sa == {mac}"
                if which == "dst":
                    return f"wlan.da == {mac}"
                return f"wlan.addr == {mac}"
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


def build_conversation_expr(state: SessionState, proto_hint: str = "") -> str:
    proto = proto_hint.lower()
    use_tcp = proto == "tcp" or bool(state.context.get("tcp_srcport") or state.context.get("tcp_dstport"))
    use_udp = not use_tcp and (proto == "udp" or bool(state.context.get("udp_srcport") or state.context.get("udp_dstport")))
    l4 = "tcp" if use_tcp else ("udp" if use_udp else "")
    src_port = state.context.get(f"{l4}_srcport") if l4 else None
    dst_port = state.context.get(f"{l4}_dstport") if l4 else None
    src_ip = state.context.get("ip_src") or state.context.get("ipv6_src")
    dst_ip = state.context.get("ip_dst") or state.context.get("ipv6_dst")
    ip_field = "ipv6" if ":" in str(src_ip or dst_ip or "") else "ip"

    if l4 and src_port and dst_port and src_ip and dst_ip:
        forward = f"({ip_field}.src == {src_ip} && {ip_field}.dst == {dst_ip} && {l4}.srcport == {src_port} && {l4}.dstport == {dst_port})"
        reverse = f"({ip_field}.src == {dst_ip} && {ip_field}.dst == {src_ip} && {l4}.srcport == {dst_port} && {l4}.dstport == {src_port})"
        return f"({forward} || {reverse})"
    return ""


def contextualize_playbook_prompt(state: SessionState, prompt: str) -> str:
    text = str(prompt)
    selected_ip = state.context.get("selected_ip") or state.context.get("selected_ipv6")
    selected_mac = state.context.get("selected_mac")
    if selected_ip:
        text = re.sub(r"\bthis host\b", "this IP", text, flags=re.IGNORECASE)
        text = re.sub(r"\bthis device\b", "this IP", text, flags=re.IGNORECASE)
    elif selected_mac:
        text = re.sub(r"\bthis host\b", "this MAC", text, flags=re.IGNORECASE)
        text = re.sub(r"\bthis device\b", "this MAC", text, flags=re.IGNORECASE)
    return text


def dedupe_action_items(actions: List[Dict[str, str]], limit: int = 6) -> List[Dict[str, str]]:
    deduped: List[Dict[str, str]] = []
    seen = set()
    for item in actions:
        key = (item.get("kind") or "prompt", item.get("prompt") or item.get("id") or item.get("label"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[:limit]


def playbook_filter_focus(playbook: Optional[Playbook]) -> List[str]:
    if not playbook:
        return [
            "Whether the result set is broader or narrower than expected",
            "Which hosts, directions, and protocols dominate the filtered traffic",
            "Whether the filter isolates the conversation or still needs another narrowing step",
        ]
    if playbook.playbook_id == "tcp_issue":
        return [
            "Which side starts, stalls, resets, retransmits, or acknowledges abnormally",
            "Whether the packets stay inside one TCP conversation or show a wider repeated failure pattern",
            "What happens immediately before and after the filtered packets so you can confirm timing and impact",
        ]
    if playbook.playbook_id == "suspicious_traffic":
        return [
            "Unexpected peers, unusual ports, repeated retries, resets, or expert-marked packets",
            "Whether the traffic stays on one host or expands to more internal or external systems",
            "Whether the packets look like normal service traffic, noisy misconfiguration, scanning, or something worth escalation",
        ]
    if playbook.playbook_id == "wifi_investigation":
        return [
            "Client, BSSID, and SSID relationships across the filtered packets",
            "Management, authentication, association, deauthentication, or retransmission patterns that repeat",
            "Whether the filter isolates one wireless exchange or still mixes several device roles together",
        ]
    if playbook.playbook_id == "btle_investigation":
        return [
            "Device roles, address reuse, and whether the packets stay inside one BLE exchange",
            "ATT/GATT or control-procedure behavior that repeats, errors, or fails unexpectedly",
            "Whether the filter isolates one device interaction or still mixes several peers together",
        ]
    return [
        "Whether the result set is broader or narrower than expected",
        "Which hosts, directions, and protocols dominate the filtered traffic",
        "What the next narrowing or expansion step should be after reviewing the results",
    ]


def detect_filter_tags(filter_text: str) -> set[str]:
    lower = str(filter_text or "").lower()
    tags: set[str] = set()
    if "tcp.analysis.retransmission" in lower:
        tags.add("tcp_retransmission")
    if "tcp.analysis.duplicate_ack" in lower:
        tags.add("tcp_duplicate_ack")
    if "tcp.flags.reset == 1" in lower:
        tags.add("tcp_reset")
    if "_ws.expert" in lower:
        tags.add("expert")
    has_ip_conversation = all(token in lower for token in ["ip.src", "ip.dst"])
    has_ipv6_conversation = all(token in lower for token in ["ipv6.src", "ipv6.dst"])
    if all(token in lower for token in ["tcp.srcport", "tcp.dstport"]) and (has_ip_conversation or has_ipv6_conversation):
        tags.add("tcp_conversation")
    if all(token in lower for token in ["udp.srcport", "udp.dstport"]) and (has_ip_conversation or has_ipv6_conversation):
        tags.add("udp_conversation")
    if "ip.addr ==" in lower or "ipv6.addr ==" in lower:
        tags.add("ip_scope")
    if any(token in lower for token in ["eth.addr ==", "wlan.addr ==", "wlan.sa ==", "wlan.da ==", "btcommon.addr =="]):
        tags.add("mac_scope")
    if re.search(r"\btcp\b", lower):
        tags.add("tcp")
    if re.search(r"\bwlan\b", lower):
        tags.add("wifi")
    if "btle" in lower or "btatt" in lower or "btl2cap" in lower or "btcommon.addr" in lower:
        tags.add("btle")
    return tags


def summarize_applied_filter(filter_text: str) -> str:
    tags = detect_filter_tags(filter_text)
    if "tcp_retransmission" in tags and "tcp_conversation" in tags:
        return "This filter isolates TCP retransmissions within one bidirectional TCP conversation."
    if "tcp_duplicate_ack" in tags and "tcp_conversation" in tags:
        return "This filter isolates TCP duplicate ACKs within one bidirectional TCP conversation."
    if "tcp_reset" in tags and "tcp_conversation" in tags:
        return "This filter isolates TCP resets within one bidirectional TCP conversation."
    if "tcp_conversation" in tags:
        return "This filter isolates one bidirectional TCP conversation."
    if "udp_conversation" in tags:
        return "This filter isolates one bidirectional UDP conversation."
    if "tcp_retransmission" in tags:
        return "This filter isolates TCP retransmissions."
    if "tcp_duplicate_ack" in tags:
        return "This filter isolates TCP duplicate ACKs."
    if "tcp_reset" in tags:
        return "This filter isolates TCP resets."
    if "expert" in tags:
        return "This filter isolates Wireshark expert-marked packets."
    if "wifi" in tags and "mac_scope" in tags:
        return "This filter scopes traffic to one wireless device-focused view."
    if "btle" in tags and "mac_scope" in tags:
        return "This filter scopes traffic to one BLE device-focused view."
    if "ip_scope" in tags:
        return "This filter scopes traffic to one IP-focused view."
    if "mac_scope" in tags:
        return "This filter scopes traffic to one MAC-focused view."
    return "This filter narrows the capture to a focused packet set."


def filter_application_count(state: SessionState, filter_text: str) -> int:
    return sum(1 for item in state.applied_filters if item.get("filter") == filter_text)


def playbook_ai_training_prompt(
    playbook: Playbook,
    *,
    filter_text: str = "",
    reason: str = "",
    repeated: bool = False,
) -> str:
    lines = [
        "Act as a Wireshark training coach for a developing analyst.",
        "Recommend the single best next Wireshark step from this context and teach the user how to do it.",
        "Prefer the workflow that helps the user learn while still moving the investigation forward.",
        "When relevant, choose from a display filter, Follow Stream, surrounding-frame review, Statistics > Conversations, Statistics > Endpoints, or Statistics > Protocol Hierarchy.",
        "Explain exactly what to click or type, why this step comes before the others, what evidence to look for, one common beginner mistake to avoid, and one short skill takeaway.",
        "End with a line that starts with 'Skill takeaway:'.",
    ]
    if repeated:
        lines.append("The user has already repeated the same filter and may be stuck, so prefer a different next step instead of repeating the same view.")
    if reason:
        lines.append(reason)
    lines.extend([
        "",
        f"Current filter: {filter_text or '(none)'}",
        f"Active playbook: {playbook.name}",
        "Recommend the single best next Wireshark step and teach it. +AI",
    ])
    return "\n".join(lines)


def playbook_ai_stuck_action(state: SessionState, playbook: Playbook, filter_text: str) -> Dict[str, str]:
    summary = summarize_applied_filter(filter_text)
    prompt = playbook_ai_training_prompt(
        playbook,
        filter_text=filter_text,
        reason=f"The user has already applied this filter more than once and may be stuck. {summary}",
        repeated=True,
    )
    return {
        "id": f"{playbook.playbook_id}_ai_stuck_next_step",
        "label": "Use AI to recommend and teach the next step",
        "prompt": prompt,
        "kind": "playbook_ai_recommendation",
    }


def playbook_ai_early_action(state: SessionState, playbook: Playbook, reason: str, filter_text: str = "") -> Dict[str, str]:
    prompt = playbook_ai_training_prompt(
        playbook,
        filter_text=filter_text,
        reason=f"Rule-based confidence is low for this playbook context. {reason}",
    )
    return {
        "id": f"{playbook.playbook_id}_ai_early_next_step",
        "label": "Use AI to recommend and teach the next step",
        "prompt": prompt,
        "kind": "playbook_ai_recommendation",
    }


def playbook_low_confidence_followup_steps(state: SessionState) -> List[Dict[str, str]]:
    steps: List[Dict[str, str]] = []
    current_filter = state.context.get("current_filter") or ""
    if current_filter:
        steps.append({
            "id": "low_confidence_explain_current_filter",
            "label": "Explain the current filter and this packet together",
            "prompt": "Explain this packet in the context of the current filter",
        })
    steps.append(playbook_selector_action("Choose a different playbook"))
    steps.append(clear_playbook_action())
    return steps


def playbook_steps_after_ai_guidance(state: SessionState, playbook: Playbook) -> List[Dict[str, str]]:
    steps: List[Dict[str, str]] = []
    current_filter = state.context.get("current_filter") or ""
    if current_filter:
        steps.append({
            "id": "post_ai_explain_current_filter",
            "label": "Explain the current filter and this packet together",
            "prompt": "Explain this packet in the context of the current filter",
        })
    steps.append(playbook_selector_action("Choose a different playbook"))
    steps.append(clear_playbook_action())
    return dedupe_action_items(steps, limit=4)


def playbook_ai_handoff_text(state: SessionState, playbook: Playbook) -> str:
    low_confidence = playbook_low_confidence_reason(state, playbook, state.context.get("current_filter") or "")
    if low_confidence:
        return (
            f"The AI recommendation should be treated as the next manual Wireshark step and a short training aid. "
            f"Do not keep repeating the same playbook action if the capture still does not fit {playbook.name}; switch playbooks or clear it."
        )
    return "Use the AI recommendation as the next manual Wireshark step, then continue the investigation from the new result. It should also explain why that workflow is worth learning."


def playbook_step_reason(state: SessionState, playbook: Playbook, filter_text: str, next_action: Optional[Dict[str, str]]) -> str:
    tags = detect_filter_tags(filter_text)
    next_label = (next_action or {}).get("label", "").replace("Recommended next step: ", "", 1)
    low_confidence = playbook_low_confidence_reason(state, playbook, filter_text)
    if low_confidence:
        return f"Why this step: {low_confidence} AI guidance is recommended early so SharkBot can account for context that the rule engine cannot safely infer."
    if playbook.playbook_id == "tcp_issue":
        if "tcp_conversation" in tags and "tcp_retransmission" not in tags and "tcp_duplicate_ack" not in tags and "tcp_reset" not in tags:
            return f"Why this step: you already isolated the TCP conversation, so the next useful pivot is packet-loss evidence inside that same conversation. {next_label} helps confirm whether the slowdown or failure is tied to retransmission behavior."
        if "tcp_retransmission" in tags:
            return f"Why this step: retransmissions are already isolated, so the next useful pivot is how the peer reacts. {next_label} helps you compare loss symptoms with ACK behavior instead of repeating the same view."
        if "tcp_duplicate_ack" in tags:
            return f"Why this step: duplicate ACKs are already isolated, so the next useful pivot is whether retransmissions, resets, or sequence progression explain them. {next_label} moves the investigation forward."
        if "tcp_reset" in tags:
            return f"Why this step: once resets are isolated, the next useful move is to explain that filtered view and determine which side terminated the flow and why."
    if playbook.playbook_id == "suspicious_traffic":
        return f"Why this step: the current filter gives you scope. {next_label} helps you decide whether the packet is expected service traffic, a noisy mistake, or an outlier that needs escalation."
    if playbook.playbook_id == "wifi_investigation":
        return f"Why this step: the current filter narrows the wireless view. {next_label} helps you identify device roles and determine whether the issue is tied to one client, one BSSID, or one management exchange."
    if playbook.playbook_id == "btle_investigation":
        return f"Why this step: the current filter narrows the BLE exchange. {next_label} helps you identify the device role and determine whether the behavior belongs to one device interaction or a wider control problem."
    return f"Why this step: {next_label} is the best next pivot from the current filtered result."


def obvious_step_after_filter(state: SessionState, playbook: Playbook, filter_text: str) -> Optional[Dict[str, str]]:
    tags = detect_filter_tags(filter_text)
    if playbook.playbook_id == "tcp_issue":
        if "tcp_retransmission" in tags:
            return {
                "id": "after_filter_tcp_dupacks",
                "label": "Recommended next step: Show duplicate ACKs in this TCP conversation",
                "prompt": contextualize_playbook_prompt(state, "Show duplicate ACKs in this TCP conversation"),
                "kind": "recommended_step",
            }
        if "tcp_duplicate_ack" in tags:
            return {
                "id": "after_filter_tcp_retransmission",
                "label": "Recommended next step: Show retransmissions in this TCP conversation",
                "prompt": contextualize_playbook_prompt(state, "Show retransmissions in this TCP conversation"),
                "kind": "recommended_step",
            }
        if "tcp_reset" in tags:
            return {
                "id": "after_filter_tcp_explain",
                "label": "Recommended next step: Explain this TCP packet in the context of the current filter",
                "prompt": "Explain this packet in the context of the current filter",
                "kind": "recommended_step",
            }
        if "tcp_conversation" in tags:
            return {
                "id": "after_filter_tcp_retransmissions",
                "label": "Recommended next step: Show retransmissions in this TCP conversation",
                "prompt": contextualize_playbook_prompt(state, "Show retransmissions in this TCP conversation"),
                "kind": "recommended_step",
            }
        if "tcp" in tags:
            return {
                "id": "after_filter_tcp_conversation",
                "label": "Recommended next step: Show this TCP conversation",
                "prompt": contextualize_playbook_prompt(state, "Show this TCP conversation"),
                "kind": "recommended_step",
            }
    if playbook.playbook_id == "suspicious_traffic":
        if "ip_scope" in tags or "mac_scope" in tags:
            return {
                "id": "after_filter_suspicious_expert",
                "label": "Recommended next step: Show unusual or expert-marked packets",
                "prompt": contextualize_playbook_prompt(state, "Show expert warnings"),
                "kind": "recommended_step",
            }
        if "expert" in tags:
            return {
                "id": "after_filter_suspicious_explain",
                "label": "Recommended next step: Why is this packet suspicious?",
                "prompt": contextualize_playbook_prompt(state, "Why is this packet suspicious?"),
                "kind": "recommended_step",
            }
    if playbook.playbook_id == "wifi_investigation":
        if "mac_scope" in tags or "wifi" in tags:
            return {
                "id": "after_filter_wifi_explain",
                "label": "Recommended next step: Explain this Wi-Fi packet",
                "prompt": contextualize_playbook_prompt(state, "Explain this Wi-Fi packet"),
                "kind": "recommended_step",
            }
    if playbook.playbook_id == "btle_investigation":
        if "mac_scope" in tags or "btle" in tags:
            return {
                "id": "after_filter_btle_explain",
                "label": "Recommended next step: Explain this BTLE packet",
                "prompt": contextualize_playbook_prompt(state, "Explain this BTLE packet"),
                "kind": "recommended_step",
            }
    return None


def playbook_steps_after_filter(
    state: SessionState,
    playbook: Playbook,
    filter_text: str,
    origin_prompt: str = "",
) -> List[Dict[str, str]]:
    steps: List[Dict[str, str]] = []
    tags = detect_filter_tags(filter_text)
    repeated_count = filter_application_count(state, filter_text)
    low_confidence = playbook_low_confidence_reason(state, playbook, filter_text)
    recommended = obvious_step_after_filter(state, playbook, filter_text)
    if repeated_count >= 2:
        steps.append(playbook_ai_stuck_action(state, playbook, filter_text))
        if low_confidence:
            steps.extend(playbook_low_confidence_followup_steps(state))
            return dedupe_action_items(steps, limit=5)
        if recommended:
            steps.append(recommended)
    elif low_confidence:
        steps.append(playbook_ai_early_action(state, playbook, low_confidence, filter_text))
        steps.extend(playbook_low_confidence_followup_steps(state))
        return dedupe_action_items(steps, limit=5)
    elif recommended:
        steps.append(recommended)
    else:
        steps.append(ai_playbook_recommendation_action(state, playbook))

    excluded_prompts = {normalize(origin_prompt)} if origin_prompt else set()
    for item in playbook.suggested_actions:
        prompt = contextualize_playbook_prompt(state, item["prompt"])
        label = item["label"]
        if playbook.playbook_id == "tcp_issue" and "tcp_conversation" in tags:
            if normalize(prompt) == normalize("Show retransmissions"):
                prompt = contextualize_playbook_prompt(state, "Show retransmissions in this TCP conversation")
                label = "Show retransmissions in this TCP conversation"
            elif normalize(prompt) == normalize("Show duplicate ACKs"):
                prompt = contextualize_playbook_prompt(state, "Show duplicate ACKs in this TCP conversation")
                label = "Show duplicate ACKs in this TCP conversation"
            elif normalize(prompt) == normalize("Show resets"):
                prompt = contextualize_playbook_prompt(state, "Show resets in this TCP conversation")
                label = "Show resets in this TCP conversation"
            elif normalize(prompt) == normalize("Explain this TCP packet"):
                prompt = "Explain this packet in the context of the current filter"
                label = "Explain this TCP packet in the current filtered view"
        elif playbook.playbook_id == "tcp_issue" and ("tcp_retransmission" in tags or "tcp_duplicate_ack" in tags or "tcp_reset" in tags):
            if normalize(prompt) == normalize("Explain this TCP packet"):
                prompt = "Explain this packet in the context of the current filter"
                label = "Explain this TCP packet in the current filtered view"
        if normalize(prompt) in excluded_prompts:
            continue
        steps.append({
            "id": f"{playbook.playbook_id}_{label.lower().replace(' ', '_')}",
            "label": label,
            "prompt": prompt,
        })
    steps.append(clear_playbook_action())
    return dedupe_action_items(steps, limit=7)


def playbook_filter_checkpoint_message(
    state: SessionState,
    playbook: Playbook,
    filter_text: str,
    note: str = "",
) -> str:
    summary = summarize_applied_filter(filter_text)
    recommended = obvious_step_after_filter(state, playbook, filter_text)
    repeated_count = filter_application_count(state, filter_text)
    low_confidence = playbook_low_confidence_reason(state, playbook, filter_text)
    lines = [
        f"Playbook active: {playbook.name}. {summary}",
    ]
    if note:
        lines.append(f"Observation noted: {note}")
    if repeated_count >= 2:
        lines.append("You have already applied this filter more than once, so SharkBot is switching to an AI-assisted recommendation to avoid repeating the same playbook step.")
        if recommended:
            lines.append(playbook_step_reason(state, playbook, filter_text, recommended))
    elif low_confidence:
        lines.append(f"Rule-based confidence is low here. {low_confidence}")
        if recommended:
            lines.append(playbook_step_reason(state, playbook, filter_text, recommended))
        else:
            lines.append("AI guidance is recommended now so SharkBot can choose the next step using broader packet-analysis context.")
    elif recommended:
        next_label = recommended["label"].replace("Recommended next step: ", "", 1)
        lines.append(f"Next, {next_label.lower()} so the playbook can narrow the investigation further.")
        lines.append(playbook_step_reason(state, playbook, filter_text, recommended))
    else:
        lines.append("The next step is not obvious from rules alone, so use the AI recommendation step to decide what to inspect next.")
    return " ".join(lines)


def explain_filter_expression(state: SessionState, filter_text: str) -> Dict[str, Any]:
    playbook = active_playbook(state)
    tags = detect_filter_tags(filter_text)
    summary: List[str] = []
    if "tcp.analysis.retransmission" in filter_text:
        summary.append("This filter isolates TCP retransmissions.")
    if "tcp.analysis.duplicate_ack" in filter_text:
        summary.append("This filter isolates TCP duplicate ACKs.")
    if "tcp.flags.reset == 1" in filter_text:
        summary.append("This filter isolates TCP resets.")
    if "_ws.expert" in filter_text:
        summary.append("This filter isolates packets with Wireshark expert markings.")
    if "tcp_conversation" in tags:
        summary.append("This filter isolates one bidirectional TCP conversation.")
    elif "udp_conversation" in tags:
        summary.append("This filter isolates one bidirectional UDP conversation.")
    elif "tcp" in filter_text:
        summary.append("This filter stays focused on TCP traffic.")
    if "ip.addr ==" in filter_text or "ipv6.addr ==" in filter_text:
        summary.append("This filter keeps traffic centered on one IP address.")
    if "eth.addr ==" in filter_text:
        summary.append("This filter keeps traffic centered on one MAC address.")
    if "wlan.addr ==" in filter_text or "wlan.sa ==" in filter_text or "wlan.da ==" in filter_text:
        summary.append("This filter keeps traffic centered on one wireless device address.")
    if "btcommon.addr ==" in filter_text:
        summary.append("This filter keeps traffic centered on one BLE device address.")
    if re.search(r"\bwlan\b", filter_text):
        summary.append("This filter stays focused on 802.11 traffic.")
    if "btle" in filter_text or "btatt" in filter_text or "btl2cap" in filter_text:
        summary.append("This filter stays focused on BLE traffic.")

    if not summary:
        summary.append("This filter narrows the capture to a specific subset of packets based on the requested fields.")

    focus_points = playbook_filter_focus(playbook)
    lines = [
        "Summary:",
        " ".join(summary),
        "",
        "What this filter matches:",
        filter_text,
        "",
        "What to look for:",
    ]
    lines.extend([f"- {item}" for item in focus_points])
    if playbook:
        lines.extend([
            "",
            "Why this matters for the active playbook:",
            f"This guidance is tuned for the {playbook.name} playbook.",
        ])
    else:
        lines.extend([
            "",
            "Why this matters:",
            "This explanation is generic packet-analysis guidance.",
        ])

    message = {
        "type": "explanation",
        "title": "Filter explanation",
        "text": "\n".join(lines),
        "provider": "rule_based",
        "model": "builtin",
        "response_source": "rule_based",
        "request_mode": "playbook" if playbook else "generic",
        "suggested_actions": guided_next_steps(state),
    }
    return enrich_rule_based_response(
        message,
        state.context,
        state.settings,
        base_prompt=f"Explain this filter: {filter_text}",
        request_mode="playbook" if playbook else "generic",
    )


def explain_filter_with_ai(state: SessionState, filter_text: str) -> Dict[str, Any]:
    provider_id = auto_ai_provider_for_failure(state)
    if not provider_id or provider_id == "rule_based":
        fallback = explain_filter_expression(state, filter_text)
        fallback["source_note"] = "No configured AI backend was available, so SharkBot used built-in filter explanation logic."
        return fallback

    provider = PROVIDERS[provider_id]
    chosen_model = chosen_model_for_provider(state, provider_id)
    playbook = active_playbook(state)
    focus = playbook_filter_focus(playbook)
    prompt_lines = [
        "Explain the following Wireshark display filter in practical analyst terms.",
        "Tell the user what the filter matches, what it excludes by implication, and what they should look for after applying it.",
        "Keep the explanation grounded in the selected packet context.",
        "Treat this as a training aid: explain when an analyst should use this filter, when a wider capture-scoping view would be better, and what a beginner should learn from it.",
        "If Statistics > Conversations, Statistics > Endpoints, Statistics > Protocol Hierarchy, Follow Stream, or surrounding-frame review would be a better next step than repeating the filter, say so explicitly.",
        "",
        f"Filter: {filter_text}",
        "",
        "What the analyst should look for:",
    ]
    prompt_lines.extend([f"- {item}" for item in focus])
    if playbook:
        prompt_lines.extend([
            "",
            f"Active playbook: {playbook.name}",
            playbook.system_guidance,
        ])
    prompt = with_playbook_guidance(state, "\n".join(prompt_lines))
    result = provider.explain_packet(state.context, prompt, chosen_model)
    if not result.meta.get("live", False):
        fallback = explain_filter_expression(state, filter_text)
        fallback["source_note"] = f"{provider.display_name} did not complete the filter explanation, so SharkBot used built-in filter explanation logic."
        return fallback

    return {
        "type": "explanation",
        "title": "Filter explanation",
        "text": result.text,
        "provider": result.meta.get("provider"),
        "model": result.meta.get("model"),
        "response_source": "ai",
        "request_mode": "playbook" if playbook else "generic",
        "source_note": f"AI-assisted filter explanation using {provider.display_name}.",
        "suggested_actions": guided_next_steps(state),
    }


def obvious_playbook_next_step(state: SessionState, playbook: Playbook) -> Optional[Dict[str, str]]:
    current_filter = state.context.get("current_filter") or ""
    if playbook.playbook_id == "tcp_issue":
        if state.context.get("tcp_srcport") or state.context.get("tcp_dstport"):
            return {
                "id": "recommended_tcp_conversation",
                "label": "Recommended next step: Show this TCP conversation",
                "prompt": "Show this TCP conversation",
                "kind": "recommended_step",
            }
        return {
            "id": "recommended_tcp_only",
            "label": "Recommended next step: Show only TCP traffic",
            "prompt": "Show only TCP traffic",
            "kind": "recommended_step",
        }
    if playbook.playbook_id == "suspicious_traffic":
        if not current_filter:
            return {
                "id": "recommended_suspicious_explain",
                "label": "Recommended next step: Why is this packet suspicious?",
                "prompt": "Why is this packet suspicious?",
                "kind": "recommended_step",
            }
        if state.context.get("selected_ip") or state.context.get("selected_ipv6"):
            return {
                "id": "recommended_scope_ip",
                "label": "Recommended next step: Show all traffic involving this IP",
                "prompt": "Show all traffic involving this IP",
                "kind": "recommended_step",
            }
        if preferred_device_mac(state.context):
            return {
                "id": "recommended_scope_mac",
                "label": "Recommended next step: Show all traffic involving this MAC",
                "prompt": "Show all traffic involving this MAC",
                "kind": "recommended_step",
            }
    if playbook.playbook_id == "wifi_investigation":
        if not current_filter:
            return {
                "id": "recommended_wifi_explain",
                "label": "Recommended next step: Explain this Wi-Fi packet",
                "prompt": "Explain this Wi-Fi packet",
                "kind": "recommended_step",
            }
        if preferred_device_mac(state.context):
            return {
                "id": "recommended_wifi_investigation_device",
                "label": "Recommended next step: Show all traffic involving this wireless device",
                "prompt": "Show all traffic involving this MAC",
                "kind": "recommended_step",
            }
    if playbook.playbook_id == "btle_investigation":
        if not current_filter:
            return {
                "id": "recommended_btle_explain",
                "label": "Recommended next step: Explain this BTLE packet",
                "prompt": "Explain this BTLE packet",
                "kind": "recommended_step",
            }
        if preferred_device_mac(state.context):
            return {
                "id": "recommended_btle_investigation_device",
                "label": "Recommended next step: Show all traffic involving this BLE device",
                "prompt": "Show all traffic involving this MAC",
                "kind": "recommended_step",
            }
    return None


def ai_playbook_recommendation_action(state: SessionState, playbook: Playbook) -> Dict[str, str]:
    prompt = playbook_ai_training_prompt(playbook, filter_text=state.context.get("current_filter") or "")
    return {
        "id": f"{playbook.playbook_id}_ai_next_step",
        "label": "Use AI to recommend and teach the next step",
        "prompt": prompt,
        "kind": "playbook_ai_recommendation",
    }


def guided_next_steps(state: SessionState) -> List[Dict[str, str]]:
    playbook = active_playbook(state)
    steps: List[Dict[str, str]] = []
    ctx = state.context
    proto = (ctx.get("packet_protocol") or ctx.get("protocol_hint") or "").lower()
    ip = ctx.get("selected_ip") or ctx.get("selected_ipv6")
    mac = ctx.get("selected_mac")
    current_filter = ctx.get("current_filter") or ""

    def add(label: str, prompt: str) -> None:
        steps.append({"id": label.lower().replace(" ", "_"), "label": label, "prompt": prompt})

    if playbook:
        low_confidence = playbook_low_confidence_reason(state, playbook)
        recommended = obvious_playbook_next_step(state, playbook)
        if low_confidence:
            steps.append(playbook_ai_early_action(state, playbook, low_confidence))
            steps.extend(playbook_low_confidence_followup_steps(state))
            return dedupe_action_items(steps, limit=5)
        elif recommended:
            steps.append(recommended)
        else:
            steps.append(ai_playbook_recommendation_action(state, playbook))
        for item in playbook.suggested_actions:
            steps.append({
                "id": f"{playbook.playbook_id}_{item['label'].lower().replace(' ', '_')}",
                "label": item["label"],
                "prompt": contextualize_playbook_prompt(state, item["prompt"]),
            })
        if current_filter:
            add("Explain the current filter and this packet together", "Explain this packet in the context of the current filter")
        steps.append(clear_playbook_action())
        return dedupe_action_items(steps, limit=7)

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
        add("Show this TCP conversation", "Show this TCP conversation")
        add("Show only TCP traffic", "Show only TCP traffic")
    elif proto in ("udp",):
        add("Show this UDP conversation", "Show this UDP conversation")
        add("Show only UDP traffic", "Show only UDP traffic")
    elif proto:
        add(f"Show only {proto.upper()} traffic", f"Show only {proto.upper()} traffic")

    if current_filter:
        add("Explain the current filter and this packet together", "Explain this packet in the context of the current filter")
    if PLAYBOOKS:
        steps.append(playbook_selector_action())
    steps.extend(ai_upgrade_suggestions(state.context, state.settings))
    return dedupe_action_items(steps, limit=7)


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
            f"User request: {with_playbook_guidance(state, cleaned_text)}\n"
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
    conversation_expr = ""
    if "conversation" in text or "stream" in text:
        proto_hint = "tcp" if "tcp" in text else ("udp" if "udp" in text else "")
        conversation_expr = build_conversation_expr(state, proto_hint)
        if conversation_expr:
            clauses.append(conversation_expr)
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
    if "duplicate ack" in text or "duplicate acks" in text:
        clauses.append("tcp.analysis.duplicate_ack")
    if "reset" in text or "resets" in text:
        clauses.append("tcp.flags.reset == 1")
    if "expert warning" in text or "expert warnings" in text or "expert-marked" in text:
        clauses.append("_ws.expert")
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
        elif ("stream" in text or "conversation" in text) and not conversation_expr:
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
        "origin_prompt": original_text,
        "provider": "rule_based",
        "model": "builtin",
        "response_source": "rule_based",
        "request_mode": "playbook" if active_playbook(state) else "generic",
        "playbook": playbook_state_payload(state),
        "upgrade_title": "Need more context or a deeper explanation?",
        "upgrade_suggestions": ai_upgrade_suggestions(state.context, state.settings),
    }
    return enrich_rule_based_response(
        result,
        state.context,
        state.settings,
        base_prompt=original_text,
        request_mode="playbook" if active_playbook(state) else "generic",
    )


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


def ai_upgrade_suggestions_for_prompt(prompt: str, settings: Dict[str, Any]) -> List[Dict[str, str]]:
    configured = available_ai_provider_ids()
    if not configured:
        return []

    base_prompt = str(prompt or "Explain this packet").strip() or "Explain this packet"
    suggestions: List[Dict[str, str]] = []
    selected_provider = settings.get("provider", "rule_based")
    if selected_provider != "rule_based" and selected_provider in configured:
        suggestions.append({
            "id": "upgrade_ai_selected",
            "label": f"{base_prompt} +AI",
            "prompt": f"{base_prompt} +AI",
        })
    else:
        suggestions.append({
            "id": "upgrade_ai_generic",
            "label": f"{base_prompt} +AI",
            "prompt": f"{base_prompt} +AI",
        })

    for provider_id in configured:
        suffix = provider_prompt_suffix(provider_id)
        suggestions.append({
            "id": f"upgrade_{provider_id}",
            "label": f"{base_prompt} +{suffix}",
            "prompt": f"{base_prompt} +{suffix}",
        })
    return suggestions


def ai_upgrade_suggestions(context: Dict[str, Any], settings: Dict[str, Any]) -> List[Dict[str, str]]:
    return ai_upgrade_suggestions_for_prompt("Explain this packet", settings)


def enrich_rule_based_response(
    message: Dict[str, Any],
    context: Dict[str, Any],
    settings: Dict[str, Any],
    *,
    base_prompt: str = "Explain this packet",
    request_mode: str = "generic",
) -> Dict[str, Any]:
    message["response_source"] = message.get("response_source") or "rule_based"
    message["request_mode"] = message.get("request_mode") or request_mode
    if message["type"] == "explanation":
        message["upgrade_title"] = (
            "Want a deeper AI-assisted playbook answer?"
            if request_mode == "playbook"
            else "Want a deeper AI-assisted answer?"
        )
        message["upgrade_suggestions"] = ai_upgrade_suggestions_for_prompt(base_prompt, settings)
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
        if has_ip and not has_mac:
            state.resolved["host_kind"] = "ip"
        elif has_mac and not has_ip:
            state.resolved["host_kind"] = "mac"
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
    playbook = active_playbook(state)
    low_confidence = playbook_low_confidence_reason(state, playbook)
    auto_playbook_ai = bool(playbook and low_confidence and not explicit_ai)
    provider_id = requested_provider if explicit_ai else "rule_based"
    if auto_playbook_ai:
        provider_id = auto_ai_provider_for_failure(state) or "rule_based"

    provider = PROVIDERS[provider_id]
    chosen_model = chosen_model_for_provider(state, provider_id)
    result = provider.explain_packet(state.context, with_playbook_guidance(state, cleaned_text), chosen_model)

    response_source = "rule_based"
    if (explicit_ai or auto_playbook_ai) and result.meta.get("live", False):
        response_source = "ai"
    elif (explicit_ai or auto_playbook_ai) and not result.meta.get("live", False):
        response_source = "fallback"

    message = {
        "type": "explanation",
        "title": "Packet explanation",
        "text": result.text,
        "provider": result.meta.get("provider"),
        "model": result.meta.get("model"),
        "suggested_actions": guided_next_steps(state),
        "response_source": response_source,
        "request_mode": "playbook" if playbook else "generic",
        "source_note": "",
    }

    if response_source == "rule_based":
        message = enrich_rule_based_response(
            message,
            state.context,
            state.settings,
            base_prompt=cleaned_text,
            request_mode="playbook" if playbook else "generic",
        )
    elif response_source == "fallback":
        backend_name = PROVIDERS[provider_id].display_name
        message["upgrade_title"] = "AI did not complete. Try again with +AI or switch the selected backend."
        message["upgrade_suggestions"] = ai_upgrade_suggestions_for_prompt(cleaned_text, state.settings)
        if auto_playbook_ai and low_confidence:
            message["source_note"] = f"SharkBot tried {backend_name} automatically because rule-based confidence was low for the active playbook context, but the assistant had to fall back to built-in logic."
        else:
            message["source_note"] = f"AI was explicitly requested, but the selected backend ({backend_name}) failed, so the assistant fell back to rule-based logic."
    else:
        backend_name = PROVIDERS[provider_id].display_name
        if auto_playbook_ai and low_confidence:
            message["source_note"] = f"AI-assisted answer using {backend_name}. SharkBot used AI automatically because rule-based confidence was low for the active playbook context."
        else:
            message["source_note"] = f"AI-assisted answer using {backend_name}. The next message will still default to rule-based unless you add +AI again."
    return message


def apply_playbook_selection(state: SessionState, playbook_id: Optional[str]) -> None:
    if playbook_id:
        playbook = PLAYBOOKS[playbook_id]
        state.playbook_id = playbook.playbook_id
        state.applied_filters = []
        state.suggested_actions = guided_next_steps(state)
        state.messages.append({
            "type": "assistant_text",
            "text": f"Playbook active: {playbook.name}. {playbook_guidance_summary(playbook)}",
        })
        state.messages.append({
            "type": "suggested_actions",
            "title": f"Next steps for {playbook.name}",
            "text": playbook_stage_text(playbook),
            "items": state.suggested_actions,
        })
        return

    state.playbook_id = None
    state.applied_filters = []
    state.suggested_actions = guided_next_steps(state)
    state.messages.append({
        "type": "assistant_text",
        "text": generic_mode_text(state),
        "message_kind": "mode_intro",
    })
    state.messages.append({
        "type": "suggested_actions",
        "title": "Back to generic guidance",
        "items": state.suggested_actions,
    })


def response_payload(state: SessionState) -> Dict[str, Any]:
    return {
        "session_id": state.session_id,
        "context": state.context,
        "messages": state.messages,
        "settings": state.settings,
        "providers": provider_payload(),
        "playbooks": playbook_payload(),
        "playbook": playbook_state_payload(state),
        "recommended_playbook": recommended_playbook_payload(state),
        "suggested_actions": state.suggested_actions,
        "backend_confirmed": state.backend_confirmed,
    }


def session_web_url(session_id: str) -> str:
    base_url = PUBLIC_BASE_URL or request.host_url.rstrip("/")
    return f"{base_url}/session/{session_id}"


def apply_context_update(state: SessionState, context: Dict[str, Any], source_label: str = "Wireshark") -> None:
    updated_context = dict(context)
    updated_context["packet_protocol"] = infer_packet_protocol(updated_context)
    state.context = updated_context
    state.pending = None
    state.resolved = {}
    state.applied_filters = []
    state.suggested_actions = guided_next_steps(state)
    summary = summary_from_context(state.context)
    state.messages.append({
        "type": "system_notice",
        "text": f"Investigation context updated from {source_label}.",
    })
    state.messages.append({
        "type": "packet_summary",
        "summary": summary,
        "provider": state.settings["provider"],
        "model": state.settings["model"],
    })
    playbook = active_playbook(state)
    if playbook:
        state.messages.append({
            "type": "assistant_text",
            "text": f"Playbook still active: {playbook.name}. {playbook_guidance_summary(playbook)}",
        })
    state.messages.append({
        "type": "suggested_actions",
        "title": f"Continue this {playbook.name} investigation" if playbook else "Continue this investigation",
        "items": state.suggested_actions,
    })


def export_transcript_markdown(state: SessionState) -> str:
    summary = summary_from_context(state.context)
    playbook = active_playbook(state)
    lines = [
        "# SharkBot Investigation Export",
        "",
        f"- Session ID: `{state.session_id}`",
        f"- Exported at: `{datetime.now().isoformat(timespec='seconds')}`",
        f"- Selected backend: `{state.settings.get('provider', '')} / {state.settings.get('model', '')}`",
        f"- Active playbook: `{playbook.name if playbook else 'generic'}`",
        "",
        "## Current Packet Context",
        "",
        f"- Frame: `{summary['frame']}`",
        f"- Protocol: `{summary['protocol']}`",
        f"- Source: `{summary['source']}`",
        f"- Destination: `{summary['destination']}`",
        f"- Selected IP: `{summary['selected_ip']}`",
        f"- Selected MAC: `{summary['selected_mac']}`",
        f"- Current filter: `{summary['current_filter'] or '(empty)'}`",
        "",
        "## Transcript",
        "",
    ]

    for message in state.messages:
        message_type = message.get("type")
        if message_type == "system_notice":
            lines.extend(["### System", "", message.get("text", ""), ""])
        elif message_type == "assistant_text":
            lines.extend(["### Assistant", "", message.get("text", ""), ""])
        elif message_type in {"user_message", "user_choice"}:
            lines.extend(["### You", "", message.get("text", ""), ""])
        elif message_type == "packet_summary":
            packet = message.get("summary", {})
            lines.extend(
                [
                    "### Packet Context",
                    "",
                    f"- Frame: `{packet.get('frame', '')}`",
                    f"- Protocol: `{packet.get('protocol', '')}`",
                    f"- Source: `{packet.get('source', '')}`",
                    f"- Destination: `{packet.get('destination', '')}`",
                    f"- Selected IP: `{packet.get('selected_ip', '')}`",
                    f"- Selected MAC: `{packet.get('selected_mac', '')}`",
                    "",
                ]
            )
        elif message_type == "clarification":
            lines.extend(["### Clarification", "", message.get("question", ""), ""])
            options = message.get("options") or []
            if options:
                lines.append("Options:")
                lines.extend([f"- {item.get('label', item.get('id', ''))}" for item in options])
                lines.append("")
        elif message_type == "filter_result":
            lines.extend(
                [
                    f"### {message.get('title') or 'Filter Result'}",
                    "",
                    message.get("explanation", ""),
                    "",
                    "```wireshark",
                    message.get("filter", ""),
                    "```",
                    "",
                ]
            )
            if message.get("source_note"):
                lines.extend([message["source_note"], ""])
        elif message_type == "explanation":
            lines.extend([f"### {message.get('title') or 'Explanation'}", "", message.get("text", ""), ""])
            if message.get("source_note"):
                lines.extend([message["source_note"], ""])
        elif message_type == "suggested_actions":
            lines.extend([f"### {message.get('title') or 'Suggested Actions'}", ""])
            lines.extend([f"- {item.get('label', '')}" for item in message.get("items") or []])
            lines.append("")
        elif message_type == "error":
            lines.extend(["### Error", "", message.get("text", ""), ""])
    return "\n".join(lines).strip() + "\n"


@app.get("/")
def home():
    return "SharkBot receiver running"


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


@app.post("/api/session/<session_id>/context")
def api_session_context(session_id: str):
    try:
        state = get_state(session_id)
    except KeyError:
        return jsonify(session_missing_payload(session_id)), 404
    payload = request.get_json(force=True, silent=True) or {}
    context = payload.get("context") or payload
    if not context:
        return jsonify({"error": "Missing context"}), 400
    source_label = str(context.get("launch_source") or payload.get("source_label") or "Wireshark").replace("_", " ")
    apply_context_update(state, context, source_label=source_label)
    return jsonify({"session_id": state.session_id, "web_url": session_web_url(state.session_id), "state": response_payload(state)})


@app.get("/api/session/<session_id>/export")
def api_session_export(session_id: str):
    try:
        state = get_state(session_id)
    except KeyError:
        return jsonify(session_missing_payload(session_id)), 404
    filename = f"sharkbot-investigation-{session_id}.md"
    body = export_transcript_markdown(state)
    return Response(
        body,
        mimetype="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
    state.suggested_actions = guided_next_steps(state)
    state.messages = initial_messages(state)
    state.pending = None
    state.resolved = {}
    state.applied_filters = []
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
    state.applied_filters = []
    state.suggested_actions = guided_next_steps(state)
    state.messages = initial_messages(state)
    return jsonify(response_payload(state))


@app.post("/api/session/<session_id>/playbook")
def api_session_playbook(session_id: str):
    state = get_state(session_id)
    payload = request.get_json(force=True, silent=True) or {}
    if backend_selection_required(state):
        state.messages.append({"type": "error", "text": "Set the background AI backend first."})
        return jsonify(response_payload(state))
    playbook_id = (payload.get("playbook_id") or "").strip()
    if not playbook_id:
        apply_playbook_selection(state, None)
        return jsonify(response_payload(state))
    if playbook_id not in PLAYBOOKS:
        return jsonify({"error": "Unknown playbook"}), 400
    apply_playbook_selection(state, playbook_id)
    return jsonify(response_payload(state))


@app.post("/api/session/<session_id>/action")
def api_session_action(session_id: str):
    state = get_state(session_id)
    payload = request.get_json(force=True, silent=True) or {}
    kind = (payload.get("kind") or "").strip()
    label = (payload.get("label") or "").strip()
    prompt = (payload.get("prompt") or "").strip()
    note = (payload.get("note") or "").strip()
    origin_prompt = (payload.get("origin_prompt") or "").strip()
    if backend_selection_required(state):
        state.messages.append({"type": "error", "text": "Set the background AI backend first."})
        return jsonify(response_payload(state))
    user_text = label or prompt or "Action"
    if kind == "playbook_open":
        state.messages.append({"type": "user_choice", "text": user_text})
        state.messages.append(playbook_selector_message(state))
        return jsonify(response_payload(state))
    if kind == "playbook_clear":
        state.messages.append({"type": "user_choice", "text": user_text})
        apply_playbook_selection(state, None)
        return jsonify(response_payload(state))
    if kind == "filter_explain_ai":
        state.messages.append({"type": "user_choice", "text": user_text})
        state.messages.append(explain_filter_with_ai(state, prompt))
        return jsonify(response_payload(state))
    if kind == "playbook_ai_recommendation":
        state.messages.append({"type": "user_choice", "text": user_text})
        message = explain_packet(state, prompt)
        message["suggested_actions"] = []
        state.messages.append(message)
        playbook = active_playbook(state)
        if playbook:
            next_steps = playbook_steps_after_ai_guidance(state, playbook)
            state.suggested_actions = next_steps
            state.messages.append({
                "type": "suggested_actions",
                "title": f"After the AI recommendation for {playbook.name}",
                "text": playbook_ai_handoff_text(state, playbook),
                "items": next_steps,
            })
        return jsonify(response_payload(state))
    if kind == "filter_applied":
        state.messages.append({"type": "user_choice", "text": user_text})
        if note:
            state.messages.append({"type": "user_message", "text": f"After applying the filter: {note}"})
        playbook = active_playbook(state)
        if not playbook:
            state.messages.append({
                "type": "assistant_text",
                "text": "No playbook is active, so SharkBot will stay in generic packet-analysis mode.",
            })
            return jsonify(response_payload(state))
        state.context["current_filter"] = prompt
        state.applied_filters.append({"filter": prompt, "note": note, "origin_prompt": origin_prompt})
        next_steps = playbook_steps_after_filter(state, playbook, prompt, origin_prompt=origin_prompt)
        state.suggested_actions = next_steps
        state.messages.append({
            "type": "assistant_text",
            "text": playbook_filter_checkpoint_message(state, playbook, prompt, note=note),
        })
        state.messages.append({
            "type": "suggested_actions",
            "title": f"Next steps for {playbook.name}",
            "text": (
                playbook_step_reason(state, playbook, prompt, next_steps[0])
                if next_steps
                else playbook_stage_text(playbook)
            ),
            "items": next_steps,
        })
        return jsonify(response_payload(state))
    if not prompt:
        return jsonify(response_payload(state))
    state.messages.append({"type": "user_choice", "text": user_text})
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
