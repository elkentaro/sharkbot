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
    investigation_goal: str = ""
    investigation_lane: str = "freeform"
    handrail: Dict[str, Any] = field(default_factory=dict)
    guided_history: List[Dict[str, Any]] = field(default_factory=list)
    user_observations: List[Dict[str, Any]] = field(default_factory=list)
    reference_assets_enabled: bool = True
    baseline_snapshot: Dict[str, Any] = field(default_factory=dict)


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

WIFI_SUBTYPE_LABELS = {
    "0x00": "Association request",
    "0x01": "Association response",
    "0x02": "Reassociation request",
    "0x03": "Reassociation response",
    "0x04": "Probe request",
    "0x05": "Probe response",
    "0x08": "Beacon",
    "0x0A": "Disassociation",
    "0x0B": "Authentication",
    "0x0C": "Deauthentication",
    "0x0D": "Action frame",
    "0x18": "Block ACK request",
    "0x19": "Block ACK",
    "0x1A": "Power save poll",
    "0x1B": "Request to send",
    "0x1C": "Clear to send",
    "0x1D": "ACK",
    "0x1E": "Contention free period end",
    "0x24": "NULL data",
    "0x28": "QoS data",
    "0x2C": "Null QoS data",
}

WIFI_ASSOC_SUBTYPE_FILTER = "(wlan.fc.type_subtype == 0x00 || wlan.fc.type_subtype == 0x01 || wlan.fc.type_subtype == 0x02 || wlan.fc.type_subtype == 0x03)"
WIFI_AUTH_ASSOC_SUBTYPE_FILTER = f"({WIFI_ASSOC_SUBTYPE_FILTER[1:-1]} || wlan.fc.type_subtype == 0x0B)"
WIFI_DEAUTH_SUBTYPE_FILTER = "(wlan.fc.type_subtype == 0x0A || wlan.fc.type_subtype == 0x0C)"
WIFI_PROBE_SUBTYPE_FILTER = "(wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x05)"
TCP_SYN_FILTER = "tcp.flags.syn == 1"
TCP_ZERO_WINDOW_FILTER = "tcp.analysis.zero_window"
ARP_ONLY_FILTER = "arp"
ICMP_ONLY_FILTER = "icmp"
DHCP_ONLY_FILTER = "dhcp || bootp"
IP_FRAGMENT_FILTER = "(ip.flags.mf == 1 || ip.frag_offset > 0)"
HTTP_RESPONSE_FILTER = "http.response"
HTTP_REDIRECT_FILTER = "(http.response.code >= 300 && http.response.code < 400)"

HANDRAIL_OBSERVATION_OPTIONS = [
    {"id": "helped", "label": "This helped"},
    {"id": "too_much_noise", "label": "Too much noise"},
    {"id": "nothing_useful", "label": "I saw nothing useful"},
    {"id": "unexpected", "label": "I saw something unexpected"},
    {"id": "different_view", "label": "I used a different Wireshark view"},
]

HANDRAIL_OBSERVATION_LABELS = {item["id"]: item["label"] for item in HANDRAIL_OBSERVATION_OPTIONS}

REFERENCE_ASSET_DEFS = {
    "conversations": {
        "id": "conversations",
        "title": "Statistics > Conversations",
        "path": "static/guides/conversations/reference.svg",
        "caption": "Use Conversations to find the pair that dominates the issue before you chase individual packets.",
    },
    "endpoints": {
        "id": "endpoints",
        "title": "Statistics > Endpoints",
        "path": "static/guides/endpoints/reference.svg",
        "caption": "Use Endpoints to identify which host or device is actually carrying the traffic you care about.",
    },
    "protocol_hierarchy": {
        "id": "protocol_hierarchy",
        "title": "Statistics > Protocol Hierarchy",
        "path": "static/guides/protocol-hierarchy/reference.svg",
        "caption": "Use Protocol Hierarchy to confirm whether you are chasing the right protocol before narrowing further.",
    },
    "expert_information": {
        "id": "expert_information",
        "title": "Analyze > Expert Information",
        "path": "static/guides/expert-info/reference.svg",
        "caption": "Use Expert Information to surface warnings and anomalies before guessing at the root cause.",
    },
    "follow_stream": {
        "id": "follow_stream",
        "title": "Analyze > Follow > TCP Stream",
        "path": "static/guides/follow-stream/reference.svg",
        "caption": "Use Follow Stream to see the full client/server exchange instead of one packet at a time.",
    },
    "io_graphs": {
        "id": "io_graphs",
        "title": "Statistics > IO Graphs",
        "path": "static/guides/io-graphs/reference.svg",
        "caption": "Use IO Graphs to see whether spikes, retries, or suspicious bursts cluster in time before chasing individual packets.",
    },
    "flow_graph": {
        "id": "flow_graph",
        "title": "Statistics > Flow Graph",
        "path": "static/guides/flow-graph/reference.svg",
        "caption": "Use Flow Graph to see where request and response direction changes or stalls across the exchange.",
    },
    "packet_lengths": {
        "id": "packet_lengths",
        "title": "Statistics > Packet Lengths",
        "path": "static/guides/packet-lengths/reference.svg",
        "caption": "Use Packet Lengths to compare whether the traffic is dominated by small control frames, normal payloads, or unusual size clusters.",
    },
    "tcp_rtt_graph": {
        "id": "tcp_rtt_graph",
        "title": "Statistics > TCP Stream Graphs > Round Trip Time",
        "path": "static/guides/tcp-rtt/reference.svg",
        "caption": "Use the RTT graph to see whether latency spikes or stalls align with the conversation you are troubleshooting.",
    },
}


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def canonical_wlan_subtype(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return f"0x{int(text, 0):02X}"
    except (TypeError, ValueError):
        lowered = text.lower()
        return lowered if lowered.startswith("0x") else text


def wlan_subtype_label(value: Any) -> str:
    return WIFI_SUBTYPE_LABELS.get(canonical_wlan_subtype(value), "")


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
    if context.get("dns_name") or "dns" in proto:
        return PLAYBOOKS.get("dns_investigation")
    if context.get("http_host") or "http" in proto:
        return PLAYBOOKS.get("web_application_issue")
    if context.get("tcp_srcport") or context.get("tcp_dstport") or "tcp" in proto:
        return PLAYBOOKS.get("tcp_issue")
    if "btle" in proto or "ble" in proto or "bluetooth" in proto:
        return PLAYBOOKS.get("btle_investigation")
    if proto in {"wlan", "wifi", "wi-fi", "802.11"} or "wlan" in proto or "wifi" in proto or "802.11" in proto:
        return PLAYBOOKS.get("wifi_investigation")
    return PLAYBOOKS.get("suspicious_traffic")


def recommended_playbook_payload(state: SessionState) -> Optional[Dict[str, Any]]:
    playbook = recommended_playbook(state)
    return playbook.payload() if playbook else None


def baseline_payload(state: SessionState) -> Optional[Dict[str, Any]]:
    return state.baseline_snapshot or None


def investigation_goal_text(state: SessionState) -> str:
    playbook = active_playbook(state)
    if not playbook:
        return "Understand the selected packet and choose the next useful Wireshark view."
    if playbook.playbook_id == "tcp_issue":
        return "Find where the TCP exchange is stalling before drilling into individual packets."
    if playbook.playbook_id == "dns_investigation":
        return "Confirm whether the DNS issue is query scope, response quality, or recursion delay."
    if playbook.playbook_id == "web_application_issue":
        return "Determine whether the web issue is in the HTTP exchange, the host pair, or the application response."
    if playbook.playbook_id == "suspicious_traffic":
        return "Scope the suspicious behavior before deciding whether it is benign, broken, or worth escalation."
    if playbook.playbook_id == "wifi_investigation":
        return "Identify the wireless role, exchange, or failure point before narrowing further."
    if playbook.playbook_id == "btle_investigation":
        return "Identify the BLE peers and exchange type before narrowing the issue further."
    return f"Use the {playbook.name} playbook to narrow the investigation."


def current_timestamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


def update_guided_history(
    state: SessionState,
    step: Dict[str, Any],
    *,
    status: str,
    observation: str = "",
    note: str = "",
) -> None:
    if not step:
        return
    entry = {
        "step_id": step.get("step_id") or step.get("id") or "",
        "kind": step.get("kind") or "",
        "title": step.get("title") or step.get("label") or "",
        "status": status,
        "observation": observation,
        "note": note,
        "timestamp": current_timestamp(),
    }
    for idx in range(len(state.guided_history) - 1, -1, -1):
        existing = state.guided_history[idx]
        if existing.get("step_id") == entry["step_id"]:
            state.guided_history[idx] = {**existing, **entry}
            return
    state.guided_history.append(entry)


def latest_user_observation(state: SessionState) -> Optional[Dict[str, Any]]:
    return state.user_observations[-1] if state.user_observations else None


def handrail_result_actions(step_id: str) -> List[Dict[str, str]]:
    return [
        {
            "id": f"{step_id}_{item['id']}",
            "label": item["label"],
            "kind": "guided_step_result",
            "step_id": step_id,
            "result": item["id"],
        }
        for item in HANDRAIL_OBSERVATION_OPTIONS
    ]


def handrail_primary_actions(step: Dict[str, Any]) -> List[Dict[str, str]]:
    step_id = step.get("step_id") or step.get("id") or "guided_step"
    return [
        {
            "id": f"{step_id}_start",
            "label": "Do this step",
            "kind": "guided_step_start",
            "step_id": step_id,
        },
        {
            "id": f"{step_id}_skip",
            "label": "Skip",
            "kind": "guided_step_skip",
            "step_id": step_id,
        },
        {
            "id": f"{step_id}_alternate",
            "label": "Ask for another approach",
            "kind": "guided_step_alternate",
            "step_id": step_id,
        },
        {
            "id": f"{step_id}_freeform",
            "label": "Continue free-form",
            "kind": "guided_step_freeform",
            "step_id": step_id,
        },
    ]


def reference_asset_id_for_step(kind: str) -> str:
    return {
        "open_conversations": "conversations",
        "open_endpoints": "endpoints",
        "open_protocol_hierarchy": "protocol_hierarchy",
        "open_expert_information": "expert_information",
        "follow_stream": "follow_stream",
        "open_io_graph": "io_graphs",
        "open_flow_graph": "flow_graph",
        "open_packet_lengths": "packet_lengths",
        "open_tcp_rtt_graph": "tcp_rtt_graph",
    }.get(kind, "")


def reference_asset_payload_by_id(asset_id: str) -> Optional[Dict[str, str]]:
    asset = REFERENCE_ASSET_DEFS.get(asset_id)
    if not asset:
        return None
    configured_path = asset["path"]
    root, ext = os.path.splitext(configured_path)
    candidate_paths = [f"{root}.png"] if ext.lower() == ".svg" else []
    candidate_paths.append(configured_path)
    resolved_path = next((path for path in candidate_paths if os.path.exists(os.path.join(APP_ROOT, path))), "")
    if not resolved_path:
        return None
    return {
        "id": asset["id"],
        "title": asset["title"],
        "url": "/" + resolved_path.replace(os.sep, "/"),
        "caption": asset["caption"],
    }


def with_reference_asset(step: Dict[str, Any]) -> Dict[str, Any]:
    asset_id = reference_asset_id_for_step(step.get("kind") or "")
    asset = reference_asset_payload_by_id(asset_id) if asset_id else None
    if not asset:
        return step
    enriched = dict(step)
    enriched["reference_image"] = asset["url"]
    enriched["reference_title"] = asset["title"]
    enriched["reference_caption"] = asset["caption"]
    return enriched


GUIDANCE_TEMPLATE_PATTERN = re.compile(r"{([a-z0-9_]+)}")
HANDRAIL_STEP_STRING_FIELDS = (
    "step_id",
    "title",
    "kind",
    "rationale",
    "instructions",
    "look_for",
    "expected_outcome",
    "common_mistake",
    "alternate_path",
)


def guidance_context_flags(state: SessionState) -> set[str]:
    context = state.context
    proto = normalize(str(context.get("packet_protocol") or context.get("protocol_hint") or ""))
    flags: set[str] = set()
    wlan_subtype = canonical_wlan_subtype(protocol_detail(context, "wlan_type_subtype", "wlan", "type_subtype"))
    if context.get("current_filter"):
        flags.add("has_current_filter")
    if context.get("selected_ip") or context.get("selected_ipv6"):
        flags.add("has_selected_ip")
    if context.get("selected_mac"):
        flags.add("has_selected_mac")
    if preferred_device_mac(context):
        flags.add("has_preferred_device_mac")
    if protocol_detail(context, "dns_name", "dns", "query_name"):
        flags.add("has_dns_name")
    if context.get("tcp_srcport") or context.get("tcp_dstport"):
        flags.add("has_tcp_ports")
    if context.get("http_host"):
        flags.add("has_http_host")
    if protocol_detail(context, "http_response_code", "http", "response_code"):
        flags.add("has_http_response_code")
    if protocol_detail(context, "dns_response_code", "dns", "response_code"):
        flags.add("has_dns_response_code")
    if context.get("arp_opcode") or proto == "arp":
        flags.add("is_arp_context")
    if context.get("icmp_type") or context.get("icmp_code") or proto == "icmp":
        flags.add("is_icmp_context")
    if proto == "dhcp" or "bootp" in proto:
        flags.add("is_dhcp_context")
    if context.get("dns_name") or proto == "dns":
        flags.add("is_dns_context")
    if context.get("http_host") or proto == "http":
        flags.add("is_http_context")
    if proto in {"wlan", "wifi", "wi-fi", "802.11"} or "wlan" in proto or "wifi" in proto or "802.11" in proto:
        flags.add("is_wireless_context")
    if protocol_detail(context, "wlan_bssid", "wlan", "bssid"):
        flags.add("has_wlan_bssid")
    if protocol_detail(context, "wlan_ssid", "wlan", "ssid"):
        flags.add("has_wlan_ssid")
    if protocol_detail(context, "wlan_type_subtype", "wlan", "type_subtype"):
        flags.add("has_wlan_type_subtype")
    if wlan_subtype == "0x08":
        flags.add("is_wlan_beacon")
    if wlan_subtype in {"0x04", "0x05"}:
        flags.add("is_wlan_probe")
    if wlan_subtype in {"0x00", "0x01", "0x02", "0x03"}:
        flags.add("is_wlan_assoc")
    if wlan_subtype in {"0x00", "0x01", "0x02", "0x03", "0x0B"}:
        flags.add("is_wlan_auth_assoc")
    if wlan_subtype in {"0x0A", "0x0C"}:
        flags.add("is_wlan_deauth")
    if protocol_detail(context, "wlan_channel", "wlan", "channel"):
        flags.add("has_wlan_channel")
    if any(
        protocol_detail(context, key, "wlan", nested)
        for key, nested in [
            ("wlan_channel", "channel"),
            ("wlan_signal_dbm", "signal_dbm"),
            ("wlan_data_rate", "data_rate"),
        ]
    ):
        flags.add("has_wlan_radio_metrics")
    if "btle" in proto or "ble" in proto or "bluetooth" in proto:
        flags.add("is_btle_context")
    return flags


def guidance_template_values(state: SessionState) -> Dict[str, str]:
    context = state.context
    dns_name = protocol_detail(context, "dns_name", "dns", "query_name")
    http_host = protocol_detail(context, "http_host", "http", "host")
    selected_ip = first_nonempty(context.get("selected_ip"), context.get("selected_ipv6"))
    selected_ip_filter = ""
    if selected_ip:
        selected_ip_filter = f"{'ipv6' if ':' in str(selected_ip) else 'ip'}.addr == {selected_ip}"
    preferred_mac = preferred_device_mac(context)
    ble_mac = preferred_mac or protocol_detail(context, "btcommon_addr", "btle", "address")
    return {
        "current_filter": str(context.get("current_filter") or ""),
        "selected_ip": selected_ip,
        "selected_ip_filter": selected_ip_filter or "ip.addr == <selected-ip>",
        "selected_mac": str(context.get("selected_mac") or ""),
        "preferred_device_mac": preferred_mac,
        "dns_name": dns_name,
        "dns_query_filter": f'dns.qry.name == "{dns_name}"' if dns_name else "dns",
        "dns_resolver_filter": f"dns && {selected_ip_filter}" if selected_ip_filter else "dns && ip.addr == <resolver-ip>",
        "http_host_filter": f'http.host == "{http_host}"' if http_host else 'http.host == "<http-host>"',
        "wireless_device_filter": f"wlan.addr == {preferred_mac}" if preferred_mac else "wlan.addr == <wireless-device-mac>",
        "wireless_bssid_filter": (
            f"wlan.bssid == {protocol_detail(context, 'wlan_bssid', 'wlan', 'bssid')}"
            if protocol_detail(context, "wlan_bssid", "wlan", "bssid")
            else "wlan.bssid == <bssid>"
        ),
        "wireless_ssid_filter": (
            f'wlan.ssid == "{protocol_detail(context, "wlan_ssid", "wlan", "ssid")}"'
            if protocol_detail(context, "wlan_ssid", "wlan", "ssid")
            else 'wlan.ssid == "<ssid>"'
        ),
        "wireless_management_filter": "wlan.fc.type == 0",
        "wireless_control_filter": "wlan.fc.type == 1",
        "wireless_data_filter": "wlan.fc.type == 2",
        "wireless_beacon_filter": "wlan.fc.type_subtype == 0x08",
        "wireless_probe_filter": WIFI_PROBE_SUBTYPE_FILTER,
        "wireless_assoc_filter": WIFI_ASSOC_SUBTYPE_FILTER,
        "wireless_auth_assoc_filter": WIFI_AUTH_ASSOC_SUBTYPE_FILTER,
        "wireless_deauth_filter": WIFI_DEAUTH_SUBTYPE_FILTER,
        "wireless_channel_filter": (
            f"wlan_radio.channel == {protocol_detail(context, 'wlan_channel', 'wlan', 'channel')}"
            if protocol_detail(context, "wlan_channel", "wlan", "channel")
            else "wlan_radio.channel == <channel>"
        ),
        "tcp_syn_filter": TCP_SYN_FILTER,
        "tcp_zero_window_filter": TCP_ZERO_WINDOW_FILTER,
        "arp_only_filter": ARP_ONLY_FILTER,
        "icmp_only_filter": ICMP_ONLY_FILTER,
        "dhcp_only_filter": DHCP_ONLY_FILTER,
        "ip_fragment_filter": IP_FRAGMENT_FILTER,
        "http_response_filter": HTTP_RESPONSE_FILTER,
        "http_redirect_filter": HTTP_REDIRECT_FILTER,
        "ble_device_filter": f"btcommon.addr == {ble_mac}" if ble_mac else "btcommon.addr == <ble-device-address>",
    }


def render_guidance_text(value: str, state: SessionState) -> str:
    if not value:
        return ""
    template_values = guidance_template_values(state)
    return GUIDANCE_TEMPLATE_PATTERN.sub(lambda match: template_values.get(match.group(1), match.group(0)), value)


def render_handrail_step_definition(state: SessionState, definition: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: render_guidance_text(str(definition.get(key) or ""), state)
        for key in HANDRAIL_STEP_STRING_FIELDS
        if definition.get(key)
    }


def rule_matches(
    state: SessionState,
    rule: Dict[str, Any],
    *,
    observation: str = "",
    filter_tags: Optional[set[str]] = None,
) -> bool:
    if rule.get("observation") and rule.get("observation") != observation:
        return False
    if "current_filter_present" in rule:
        current_filter_present = bool(state.context.get("current_filter"))
        if current_filter_present != bool(rule.get("current_filter_present")):
            return False

    flags = guidance_context_flags(state)
    flags_all = set(rule.get("context_flags_all") or [])
    if flags_all and not flags_all.issubset(flags):
        return False
    flags_any = set(rule.get("context_flags_any") or [])
    if flags_any and not flags.intersection(flags_any):
        return False

    if filter_tags is not None:
        tags_any = set(rule.get("filter_tags_any") or [])
        if tags_any and not filter_tags.intersection(tags_any):
            return False
        tags_all = set(rule.get("filter_tags_all") or [])
        if tags_all and not tags_all.issubset(filter_tags):
            return False
        tags_none = set(rule.get("filter_tags_none") or [])
        if tags_none and filter_tags.intersection(tags_none):
            return False

    return True


def resolve_guided_action_rule(
    state: SessionState,
    rules: List[Dict[str, Any]],
    *,
    filter_tags: Optional[set[str]] = None,
) -> Optional[Dict[str, str]]:
    for rule in rules:
        if not rule_matches(state, rule, filter_tags=filter_tags):
            continue
        label = render_guidance_text(str(rule.get("label") or ""), state)
        prompt = render_guidance_text(str(rule.get("prompt") or ""), state)
        if not label or not prompt:
            continue
        return {
            "id": str(rule.get("id") or f"guided_{label.lower().replace(' ', '_')}"),
            "label": label,
            "prompt": prompt,
            **({"kind": str(rule.get("kind") or "")} if rule.get("kind") else {}),
        }
    return None


def resolve_handrail_step(state: SessionState, playbook: Playbook) -> Dict[str, Any]:
    observation = str((latest_user_observation(state) or {}).get("result") or "")
    for rule in playbook.handrail_rules:
        if rule_matches(state, rule, observation=observation):
            return render_handrail_step_definition(state, rule)
    return {}


def reference_assets_payload(state: SessionState) -> Dict[str, Any]:
    items: List[Dict[str, str]] = []
    current_step = (state.handrail or {}).get("current_step") or {}
    asset_id = reference_asset_id_for_step(current_step.get("kind") or "")
    asset = reference_asset_payload_by_id(asset_id) if asset_id else None
    if asset:
        items.append(asset)
    return {
        "enabled": bool(state.reference_assets_enabled),
        "items": items,
    }


def build_handrail(state: SessionState) -> Dict[str, Any]:
    playbook = active_playbook(state)
    if not playbook:
        return {}

    current_step = resolve_handrail_step(state, playbook)
    if not current_step:
        return {}
    alternates = [render_handrail_step_definition(state, item) for item in playbook.handrail_alternates]
    reason = playbook.handrail_reason

    current_step = with_reference_asset(current_step)
    step_id = current_step["step_id"]
    history_entry = next((item for item in reversed(state.guided_history) if item.get("step_id") == step_id), None)
    current_step = {
        **current_step,
        "status": history_entry.get("status", "ready") if history_entry else "ready",
        "actions": handrail_primary_actions(current_step),
        "observation_actions": handrail_result_actions(step_id),
    }
    alternates = rank_playbook_guidance_items(playbook, [with_reference_asset(item) for item in alternates])

    latest = latest_user_observation(state)
    return {
        "playbook_bias": playbook.playbook_id,
        "reason": reason,
        "current_step": current_step,
        "alternates": alternates,
        "latest_observation": latest,
    }


def refresh_handrail_state(state: SessionState) -> None:
    state.investigation_goal = state.investigation_goal or investigation_goal_text(state)
    state.investigation_lane = state.investigation_lane or ("guided" if active_playbook(state) else "freeform")
    state.handrail = build_handrail(state)


def refresh_guidance_state(state: SessionState) -> None:
    state.suggested_actions = guided_next_steps(state)
    refresh_handrail_state(state)


def reset_investigation_state(state: SessionState) -> None:
    state.guided_history = []
    state.user_observations = []
    state.investigation_goal = investigation_goal_text(state)
    state.investigation_lane = "guided" if active_playbook(state) else "freeform"
    state.handrail = {}


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


def first_nonempty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def protocol_detail(context: Dict[str, Any], flat_key: str, *path: str) -> str:
    flat_value = first_nonempty(context.get(flat_key))
    if flat_value:
        return flat_value
    current: Any = context.get("protocol_details") or {}
    for key in path:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return first_nonempty(current)


def normalize_context_payload(context: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(context or {})
    details = normalized.get("protocol_details")
    if not isinstance(details, dict):
        details = {}
    else:
        details = {key: value for key, value in details.items() if isinstance(value, dict)}

    tcp = dict(details.get("tcp") or {})
    udp = dict(details.get("udp") or {})
    dns = dict(details.get("dns") or {})
    http = dict(details.get("http") or {})
    tls = dict(details.get("tls") or {})
    icmp = dict(details.get("icmp") or {})
    arp = dict(details.get("arp") or {})
    wlan = dict(details.get("wlan") or {})
    btle = dict(details.get("btle") or {})

    def promote(flat_key: str, target: Dict[str, Any], nested_key: str) -> None:
        value = first_nonempty(normalized.get(flat_key), target.get(nested_key))
        if value:
            normalized[flat_key] = value
            target[nested_key] = value

    promote("tcp_srcport", tcp, "srcport")
    promote("tcp_dstport", tcp, "dstport")
    promote("tcp_stream", tcp, "stream")
    promote("tcp_flags", tcp, "flags")
    promote("tcp_expert", tcp, "expert")
    promote("udp_srcport", udp, "srcport")
    promote("udp_dstport", udp, "dstport")
    promote("dns_name", dns, "query_name")
    promote("dns_query_type", dns, "query_type")
    promote("dns_response_code", dns, "response_code")
    promote("dns_answer_count", dns, "answer_count")
    promote("http_host", http, "host")
    promote("http_method", http, "method")
    promote("http_request_uri", http, "request_uri")
    promote("http_response_code", http, "response_code")
    promote("tls_sni", tls, "server_name")
    promote("tls_handshake_type", tls, "handshake_type")
    promote("tls_record_version", tls, "record_version")
    promote("icmp_type", icmp, "type")
    promote("icmp_code", icmp, "code")
    promote("arp_opcode", arp, "opcode")
    promote("arp_src_proto_ipv4", arp, "src_proto_ipv4")
    promote("arp_dst_proto_ipv4", arp, "dst_proto_ipv4")
    promote("arp_src_hw_mac", arp, "src_hw_mac")
    promote("arp_dst_hw_mac", arp, "dst_hw_mac")
    promote("wlan_sa", wlan, "sa")
    promote("wlan_da", wlan, "da")
    promote("wlan_ra", wlan, "ra")
    promote("wlan_ta", wlan, "ta")
    promote("wlan_bssid", wlan, "bssid")
    promote("wlan_ssid", wlan, "ssid")
    promote("wlan_type_subtype", wlan, "type_subtype")
    promote("wlan_channel", wlan, "channel")
    promote("wlan_signal_dbm", wlan, "signal_dbm")
    promote("wlan_data_rate", wlan, "data_rate")
    promote("btcommon_addr", btle, "address")
    promote("btatt_opcode", btle, "att_opcode")
    promote("btatt_handle", btle, "att_handle")
    promote("btl2cap_cid", btle, "l2cap_cid")

    normalized["protocol_details"] = {
        "tcp": tcp,
        "udp": udp,
        "dns": dns,
        "http": http,
        "tls": tls,
        "icmp": icmp,
        "arp": arp,
        "wlan": wlan,
        "btle": btle,
    }

    normalized["eth_src"] = first_nonempty(normalized.get("eth_src"), normalized.get("wlan_sa"), normalized.get("wlan_ta"))
    normalized["eth_dst"] = first_nonempty(normalized.get("eth_dst"), normalized.get("wlan_da"), normalized.get("wlan_ra"))
    normalized["selected_ip"] = first_nonempty(normalized.get("selected_ip"), normalized.get("ip_src"))
    normalized["selected_ipv6"] = first_nonempty(normalized.get("selected_ipv6"), normalized.get("ipv6_src"))
    normalized["selected_mac"] = first_nonempty(
        normalized.get("selected_mac"),
        normalized.get("wlan_sa"),
        normalized.get("wlan_ta"),
        normalized.get("btcommon_addr"),
        normalized.get("eth_src"),
    )
    normalized["payload_version"] = first_nonempty(
        normalized.get("payload_version"),
        normalized.get("context_payload_version"),
        "1.8.0" if any(normalized.get(key) for key in ["tcp_stream", "dns_query_type", "http_method", "tls_sni", "icmp_type", "arp_opcode", "wlan_bssid", "btcommon_addr"]) or any(details.values()) else "",
    )
    normalized["context_schema"] = first_nonempty(
        normalized.get("context_schema"),
        "protocol_native_v1" if normalized.get("payload_version") else "",
    )
    return normalized


def infer_packet_protocol(context: Dict[str, Any]) -> str:
    candidates = [
        context.get("packet_protocol"),
        context.get("protocol_identity"),
        context.get("protocol_hint"),
        "wlan" if any(context.get(key) for key in ["wlan_sa", "wlan_da", "wlan_ra", "wlan_ta", "wlan_bssid", "wlan_ssid"]) else None,
        "btle" if context.get("btcommon_addr") or protocol_detail(context, "btcommon_addr", "btle", "address") else None,
        "dns" if context.get("dns_name") else None,
        "http" if context.get("http_host") else None,
        "tls" if context.get("tls_sni") or protocol_detail(context, "tls_sni", "tls", "server_name") else None,
        "icmp" if context.get("icmp_type") or context.get("icmp_code") else None,
        "arp" if context.get("arp_opcode") else None,
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


def protocol_summary_details(context: Dict[str, Any]) -> str:
    proto = infer_packet_protocol(context).lower()
    if proto == "dns":
        parts = []
        if protocol_detail(context, "dns_name", "dns", "query_name"):
            parts.append(f"Query {protocol_detail(context, 'dns_name', 'dns', 'query_name')}")
        if protocol_detail(context, "dns_query_type", "dns", "query_type"):
            parts.append(f"type {protocol_detail(context, 'dns_query_type', 'dns', 'query_type')}")
        if protocol_detail(context, "dns_response_code", "dns", "response_code"):
            parts.append(f"rcode {protocol_detail(context, 'dns_response_code', 'dns', 'response_code')}")
        if protocol_detail(context, "dns_answer_count", "dns", "answer_count"):
            parts.append(f"answers {protocol_detail(context, 'dns_answer_count', 'dns', 'answer_count')}")
        return " · ".join(parts)
    if proto == "http":
        parts = []
        method = protocol_detail(context, "http_method", "http", "method")
        host = protocol_detail(context, "http_host", "http", "host")
        uri = protocol_detail(context, "http_request_uri", "http", "request_uri")
        code = protocol_detail(context, "http_response_code", "http", "response_code")
        if method or host or uri:
            request = " ".join(part for part in [method, uri] if part).strip()
            if host:
                request = f"{request} @ {host}".strip()
            if request:
                parts.append(request)
        if code:
            parts.append(f"response {code}")
        return " · ".join(parts)
    if proto == "tls":
        parts = []
        if protocol_detail(context, "tls_sni", "tls", "server_name"):
            parts.append(f"SNI {protocol_detail(context, 'tls_sni', 'tls', 'server_name')}")
        if protocol_detail(context, "tls_handshake_type", "tls", "handshake_type"):
            parts.append(f"handshake {protocol_detail(context, 'tls_handshake_type', 'tls', 'handshake_type')}")
        if protocol_detail(context, "tls_record_version", "tls", "record_version"):
            parts.append(f"version {protocol_detail(context, 'tls_record_version', 'tls', 'record_version')}")
        return " · ".join(parts)
    if proto == "tcp":
        parts = []
        if protocol_detail(context, "tcp_stream", "tcp", "stream"):
            parts.append(f"stream {protocol_detail(context, 'tcp_stream', 'tcp', 'stream')}")
        if protocol_detail(context, "tcp_flags", "tcp", "flags"):
            parts.append(protocol_detail(context, "tcp_flags", "tcp", "flags"))
        if protocol_detail(context, "tcp_expert", "tcp", "expert"):
            parts.append(protocol_detail(context, "tcp_expert", "tcp", "expert"))
        return " · ".join(parts)
    if proto == "icmp":
        parts = []
        if protocol_detail(context, "icmp_type", "icmp", "type"):
            parts.append(f"type {protocol_detail(context, 'icmp_type', 'icmp', 'type')}")
        if protocol_detail(context, "icmp_code", "icmp", "code"):
            parts.append(f"code {protocol_detail(context, 'icmp_code', 'icmp', 'code')}")
        return " · ".join(parts)
    if proto == "arp":
        parts = []
        if protocol_detail(context, "arp_opcode", "arp", "opcode"):
            parts.append(f"op {protocol_detail(context, 'arp_opcode', 'arp', 'opcode')}")
        sender = first_nonempty(
            protocol_detail(context, "arp_src_proto_ipv4", "arp", "src_proto_ipv4"),
            protocol_detail(context, "arp_src_hw_mac", "arp", "src_hw_mac"),
        )
        target = first_nonempty(
            protocol_detail(context, "arp_dst_proto_ipv4", "arp", "dst_proto_ipv4"),
            protocol_detail(context, "arp_dst_hw_mac", "arp", "dst_hw_mac"),
        )
        if sender:
            parts.append(f"sender {sender}")
        if target:
            parts.append(f"target {target}")
        return " · ".join(parts)
    if proto == "wlan":
        parts = []
        if protocol_detail(context, "wlan_ssid", "wlan", "ssid"):
            parts.append(f"SSID {protocol_detail(context, 'wlan_ssid', 'wlan', 'ssid')}")
        if protocol_detail(context, "wlan_bssid", "wlan", "bssid"):
            parts.append(f"BSSID {protocol_detail(context, 'wlan_bssid', 'wlan', 'bssid')}")
        if protocol_detail(context, "wlan_type_subtype", "wlan", "type_subtype"):
            subtype = protocol_detail(context, "wlan_type_subtype", "wlan", "type_subtype")
            subtype_label = wlan_subtype_label(subtype)
            if subtype_label:
                parts.append(f"{subtype_label} ({canonical_wlan_subtype(subtype)})")
            else:
                parts.append(f"subtype {subtype}")
        if protocol_detail(context, "wlan_channel", "wlan", "channel"):
            parts.append(f"channel {protocol_detail(context, 'wlan_channel', 'wlan', 'channel')}")
        if protocol_detail(context, "wlan_signal_dbm", "wlan", "signal_dbm"):
            parts.append(f"signal {protocol_detail(context, 'wlan_signal_dbm', 'wlan', 'signal_dbm')} dBm")
        if protocol_detail(context, "wlan_data_rate", "wlan", "data_rate"):
            parts.append(f"rate {protocol_detail(context, 'wlan_data_rate', 'wlan', 'data_rate')}")
        return " · ".join(parts)
    if proto == "btle":
        parts = []
        if protocol_detail(context, "btcommon_addr", "btle", "address"):
            parts.append(f"peer {protocol_detail(context, 'btcommon_addr', 'btle', 'address')}")
        if protocol_detail(context, "btatt_opcode", "btle", "att_opcode"):
            parts.append(f"ATT {protocol_detail(context, 'btatt_opcode', 'btle', 'att_opcode')}")
        if protocol_detail(context, "btl2cap_cid", "btle", "l2cap_cid"):
            parts.append(f"L2CAP {protocol_detail(context, 'btl2cap_cid', 'btle', 'l2cap_cid')}")
        return " · ".join(parts)
    return ""


def inferred_guidance_kind(label: str = "", prompt: str = "", explicit_kind: str = "") -> str:
    kind = str(explicit_kind or "").strip()
    if kind and kind not in {"recommended_step", "playbook_ai_recommendation"}:
        return kind
    if kind == "playbook_ai_recommendation":
        return "ask_ai_for_next_move"

    combined = normalize(" ".join([label, prompt]))
    if "follow" in combined and "stream" in combined:
        return "follow_stream"
    if "expert information" in combined or "expert warning" in combined or "expert-marked" in combined:
        return "open_expert_information"
    if "protocol hierarchy" in combined:
        return "open_protocol_hierarchy"
    if "endpoints" in combined:
        return "open_endpoints"
    if "conversations" in combined or "conversation" in combined:
        return "open_conversations"
    if "flow graph" in combined:
        return "open_flow_graph"
    if "io graph" in combined:
        return "open_io_graph"
    if "packet length" in combined:
        return "open_packet_lengths"
    if "rtt" in combined:
        return "open_tcp_rtt_graph"
    if "current filter" in combined or "filtered view" in combined or "different wireshark view" in combined:
        return "review_current_filter"
    if "all traffic involving" in combined or "this host" in combined or "this device" in combined or "this ip" in combined or "this mac" in combined:
        return "scope_host_or_device"
    if combined.startswith("explain") or "why is" in combined or "why does" in combined:
        return "explain_packet"
    if combined.startswith("show") or "filter" in combined:
        return "apply_filter"
    return kind or "generic"


def rank_playbook_guidance_items(playbook: Optional[Playbook], items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not playbook or not items:
        return items

    preferred = {name: idx for idx, name in enumerate(playbook.preferred_guidance)}
    fallback = {name: idx for idx, name in enumerate(playbook.fallback_guidance)}
    indexed = list(enumerate(items))

    def sort_key(entry: tuple[int, Dict[str, Any]]) -> tuple[int, int, int]:
        idx, item = entry
        kind = inferred_guidance_kind(
            str(item.get("label") or item.get("title") or ""),
            str(item.get("prompt") or item.get("instructions") or ""),
            str(item.get("kind") or ""),
        )
        if kind in preferred:
            return (0, preferred[kind], idx)
        if kind in fallback:
            return (2, fallback[kind], idx)
        return (1, idx, idx)

    return [item for _, item in sorted(indexed, key=sort_key)]


def ranked_playbook_focus(playbook: Playbook) -> List[Dict[str, str]]:
    return rank_playbook_guidance_items(playbook, [dict(item) for item in playbook.suggested_actions])


def summary_from_context(context: Dict[str, Any]) -> Dict[str, str]:
    proto = infer_packet_protocol(context).upper()
    src = (
        context.get("ip_src")
        or context.get("ipv6_src")
        or context.get("wlan_sa")
        or context.get("wlan_ta")
        or context.get("eth_src")
        or context.get("btcommon_addr")
        or context.get("selected_mac")
        or "(unknown)"
    )
    dst = (
        context.get("ip_dst")
        or context.get("ipv6_dst")
        or context.get("wlan_da")
        or context.get("wlan_ra")
        or context.get("eth_dst")
        or context.get("wlan_bssid")
        or "(unknown)"
    )
    return {
        "frame": str(context.get("frame_number") or "(unknown)"),
        "protocol": proto,
        "source": str(src),
        "destination": str(dst),
        "selected_ip": str(context.get("selected_ip") or context.get("selected_ipv6") or "(none)"),
        "selected_mac": str(context.get("selected_mac") or "(none)"),
        "current_filter": str(context.get("current_filter") or ""),
        "details": protocol_summary_details(context),
    }


def baseline_snapshot_from_state(state: SessionState, note: str = "") -> Dict[str, Any]:
    summary = summary_from_context(state.context)
    return {
        "saved_at": current_timestamp(),
        "note": note,
        "playbook_id": state.playbook_id or "",
        "playbook_name": active_playbook(state).name if active_playbook(state) else "",
        "summary": summary,
        "comparison_keys": {
            "protocol": str(state.context.get("packet_protocol") or state.context.get("protocol_hint") or ""),
            "selected_ip": first_nonempty(state.context.get("selected_ip"), state.context.get("selected_ipv6")),
            "selected_mac": str(state.context.get("selected_mac") or ""),
            "current_filter": str(state.context.get("current_filter") or ""),
            "dns_name": protocol_detail(state.context, "dns_name", "dns", "query_name"),
            "http_host": protocol_detail(state.context, "http_host", "http", "host"),
            "http_uri": protocol_detail(state.context, "http_request_uri", "http", "request_uri"),
            "wlan_ssid": protocol_detail(state.context, "wlan_ssid", "wlan", "ssid"),
            "wlan_bssid": protocol_detail(state.context, "wlan_bssid", "wlan", "bssid"),
            "wlan_channel": protocol_detail(state.context, "wlan_channel", "wlan", "channel"),
            "wlan_signal_dbm": protocol_detail(state.context, "wlan_signal_dbm", "wlan", "signal_dbm"),
            "wlan_data_rate": protocol_detail(state.context, "wlan_data_rate", "wlan", "data_rate"),
            "btcommon_addr": protocol_detail(state.context, "btcommon_addr", "btle", "address"),
        },
    }


def baseline_actions(state: SessionState) -> List[Dict[str, str]]:
    actions: List[Dict[str, str]] = []
    if state.baseline_snapshot:
        actions.append({
            "id": "baseline_compare",
            "label": "Compare to saved baseline",
            "prompt": "",
            "kind": "baseline_compare",
        })
        actions.append({
            "id": "baseline_save",
            "label": "Replace saved baseline with this view",
            "prompt": "",
            "kind": "baseline_save",
        })
        actions.append({
            "id": "baseline_clear",
            "label": "Clear saved baseline",
            "prompt": "",
            "kind": "baseline_clear",
        })
        return actions
    actions.append({
        "id": "baseline_save",
        "label": "Save this view as baseline",
        "prompt": "",
        "kind": "baseline_save",
    })
    return actions


def baseline_comparison_message(state: SessionState) -> Dict[str, Any]:
    baseline = state.baseline_snapshot
    if not baseline:
        return {
            "type": "assistant_text",
            "text": "No saved baseline is available yet. Save the current view as a baseline first, then compare later packet contexts against it.",
        }

    current = summary_from_context(state.context)
    saved = baseline.get("summary") or {}
    saved_keys = baseline.get("comparison_keys") or {}

    changed: List[str] = []
    same: List[str] = []

    def compare_field(label: str, current_value: str, saved_value: str) -> None:
        current_text = str(current_value or "").strip()
        saved_text = str(saved_value or "").strip()
        if not current_text and not saved_text:
            return
        if current_text == saved_text:
            same.append(f"{label}: {current_text}")
        else:
            changed.append(f"{label}: baseline `{saved_text or '(empty)'}` -> current `{current_text or '(empty)'}`")

    compare_field("Protocol", current.get("protocol", ""), saved.get("protocol", ""))
    compare_field("Source", current.get("source", ""), saved.get("source", ""))
    compare_field("Destination", current.get("destination", ""), saved.get("destination", ""))
    compare_field("Selected IP", current.get("selected_ip", ""), saved.get("selected_ip", ""))
    compare_field("Selected MAC", current.get("selected_mac", ""), saved.get("selected_mac", ""))
    compare_field("Current filter", current.get("current_filter", ""), saved.get("current_filter", ""))
    compare_field("DNS name", protocol_detail(state.context, "dns_name", "dns", "query_name"), saved_keys.get("dns_name", ""))
    compare_field("HTTP host", protocol_detail(state.context, "http_host", "http", "host"), saved_keys.get("http_host", ""))
    compare_field("HTTP URI", protocol_detail(state.context, "http_request_uri", "http", "request_uri"), saved_keys.get("http_uri", ""))
    compare_field("Wi-Fi SSID", protocol_detail(state.context, "wlan_ssid", "wlan", "ssid"), saved_keys.get("wlan_ssid", ""))
    compare_field("Wi-Fi BSSID", protocol_detail(state.context, "wlan_bssid", "wlan", "bssid"), saved_keys.get("wlan_bssid", ""))
    compare_field("Wi-Fi channel", protocol_detail(state.context, "wlan_channel", "wlan", "channel"), saved_keys.get("wlan_channel", ""))
    compare_field("Wi-Fi signal", protocol_detail(state.context, "wlan_signal_dbm", "wlan", "signal_dbm"), saved_keys.get("wlan_signal_dbm", ""))
    compare_field("Wi-Fi data rate", protocol_detail(state.context, "wlan_data_rate", "wlan", "data_rate"), saved_keys.get("wlan_data_rate", ""))
    compare_field("BLE peer", protocol_detail(state.context, "btcommon_addr", "btle", "address"), saved_keys.get("btcommon_addr", ""))

    lines = [
        f"Baseline saved at: {baseline.get('saved_at', '')}",
    ]
    if baseline.get("note"):
        lines.append(f"Baseline note: {baseline['note']}")
    if baseline.get("playbook_name"):
        lines.append(f"Baseline playbook: {baseline['playbook_name']}")
    lines.extend(["", "What changed:"])
    if changed:
        lines.extend([f"- {item}" for item in changed])
    else:
        lines.append("- No major context fields changed from the saved baseline.")
    lines.extend(["", "What stayed similar:"])
    if same:
        lines.extend([f"- {item}" for item in same[:5]])
    else:
        lines.append("- No major context fields stayed identical enough to call out.")
    takeaway = "The current view still looks close to the saved baseline." if not changed else "Use the changed fields to decide whether this is a normal variation, a broader scope shift, or a genuinely new anomaly."
    lines.extend(["", "Analyst takeaway:", takeaway])
    return {
        "type": "explanation",
        "title": "Baseline comparison",
        "text": "\n".join(lines),
        "provider": "rule_based",
        "model": "builtin",
        "response_source": "rule_based",
        "request_mode": "baseline",
        "suggested_actions": guided_next_steps(state),
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
    focus = [item["label"] for item in ranked_playbook_focus(playbook)[:3]]
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
        return "Why this sequence: first isolate the TCP conversation, then explain the packet role, then check connection setup, retransmissions, duplicate ACKs, resets, zero-window behavior, or other stall indicators so you can tell which side is failing, whether the issue repeats, and whether the symptoms look client-side, server-side, or in transit."
    if playbook.playbook_id == "dns_investigation":
        return "Why this sequence: first explain the DNS packet, then scope the name, host, or exchange involved, then confirm whether the issue looks like resolver-path trouble, missing response, caching behavior, recursion delay, or noisy background traffic."
    if playbook.playbook_id == "web_application_issue":
        return "Why this sequence: first explain the web packet and scope the HTTP exchange, then isolate the host or conversation, then decide whether the issue looks like missing content, redirection, intermediary or caching behavior, latency, or application-side behavior."
    if playbook.playbook_id == "suspicious_traffic":
        return "Why this sequence: first explain why the packet stands out, then scope the host or device, then isolate expert-marked, control-plane, or repeated traffic so you can decide whether the activity looks routine, misconfigured, path-related, or worth escalation."
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
    context = normalize_context_payload(context)
    context["packet_protocol"] = infer_packet_protocol(context)
    state = SessionState(
        session_id=sid,
        created_at=time.time(),
        context=context,
        settings={"provider": provider, "model": model},
    )
    state.backend_confirmed = not bool(available_ai_provider_ids())
    reset_investigation_state(state)
    refresh_guidance_state(state)
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
            "Which side starts, stalls, resets, retransmits, zero-windows, or acknowledges abnormally",
            "Whether the packets stay inside one TCP conversation or show a wider repeated failure pattern",
            "What happens immediately before and after the filtered packets so you can confirm connection setup, timing, and impact",
        ]
    if playbook.playbook_id == "dns_investigation":
        return [
            "Which client, local resolver, or upstream peer owns the query and response flow",
            "Whether the packets show a clean question-and-answer pattern, missing response, retry, negative answer, or unusual record type",
            "Whether the traffic isolates one DNS problem or still mixes normal background name lookups, caching effects, or resolver-path behavior with the issue",
        ]
    if playbook.playbook_id == "web_application_issue":
        return [
            "Which host pair, request, response, or Host header is central to the web problem",
            "Whether the packets show missing content, unexpected redirects, proxy/cache effects, slow server response, or repeated retries",
            "Whether the issue looks application-side, intermediary-side, network-side, or tied to supporting DNS or content-provider traffic",
        ]
    if playbook.playbook_id == "suspicious_traffic":
        return [
            "Unexpected peers, unusual ports, repeated retries, resets, ARP/DHCP/ICMP anomalies, or expert-marked packets",
            "Whether the traffic stays on one host or expands to more internal or external systems",
            "Whether the packets look like normal service traffic, noisy misconfiguration, address/path control trouble, scanning, or something worth escalation",
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
    if "tcp.flags.syn == 1" in lower:
        tags.add("tcp_syn")
    if "tcp.analysis.retransmission" in lower:
        tags.add("tcp_retransmission")
    if "tcp.analysis.duplicate_ack" in lower:
        tags.add("tcp_duplicate_ack")
    if "tcp.analysis.zero_window" in lower:
        tags.add("tcp_zero_window")
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
    if "wlan.bssid ==" in lower:
        tags.add("wifi_bssid_scope")
    if 'wlan.ssid ==' in lower:
        tags.add("wifi_ssid_scope")
    if 'dns.qry.name ==' in lower:
        tags.add("dns_name_scope")
    if 'http.host ==' in lower:
        tags.add("http_host_scope")
    if "wlan.fc.type == 0" in lower:
        tags.add("wifi_management")
    if "wlan.fc.type == 1" in lower:
        tags.add("wifi_control")
    if "wlan.fc.type == 2" in lower:
        tags.add("wifi_data")
    if "wlan.fc.type_subtype == 0x08" in lower:
        tags.add("wifi_beacon")
    if "wlan.fc.type_subtype == 0x04" in lower or "wlan.fc.type_subtype == 0x05" in lower:
        tags.add("wifi_probe")
    if "wlan.fc.type_subtype == 0x0b" in lower or "wlan.fc.type_subtype == 0x00" in lower or "wlan.fc.type_subtype == 0x01" in lower or "wlan.fc.type_subtype == 0x02" in lower or "wlan.fc.type_subtype == 0x03" in lower:
        tags.add("wifi_auth_assoc")
    if "wlan.fc.type_subtype == 0x00" in lower or "wlan.fc.type_subtype == 0x01" in lower or "wlan.fc.type_subtype == 0x02" in lower or "wlan.fc.type_subtype == 0x03" in lower:
        tags.add("wifi_assoc")
    if "wlan.fc.type_subtype == 0x0a" in lower or "wlan.fc.type_subtype == 0x0c" in lower:
        tags.add("wifi_deauth")
    if "wlan_radio.channel ==" in lower:
        tags.add("wifi_channel_scope")
    if "http.response" in lower:
        tags.add("http_response")
    if "http.response.code >= 300" in lower and "http.response.code < 400" in lower:
        tags.add("http_redirect")
    if "arp" in lower:
        tags.add("arp")
    if re.search(r"\bicmp\b", lower):
        tags.add("icmp")
    if "dhcp" in lower or "bootp" in lower:
        tags.add("dhcp")
    if "ip.flags.mf == 1" in lower or "ip.frag_offset > 0" in lower:
        tags.add("ip_fragments")
    if re.search(r"\bdns\b", lower):
        tags.add("dns")
    if re.search(r"\bhttp\b", lower):
        tags.add("http")
    if re.search(r"\btcp\b", lower):
        tags.add("tcp")
    if re.search(r"\bwlan\b", lower):
        tags.add("wifi")
    if "btle" in lower or "btatt" in lower or "btl2cap" in lower or "btcommon.addr" in lower:
        tags.add("btle")
    return tags


def summarize_applied_filter(filter_text: str) -> str:
    tags = detect_filter_tags(filter_text)
    if "tcp_syn" in tags and "tcp_conversation" in tags:
        return "This filter isolates TCP SYN and connection-setup packets within one bidirectional TCP conversation."
    if "tcp_retransmission" in tags and "tcp_conversation" in tags:
        return "This filter isolates TCP retransmissions within one bidirectional TCP conversation."
    if "tcp_duplicate_ack" in tags and "tcp_conversation" in tags:
        return "This filter isolates TCP duplicate ACKs within one bidirectional TCP conversation."
    if "tcp_reset" in tags and "tcp_conversation" in tags:
        return "This filter isolates TCP resets within one bidirectional TCP conversation."
    if "tcp_zero_window" in tags:
        return "This filter isolates TCP zero-window behavior."
    if "tcp_conversation" in tags:
        return "This filter isolates one bidirectional TCP conversation."
    if "udp_conversation" in tags:
        return "This filter isolates one bidirectional UDP conversation."
    if "tcp_syn" in tags:
        return "This filter isolates TCP SYN and connection-setup packets."
    if "tcp_retransmission" in tags:
        return "This filter isolates TCP retransmissions."
    if "tcp_duplicate_ack" in tags:
        return "This filter isolates TCP duplicate ACKs."
    if "tcp_reset" in tags:
        return "This filter isolates TCP resets."
    if "expert" in tags:
        return "This filter isolates Wireshark expert-marked packets."
    if "dns_name_scope" in tags:
        return "This filter scopes DNS traffic to one queried name."
    if "http_host_scope" in tags:
        return "This filter scopes HTTP traffic to one Host header value."
    if "http_redirect" in tags:
        return "This filter isolates HTTP redirect responses."
    if "http_response" in tags:
        return "This filter isolates HTTP responses."
    if "arp" in tags:
        return "This filter isolates ARP traffic."
    if "icmp" in tags:
        return "This filter isolates ICMP traffic."
    if "dhcp" in tags:
        return "This filter isolates DHCP or BOOTP traffic."
    if "ip_fragments" in tags:
        return "This filter isolates IPv4 fragmentation-related traffic."
    if "wifi_beacon" in tags:
        return "This filter isolates 802.11 beacon frames."
    if "wifi_probe" in tags:
        return "This filter isolates 802.11 probe request and response frames."
    if "wifi" in tags and "mac_scope" in tags:
        return "This filter scopes traffic to one wireless device-focused view."
    if "wifi_bssid_scope" in tags:
        return "This filter scopes traffic to one wireless BSSID."
    if "wifi_ssid_scope" in tags:
        return "This filter scopes traffic to one wireless SSID."
    if "wifi_management" in tags:
        return "This filter isolates 802.11 management frames."
    if "wifi_control" in tags:
        return "This filter isolates 802.11 control frames."
    if "wifi_data" in tags:
        return "This filter isolates 802.11 data frames."
    if "wifi_auth_assoc" in tags:
        return "This filter isolates authentication and association management frames."
    if "wifi_deauth" in tags:
        return "This filter isolates deauthentication and disassociation management frames."
    if "wifi_channel_scope" in tags:
        return "This filter isolates traffic captured on one wireless channel."
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
    steps.extend(baseline_actions(state))
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
    steps.extend(baseline_actions(state))
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
        if "tcp_syn" in tags:
            return f"Why this step: connection setup packets are already isolated, so the next useful pivot is whether the session progresses into loss, delay, or an immediate refusal. {next_label} moves the investigation past the handshake."
        if "tcp_conversation" in tags and "tcp_retransmission" not in tags and "tcp_duplicate_ack" not in tags and "tcp_reset" not in tags:
            return f"Why this step: you already isolated the TCP conversation, so the next useful pivot is packet-loss evidence inside that same conversation. {next_label} helps confirm whether the slowdown or failure is tied to retransmission behavior."
        if "tcp_retransmission" in tags:
            return f"Why this step: retransmissions are already isolated, so the next useful pivot is how the peer reacts. {next_label} helps you compare loss symptoms with ACK behavior instead of repeating the same view."
        if "tcp_duplicate_ack" in tags:
            return f"Why this step: duplicate ACKs are already isolated, so the next useful pivot is whether retransmissions, resets, or sequence progression explain them. {next_label} moves the investigation forward."
        if "tcp_zero_window" in tags:
            return f"Why this step: zero-window behavior is already isolated, so the next useful pivot is whether the stall is receiver-side flow control or a wider application pause. {next_label} helps you confirm that."
        if "tcp_reset" in tags:
            return f"Why this step: once resets are isolated, the next useful move is to explain that filtered view and determine which side terminated the flow and why."
    if playbook.playbook_id == "dns_investigation":
        if "dns_name_scope" in tags:
            return f"Why this step: one queried name is already isolated, so the next useful pivot is whether the answers, failures, or retries fit one resolver path. {next_label} helps you confirm that."
        if "udp_conversation" in tags and "dns" in tags:
            return f"Why this step: you already narrowed the DNS exchange to one conversation, so the next useful pivot is whether the name, answer pattern, or caching behavior explains the issue. {next_label} keeps the resolver path in scope."
    if playbook.playbook_id == "web_application_issue":
        if "http_host_scope" in tags:
            return f"Why this step: one HTTP host is already isolated, so the next useful pivot is whether one request/response chain or redirect path explains the problem. {next_label} keeps that web context focused."
        if "http_redirect" in tags:
            return f"Why this step: redirect responses are already isolated, so the next useful move is to explain whether the redirect chain is expected or part of the failure."
    if playbook.playbook_id == "suspicious_traffic":
        if "arp" in tags or "icmp" in tags or "dhcp" in tags or "ip_fragments" in tags:
            return f"Why this step: the current filter already isolates a control-plane clue. {next_label} helps you decide whether it reflects expected address/path behavior, misconfiguration, or something more suspicious."
        return f"Why this step: the current filter gives you scope. {next_label} helps you decide whether the packet is expected service traffic, a noisy mistake, or an outlier that needs escalation."
    if playbook.playbook_id == "wifi_investigation":
        return f"Why this step: the current filter narrows the wireless view. {next_label} helps you identify device roles and determine whether the issue is tied to one client, one BSSID, or one management exchange."
    if playbook.playbook_id == "btle_investigation":
        return f"Why this step: the current filter narrows the BLE exchange. {next_label} helps you identify the device role and determine whether the behavior belongs to one device interaction or a wider control problem."
    return f"Why this step: {next_label} is the best next pivot from the current filtered result."


def obvious_step_after_filter(state: SessionState, playbook: Playbook, filter_text: str) -> Optional[Dict[str, str]]:
    return resolve_guided_action_rule(state, playbook.filter_step_rules, filter_tags=set(detect_filter_tags(filter_text)))


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
    ranked_actions = rank_playbook_guidance_items(playbook, [dict(item) for item in playbook.suggested_actions])
    for item in ranked_actions:
        prompt = contextualize_playbook_prompt(state, item["prompt"])
        label = item["label"]
        action_kind = item.get("kind", "")
        if normalize(prompt) in excluded_prompts:
            continue
        steps.append({
            "id": f"{playbook.playbook_id}_{label.lower().replace(' ', '_')}",
            "label": label,
            "prompt": prompt,
            **({"kind": action_kind} if action_kind else {}),
        })
    steps.extend(baseline_actions(state))
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
    if "tcp.analysis.zero_window" in filter_text:
        summary.append("This filter isolates TCP zero-window behavior.")
    if "tcp.flags.syn == 1" in filter_text:
        summary.append("This filter isolates TCP SYN and connection-setup packets.")
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
    if "wlan.bssid ==" in filter_text:
        summary.append("This filter keeps traffic centered on one wireless BSSID.")
    if 'dns.qry.name ==' in filter_text:
        summary.append("This filter keeps traffic centered on one DNS queried name.")
    if 'http.host ==' in filter_text:
        summary.append("This filter keeps traffic centered on one HTTP Host header value.")
    if 'wlan.ssid ==' in filter_text:
        summary.append("This filter keeps traffic centered on one wireless SSID.")
    if "wlan.fc.type == 0" in filter_text:
        summary.append("This filter isolates 802.11 management frames.")
    if "wlan.fc.type == 1" in filter_text:
        summary.append("This filter isolates 802.11 control frames.")
    if "wlan.fc.type == 2" in filter_text:
        summary.append("This filter isolates 802.11 data frames.")
    if "wlan.fc.type_subtype == 0x08" in filter_text:
        summary.append("This filter isolates beacon frames.")
    if "wlan.fc.type_subtype == 0x04" in filter_text or "wlan.fc.type_subtype == 0x05" in filter_text:
        summary.append("This filter isolates probe request and response frames.")
    if "http.response" in filter_text:
        summary.append("This filter isolates HTTP responses.")
    if "http.response.code >= 300" in filter_text and "http.response.code < 400" in filter_text:
        summary.append("This filter isolates HTTP redirect responses.")
    if "wlan.fc.type_subtype == 0x0A" in filter_text or "wlan.fc.type_subtype == 0x0C" in filter_text:
        summary.append("This filter isolates deauthentication and disassociation frames.")
    if "wlan.fc.type_subtype == 0x0B" in filter_text or "wlan.fc.type_subtype == 0x00" in filter_text or "wlan.fc.type_subtype == 0x01" in filter_text or "wlan.fc.type_subtype == 0x02" in filter_text or "wlan.fc.type_subtype == 0x03" in filter_text:
        summary.append("This filter isolates authentication and association frames.")
    if "wlan_radio.channel ==" in filter_text:
        summary.append("This filter keeps traffic centered on one wireless channel.")
    if "btcommon.addr ==" in filter_text:
        summary.append("This filter keeps traffic centered on one BLE device address.")
    if re.search(r"\barp\b", filter_text):
        summary.append("This filter stays focused on ARP traffic.")
    if re.search(r"\bicmp\b", filter_text):
        summary.append("This filter stays focused on ICMP traffic.")
    if "dhcp" in filter_text or "bootp" in filter_text:
        summary.append("This filter stays focused on DHCP or BOOTP traffic.")
    if "ip.flags.mf == 1" in filter_text or "ip.frag_offset > 0" in filter_text:
        summary.append("This filter isolates IPv4 fragmentation-related traffic.")
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
    return resolve_guided_action_rule(state, playbook.next_step_rules)


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
        ranked_actions = rank_playbook_guidance_items(playbook, [dict(item) for item in playbook.suggested_actions])
        for item in ranked_actions:
            steps.append({
                "id": f"{playbook.playbook_id}_{item['label'].lower().replace(' ', '_')}",
                "label": item["label"],
                "prompt": contextualize_playbook_prompt(state, item["prompt"]),
                **({"kind": item["kind"]} if item.get("kind") else {}),
            })
        if current_filter:
            add("Explain the current filter and this packet together", "Explain this packet in the context of the current filter")
        steps.extend(baseline_actions(state))
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
    steps.extend(baseline_actions(state))
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
    if "zero-window" in text or "zero window" in text:
        clauses.append(TCP_ZERO_WINDOW_FILTER)
    if "handshake" in text or "syn packet" in text or "syn packets" in text or "connection setup" in text:
        clauses.append(TCP_SYN_FILTER)
    if "reset" in text or "resets" in text:
        clauses.append("tcp.flags.reset == 1")
    if "expert warning" in text or "expert warnings" in text or "expert-marked" in text:
        clauses.append("_ws.expert")
    if "bssid" in text and protocol_detail(state.context, "wlan_bssid", "wlan", "bssid"):
        clauses.append(f"wlan.bssid == {protocol_detail(state.context, 'wlan_bssid', 'wlan', 'bssid')}")
    if "ssid" in text and protocol_detail(state.context, "wlan_ssid", "wlan", "ssid"):
        clauses.append(f'wlan.ssid == "{protocol_detail(state.context, "wlan_ssid", "wlan", "ssid")}"')
    if ("http host" in text or "web host" in text) and protocol_detail(state.context, "http_host", "http", "host"):
        clauses.append(f'http.host == "{protocol_detail(state.context, "http_host", "http", "host")}"')
    if "http response" in text or "http responses" in text:
        clauses.append(HTTP_RESPONSE_FILTER)
    if "redirect response" in text or "redirect responses" in text or "http redirect" in text or "http redirects" in text:
        clauses.append(HTTP_REDIRECT_FILTER)
    if "management frame" in text or "management frames" in text:
        clauses.append("wlan.fc.type == 0")
    if "control frame" in text or "control frames" in text:
        clauses.append("wlan.fc.type == 1")
    if "data frame" in text or "data frames" in text:
        clauses.append("wlan.fc.type == 2")
    if "beacon" in text or "beacons" in text:
        clauses.append("wlan.fc.type_subtype == 0x08")
    if "probe request and response" in text or "probe requests and responses" in text or "probe traffic" in text or "probe frame" in text or "probe frames" in text:
        clauses.append(WIFI_PROBE_SUBTYPE_FILTER)
    elif "probe request" in text or "probe requests" in text:
        clauses.append("wlan.fc.type_subtype == 0x04")
    elif "probe response" in text or "probe responses" in text:
        clauses.append("wlan.fc.type_subtype == 0x05")
    if "authentication and association" in text or "authentication or association" in text:
        clauses.append(WIFI_AUTH_ASSOC_SUBTYPE_FILTER)
    elif "reassociation" in text:
        clauses.append("(wlan.fc.type_subtype == 0x02 || wlan.fc.type_subtype == 0x03)")
    elif "association" in text and "reassociation" not in text:
        clauses.append(WIFI_ASSOC_SUBTYPE_FILTER)
    elif "authentication" in text:
        clauses.append("wlan.fc.type_subtype == 0x0B")
    if "deauthentication" in text or "disassociation" in text:
        clauses.append(WIFI_DEAUTH_SUBTYPE_FILTER)
    channel_match = re.search(r"\bchannel\s+(\d{1,3})\b", text)
    if channel_match and ("wireless" in text or "wifi" in text or "wi-fi" in text or "wlan" in text or "802.11" in text or protocol_detail(state.context, "wlan_channel", "wlan", "channel")):
        clauses.append(f"wlan_radio.channel == {channel_match.group(1)}")
    elif ("this wireless channel" in text or "this wifi channel" in text or "this wi-fi channel" in text or "this wlan channel" in text or "this 802.11 channel" in text) and protocol_detail(state.context, "wlan_channel", "wlan", "channel"):
        clauses.append(f"wlan_radio.channel == {protocol_detail(state.context, 'wlan_channel', 'wlan', 'channel')}")
    if state.context.get("dns_name") and "this queried name" in text:
        clauses.append(f'dns.qry.name == "{state.context["dns_name"]}"')
    if "fragment" in text or "fragments" in text or "mtu" in text:
        clauses.append(IP_FRAGMENT_FILTER)
    if "time exceeded" in text and "icmp" in text:
        clauses.append("icmp.type == 11")
    if "destination unreachable" in text and "icmp" in text:
        clauses.append("icmp.type == 3")
    if "redirect" in text and "icmp" in text:
        clauses.append("icmp.type == 5")
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
        reset_investigation_state(state)
        refresh_guidance_state(state)
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
    reset_investigation_state(state)
    refresh_guidance_state(state)
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
        "investigation_goal": state.investigation_goal,
        "investigation_lane": state.investigation_lane,
        "handrail": state.handrail,
        "guided_history": state.guided_history,
        "user_observations": state.user_observations,
        "baseline": baseline_payload(state),
        "reference_assets": reference_assets_payload(state),
        "backend_confirmed": state.backend_confirmed,
    }


def session_web_url(session_id: str) -> str:
    base_url = PUBLIC_BASE_URL or request.host_url.rstrip("/")
    return f"{base_url}/session/{session_id}"


def apply_context_update(state: SessionState, context: Dict[str, Any], source_label: str = "Wireshark") -> None:
    updated_context = normalize_context_payload(context)
    updated_context["packet_protocol"] = infer_packet_protocol(updated_context)
    state.context = updated_context
    state.pending = None
    state.resolved = {}
    state.applied_filters = []
    refresh_guidance_state(state)
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
    ]

    if state.baseline_snapshot:
        baseline = state.baseline_snapshot
        baseline_summary = baseline.get("summary") or {}
        lines.extend([
            "## Saved Baseline",
            "",
            f"- Saved at: `{baseline.get('saved_at', '')}`",
            f"- Playbook: `{baseline.get('playbook_name') or 'generic'}`",
            f"- Protocol: `{baseline_summary.get('protocol', '')}`",
            f"- Source: `{baseline_summary.get('source', '')}`",
            f"- Destination: `{baseline_summary.get('destination', '')}`",
            f"- Current filter: `{baseline_summary.get('current_filter') or '(empty)'}`",
        ])
        if baseline.get("note"):
            lines.append(f"- Note: {baseline['note']}")
        lines.extend([
            "",
        ])

    lines.extend([
        "## Transcript",
        "",
    ])

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
    state.investigation_lane = "freeform"
    refresh_handrail_state(state)
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
    state.investigation_lane = "freeform"
    refresh_handrail_state(state)
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
    reset_investigation_state(state)
    refresh_guidance_state(state)
    state.baseline_snapshot = {}
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
    reset_investigation_state(state)
    refresh_guidance_state(state)
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
    playbook = PLAYBOOKS[playbook_id]
    state.messages.append({"type": "user_choice", "text": f"Use Playbook: {playbook.name}"})
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
    step_id = (payload.get("step_id") or "").strip()
    result = (payload.get("result") or "").strip()
    if backend_selection_required(state):
        state.messages.append({"type": "error", "text": "Set the background AI backend first."})
        return jsonify(response_payload(state))
    user_text = label or prompt or "Action"
    current_step = (state.handrail or {}).get("current_step") or {}
    guided_step = current_step if current_step.get("step_id") == step_id or not step_id else {"step_id": step_id}
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
    if kind == "baseline_save":
        state.messages.append({"type": "user_choice", "text": user_text or "Save this view as baseline"})
        state.baseline_snapshot = baseline_snapshot_from_state(state, note=note)
        refresh_guidance_state(state)
        baseline_summary = state.baseline_snapshot.get("summary") or {}
        state.messages.append({
            "type": "assistant_text",
            "text": (
                f"Baseline saved for {baseline_summary.get('protocol', '')} traffic "
                f"from {baseline_summary.get('source', '')} to {baseline_summary.get('destination', '')}. "
                "You can now compare later packet contexts against this saved view."
            ),
        })
        return jsonify(response_payload(state))
    if kind == "baseline_compare":
        state.messages.append({"type": "user_choice", "text": user_text or "Compare to saved baseline"})
        state.messages.append(baseline_comparison_message(state))
        return jsonify(response_payload(state))
    if kind == "baseline_clear":
        state.messages.append({"type": "user_choice", "text": user_text or "Clear saved baseline"})
        state.baseline_snapshot = {}
        refresh_guidance_state(state)
        state.messages.append({
            "type": "assistant_text",
            "text": "Saved baseline cleared. SharkBot will treat the current packet view as the only active context again.",
        })
        return jsonify(response_payload(state))
    if kind == "guided_step_start":
        state.investigation_lane = "guided"
        state.messages.append({"type": "user_choice", "text": user_text})
        update_guided_history(state, guided_step, status="started", note=note)
        if current_step:
            state.messages.append({
                "type": "assistant_text",
                "text": (
                    f"Handrail step active: {current_step.get('title', 'Guided step')}. "
                    f"{current_step.get('instructions', '')}"
                ).strip(),
            })
        refresh_handrail_state(state)
        return jsonify(response_payload(state))
    if kind == "guided_step_result":
        state.investigation_lane = "guided"
        state.messages.append({"type": "user_choice", "text": user_text})
        if note:
            state.messages.append({"type": "user_message", "text": f"Guided note: {note}"})
        if result:
            state.user_observations.append({
                "step_id": step_id or current_step.get("step_id", ""),
                "result": result,
                "label": HANDRAIL_OBSERVATION_LABELS.get(result, result),
                "note": note,
                "timestamp": current_timestamp(),
            })
        update_guided_history(state, guided_step, status="done", observation=result, note=note)
        refresh_handrail_state(state)
        next_step = (state.handrail or {}).get("current_step") or {}
        if next_step:
            state.messages.append({
                "type": "assistant_text",
                "text": (
                    f"Recorded: {HANDRAIL_OBSERVATION_LABELS.get(result, result)}. "
                    f"Next guided step: {next_step.get('title', 'Continue the investigation')}."
                ),
            })
        return jsonify(response_payload(state))
    if kind == "guided_step_skip":
        state.investigation_lane = "guided"
        state.messages.append({"type": "user_choice", "text": user_text})
        update_guided_history(state, guided_step, status="skipped", note=note)
        refresh_handrail_state(state)
        return jsonify(response_payload(state))
    if kind == "guided_step_alternate":
        state.investigation_lane = "guided"
        state.messages.append({"type": "user_choice", "text": user_text})
        state.user_observations.append({
            "step_id": step_id or current_step.get("step_id", ""),
            "result": "different_view",
            "label": HANDRAIL_OBSERVATION_LABELS["different_view"],
            "note": note or "User requested another guided approach.",
            "timestamp": current_timestamp(),
        })
        update_guided_history(
            state,
            guided_step,
            status="done",
            observation="different_view",
            note=note or "User requested another guided approach.",
        )
        refresh_handrail_state(state)
        return jsonify(response_payload(state))
    if kind == "guided_step_freeform":
        state.investigation_lane = "freeform"
        state.messages.append({"type": "user_choice", "text": user_text})
        state.messages.append({
            "type": "assistant_text",
            "text": "Free-form lane active. The handrail stays available while you investigate independently in Wireshark.",
        })
        refresh_handrail_state(state)
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
            state.investigation_lane = "guided"
            refresh_handrail_state(state)
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
        state.investigation_lane = "guided"
        refresh_handrail_state(state)
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
    state.investigation_lane = "freeform"
    refresh_handrail_state(state)
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
