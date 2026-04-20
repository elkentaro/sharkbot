from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class ProviderResult:
    text: str
    meta: Dict[str, Any]


class AIProvider:
    provider_id = "base"
    display_name = "Base"
    models: List[str] = ["default"]

    def available(self) -> bool:
        return True

    def explain_packet(self, context: Dict[str, Any], user_text: str, model: str | None = None) -> ProviderResult:
        raise NotImplementedError

    def suggest_actions(self, context: Dict[str, Any]) -> List[Dict[str, str]]:
        return []

    def build_explanation_prompt(self, context: Dict[str, Any], user_text: str) -> str:
        lines = [
            "You are helping a Wireshark user understand a selected packet.",
            "Be concise, practical, and accurate.",
            "Do not invent fields that are not provided.",
            "Return plain text with these sections:",
            "Summary:",
            "Why it matters:",
            "What looks normal or unusual:",
            "Useful next steps:",
            "",
            f"User request: {user_text}",
            "",
            "Packet context:",
        ]
        preferred_order = [
            "frame_number",
            "packet_protocol",
            "current_filter",
            "eth_src",
            "eth_dst",
            "selected_mac",
            "ip_src",
            "ip_dst",
            "selected_ip",
            "ipv6_src",
            "ipv6_dst",
            "selected_ipv6",
            "tcp_srcport",
            "tcp_dstport",
            "udp_srcport",
            "udp_dstport",
            "http_host",
            "dns_name",
            "btcommon_addr",
        ]
        used = set()
        for key in preferred_order:
            value = context.get(key)
            if value not in (None, ""):
                lines.append(f"- {key}: {value}")
                used.add(key)
        for key in sorted(context.keys()):
            if key in used:
                continue
            value = context.get(key)
            if value not in (None, ""):
                lines.append(f"- {key}: {value}")
        return "\n".join(lines)
