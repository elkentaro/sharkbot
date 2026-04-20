from __future__ import annotations

from typing import Dict, List

from .base import AIProvider, ProviderResult


class RuleBasedProvider(AIProvider):
    provider_id = "rule_based"
    display_name = "Rule-based"
    models = ["builtin"]

    def explain_packet(self, context: Dict[str, str], user_text: str, model: str | None = None) -> ProviderResult:
        proto = (context.get("packet_protocol") or context.get("protocol_hint") or "packet").upper()
        src = context.get("ip_src") or context.get("ipv6_src") or context.get("eth_src") or context.get("selected_mac") or "(unknown source)"
        dst = context.get("ip_dst") or context.get("ipv6_dst") or context.get("eth_dst") or context.get("selected_mac") or "(unknown destination)"
        frame = context.get("frame_number") or "(unknown frame)"
        dns_name = context.get("dns_name")
        http_host = context.get("http_host")

        lines = [
            f"This looks like a {proto} packet from {src} to {dst}.",
            f"Selected frame: {frame}.",
        ]
        if proto == "ARP":
            lines.append("ARP is used to map IP addresses to MAC addresses on the local network. Broadcast ARP is common local discovery traffic.")
        elif proto == "DNS":
            if dns_name:
                lines.append(f"This appears to involve the DNS name '{dns_name}'.")
            lines.append("DNS is used to resolve names to IP addresses. Useful follow-ups are filtering this client, this name, or DNS only.")
        elif proto in {"HTTP", "TLS", "TCP", "UDP"}:
            if http_host:
                lines.append(f"The HTTP host looks like '{http_host}'.")
            lines.append(f"Useful next steps are to filter all {proto} traffic for this endpoint or narrow by port.")
        else:
            lines.append("Useful next steps are to explain the packet in more detail, show related traffic, or build a filter around the visible addresses and ports.")

        return ProviderResult(text="\n\n".join(lines), meta={"provider": self.provider_id, "model": "builtin"})

    def suggest_actions(self, context: Dict[str, str]) -> List[Dict[str, str]]:
        proto = (context.get("packet_protocol") or context.get("protocol_hint") or "packet").lower()
        actions = [{"id": "explain", "label": "Explain this packet", "prompt": "Explain this packet"}]
        if proto == "arp":
            actions.extend([
                {"id": "arp_mac", "label": "Show all ARP involving this MAC", "prompt": "Show all ARP involving this MAC"},
                {"id": "arp_ip", "label": "Show traffic involving this IP", "prompt": "Show traffic involving this IP"},
                {"id": "arp_noise", "label": "Exclude ARP noise", "prompt": "Exclude ARP noise from the current view"},
            ])
        elif proto == "dns":
            actions.extend([
                {"id": "dns_only", "label": "Show all DNS except mDNS", "prompt": "Show all DNS except mDNS"},
                {"id": "dns_client", "label": "Show traffic involving this client", "prompt": "Show traffic involving this host"},
                {"id": "dns_name", "label": "Filter by queried name", "prompt": "Show DNS for this queried name"},
            ])
        else:
            actions.extend([
                {"id": "related", "label": "Show related traffic", "prompt": "Show traffic related to this host"},
                {"id": "src_only", "label": "Build filter from this source", "prompt": "Show traffic from this host"},
                {"id": "noise", "label": "Exclude local noise", "prompt": "Exclude common local noise"},
            ])
        return actions
