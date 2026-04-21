from __future__ import annotations

from typing import Dict, List

from .base import AIProvider, ProviderResult


class RuleBasedProvider(AIProvider):
    provider_id = "rule_based"
    display_name = "Rule-based"
    models = ["builtin"]

    def explain_packet(self, context: Dict[str, str], user_text: str, model: str | None = None) -> ProviderResult:
        request = str(user_text or "").lower()
        proto = (context.get("packet_protocol") or context.get("protocol_hint") or "packet").upper()
        src = context.get("ip_src") or context.get("ipv6_src") or context.get("eth_src") or context.get("selected_mac") or "(unknown source)"
        dst = context.get("ip_dst") or context.get("ipv6_dst") or context.get("eth_dst") or context.get("selected_mac") or "(unknown destination)"
        frame = context.get("frame_number") or "(unknown frame)"
        dns_name = context.get("dns_name")
        http_host = context.get("http_host")
        tcp_srcport = context.get("tcp_srcport")
        tcp_dstport = context.get("tcp_dstport")
        udp_srcport = context.get("udp_srcport")
        udp_dstport = context.get("udp_dstport")

        lines = [
            f"This looks like a {proto} packet from {src} to {dst}.",
            f"Selected frame: {frame}.",
        ]
        if "tcp" in request or proto == "TCP":
            if tcp_srcport and tcp_dstport:
                lines.append(f"This packet is part of a TCP exchange between ports {tcp_srcport} and {tcp_dstport}.")
            if "duplicate ack" in request:
                lines.append("A duplicate ACK usually means the receiver is still acknowledging the same sequence number, which often points to packet loss, reordering, or delayed delivery earlier in the stream.")
            elif "retransmission" in request:
                lines.append("Retransmissions usually indicate packet loss, delay, or an application retry pattern. The next useful check is whether these are isolated or repeated throughout the same conversation.")
            elif "reset" in request:
                lines.append("A TCP reset means one side is aborting the connection immediately. The next useful check is which host sent the reset and what happened just before it.")
            elif "conversation" in request or "stream" in request:
                lines.append("For TCP troubleshooting, the most useful next pivot is the full bidirectional conversation so you can inspect sequence numbers, ACK progression, retransmissions, and resets together.")
            else:
                lines.append("For TCP analysis, useful next steps are to inspect the full conversation, look for retransmissions or duplicate ACKs, and compare sequence and ACK progression around this frame.")
        elif proto == "ARP":
            lines.append("ARP is used to map IP addresses to MAC addresses on the local network. Broadcast ARP is common local discovery traffic.")
        elif proto == "DNS":
            if dns_name:
                lines.append(f"This appears to involve the DNS name '{dns_name}'.")
            lines.append("DNS is used to resolve names to IP addresses. Useful follow-ups are filtering this client, this name, or DNS only.")
        elif "wifi" in request or "wi-fi" in request or "wlan" in request or "802.11" in request:
            lines.append("This should be treated as Wi-Fi analysis only if the selected packet is really a wireless management, control, or data frame of interest. If the useful details are TCP or IP, the transport-oriented playbooks are usually the better fit.")
        elif "btle" in request or "ble" in request or "bluetooth" in request:
            lines.append("For BTLE analysis, focus on device roles, address relationships, and ATT/GATT or control exchanges around this frame.")
        elif proto in {"HTTP", "TLS", "UDP"}:
            if http_host:
                lines.append(f"The HTTP host looks like '{http_host}'.")
            if udp_srcport and udp_dstport and proto == "UDP":
                lines.append(f"This packet is part of a UDP exchange between ports {udp_srcport} and {udp_dstport}.")
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
