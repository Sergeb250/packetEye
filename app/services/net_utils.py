"""Shared IP classification for ML scoring, whitelisting, and OSINT."""

from __future__ import annotations

import ipaddress


def is_internal_ip(ip_str: str) -> bool:
    """Private, loopback, link-local, multicast, broadcast, or reserved — not public Internet."""
    if not ip_str or not str(ip_str).strip():
        return True
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or str(ip) == "255.255.255.255"
        )
    except ValueError:
        return False


def is_external_ip(ip_str: str) -> bool:
    return not is_internal_ip(ip_str)


def is_local_only_flow(flow: dict) -> bool:
    """True when neither side is a public Internet endpoint."""
    src = flow.get("src_ip") or ""
    dst = flow.get("dst_ip") or ""
    return is_internal_ip(src) and is_internal_ip(dst)


def ml_alert_suppressed(flow: dict, whitelist=None) -> tuple[bool, str]:
    """Suppress ML C2-style alerts for LAN/multicast/whitelisted traffic."""
    if is_local_only_flow(flow):
        return True, "local-only endpoints — not Internet C2"
    dst = flow.get("dst_ip") or ""
    if is_internal_ip(dst):
        return True, "destination is private, multicast, or link-local — not Internet C2"
    if is_likely_cdn_endpoint(flow):
        return True, "destination is known CDN/cloud HTTPS — likely benign"
    if is_benign_local_service(flow):
        return True, "benign LAN discovery/service traffic"
    if whitelist is not None and whitelist.is_whitelisted_flow(flow):
        return True, "whitelisted flow"
    return False, ""


# Common LAN discovery / broadcast services (SSDP, mDNS, DHCP)
BENIGN_LOCAL_PORTS = frozenset({
    (1900, "UDP"),   # SSDP → 239.255.255.250
    (5353, "UDP"),   # mDNS
    (5355, "UDP"),   # LLMNR
    (67, "UDP"),
    (68, "UDP"),
})

# Known CDN / cloud prefixes (Google, Cloudflare sample ranges)
_CDN_NETWORKS = []
for cidr in (
    "142.251.0.0/16", "172.217.0.0/16", "216.58.0.0/16",  # Google
    "104.16.0.0/12",  # Cloudflare
    "13.107.0.0/16", "52.96.0.0/12",  # Microsoft
):
    try:
        _CDN_NETWORKS.append(ipaddress.ip_network(cidr))
    except ValueError:
        pass


def is_likely_cdn_endpoint(flow: dict) -> bool:
    dst = str(flow.get("dst_ip") or "").strip()
    port = int(flow.get("dst_port") or 0)
    if port not in (443, 80):
        return False
    try:
        ip = ipaddress.ip_address(dst)
        return any(ip in net for net in _CDN_NETWORKS)
    except ValueError:
        return False


def is_benign_local_service(flow: dict) -> bool:
    dst = flow.get("dst_ip") or ""
    if not is_internal_ip(dst):
        return False
    port = int(flow.get("dst_port") or 0)
    proto = str(flow.get("protocol") or "TCP").upper()
    return (port, proto) in BENIGN_LOCAL_PORTS or (port, "UDP") in BENIGN_LOCAL_PORTS and proto == "UDP"
