import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]



def normalize_url(raw: str) -> str:
    raw = raw.strip()
    p = urlparse(raw)
    scheme = p.scheme or "https"
    netloc = p.netloc or p.path
    path = p.path if p.netloc else ""
    normalized = urlunparse((scheme, netloc, path or "/", "", "", ""))
    return normalized


def resolve_host_to_ips(host: str) -> list[str]:
    ips = set()
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
        ip = sockaddr[0]
        ips.add(ip)
    return list(ips)

def is_private_ip(ip: str) -> bool:

    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in PRIVATE_NETS)

def validate_target_url(url: str) -> tuple[bool, str]:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False, "Faqat http/https ruxsat."
    if not p.hostname:
        return False, "Hostname topilmadi."

    host = p.hostname.lower()
    if host in ("localhost",):
        return False, "localhost taqiqlangan."

    try:
        ips = resolve_host_to_ips(host)
    except Exception:
        return False, "DNS resolve bo‘lmadi."

    for ip in ips:
        if is_private_ip(ip):
            return False, f"Private IP taqiqlangan: {ip}"
    return True, ""
