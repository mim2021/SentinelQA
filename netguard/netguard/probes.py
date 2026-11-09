"""Side-effecting probes: read OS tables, resolve names, open TLS connections.

Passive by design. It reads the operating system's own ARP/route tables and Wi-Fi status and makes
ordinary HTTPS connections. No packet capture, no ARP requests, no scanning."""

from __future__ import annotations

import json
import platform
import socket
import ssl
import subprocess
import urllib.parse
import urllib.request

SYSTEM = platform.system()


def run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10, errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def neighbors_output() -> str:
    return run(["ip", "neigh"]) if SYSTEM == "Linux" else run(["arp", "-a"])


def gateway_output() -> str:
    if SYSTEM == "Windows":
        return run(["route", "print", "-4"])
    if SYSTEM == "Darwin":
        return run(["route", "-n", "get", "default"])
    return run(["ip", "route", "show", "default"])


def ssid_output() -> str:
    if SYSTEM == "Windows":
        return run(["netsh", "wlan", "show", "interfaces"])
    if SYSTEM == "Darwin":
        return run(["networksetup", "-getairportnetwork", "en0"])
    return run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"])


def system_resolve(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError:
        return []


def doh_resolve(host: str) -> list[str]:
    """A records from Cloudflare DNS-over-HTTPS. Sends only the probe hostname."""
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": host, "type": "A"})
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.load(res)
    except (OSError, ValueError):
        return []   # includes TLS failures to the resolver itself; the TLS probe reports those
    return sorted({a["data"] for a in data.get("Answer", []) if a.get("type") == 1})


def tls_probe(host: str) -> tuple[str | None, bool]:
    """(error, is_certificate_error). (None, False) means the certificate verified."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return None, False
    except ssl.SSLCertVerificationError as e:
        return e.verify_message or str(e), True
    except (OSError, ssl.SSLError) as e:
        return type(e).__name__ + (f": {e.strerror}" if getattr(e, "strerror", None) else ""), False
