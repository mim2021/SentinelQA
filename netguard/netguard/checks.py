"""Pure parsing and decision logic. No network or subprocess calls here, so everything in this
module is unit-tested with captured command output (see tests/)."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass

IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
MAC = re.compile(r"\b((?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2})\b", re.IGNORECASE)


@dataclass
class Finding:
    severity: str   # "info" | "warn" | "critical"
    code: str
    text: str


def normalize_mac(mac: str) -> str:
    """aa-bb-cc-dd-ee-ff / 0:1b:2:... -> aa:bb:cc:dd:ee:ff"""
    return ":".join(part.zfill(2) for part in re.split(r"[:-]", mac.lower()))


def parse_neighbors(output: str) -> dict[str, str]:
    """IP -> MAC from `arp -a` (Windows, macOS) or `ip neigh` (Linux). Reads the OS cache only."""
    table: dict[str, str] = {}
    for line in output.splitlines():
        ip, mac = re.search(IPV4, line), MAC.search(line)
        if ip and mac and "incomplete" not in line.lower():
            table.setdefault(ip.group(0), normalize_mac(mac.group(1)))
    return table


def parse_default_gateway(output: str) -> str | None:
    """Default gateway from `ip route show default`, `route -n get default` or `route print -4`."""
    m = re.search(r"^default via (" + IPV4 + ")", output, re.MULTILINE)          # Linux
    if m:
        return m.group(1)
    m = re.search(r"^\s*gateway:\s*(" + IPV4 + ")", output, re.MULTILINE)       # macOS
    if m:
        return m.group(1)
    best: tuple[int, str] | None = None                                         # Windows: lowest metric
    for line in output.splitlines():
        m = re.match(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(" + IPV4 + r")\s+" + IPV4 + r"\s+(\d+)", line)
        if m and (best is None or int(m.group(2)) < best[0]):
            best = (int(m.group(2)), m.group(1))
    return best[1] if best else None


def parse_ssid(output: str) -> str | None:
    """SSID from `netsh wlan show interfaces`, `nmcli -t -f active,ssid dev wifi` or
    `networksetup -getairportnetwork en0`."""
    m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", output, re.MULTILINE)             # Windows (not BSSID)
    if m:
        return m.group(1)
    m = re.search(r"^yes:(.+)$", output, re.MULTILINE)                          # Linux nmcli
    if m:
        return m.group(1).strip()
    m = re.search(r"Current Wi-Fi Network:\s*(.+)$", output, re.MULTILINE)      # macOS
    return m.group(1).strip() if m else None


def network_id(ssid: str | None, gateway_ip: str) -> str:
    """Stable id for "this network" without storing the network's name in clear text."""
    return hashlib.sha256(f"{ssid or ''}|{gateway_ip}".encode()).hexdigest()[:16]


def gateway_finding(baseline_mac: str | None, current_mac: str | None, ssid: str | None) -> Finding | None:
    """Trust-on-first-use: the router behind a known network should keep the same hardware address.
    A different one on the same network name + gateway IP is what an evil-twin hotspot or ARP
    spoofing looks like from the client side."""
    where = f"network '{ssid}'" if ssid else "this wired network"
    if not current_mac:
        return Finding("info", "gateway_unknown", "Could not read the gateway's hardware address from the ARP cache.")
    if not baseline_mac:
        return None
    if baseline_mac != current_mac:
        return Finding("critical", "gateway_changed",
                       f"The router for {where} has a different hardware address than last time "
                       f"({baseline_mac} -> {current_mac}). This is how an evil-twin hotspot or ARP spoofing "
                       "appears. Disconnect and use mobile data or the VPN, unless IT replaced the router "
                       "(then run `netguard trust`).")
    return None


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified


def _block(ip: str) -> str:
    return ".".join(ip.split(".")[:2])


def dns_finding(host: str, system_ips: list[str], doh_ips: list[str], cert_error: bool = False) -> Finding | None:
    """Compares the local resolver's answer with a DNS-over-HTTPS answer for the same host.
    cert_error: whether the same host also failed certificate validation on this network."""
    if not system_ips or not doh_ips:
        return None
    if any(_is_private(ip) for ip in system_ips) and not any(_is_private(ip) for ip in doh_ips):
        return Finding("critical", "dns_private_answer",
                       f"The local network resolves {host} to a private address ({', '.join(system_ips[:3])}) "
                       f"while DNS-over-HTTPS returns public ones ({', '.join(doh_ips[:3])}). The network is "
                       "redirecting this site; do not sign in.")
    # Load-balanced services hand out different servers from the same block (seen live with
    # login.microsoftonline.com), so only answers with no shared /16 count as a disagreement.
    if not {_block(ip) for ip in system_ips} & {_block(ip) for ip in doh_ips}:
        # CDNs and geo-DNS legitimately differ (seen live with slack.com on a home network), so on
        # its own this is only worth a note; it becomes a warning next to a certificate error.
        if cert_error:
            return Finding("warn", "dns_mismatch",
                           f"The local resolver and DNS-over-HTTPS disagree on {host} "
                           f"({', '.join(system_ips[:3])} vs {', '.join(doh_ips[:3])}), and {host} also "
                           "failed certificate checks. Together these point to redirection.")
        return Finding("info", "dns_mismatch",
                       f"The local resolver and DNS-over-HTTPS disagree on {host} "
                       f"({', '.join(system_ips[:3])} vs {', '.join(doh_ips[:3])}). Usually just a CDN; "
                       "only a concern together with certificate errors.")
    return None


def tls_finding(host: str, error: str | None, cert_error: bool) -> Finding | None:
    if error is None:
        return None
    if cert_error:
        return Finding("critical", "tls_cert_invalid",
                       f"{host} presented a certificate your system does not trust ({error}). For a "
                       "major site on public Wi-Fi this is the typical sign of interception. Do not sign "
                       "in on this network.")
    return Finding("info", "tls_unreachable",
                   f"Could not open a secure connection to {host} ({error}). The network may need a "
                   "captive-portal sign-in, or blocks the site.")


def overall(findings: list[Finding]) -> str:
    severities = {f.severity for f in findings}
    return "critical" if "critical" in severities else "warn" if "warn" in severities else "ok"
