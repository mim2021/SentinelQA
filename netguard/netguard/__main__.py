"""netguard: checks the network you are on for the symptoms of the first incident stage
(credentials or sessions stolen on public Wi-Fi).

  python -m netguard check            run all checks (exit 0 ok, 1 warning, 2 critical)
  python -m netguard check --json     machine-readable output
  python -m netguard trust            accept the current router as known (after a legitimate change)

The baseline file holds a hashed network id and the router's hardware address per network.
No network names, browsing data or traffic are stored."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import date
from pathlib import Path

from . import checks, probes

DEFAULT_HOSTS = ["slack.com", "login.microsoftonline.com", "accounts.google.com"]
DEFAULT_STATE = Path(os.environ.get("NETGUARD_STATE") or Path.home() / ".netguard" / "baseline.json")


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def current_network() -> tuple[str | None, str | None, str | None]:
    """(ssid, gateway ip, gateway mac); any part may be None."""
    gateway = checks.parse_default_gateway(probes.gateway_output())
    ssid = checks.parse_ssid(probes.ssid_output())
    mac = checks.parse_neighbors(probes.neighbors_output()).get(gateway) if gateway else None
    return ssid, gateway, mac


def check(hosts: list[str], state_path: Path, use_doh: bool) -> list[checks.Finding]:
    findings: list[checks.Finding] = []
    ssid, gateway, mac = current_network()
    if gateway:
        state = load_state(state_path)
        net = checks.network_id(ssid, gateway)
        known = state.get(net, {}).get("gateway_mac")
        f = checks.gateway_finding(known, mac, ssid)
        if f:
            findings.append(f)
        elif mac and not known:
            state[net] = {"gateway_mac": mac, "first_seen": date.today().isoformat()}
            save_state(state_path, state)
            findings.append(checks.Finding("info", "gateway_recorded",
                                           "First time on this network: router recorded for future checks."))
    else:
        findings.append(checks.Finding("info", "no_gateway", "No default gateway found (offline?)."))

    for host in hosts:
        error, cert_error = probes.tls_probe(host)
        f = checks.tls_finding(host, error, cert_error)
        if f:
            findings.append(f)
        if use_doh:
            f = checks.dns_finding(host, probes.system_resolve(host), probes.doh_resolve(host), cert_error)
            if f:
                findings.append(f)
    return findings


def trust(state_path: Path) -> str:
    ssid, gateway, mac = current_network()
    if not (gateway and mac):
        return "Could not read the current router; nothing changed."
    state = load_state(state_path)
    state[checks.network_id(ssid, gateway)] = {"gateway_mac": mac, "first_seen": date.today().isoformat()}
    save_state(state_path, state)
    return "Current router accepted as known for this network."


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state", type=Path, default=DEFAULT_STATE, help="baseline file (default: %(default)s)")
    ap = argparse.ArgumentParser(prog="netguard", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", parents=[common], help="run the network checks")
    c.add_argument("--host", action="append", help="host to probe (repeatable); default: " + ", ".join(DEFAULT_HOSTS))
    c.add_argument("--no-doh", action="store_true", help="skip the DNS-over-HTTPS comparison (no Cloudflare lookup)")
    c.add_argument("--json", action="store_true")
    sub.add_parser("trust", parents=[common], help="accept the current router for this network")
    args = ap.parse_args(argv)

    if args.cmd == "trust":
        print(trust(args.state))
        return 0

    findings = check(args.host or DEFAULT_HOSTS, args.state, not args.no_doh)
    verdict = checks.overall(findings)
    if args.json:
        print(json.dumps({"verdict": verdict, "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print({"ok": "OK - no interception symptoms found.", "warn": "WARNING - see below.",
               "critical": "DANGER - this network shows signs of interception."}[verdict])
        for f in findings:
            print(f"  [{f.severity}] {f.text}")
    return {"ok": 0, "warn": 1, "critical": 2}[verdict]


if __name__ == "__main__":
    sys.exit(main())
