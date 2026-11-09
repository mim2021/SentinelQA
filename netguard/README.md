# netguard

A small, dependency-free command-line check for the first stage of the incident: a colleague's
session or credentials stolen on public Wi-Fi. Run it after joining a network, before signing in
to anything.

**Easiest (Windows, no setup):** double-click `netguard.cmd` in the project folder, or type
`.\netguard` in a terminal opened there. Add options after it, e.g.
`.\netguard check --host self-signed.badssl.com`.

Any OS, from the `netguard` folder:

```bash
python -m netguard check
```

Exit code 0 = ok, 1 = warning, 2 = critical, so it can run from a login script or scheduled task.

## What it checks

| Check | How | Severity |
|---|---|---|
| Router changed | Trust-on-first-use: the router's hardware address (read from the OS ARP cache) for this network name + gateway IP is recorded on first visit; a different one later is what an evil-twin hotspot or ARP spoofing looks like | critical |
| DNS redirected | A probe host resolves to a private address locally but to public addresses over DNS-over-HTTPS | critical |
| DNS disagreement | Local and DNS-over-HTTPS answers share no /16 block (often a CDN, so weak on its own) | warning |
| Certificate rejected | A TLS connection to a major site fails certificate verification | critical |

Probe hosts default to `slack.com`, `login.microsoftonline.com` and `accounts.google.com`; change
them with `--host` (repeatable). After IT legitimately replaces a router, run `netguard trust`.

## Privacy and scope

- **Passive.** It reads the operating system's own ARP, route and Wi-Fi status and makes ordinary
  HTTPS connections. It sends no ARP packets and does no scanning or packet capture.
- **Stored:** `~/.netguard/baseline.json` (or `NETGUARD_STATE`) holds a hash of network name and
  gateway IP, the router's hardware address and the first-seen date. Network names are never
  stored in clear text.
- **Sent out:** TLS connections to the probe hosts; with DoH on, the probe hostnames (not your
  browsing) to Cloudflare. `--no-doh` turns that off.

## Limits

- Trust-on-first-use cannot catch an attacker who is already there on your first visit, and
  networks with several routers or failover can trigger a false "router changed".
- It detects the usual *symptoms* of interception, not token theft itself; an attacker who
  harvests session cookies from unencrypted traffic without touching DNS or TLS is invisible here.
- Windows 11 may require location permission for `netsh wlan`; without the network name the
  check keys on the gateway IP alone.
