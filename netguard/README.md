# NetGuard

A small Wi-Fi checker for the first stage of the incident: a colleague's login stolen on public
Wi-Fi. Run it after you join a network and before you sign in to anything. It needs nothing beyond
Python.

**Easiest (Windows, no setup):** double-click `netguard.cmd` in the project folder, or run it from
a terminal opened there:
```bash
.\netguard.cmd
```
You can add options after it, for example:
```bash
.\netguard.cmd check --host self-signed.badssl.com
```

On any system, from the `netguard` folder:
```bash
python -m netguard check
```
Add `--json` for machine-readable output. The exit code is 0 for OK, 1 for a warning and 2 for
critical, so you can run it from a login script or scheduled task.

## What it checks

| Check | How | Severity |
|---|---|---|
| Router changed | The first time you join a network, it records the router's hardware address (from the operating system's ARP cache, its list of nearby devices) for that network name and gateway IP. A different one later is what a fake "evil twin" hotspot or ARP spoofing looks like | critical |
| DNS redirected | A test site resolves to a private address on this network, but to public addresses over DNS-over-HTTPS (a trusted DNS service queried over HTTPS) | critical |
| Certificate rejected | A secure connection to a major site fails its certificate check | critical |
| DNS disagreement | This network's DNS and DNS-over-HTTPS give answers with nothing in common (no shared /16 block) | warning if the same site also fails its certificate check, otherwise info |

A DNS disagreement on its own is only a note. Big services hand out different servers to different
resolvers, and slack.com caused a false WARNING on a normal home network during testing. It
becomes a warning only when it comes with a certificate failure for the same site.

The test sites are `slack.com`, `login.microsoftonline.com` and `accounts.google.com` by default.
Change them with `--host`, which you can repeat. If IT replaces a router for a real reason, run
`.\netguard.cmd trust` (or `python -m netguard trust` from the `netguard` folder) to accept the
new one.

## What stays private

- **It only looks.** It reads the operating system's own ARP, route and Wi-Fi status and makes
  ordinary HTTPS connections. It sends no ARP packets, doesn't scan your network and doesn't
  capture traffic.
- **What it stores:** `~/.netguard/baseline.json` (or the file in `NETGUARD_STATE`) holds a hash
  of the network name and gateway IP, the router's hardware address and the date it was first
  seen. Network names are never stored in plain text.
- **What it sends:** secure connections to the test sites, and, with DNS-over-HTTPS on, the test
  site names (not your browsing) to Cloudflare. `--no-doh` turns that off.

## Honest limits

- Remembering the router on first use can't catch an attacker who is already there on your first
  visit. Networks with several routers or a backup link can trigger a false "router changed".
- It spots the usual symptoms of interception, not the theft itself. An attacker who copies
  session cookies from unencrypted traffic without touching DNS or certificates won't show up.
- Windows 11 may need location permission before `netsh wlan` will show the network name. Without
  it, the check goes by the gateway IP alone.
