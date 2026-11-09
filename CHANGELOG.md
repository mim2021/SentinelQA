# Changelog

Versions follow the phases in the project roadmap. The extension (`manifest.json`) is versioned
0.x; the repository release that adds the TrustGuard bot is 1.0.0. Each feature is tied to the
stage of the incident it addresses (see "Incident-driven design" in the README).

## 1.1.0 — Office rollout (2026-11-09)

Extension 0.5.0, TrustGuard bot 1.1.0, netguard 0.1.0 (new). Tested end to end on Windows:
extension in Chrome, netguard on a home network, and the bot live on a Discord test server.
The Slack adapter is unit-tested with a fake client but has not had a live workspace test yet.

| Incident stage | Feature |
|---|---|
| Re-infiltration | Re-verification state (removed and compromised accounts, approvals, lockdown) persisted to SQLite via `TRUSTGUARD_STATE_PATH`, so a bot restart no longer lets a removed attacker back in. Stores ids, names and timestamps only, never message text |
| Spread | Moderator alerts quote the quarantined message with every link defanged |
| Spread | Masked-link signal: link text shows one domain but opens another (Slack `<url\|label>`, Discord `[label](url)`) |
| Spread | Slack: edited messages are re-scored; reports via *Share message* count the original author as the suspect |
| Spread | Discord: edited messages are re-scored, as on Slack; adapter tests with fake messages |
| Re-infiltration | Slack: `!tg compromised / removed / approve` in the moderators channel (workspace admins/owners or `TRUSTGUARD_ADMIN_IDS`); deactivated accounts recorded automatically; channel joins by removed ids or look-alike names (including Slack Connect guests) alert, and can be removed with `TRUSTGUARD_SLACK_REMOVE_HELD` |
| Network | `netguard` CLI (new, stdlib only): router hardware-address change on a known network (evil twin / ARP spoofing symptom), DNS answers redirected to private addresses, rejected certificates on major sites. Passive: reads OS tables, no scanning; network names stored only as hashes |
| Lure link | One rule set for every layer: `shared/rules.json` generates the extension's and the bot's copies; a test fails when they drift. The extension now also recognises Slack impersonation and the `.gift` TLD, as the bot already did; the bot no longer treats `.ru` / `.su` as suspicious by themselves |

- Slack is the office deployment: `slack-app-manifest.yml` installs the app with minimal scopes
  in Socket Mode. The Slack adapter's logic is SDK-independent and unit-tested with a fake client.
- Popup: Re-scan works 3 times per page load, then becomes "Refresh page"; every reload starts a
  new cycle. Pages that cannot be scanned (new tab, settings) show a grey "?" with an explanation
  and no Re-scan button.
- Popup: the grade, verdict, score and site stay pinned at the top while a long findings list
  scrolls under them.
- Popup: an "Online checks" line always shows whether the online lookups ran and what they found
  (domain age, DNS match, Safe Browsing), or that they are off, so the setting has a visible effect
  even when nothing is flagged.
- netguard: a DNS disagreement on its own is now a note, not a warning. Large services such as
  slack.com hand out different servers per resolver, which produced a WARNING on a normal home
  network during testing. It is still a warning when the same site also fails certificate checks.
- Discord: a quarantine alert now says which action failed. Discord never lets a bot time out the
  server owner, so the alert used to read "missing permission to delete/timeout" even when the
  message had been deleted.
- `netguard.cmd`: double-click or `.\netguard` from the project folder, no setup needed.
- `python -m trustguard.demo` (type messages) and `python -m trustguard.demo incident` (replay the
  incident) show the bot's verdicts without Slack or Discord.
- `docs/demo.gif`: recorded from the real extension and popup (headless browser run).
- A rejected certificate now always grades F (70 points instead of 50, which only reached D).
- The bot reads `trustguard/.env` and names any missing setting instead of crashing;
  `docs/pilot-guide.md` walks through a live Slack and Discord test.
- Bot reason text for brand names in domains now names the full host and reads correctly.
- Technical write-up expanded to a full document (`docs/case-study.md`, 9-page PDF) with worked
  examples taken from the code; README "Known limitations and future work" section.
- `docs/rollout-guide.md`: what colleagues get, what to do with a suspicious message, what is and
  isn't collected, admin deployment and compromised-account runbook.
- Warn/quarantine thresholds configurable (`TRUSTGUARD_WARN_AT`, `TRUSTGUARD_QUARANTINE_AT`) so a
  pilot can start in warn-only mode.

## 1.0.0 — TrustGuard bot MVP

A chat bot for the stages that happen *inside* the chat app, where the sender is a trusted but
compromised account. Heuristic, explainable prototype: every verdict lists the signals behind it.

| Incident stage | Feature |
|---|---|
| Spread | Message scoring: money/gift lure + external link + short greeting-less text + brand look-alike link |
| Spread | Same-message burst detection (one sender, ≥3 destinations, 10 minutes) |
| Spread (private DMs) | User reports: forward a DM to the bot; two independent reporters against one sender escalate to moderators |
| Spread | Quarantine: Discord deletes the message, times out the sender and alerts the mod channel; Slack posts a threaded warning and alerts moderators |
| Re-infiltration | Re-verification: joins are held for removed IDs, look-alike names, very new accounts, and during a 72-hour lockdown after `!tg compromised`; released only after an out-of-band check (`!tg approve`) |

- Platform-neutral engine (`trustguard/core`) with thin Discord and Slack adapters.
- 17 unit tests over fictional incident-style and benign fixtures; CI runs them on every push.
- Known limits: in-memory state, rules tuned on a small fictional set, no measured precision or
  recall, and an informed attacker can write around the rules.

## 0.4.0 — Closing the incident gap (extension)

| Incident stage | Feature |
|---|---|
| Network | Certificate/TLS error capture (`ERR_CERT_*`, `ERR_SSL_*`), kept on the report even after clicking through the warning |
| Network | DNS-over-HTTPS cross-check: connected server IP vs. Cloudflare DoH answers (weak signal, 10 points) |
| Lure link | Brand look-alike domains (`steamcommunnity.com`, `paypa1.com`) and brand names in unrelated domains, plus brand + reward-lure combination |
| Lure link | Domain age via RDAP (younger than 30 days scores high) |
| Lure link | Optional Google Safe Browsing lookup with your own API key, cached |
| Lure link | Redirect-chain logging across domains |
| Credential harvest | Fake login detection: password form whose title, site name or heading claims a brand the domain does not own |

- Online checks run only from the popup, for the site being scanned, and can be switched off in
  Settings.
- README "Incident-driven design" section and `docs/case-study.md`.

## 0.3.0 — Hardening

- Findings rendered with DOM APIs (`textContent`) instead of `innerHTML`.
- Shared, dependency-free detection core (`lib/core.js`) used by the popup, content script,
  service worker and tests; `isLocalHost` defined once.
- Node unit tests for `checkUrl()` (homoglyph, raw IP, `@` trick, clean site, long URL,
  suspicious TLD and more) and a GitHub Actions workflow.
- Version read from the manifest instead of hard-coded strings; MIT license.
