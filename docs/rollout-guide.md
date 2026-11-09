# Office rollout guide

This guide is for two readers: **colleagues** who will have SentinelQA in their browser and
TrustGuard in team chat, and the **admins** who deploy and run them. The tools exist because a
colleague's hijacked chat account was used to phish the rest of the team (see "Incident-driven
design" in the README). The aim is to stop that chain early without watching people.

## For colleagues

### What you get

**SentinelQA (browser extension).** Click the shield icon on any page to get an A–F grade with
reasons. It flags look-alike brand domains (`steamcommunnity.com`), fake sign-in pages that claim
to be a brand they are not, password forms sent without encryption, certificate errors (the usual
sign of a fake Wi-Fi hotspot), and missing security headers. It does not block anything. It only
tells you what it found.

**TrustGuard (chat bot).** In channels it has been added to, the bot warns on, or quarantines,
messages that look like the incident lure: a money or gift offer, an outside link, a look-alike
brand domain, the same text sent to many places at once. It also holds new or returning members
for a quick identity check when a removed account may be trying to get back in.

### If you get a suspicious message from someone you know

1. Don't click. A real name on the message does not mean that person sent it.
2. Ask them another way (phone, in person, a different app). Don't reply in the same chat.
3. Report it to the TrustGuard bot. In Slack: hover the message → **⋮ More actions → Share
   message** → send it to *TrustGuard*. You can also paste it into a DM with the bot and
   mention the sender (`@name`). You get a verdict back. If two people report the same sender,
   the moderators are told the account may be compromised.
4. Hover over a link before trusting its text. The text can show one site while the link opens
   another; TrustGuard flags this as a "masked link".

### If you already clicked or typed a password

Change that password, and any other account that used the same one. Turn on two-factor
authentication, sign out of all other sessions (Discord: Settings → Devices; Google/Microsoft:
security page), then tell an admin so they can warn others.

### On public Wi-Fi

If the extension shows a certificate error on a site you use every day, stop. Disconnect, and
continue on mobile data or the company VPN. Never click through certificate warnings on open
networks.

If you travel, run `netguard check` after joining a new network and before signing in. Exit
code 2 or "DANGER" means disconnect. It remembers the router of networks you have used before
and warns if a hotspot with the same name has a different one (the evil-twin trick behind our
incident). It stores only a hash of the network name and the router's hardware address, on your
machine.

## What is and isn't collected

| | SentinelQA extension | TrustGuard bot |
|---|---|---|
| **Reads** | URL, response headers and page structure of the tab you are on | Messages in channels the bot was added to; DMs you send **to the bot** |
| **Cannot read** | Other apps, network packets, other people's devices | Private DMs between colleagues (no chat platform allows a bot to read them) |
| **Stores** | Per-tab results in browser session storage, cleared when the tab closes; cached online-lookup results on your machine | Removed/compromised account IDs and names, approvals and lockdown end time (SQLite, if enabled). **No message text.** Burst and report counters live in memory only and reset when the bot restarts |
| **Sends out** | Only when you open the popup, and only for that site: the hostname to rdap.org (domain age) and Cloudflare DNS (IP cross-check), and the full URL to Google Safe Browsing if an admin set a key. All of it can be switched off in Settings | Moderator alerts inside the chat workspace. Quarantine alerts include up to 500 characters of the flagged message with its links disabled, so moderators can judge it |
| **Never** | Sends your browsing history anywhere, records passwords or form contents | Logs conversations, sends message content to any outside service |

`netguard` (optional, for travellers) stores a hashed network id, the router's hardware address and
a date in `~/.netguard/baseline.json`; it sends only TLS connections and DNS-over-HTTPS lookups for
three fixed probe hosts (off with `--no-doh`), never browsing data.

## For admins

### Before rollout

These need sign-off before anything reaches colleagues' machines or the work chat:

- **Security review.** Both components need a security review and a change record (ISO 27001
  change management; SOC 2 CC8.1). The extension asks for `host_permissions` on all sites,
  which is broad but needed to read headers and page structure on whatever site is scanned.
  Record that as an accepted risk, or narrow it.
- **Employee notice.** The bot processes colleagues' messages in the channels it is added to.
  Tell people before it goes live. Counsel should confirm the notice and lawful basis (GDPR
  Arts. 6 and 13, plus any local employee-monitoring rules). This guide is not legal advice.
- **Third-party lookups.** rdap.org, Cloudflare DoH and Google Safe Browsing receive hostnames
  or URLs. Either approve them as sub-processors for this use, or set the extension's online
  checks to off by default.

### Deploy the extension

- **Pilot:** `chrome://extensions` → Developer mode → Load unpacked → repository folder.
- **Fleet:** pack the extension and force-install it with the Chrome Enterprise policy
  `ExtensionInstallForcelist`, either self-hosted with an update manifest or as an unlisted
  Chrome Web Store item. Use `ExtensionSettings` to keep users from disabling it, if policy
  allows.
- Safe Browsing key: create a key restricted to the Safe Browsing API. Keep the key in
  1Password and enter it in each install's Settings page. Don't commit it to the repository.

### Run the bot

Our office runs Slack; the Discord adapter is identical in logic and is the right choice for
communities on Discord.

**Slack setup.** Create the app from `trustguard/slack-app-manifest.yml`. It uses Socket Mode,
so there's no inbound endpoint or firewall change. The manifest requests read access only to
channels the bot is invited to and DMs sent to it, plus `chat:write` and `users:read`; email
addresses are not requested. A workspace owner must approve the install. Then:

1. Create a private `#trustguard-mods` channel, invite the bot, and set
   `TRUSTGUARD_MOD_CHANNEL_ID` to its id.
2. Invite the bot to the channels to protect. Start with the busiest shared channels and any
   Slack Connect channels.
3. Workspace admins and owners can run `!tg` commands in the mods channel automatically. Add
   anyone else through `TRUSTGUARD_ADMIN_IDS`.
4. Optional: `TRUSTGUARD_SLACK_REMOVE_HELD=1` (plus the `channels:manage` and `groups:write`
   scopes) lets the bot remove a held person from protected channels instead of only alerting.

**Common to both platforms:**

- Install with `pip install -e "trustguard[slack]"` (or `[discord]`). Configuration comes from
  environment variables (`trustguard/.env.example`). Keep bot tokens in 1Password or the
  deployment platform's secret store. Never put them in `.env` files on shared machines.
- Set `TRUSTGUARD_STATE_PATH` to a file on a persistent, encrypted volume. Without it, a restart
  forgets every ban and compromised mark, and a removed attacker can rejoin unchecked, which is
  exactly what happened in the incident.
- Give the bot the least it needs. Discord: View Channels, Send Messages, Manage Messages,
  Moderate Members, Manage Roles (only for the hold role); intents Message Content and Server
  Members. Slack: `channels:history`, `groups:history`, `im:history`, `chat:write`,
  `users:read`. Add it only to the channels you mean to protect.
- Create a private moderator channel for alerts and set `TRUSTGUARD_MOD_CHANNEL_ID`.
- Discord re-verification: create a "hold" role with no channel access and set
  `TRUSTGUARD_HOLD_ROLE_ID`.

### When an account is compromised

1. **Slack:** in the mods channel, `!tg compromised @user`. Then, in Slack admin, reset the
   user's sessions (Manage members → the user → Reset sessions) or deactivate the account. The
   bot cannot do either; deactivations are recorded automatically.
   **Discord:** `!tg compromised <user>` (needs Manage Server) kicks the account.
   On both platforms the account is recorded and a 72-hour lockdown starts, during which every
   new member is held for verification.
2. Warn the team in a general channel. Tell anyone who clicked to follow the "If you already
   clicked" steps above.
3. Before letting anyone back in, held or not, confirm who they are out-of-band (call, in
   person), then `!tg approve <user>`.
4. Ask the owner of the compromised account to reset their password, revoke sessions, and turn
   on 2FA before they are approved.

### Known limits to communicate

The rules are heuristics, tuned on a small fictional set modelled on one incident. Expect some
false alarms, and expect a careful attacker to slip past now and then. Nobody has measured the
false-positive rate on real traffic yet. Collect moderator feedback during the pilot before
deciding to auto-quarantine in busy channels. One option is to raise the quarantine threshold so
the bot only warns at first.
