# Bot pilot guide (Slack and Discord)

This guide shows you how to watch TrustGuard work live in a **test** workspace or server. Use
test accounts and test channels only. Keep the bot away from real colleagues' conversations until
the rollout approvals in `docs/rollout-guide.md` are done.

Steps marked **(you)** need your own account and create secret tokens, so they can't be
scripted. The Discord pilot was run live in November 2026. The Slack pilot hasn't been run in a
real workspace yet; it's the next step.

## 0. One-time setup on your computer

Open a terminal in the project folder and run these one at a time:

```bash
pip install -e "trustguard[slack,discord]"
```
```bash
copy trustguard\.env.example trustguard\.env
```

The bot reads its settings from `trustguard\.env`. Git ignores this file, so tokens you put there
are never committed. Use it for the pilot only; for the office deployment, keep tokens in
1Password. If a setting is missing, the bot stops and names it, for example
`Missing setting(s): SLACK_BOT_TOKEN ...`.

**Keep the token safe.** A bot token is the bot's password. Keep it only in `trustguard\.env`;
never paste it anywhere or show it in a screenshot, and close `.env` before sharing your screen.
If VS Code offers to inject `.env` into terminals, choose **Don't Show Again** rather than
turning it on, and don't attach `.env` to an AI chat panel. If the token leaks, reset it
straight away.

## Slack pilot (not yet run live)

### 1. Create the app (you, about 5 minutes)

1. Go to https://api.slack.com/apps → **Create New App** → **From an app manifest**.
2. Pick your **test** workspace, paste the contents of `trustguard/slack-app-manifest.yml`,
   and click **Create**.
3. **Basic Information → App-Level Tokens → Generate Token and Scopes**: name it `socket`, add
   the scope `connections:write`, and generate. Put the `xapp-...` value in
   `trustguard\.env` as `SLACK_APP_TOKEN`.
4. **Install App → Install to Workspace → Allow.** Put the **Bot User OAuth Token**
   (`xoxb-...`) in `.env` as `SLACK_BOT_TOKEN`.
5. In Slack, create a private channel `#trustguard-mods` and a public channel
   `#trustguard-test`. In each, type `/invite @TrustGuard`.
6. Open `#trustguard-mods` → channel name → scroll to the bottom → copy the **Channel ID**
   (`C0...`). Put it in `.env` as `TRUSTGUARD_MOD_CHANNEL_ID`.
7. Optional, so bans survive restarts: set `TRUSTGUARD_STATE_PATH=trustguard-state.db` in `.env`.

### 2. Start the bot

```bash
python -m trustguard.adapters.slack_adapter
```

It runs until you press Ctrl+C. Socket Mode means the bot connects out to Slack, so you don't
need a web address or a firewall change.

### 3. Test script

| # | Do this | Expected |
|---|---|---|
| 1 | In `#trustguard-test` post `hey, standup moved to 10:30 today` | Nothing. Normal messages are left alone |
| 2 | Post `steamcommunnity.com/gift-card/pay/50` | Threaded reply "Likely phishing - do not click", plus a **QUARANTINE** alert in `#trustguard-mods` with the link shown as `steamcommunnity[.]com` |
| 3 | Post `free gift`, select the text, press Ctrl+Shift+U, and link it to `https://slack-login.example.net/x` with the text `slack.com` | Warning: "link text shows slack.com but actually opens example.net" |
| 4 | Post `see you at lunch`, then edit it to `$50 steam gift https://steam-giftcard.xyz/claim` | A warning appears after the edit |
| 5 | Post the message from #2 as test user A. As test user B, hover it → **⋮ → Share message** → send to **TrustGuard** | B gets a DM verdict "Likely phishing" |
| 6 | Repeat #5 as test user C | `#trustguard-mods` gets **Possible compromised account** for user A |
| 7 | In `#trustguard-mods`, as a non-admin test user, type `!tg compromised @userA` | "Only workspace admins/owners ... can run TrustGuard commands" |
| 8 | As a workspace admin, type the same | "Marked @userA as compromised ..." |
| 9 | As admin, type `!tg removed @userD`; then user D leaves `#trustguard-test` and joins again | `#trustguard-mods` gets **Channel join needs re-verification** |
| 10 | Stop the bot (Ctrl+C), start it again, and repeat the rejoin from #9 | Still held, if `TRUSTGUARD_STATE_PATH` is set |
| 11 | As admin, `!tg approve @userD`, then D rejoins | No alert |

Some Slack limits are by design, not bugs. The bot can't read DMs between users (that's why
*Share message* exists), can't delete other users' messages (an admin deletes from the alert),
and can't deactivate accounts (an admin does that in Slack admin).

## Discord pilot

### 1. Create the bot (you, about 5 minutes)

1. Go to https://discord.com/developers/applications → **New Application** → name it `TrustGuard`.
2. To keep the bot private, first open **Installation**, set **Install Link** to **None** and
   untick **User Install**. Then turn **Public Bot** off on the **Bot** tab. In the other order,
   saving fails with a validation error.
3. **Bot** tab → **Reset Token** → copy it into `trustguard\.env` as `DISCORD_TOKEN`. On the
   same tab, turn on **Message Content Intent** and **Server Members Intent**.
4. **OAuth2 → URL Generator**: tick the scope `bot`, then only the permissions View Channels,
   Send Messages, Read Message History, Manage Messages, Moderate Members and Manage Roles. Don't
   tick Administrator. Open the generated URL and add the bot to your **test** server.
5. In Discord, switch on **User Settings → Advanced → Developer Mode**. Create a private
   `#trustguard-mods` channel and add the bot to it (**Edit Channel → Permissions → Add members
   or roles → TrustGuard**), or it can't post alerts there. Right-click the channel → **Copy
   Channel ID** → put it in `.env` as `TRUSTGUARD_MOD_CHANNEL_ID`.
6. Optional: create a role `held` with no channel access, drag it **below** the TrustGuard role,
   and copy its ID into `.env` as `TRUSTGUARD_HOLD_ROLE_ID`.

### 2. Start the bot

```bash
python -m trustguard.adapters.discord_adapter
```

The terminal prints `TrustGuard connected as ...`. Then leave it alone: you type test messages
in Discord, not in that terminal (anything typed there never reaches Discord). Pressing Ctrl+C
or closing the terminal stops the bot. To DM the bot,
press Ctrl+K in Discord, type `@TrustGuard` and open the DM.

### 3. Test script

| # | Do this | Expected |
|---|---|---|
| 1 | Post `hey, standup moved to 10:30 today` in a channel | Nothing |
| 2 | As a test user (not an admin), post `steamcommunnity.com/gift-card/pay/50` | Message deleted, user timed out for 1 hour, notice in the channel, **Quarantined** alert in `#trustguard-mods` |
| 3 | Post `[slack.com](https://slack-login.example.net/x) free gift` | Warning about a masked link |
| 4 | Post `see you at lunch`, then edit it to `$50 steam gift https://steam-giftcard.xyz/claim` | Handled after the edit |
| 5 | Two different test users each DM the bot the lure text **and mention the sender** (`@user`). The mention is what counts it as a report against that person | Each gets a verdict; after the second, **Possible compromised account** in `#trustguard-mods` |
| 6 | As an admin (Manage Server), `!tg compromised @user` | User kicked and recorded; 72-hour lockdown starts |
| 7 | A test account joins the server during lockdown | **Join held for re-verification** alert; gets the `held` role if configured |
| 8 | Ban a test user, then have them rejoin with a new account whose name resembles the old one | Held: "name resembles removed account" |
| 9 | `!tg approve <id>` | Hold role removed |

As on Slack, the bot can't read DMs between users; forwarding a message to it is how it hears
about DM scams.

**Testing with only your own account.** No bot can time out a server owner, so if you post as the
owner the alert says "could not time out the sender". The message is still deleted. Tests that
need a second person (two reporters, the kick, rejoining) can't be done with one account. The
offline replay covers them; run it from the `trustguard` folder:

```bash
python -m trustguard.demo incident
```

## After the pilot

Reset the test tokens so they stop working: Slack → **Basic Information → Revoke**; Discord →
**Bot → Reset Token**. Then clear them from `trustguard\.env`. Note how many alerts were real and
how many were false alarms. That's the first real measurement of how well the rules work.
