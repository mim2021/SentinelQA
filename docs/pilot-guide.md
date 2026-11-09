# Bot pilot guide (Slack and Discord)

How to see TrustGuard working live in a **test** workspace or server. Use test accounts and
test channels only, never real colleagues' conversations, until the rollout approvals in
`docs/rollout-guide.md` are done.

The parts marked **(you)** need your own Slack/Discord account and create secret tokens, so they
cannot be scripted. Everything else is ready.

## 0. One-time setup on your computer

In a terminal in the project folder:

```
pip install -e "trustguard[slack,discord]"
```
```
copy trustguard\.env.example trustguard\.env
```

`trustguard\.env` is where the bot reads its settings. It is git-ignored, so tokens put there are
never committed. Use it for the pilot only; for the office deployment keep tokens in 1Password.

If a setting is missing, the bot stops and names it, e.g.
`Missing setting(s): SLACK_BOT_TOKEN ...`.

---

## Slack pilot

### 1. Create the app (you, ~5 minutes)

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

```
python -m trustguard.adapters.slack_adapter
```

It runs until you press Ctrl+C. No web address or firewall change is needed (Socket Mode).

### 3. Test script

Do these in Slack and tick each one off.

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

Slack limits to expect (by design, not bugs): the bot cannot read DMs between users (hence
*Share message*), cannot delete other users' messages (an admin deletes from the alert), and
cannot deactivate accounts (an admin does that in Slack admin).

---

## Discord pilot

### 1. Create the bot (you, ~5 minutes)

1. Go to https://discord.com/developers/applications → **New Application** → name it `TrustGuard`.
2. **Bot** tab → **Reset Token** → copy it into `trustguard\.env` as `DISCORD_TOKEN`. On the
   same tab, turn on **Message Content Intent** and **Server Members Intent**.
3. **OAuth2 → URL Generator**: tick the scope `bot`, then the permissions View Channels, Send
   Messages, Read Message History, Manage Messages, Moderate Members and Manage Roles. Open
   the generated URL and add the bot to your **test** server.
4. In Discord: **User Settings → Advanced → Developer Mode** on. Create a private
   `#trustguard-mods` channel, right-click it → **Copy Channel ID** → put it in `.env` as
   `TRUSTGUARD_MOD_CHANNEL_ID`.
5. Optional: create a role `held` with no channel access, drag it **below** the TrustGuard role,
   copy its ID → `TRUSTGUARD_HOLD_ROLE_ID`.

### 2. Start the bot

```
python -m trustguard.adapters.discord_adapter
```

The terminal prints `TrustGuard connected as ...`.

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

The bot cannot read DMs between users here either; forwarding to the bot is the DM-side signal.

---

## After the pilot

Delete the test tokens: Slack → **Basic Information → Revoke**; Discord → **Bot → Reset Token**.
Then clear them from `trustguard\.env`. Note how many alerts were real and how many were false
alarms. That is the first real measurement of the heuristics.
