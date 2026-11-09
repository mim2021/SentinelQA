# TrustGuard

A chat bot that spots scam messages sent from a trusted colleague's hijacked account, and checks
the identity of people who come back after being removed. The rules are deliberately simple: every
verdict lists the signals that fired and how many points each one added.

**Status (release 1.1.0, bot 1.1.0).** The Discord version was tested live on a test server in
November 2026. The Slack version is built and passes its automated tests, but hasn't been tried in
a real workspace yet.

```
trustguard/core/        the shared engine (no third-party dependencies)
  scoring.py            signals for a single message
  mass_message.py       same message sent to many places, several people reporting one sender
  reverify.py           rules for holding people who rejoin
  engine.py             TrustGuard: the one object the adapters talk to
trustguard/adapters/    discord_adapter.py, slack_adapter.py (receive -> normalize -> score -> act)
tests/                  unit tests and made-up, incident-style examples
```

## How a message is scored

Each signal adds points:

| Signal | Points |
|---|---|
| External link (not in `TRUSTGUARD_TRUSTED_DOMAINS`) | 20 |
| Money, gift or reward lure, or a currency amount | 25 |
| Link domain is a look-alike of a known brand / uses a brand name | 40 / 30 |
| Masked link: the visible text shows one domain, the link opens another | 30 |
| Short message with a link and no greeting | 10 |
| Urgent wording, link shortener, a domain ending common in phishing, @everyone | 10 each |
| Sender account under 7 days old (with a link) | 10 |
| Sender with a history shares a domain they've never used before | 10 |
| Same message sent to 3 or more places within 10 minutes | 35 |

A score of 35 or more gets a warning. At 60 or more the message is quarantined. On Discord that
means the message is deleted, the sender gets a 1-hour timeout, and moderators get an alert. On
Slack, where a bot can't delete other people's messages, it means a threaded warning plus a
moderator alert quoting the message, for an admin to delete. In both cases links in the alert are
"defanged" (made unclickable, like `steamcommunnity[.]com`). Edited messages are scored again, so
nobody can turn a harmless message into a scam after people have seen it.

**Reports.** No bot can read private DMs between two people, on Discord or Slack. Instead, you
forward or paste the suspicious DM to the bot and mention the sender. The bot replies with a
verdict, and if two different people report the same sender within 30 minutes, moderators get a
"possible compromised account" alert.

**Re-verification.** A new join is held (Discord: a hold role plus a moderator alert; Slack: a
moderator alert) when the user ID was banned or marked compromised, the name looks like a removed
account, the account is under 7 days old, or the community is in the 72-hour lockdown that
follows `!tg compromised`. Moderators confirm who the person is some other way, such as a call or
in person, then run `!tg approve <user>`.

## Try it without Slack or Discord

From the `trustguard` folder:
```bash
python -m trustguard.demo incident
```
This replays the incident step by step, with made-up names.
```bash
python -m trustguard.demo
```
This lets you type a message and see the verdict, score and reasons the bot would give.

## Run it on Discord

```bash
pip install -e ".[discord]"
```
```bash
python -m trustguard.adapters.discord_adapter
```

Settings come from environment variables, which the bot reads from `trustguard/.env`. Copy
`.env.example` to `.env` and fill it in: the bot token, the moderators channel, trusted domains,
score thresholds and an optional state file. The full walkthrough is in
[docs/pilot-guide.md](../docs/pilot-guide.md); use a test server first.

Tested live on a Discord test server:
- Normal messages are left alone.
- Scam links are deleted, the channel gets a warning, and moderators get an alert with the links
  defanged.
- Masked links (the text shows one site, the link opens another) are caught.
- Editing a message into a scam gets caught.
- DMing a message to the bot gets a verdict back.

Discord never lets a bot time out the server owner, or anyone with a role above the bot's. The
moderator alert says separately whether the delete or the timeout failed, so you know which step
needs doing by hand.

**Keep the token secret.** Bot tokens are passwords for the bot. For a pilot, keep them only in
`trustguard/.env`, which git ignores. For a real deployment, keep them in a secrets manager
(at SuccessKPI, 1Password) and load them into the environment from there. Either way, never paste
a token into chats or screenshots. If one leaks, reset it in the platform's developer portal (on
Discord, **Reset Token**).

## Slack: the next step

The Slack version is built and unit-tested against a fake Slack client, but it hasn't run in a
real workspace yet. The plan is to run the Slack test in
[docs/pilot-guide.md](../docs/pilot-guide.md) in a separate test workspace, fix what it turns up,
then pilot in warn-only mode by raising `TRUSTGUARD_QUARANTINE_AT` before turning quarantine on.

Setting it up:

1. Create the app from [`slack-app-manifest.yml`](slack-app-manifest.yml) (api.slack.com/apps →
   From an app manifest). It asks only for the permissions the bot uses and runs in Socket Mode
   (it connects out to Slack), so you don't need a public web address.
2. Generate an app-level token with `connections:write` (`SLACK_APP_TOKEN`), install the app,
   and copy the bot token (`SLACK_BOT_TOKEN`).
3. Create a private moderators channel, invite the bot, and set `TRUSTGUARD_MOD_CHANNEL_ID`.
   Invite the bot to every channel it should protect.
4. `pip install -e ".[slack]"`, then `python -m trustguard.adapters.slack_adapter`.

Commands are posted in the moderators channel by a workspace admin or owner, or by someone listed
in `TRUSTGUARD_ADMIN_IDS`:

| Command | Effect |
|---|---|
| `!tg compromised @user` | Record the account as compromised and start the 72-hour lockdown |
| `!tg removed @user` | Record a removal (deactivated accounts are also recorded automatically) |
| `!tg approve @user` | Release a hold after checking the person's identity some other way |

Colleagues report a suspicious DM with **Share message → TrustGuard**, or by pasting it and
mentioning the sender. If a held person joins a protected channel (a look-alike of a removed
account, or a removed ID coming back, for example through Slack Connect), moderators get an alert.
With `TRUSTGUARD_SLACK_REMOVE_HELD=1` and the extra `channels:manage` / `groups:write` permissions,
the bot also removes them from that channel.

## Run the tests

From inside the `trustguard` folder (the `tests` folder has no `__init__.py`, so run it from here):
```bash
python -m unittest discover -s tests -v
```
The Discord and Slack adapter tests are skipped unless you install with
`pip install -e "trustguard[slack,discord]"` (from the project root).

## Honest limits

- Message bursts, reports and each sender's history are kept in memory and reset when the bot
  restarts. Set `TRUSTGUARD_STATE_PATH` so removals, approvals and lockdowns survive a restart.
  That's a small SQLite database holding IDs, names and timestamps only, never message text.
  Without it, a restart reopens the gap for a removed attacker to rejoin.
- The rules are tuned on a small, made-up set of examples based on one incident. Nobody has
  measured how accurate they are on real traffic, and an attacker who knows them can write around
  them (adding a greeting, avoiding money words). Detection that holds up against that is the open
  problem this prototype is meant to show.
