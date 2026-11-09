# TrustGuard

Detects messages sent from compromised-but-trusted accounts, and re-verifies people who rejoin
after a removal. Heuristic, explainable prototype: every verdict lists the signals and points
that produced it.

```
trustguard/core/        platform-neutral engine (no third-party dependencies)
  scoring.py            per-message signals
  mass_message.py       same-message bursts, multi-reporter escalation
  reverify.py           rejoin / re-verification policy
  engine.py             TrustGuard: the single object adapters call
trustguard/adapters/    discord_adapter.py, slack_adapter.py (receive -> normalize -> score -> act)
tests/                  unit tests + fictional incident-style fixtures
```

## Signals

| Signal | Points |
|---|---|
| External link (not in `TRUSTGUARD_TRUSTED_DOMAINS`) | 20 |
| Money / gift / reward lure, or a currency amount | 25 |
| Link domain is a look-alike of a known brand / uses a brand name | 40 / 30 |
| Masked link: the visible text shows one domain, the link opens another | 30 |
| Short, greeting-less message with a link | 10 |
| Urgency wording, link shortener, abused TLD, @everyone | 10 each |
| Sender account under 7 days old (with a link) | 10 |
| Sender with history shares a never-before-seen domain | 10 |
| Same message to ≥3 destinations within 10 minutes | 35 |

Score ≥ 35 warns, ≥ 60 quarantines (Discord: delete + 1h timeout + mod alert; Slack: threaded
warning + mod alert quoting the message with links defanged, for an admin to delete). Edited
messages are re-scored, so a harmless message cannot be turned into a lure after people saw it.

**Reports.** Bots cannot read private user-to-user DMs on Discord or Slack. Users forward or paste
the suspicious DM to the bot and mention the sender; the bot replies with a verdict, and two
independent reporters against one sender within 30 minutes trigger a "possible compromised
account" alert.

**Re-verification.** A join is held (Discord: hold role + mod alert; Slack: mod alert) when the
user id was banned or marked compromised, the name resembles a removed account, the account is
under 7 days old, or the community is in the 72-hour lockdown that follows `!tg compromised`.
Moderators confirm identity out-of-band, then `!tg approve <user>`.

## Try it without Slack or Discord

```bash
python -m trustguard.demo incident
```
replays the incident step by step (fictional names). `python -m trustguard.demo` lets you type
messages and see the verdict, score and reasons the bot would give.

## Run

```bash
pip install -e ".[discord]"
```
```bash
python -m trustguard.adapters.discord_adapter
```

Configure via environment variables (see `.env.example`: trusted domains, score thresholds,
state file; never commit real tokens — keep them in a
secrets manager).

### Slack

1. Create the app from [`slack-app-manifest.yml`](slack-app-manifest.yml) (api.slack.com/apps →
   From an app manifest). It requests only the scopes the adapter uses and runs in Socket Mode,
   so no public endpoint is needed.
2. Generate an app-level token with `connections:write` (`SLACK_APP_TOKEN`), install the app,
   and copy the bot token (`SLACK_BOT_TOKEN`).
3. Create a private moderators channel, invite the bot, and set `TRUSTGUARD_MOD_CHANNEL_ID`.
   Invite the bot to every channel it should protect.
4. `pip install -e ".[slack]"`, then `python -m trustguard.adapters.slack_adapter`.

Commands, posted in the moderators channel by a workspace admin/owner or a user listed in
`TRUSTGUARD_ADMIN_IDS`:

| Command | Effect |
|---|---|
| `!tg compromised @user` | Record the account as compromised and start the 72-hour lockdown |
| `!tg removed @user` | Record a removal (deactivations are also recorded automatically) |
| `!tg approve @user` | Release a hold after an out-of-band identity check |

Colleagues report a suspicious DM with **Share message → TrustGuard** (or by pasting it and
mentioning the sender). A held person joining a protected channel (a look-alike of a removed
account, or a removed id coming back, for example through Slack Connect) raises an alert. With
`TRUSTGUARD_SLACK_REMOVE_HELD=1` and the extra `channels:manage` / `groups:write` scopes the bot
also removes them from that channel.

## Test

```bash
python -m unittest discover -s tests -v
```

## Limits
- Burst, report and per-sender history state is in memory and resets on restart. Set
  `TRUSTGUARD_STATE_PATH` so removals, approvals and lockdown survive restarts (SQLite; ids,
  names and timestamps only, never message text). Without it, a restart reopens the rejoin gap.
- Heuristics are tuned on a small fictional set modelled on one incident. Precision/recall on real
  traffic is unmeasured, and an attacker who knows the rules can write around them (adding a
  greeting, avoiding lure words). Evasion-robust detection is the open problem this prototype
  is meant to expose.
