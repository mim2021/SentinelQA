# SentinelQA + TrustGuard

Three small tools that work together against one kind of attack: a trusted colleague's account
gets hijacked and starts sending scam links to everyone they know.

- **SentinelQA**: a Chrome extension. Click its icon on any page and it grades the site A to F,
  with a plain-English reason for every point it takes off.
- **NetGuard**: a Wi-Fi checker you can double-click. It looks for signs that the network you're
  on is intercepting your traffic.
- **TrustGuard**: a chat bot. It spots scam messages, even when they come from a real colleague's
  account, and stops a removed attacker from quietly coming back.

![SentinelQA grading the real Steam store A, the incident's fake Steam gift-card login page F, and a rejected certificate F](docs/demo.gif)

It started with a QA engineer's question: *"We test functionality all day. Who tests security?"*
Then a real phishing incident showed why checking links alone isn't enough.

## The story behind it

A colleague's chat account was hijacked, most likely after their login was stolen on public Wi-Fi
a few days earlier. The attacker messaged everyone on their friend list with a short, greeting-less
"$50 Steam gift" link to a fake Steam site. Because the message came from someone they knew,
several people clicked and typed in their passwords. Anyone who reused that password lost other
accounts too. One person even asked "what is this?", but trust still won.

When the account was finally removed from the work server, the attacker simply came back with a
*new* account. Nothing asked who they were.

Spam filters miss this, because the sender is real. So each tool here covers a different moment
of the attack:

| Moment in the attack | What happened | What catches it | Which tool |
|---|---|---|---|
| On the network | Login stolen on open Wi-Fi | Certificate errors, DNS answers that don't match a trusted resolver, a swapped router | SentinelQA + NetGuard |
| The scam spreads | Hijacked account mass-messages a lure | Message scoring (money words, external link, no greeting, look-alike brand, disguised link), same message sent to many people, reports from several recipients | TrustGuard |
| The link | `steamcommunnity.com/gift-card/pay/50` | Look-alike and brand-in-domain detection, very new domains, optional Google Safe Browsing | SentinelQA + TrustGuard |
| The fake login page | A Steam-looking sign-in form | A password form claiming to be a brand the site doesn't belong to | SentinelQA |
| The attacker returns | New account, same person | Joins held for removed accounts, look-alike names, brand-new accounts, and during a lockdown | TrustGuard |

## What's done and tested

Version **1.1.0** (extension 0.5.0, bot 1.1.0, NetGuard 0.1.0). Everything below was tested by
hand on Windows in November 2026, on top of 83 automated tests.

**SentinelQA extension**, tested in Chrome
- Grades pages A–F and lists the reason for every point.
- Caught the fake Steam login page (F), a site with a bad certificate (F), and graded a normal
  site fairly (C, for missing security headers only).
- Browser pages like the new tab show a grey **?** instead of a grade.
- The grade stays pinned at the top while you scroll a long list of findings.
- An **Online checks** line shows whether the online lookups ran and what they found, or that
  they're switched off.
- Re-scan works three times per page load, then offers a page refresh.

**NetGuard Wi-Fi checker**, tested on a home network
- Runs from a terminal, prints JSON with `--json`, or runs on a double-click with no setup.
- Remembers your router per network and warns if it changes.
- A DNS difference on its own is now shown as a note. Big services like Slack hand out different
  servers to different resolvers, which caused a false WARNING during testing.

**TrustGuard bot**, tested live on a Discord test server
- Normal messages are left alone.
- Scam links are deleted, the channel gets a warning, and moderators get an alert with every link
  made unclickable (`steamcommunnity[.]com`).
- Disguised links (the text says one site, the link opens another) are caught.
- Editing an innocent message into a scam gets caught too.
- DMing a suspicious message to the bot gets a verdict back with the reasons.
- `python -m trustguard.demo incident` replays the whole incident offline, no chat app needed.

## Try it yourself

You'll need Chrome, Node 18+ and Python 3.10+. All commands run from this folder.

**Run the tests**
```bash
npm test
```
```bash
cd trustguard; python -m unittest discover -s tests; cd ..
```
```bash
cd netguard; python -m unittest discover -s tests; cd ..
```

In Windows PowerShell, if `npm` says "running scripts is disabled", type `npm.cmd test` instead.
You don't need to change any Windows security settings. The bot's Discord and Slack tests are
skipped unless you install it with `pip install -e "trustguard[slack,discord]"`.

**Load the extension**
1. Open `chrome://extensions` and switch on **Developer mode** (top right).
2. Click **Load unpacked** and choose this folder.
3. Pin the icon, open any website and click it.

To see it catch the fake login page, serve this folder with
`python -m http.server 8000 --bind 127.0.0.1`, then open
`http://steam-gift-card.127.0.0.1.nip.io:8000/test-fake-login.html`. The address resolves to your
own machine, so nothing leaves your computer. `https://self-signed.badssl.com` shows the
certificate check.

**Check your Wi-Fi**: double-click `netguard.cmd`, or run `.\netguard.cmd` in a terminal.

**Try the bot without any chat app**
From the `trustguard` folder:
```bash
python -m trustguard.demo
```
Type a message and press Enter to see its verdict. An empty line quits.

To run the bot live on Discord, follow [docs/pilot-guide.md](docs/pilot-guide.md). Use a test
server, and keep the bot token in `trustguard/.env` (git ignores it). Don't paste the token into
chats or screenshots. If it ever leaks, click **Reset Token** in the Discord developer portal.

## What stays private

- **Extension:** results live in your browser and are cleared when the tab closes. When
  **Online checks** is on (it is by default), the popup sends the scanned site's host name to
  rdap.org (domain age) and Cloudflare DNS (address check), and the full URL to Google Safe
  Browsing if you add your own key. Nothing is sent while you browse normally, only when you open
  the popup. You can switch this off in the extension's Settings.
- **NetGuard:** stores a hashed network name and your router's hardware address. It doesn't scan
  your network or record traffic.
- **Bot:** never stores message text. With `TRUSTGUARD_STATE_PATH` set, it keeps removed-account
  IDs, names and approvals in a small local database.

More detail for an office rollout is in [docs/rollout-guide.md](docs/rollout-guide.md).

## What's next

**Slack: the next big step.** The office runs on Slack, and the Slack version of the bot is
already built. It has moderator commands, re-scoring of edited messages, reporting with *Share
message*, and re-verification when someone joins a channel. Its automated tests use a fake Slack
client, but it hasn't been tried in a real workspace yet. The plan:

1. Run the 11-step Slack test in [docs/pilot-guide.md](docs/pilot-guide.md) in a separate test
   workspace.
2. Fix whatever that turns up.
3. Pilot in warn-only mode (raise `TRUSTGUARD_QUARANTINE_AT`) before turning on quarantine.

A Slack bot can't delete other people's messages, so on Slack "quarantine" means a threaded
warning plus an alert for an admin to act on.

**Before the office rollout**
- Decide whether **Online checks** should start switched off, or get rdap.org and Cloudflare
  approved as services that receive scanned host names. Whoever owns privacy should make that
  call.

**Later**
- A Microsoft Teams adapter.
- Language checks for scam messages that aren't in English.
- Smarter scoring that's harder to write around. The current rules are deliberately simple and
  explainable.

## Honest limits

Every check here is a simple, explainable rule: each grade or verdict shows exactly which signals
added points. That makes the tools easy to audit and tune. It also means:

- **The rules can be dodged.** An attacker who knows them can add a greeting or avoid money
  words. The scores are tuned on a small set of made-up examples, and nobody has measured accuracy
  on real traffic yet.
- **Bots can't read private DMs** between two people, on Discord or Slack. DM scams are caught only
  when someone forwards them to the bot.
- **Network attacks are spotted by their symptoms** (certificate errors, redirected DNS, a changed
  router), not by watching the attack itself.
- **People still click.** In the incident, someone doubted the message and the scam spread anyway.
  Good warnings matter as much as good detection.
- **Some test addresses look odd.** The nip.io test page also gets a "digits in the domain"
  finding, because its name contains `127.0.0.1`.

## What's in this folder

```
manifest.json, background.js, content.js,
popup.*, options.*        the Chrome extension
lib/core.js               detection and scoring (shared by popup, content script and tests)
lib/netchecks.js          online lookups (domain age, DNS check, Safe Browsing), popup only
lib/rules.js              generated from shared/rules.json, don't edit by hand
shared/rules.json         the one rule set used by the extension and the bot
tests/                    extension tests (npm test)
netguard/, netguard.cmd   the Wi-Fi checker and its tests
trustguard/               the bot: shared engine, Discord and Slack adapters, tests, offline demo
docs/                     pilot guide, rollout guide, case study (Markdown and PDF), demo GIF
CHANGELOG.md              what changed in each release, and why
```

After editing brands or look-alike domains in `shared/rules.json`, run `npm run build:rules` to
regenerate the copies. A test fails if they drift apart.

For the details: [trustguard/README.md](trustguard/README.md),
[netguard/README.md](netguard/README.md), and the full write-up in
[docs/case-study.md](docs/case-study.md).

## License

MIT
