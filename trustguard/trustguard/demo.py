"""Try TrustGuard without Slack or Discord.

  python -m trustguard.demo             type messages and see what the bot would do
  python -m trustguard.demo incident    replay the incident step by step

Everything runs locally with fictional names; nothing is sent or stored."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

from .core import Action, JoinEvent, Message, TrustGuard, defang

ICON = {Action.ALLOW: "ALLOW     ", Action.WARN: "WARN      ", Action.QUARANTINE: "QUARANTINE"}


def show(verdict) -> None:
    print(f"  -> {ICON[verdict.action]} score {verdict.score}/100")
    for r in verdict.reasons:
        print(f"       +{r.points:<3} {r.text}")
    if verdict.links:
        print("       links (defanged): " + ", ".join(defang(l) for l in verdict.links))


def interactive() -> None:
    tg = TrustGuard()
    now = datetime.now(timezone.utc)
    print(__doc__.split("\n\n")[0])
    print("Type a chat message and press Enter (empty line to quit).")
    print("Tip: send the same message 3 times to see mass-message detection.\n")
    n = 0
    while True:
        try:
            text = input("message> ").strip()
        except EOFError:
            break
        if not text:
            break
        n += 1
        # Each message goes to a different chat, as when a hijacked account messages its friend list.
        show(tg.process_message(Message("demo", str(n), "colleague", f"dm-{n}", text, now + timedelta(seconds=n))))
        print()


def step(title: str) -> None:
    print(f"\n=== {title} ===")


def incident() -> None:
    tg = TrustGuard()
    t = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
    old = t - timedelta(days=900)
    lure = "steamcommunnity.com/gift-card/pay/50"

    step("1. A normal message from a colleague")
    print('  colleague_a: "hey, standup moved to 10:30 today"')
    show(tg.process_message(Message("demo", "1", "colleague_a", "dm-1", "hey, standup moved to 10:30 today", t, old)))

    step("2. The account is hijacked and sends the lure to the friend list")
    for i, who in enumerate(["colleague_b", "colleague_c", "colleague_d"], start=1):
        print(f'  colleague_a -> {who}: "{lure}"')
        v = tg.process_message(Message("demo", f"2{i}", "colleague_a", f"dm-{who}", lure, t + timedelta(minutes=i), old))
        show(v)

    step("3. Bots cannot read private DMs, so two recipients report it to the bot")
    for i, reporter in enumerate(["colleague_b", "colleague_c"], start=1):
        verdict, escalate = tg.process_report(reporter, "colleague_a", lure, t + timedelta(minutes=5 + i))
        print(f"  {reporter} shares the DM with the bot -> {verdict.action.value}, score {verdict.score}"
              + ("  ==> MODERATORS ALERTED: possible compromised account" if escalate else ""))

    step("4. A moderator runs  !tg compromised @colleague_a")
    tg.mark_compromised("colleague_a", ["rahim.dev", "Rahim"], t + timedelta(minutes=10))
    print("  account recorded as compromised; 72-hour lockdown starts")

    step("5. The attacker rejoins with a NEW look-alike account (what happened in the incident)")
    join = JoinEvent("demo", "new-account-77", "rahim_dev", "Rahim", t + timedelta(days=1), account_created_at=t + timedelta(hours=20))
    d = tg.process_join(join)
    print(f"  new account 'rahim_dev' joins -> {'HELD for re-verification' if d.hold else 'admitted'}")
    for r in d.reasons:
        print(f"       - {r}")

    step("6. An ordinary new colleague joins after the lockdown ends")
    d = tg.process_join(JoinEvent("demo", "newhire-1", "new.hire", "New Hire", t + timedelta(days=5), account_created_at=old))
    print(f"  'new.hire' joins -> {'HELD' if d.hold else 'admitted'}")

    step("7. Moderators confirm the real colleague by phone, then  !tg approve")
    tg.approve("new-account-77")
    d = tg.process_join(join)
    print(f"  'rahim_dev' -> {'HELD' if d.hold else 'admitted'} ({'; '.join(d.reasons)})")
    print("\nIn the real incident steps 2, 3 and 5 went unnoticed. Here each one is caught.")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    incident() if args[:1] == ["incident"] else interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
