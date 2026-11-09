"""Slack adapter (Bolt for Python, Socket Mode): receive -> normalize -> score -> act.

Scope, stated honestly:
  - The bot sees messages only in channels it has been invited to, plus DMs sent to the bot.
    It cannot read private DMs between users. This is workspace/channel protection; the DM side
    is covered by reports (share or paste the DM to the bot).
  - A bot token cannot delete other users' messages, so "quarantine" here means a threaded
    warning plus a moderator alert; a workspace admin deletes the message by hand.
  - The bot cannot deactivate users or hold a workspace join (admin APIs, Enterprise Grid).
    It records removals, alerts on re-verification, and can optionally remove a held person
    from protected channels (TRUSTGUARD_SLACK_REMOVE_HELD=1 plus the channels:manage and
    groups:write scopes).

Install with slack-app-manifest.yml (scopes and events are listed there).

Run:  python -m trustguard.adapters.slack_adapter
Env:  SLACK_BOT_TOKEN, SLACK_APP_TOKEN, TRUSTGUARD_MOD_CHANNEL_ID,
      TRUSTGUARD_ADMIN_IDS (optional, comma-separated user ids allowed to run !tg commands in
      addition to workspace admins/owners),
      TRUSTGUARD_SLACK_REMOVE_HELD (optional, "1" to remove held people from protected channels),
      plus the shared TRUSTGUARD_* engine settings (see .env.example)
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

from ..core import Action, EngineConfig, JoinEvent, Message, TrustGuard, defang, defang_text
from . import load_env, require

PREFIX = "!tg"
# Slack wraps links as <https://x.example|label>; keep the URL for scoring, and keep the label in
# "[label](url)" form so the engine can spot a label that shows a different domain.
SLACK_LINK = re.compile(r"<((?:https?|mailto):[^|>]+)(?:\|([^>]*))?>")
USER_REF = re.compile(r"<@([A-Z0-9]+)(?:\|[^>]*)?>")
# Message subtypes that are still a person posting text; everything else (joins, bot posts,
# channel topic changes...) is ignored.
SCORED_SUBTYPES = {None, "thread_broadcast", "file_share"}


def unwrap_links(text: str) -> str:
    def bare(s: str) -> str:
        return re.sub(r"^https?://", "", s, flags=re.IGNORECASE).rstrip("/").lower()

    def repl(m: re.Match) -> str:
        url, label = m.group(1), m.group(2)
        # Auto-linked text arrives as <https://x.example/a|x.example/a>: same target, not masked.
        return f"[{label}]({url})" if label and bare(label) != bare(url) and url.startswith("http") else url
    return SLACK_LINK.sub(repl, text or "")


def to_message(event: dict, channel: str | None = None) -> Message:
    return Message(
        platform="slack",
        message_id=event.get("ts", ""),
        sender_id=event.get("user", ""),
        destination_id=channel or event.get("channel", ""),
        text=unwrap_links(event.get("text", "")),
        sent_at=datetime.fromtimestamp(float(event.get("ts", "0")), tz=timezone.utc),
        is_direct=event.get("channel_type") == "im",
    )


def shared_messages(event: dict) -> list[tuple[str, str]]:
    """(author id, text) of messages shared/forwarded into this one (Slack "Share message")."""
    return [(a.get("author_id", ""), unwrap_links(a.get("text", "")))
            for a in event.get("attachments") or [] if a.get("author_id") and a.get("text")]


def user_names(user: dict) -> list[str]:
    profile = user.get("profile") or {}
    return [n for n in (user.get("name"), profile.get("display_name"), profile.get("real_name")) if n]


class SlackGuard:
    """All Slack behaviour, independent of Bolt so it can be tested with a fake client.
    `client` is a slack_sdk WebClient (or anything with the same methods).
    Reason texts name domains and Slack auto-links bare domains, so every post is defanged."""

    def __init__(self, engine: TrustGuard, mod_channel: str, admin_ids: set[str] = frozenset(),
                 remove_held: bool = False):
        self.engine = engine
        self.mod_channel = mod_channel
        self.admin_ids = set(admin_ids)
        self.remove_held = remove_held

    def alert(self, client, text: str) -> None:
        client.chat_postMessage(channel=self.mod_channel, text=text[:3000], unfurl_links=False, unfurl_media=False)

    def _user(self, client, user_id: str) -> dict:
        try:
            return client.users_info(user=user_id)["user"]
        except Exception:
            return {"id": user_id}

    # --- messages ---------------------------------------------------------------------------

    def on_message(self, event: dict, client) -> None:
        subtype = event.get("subtype")
        if subtype == "message_changed":
            # An edit can turn a harmless message into a lure after people have seen it.
            new, old = event.get("message") or {}, event.get("previous_message") or {}
            if new.get("bot_id") or new.get("text") == old.get("text"):
                return   # unfurls and other non-text edits
            event = dict(new, channel=event.get("channel"), channel_type=event.get("channel_type"))
        elif subtype not in SCORED_SUBTYPES or event.get("bot_id"):
            return
        if not event.get("user"):
            return

        if event.get("channel_type") == "im":
            self.handle_report(event, client)
        elif event.get("channel") == self.mod_channel and event.get("text", "").startswith(PREFIX):
            self.handle_command(event, client)
        else:
            self.handle_channel_message(event, client)

    def handle_channel_message(self, event: dict, client) -> None:
        msg = to_message(event)
        verdict = self.engine.process_message(msg)
        if verdict.action is Action.ALLOW:
            return
        links = ", ".join(defang(l) for l in verdict.links) or "-"
        quarantine = verdict.action is Action.QUARANTINE
        client.chat_postMessage(
            channel=msg.destination_id, thread_ts=event.get("thread_ts") or msg.message_id,
            unfurl_links=False, unfurl_media=False,
            text=(":rotating_light: *Likely phishing - do not click.* " if quarantine else ":warning: Careful: ")
                 + defang_text(verdict.summary()) + ". The sender's account may be compromised; confirm with them another way.")
        self.alert(client, f"*{'QUARANTINE' if quarantine else 'WARN'}*: message from <@{msg.sender_id}> in "
                           f"<#{msg.destination_id}> (score {verdict.score}): {defang_text(verdict.summary())}.\nLinks: {links}"
                           + (f"\nText: `{defang_text(msg.text[:500])}`\nA workspace admin should delete the "
                              "message and reset the sender's sessions." if quarantine else ""))

    def handle_report(self, event: dict, client) -> None:
        """A user shared or pasted a suspicious (usually private) message to the bot. The author
        of a shared message, or the first @mention, is counted as the suspected sender."""
        shares = shared_messages(event)
        text = "\n".join([unwrap_links(event.get("text", ""))] + [t for _, t in shares]).strip()
        mention = USER_REF.search(event.get("text", ""))
        suspect = shares[0][0] if shares else (mention.group(1) if mention else None)
        if not text:
            return
        sent_at = datetime.fromtimestamp(float(event.get("ts", "0")), tz=timezone.utc)
        verdict, escalate = self.engine.process_report(event["user"], suspect, text, sent_at)
        if verdict.action is Action.ALLOW:
            reply = "No strong phishing signals found. If it still feels off, verify with the sender another way."
        else:
            reply = (f":warning: Likely phishing (score {verdict.score}): {defang_text(verdict.summary())}.\nDo not click it. "
                     "If you already did: change that password, turn on 2FA, and sign out of other sessions.")
        if not suspect:
            reply += "\nTip: use *Share message* to send it here, or mention the sender, so repeated reports reach the moderators."
        client.chat_postMessage(channel=event["channel"], text=reply, unfurl_links=False, unfurl_media=False)
        if escalate and suspect:
            self.alert(client, f"*Possible compromised account* <@{suspect}>: reported by several people for "
                               f"sending: {defang_text(verdict.summary())}.\nLinks: {', '.join(defang(l) for l in verdict.links) or '-'}\n"
                               f"If confirmed: `{PREFIX} compromised <@{suspect}>`, then reset their sessions in Slack admin.")

    # --- moderator commands -----------------------------------------------------------------

    def is_admin(self, client, user_id: str) -> bool:
        if user_id in self.admin_ids:
            return True
        user = self._user(client, user_id)
        return bool(user.get("is_admin") or user.get("is_owner"))

    def handle_command(self, event: dict, client) -> None:
        def reply(text: str) -> None:
            client.chat_postMessage(channel=event["channel"], thread_ts=event.get("ts"), text=text)

        if not self.is_admin(client, event["user"]):
            reply("Only workspace admins/owners or ids in TRUSTGUARD_ADMIN_IDS can run TrustGuard commands.")
            return
        parts = event.get("text", "").split()
        target = USER_REF.fullmatch(parts[2]) if len(parts) >= 3 else None
        if len(parts) < 3 or parts[1] not in ("compromised", "removed", "approve") or not target:
            reply(f"Usage: `{PREFIX} compromised @user` | `{PREFIX} removed @user` | `{PREFIX} approve @user`")
            return
        cmd, uid = parts[1], target.group(1)
        now = datetime.now(timezone.utc)
        if cmd == "approve":
            self.engine.approve(uid)
            reply(f"Approved <@{uid}>. Invite them back to the channels they need.")
        elif cmd == "compromised":
            self.engine.mark_compromised(uid, user_names(self._user(client, uid)), now)
            reply(f"Marked <@{uid}> as compromised. Next: reset their sessions and password in Slack admin "
                  "(the bot cannot), warn the team, and verify anyone new out-of-band during the 72-hour lockdown.")
        else:
            self.engine.record_ban(uid, user_names(self._user(client, uid)), now)
            reply(f"Recorded <@{uid}> as removed. A rejoin with this id or a look-alike name will be held.")

    # --- membership -------------------------------------------------------------------------

    def on_user_change(self, event: dict, client) -> None:
        """A deactivated account is recorded as removed, like a Discord ban."""
        user = event.get("user") or {}
        if user.get("deleted") and user.get("id") and not user.get("is_bot"):
            self.engine.record_ban(user["id"], user_names(user), datetime.now(timezone.utc))

    def on_team_join(self, event: dict, client) -> None:
        user = event.get("user") or {}
        decision = self.engine.process_join(self._join_event(user))
        if decision.hold:
            self.alert(client, f"*New member needs re-verification*: <@{user.get('id')}> - {'; '.join(decision.reasons)}.\n"
                               f"Confirm their identity out-of-band (call / in person) before adding them to "
                               f"channels, then `{PREFIX} approve <@{user.get('id')}>`.")

    def on_member_joined_channel(self, event: dict, client) -> None:
        """Covers people the workspace already knows and Slack Connect guests entering a protected
        channel. Identity checks only: a lockdown must not hold every colleague who opens a channel."""
        user = self._user(client, event.get("user", ""))
        if user.get("is_bot"):
            return
        decision = self.engine.process_join(self._join_event(user), include_lockdown=False)
        if not decision.hold:
            return
        removed = False
        if self.remove_held:
            try:
                client.conversations_kick(channel=event.get("channel"), user=user["id"])
                removed = True
            except Exception:
                pass
        self.alert(client, f"*Channel join needs re-verification*: <@{user['id']}> joined <#{event.get('channel')}> - "
                           f"{'; '.join(decision.reasons)}." + (" Removed from the channel." if removed else "")
                           + f"\nConfirm identity out-of-band, then `{PREFIX} approve <@{user['id']}>`.")

    @staticmethod
    def _join_event(user: dict) -> JoinEvent:
        profile = user.get("profile") or {}
        return JoinEvent(platform="slack", user_id=user.get("id", ""), username=user.get("name", ""),
                         display_name=profile.get("display_name") or profile.get("real_name", ""),
                         joined_at=datetime.now(timezone.utc))


def build_app(guard: SlackGuard):
    from slack_bolt import App

    app = App(token=os.environ["SLACK_BOT_TOKEN"])
    app.event("message")(lambda event, client: guard.on_message(event, client))
    app.event("team_join")(lambda event, client: guard.on_team_join(event, client))
    app.event("user_change")(lambda event, client: guard.on_user_change(event, client))
    app.event("member_joined_channel")(lambda event, client: guard.on_member_joined_channel(event, client))
    return app


def main() -> None:
    from slack_bolt.adapter.socket_mode import SocketModeHandler

    load_env()
    require("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "TRUSTGUARD_MOD_CHANNEL_ID")
    admins ={u.strip() for u in os.environ.get("TRUSTGUARD_ADMIN_IDS", "").split(",") if u.strip()}
    guard = SlackGuard(TrustGuard(EngineConfig.from_env()), os.environ["TRUSTGUARD_MOD_CHANNEL_ID"],
                       admin_ids=admins, remove_held=os.environ.get("TRUSTGUARD_SLACK_REMOVE_HELD") == "1")
    SocketModeHandler(build_app(guard), os.environ["SLACK_APP_TOKEN"]).start()


if __name__ == "__main__":
    main()
