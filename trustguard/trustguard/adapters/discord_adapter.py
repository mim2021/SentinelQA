"""Discord adapter: receive -> normalize -> score -> act.

What a Discord bot can and cannot see (be precise about this in write-ups):
  - Server channel messages: yes, with the privileged Message Content intent.
  - DMs *to the bot*: yes.
  - Private DMs *between two users*: NO. No bot can read them. So the DM side of the
    incident is covered by reports: recipients forward the suspicious DM to the bot, and
    independent reports against one sender escalate to moderators.

Required bot permissions: View Channels, Send Messages, Manage Messages (delete),
Moderate Members (timeout), Manage Roles (hold role). Intents: Message Content, Server Members.

Run:  python -m trustguard.adapters.discord_adapter
Env:  DISCORD_TOKEN, TRUSTGUARD_MOD_CHANNEL_ID, TRUSTGUARD_HOLD_ROLE_ID (optional),
      TRUSTGUARD_TRUSTED_DOMAINS (optional, comma-separated),
      TRUSTGUARD_STATE_PATH (optional SQLite file; keeps bans/approvals across restarts),
      TRUSTGUARD_WARN_AT / TRUSTGUARD_QUARANTINE_AT (optional score thresholds, default 35 / 60)
"""

from __future__ import annotations

import os
from datetime import timedelta

import discord

from ..core import Action, EngineConfig, JoinEvent, Message, TrustGuard, defang, defang_text
from . import load_env, require

PREFIX = "!tg"
TIMEOUT = timedelta(hours=1)


def to_message(m: discord.Message) -> Message:
    text = m.content
    # Forwarded messages carry their content in snapshots, not in .content.
    for snap in getattr(m, "message_snapshots", None) or []:
        text += "\n" + (getattr(snap, "content", "") or "")
    return Message(
        platform="discord",
        message_id=str(m.id),
        sender_id=str(m.author.id),
        destination_id=str(m.channel.id),
        text=text,
        sent_at=m.created_at,
        sender_created_at=m.author.created_at,
        is_direct=m.guild is None,
    )


class TrustGuardDiscord(discord.Client):
    def __init__(self, engine: TrustGuard, mod_channel_id: int, hold_role_id: int | None):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        super().__init__(intents=intents)
        self.engine = engine
        self.mod_channel_id = mod_channel_id
        self.hold_role_id = hold_role_id

    async def alert(self, text: str) -> None:
        channel = self.get_channel(self.mod_channel_id)
        if channel:
            await channel.send(text[:1900], allowed_mentions=discord.AllowedMentions.none())

    async def on_ready(self) -> None:
        print(f"TrustGuard connected as {self.user}")

    async def on_message(self, m: discord.Message) -> None:
        if m.author.bot:
            return
        if m.guild is None:
            await self.handle_report(m)
            return
        if m.content.startswith(PREFIX):
            await self.handle_command(m)
            return
        await self.handle_channel_message(m)

    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        """An edit can turn a harmless message into a lure after people have seen it. Fires for
        messages still in the client cache; embeds being attached do not change .content."""
        if after.author.bot or after.guild is None or after.content == before.content \
                or after.content.startswith(PREFIX):
            return
        await self.handle_channel_message(after)

    async def handle_channel_message(self, m: discord.Message) -> None:
        verdict = self.engine.process_message(to_message(m))
        if verdict.action is Action.ALLOW:
            return
        links = ", ".join(defang(l) for l in verdict.links) or "-"
        summary = f"score {verdict.score}: {verdict.summary()}"

        if verdict.action is Action.QUARANTINE:
            # Delete and timeout fail independently: Discord never lets a bot time out the server
            # owner or anyone above its role, even when the delete went through.
            try:
                await m.delete()
            except discord.Forbidden:
                summary += " (could not delete the message: missing permission)"
            if isinstance(m.author, discord.Member):
                try:
                    await m.author.timeout(TIMEOUT, reason="TrustGuard: possible compromised account")
                except discord.Forbidden:
                    summary += " (could not time out the sender: server owner or role above the bot)"
            await m.channel.send(
                f"⚠️ A message from {m.author.mention} was quarantined as likely phishing. "
                "If you clicked a link from them recently, change your password and log out other sessions.",
                allowed_mentions=discord.AllowedMentions.none())
            await self.alert(f"**Quarantined** message from {m.author} (`{m.author.id}`) in {m.channel.mention}\n"
                             f"{summary}\nLinks: {links}\nText: {defang_text(m.content[:500])!r}")
        else:
            await m.reply(f"⚠️ Careful with this message ({verdict.summary()}). "
                          "Even if you know the sender, their account may be compromised - confirm with them another way.",
                          mention_author=False)
            await self.alert(f"Warned on message from {m.author} (`{m.author.id}`) in {m.channel.mention}: {summary}")

    async def handle_report(self, m: discord.Message) -> None:
        """A user forwarded/pasted a suspicious DM. Mention the sender to count it as a report."""
        msg = to_message(m)
        suspect = next((u for u in m.mentions if u.id != self.user.id), None)
        verdict, escalate = self.engine.process_report(str(m.author.id), str(suspect.id) if suspect else None,
                                                       msg.text, msg.sent_at)
        if verdict.action is Action.ALLOW:
            await m.reply("No strong phishing signals found. If it still feels off, verify with the sender another way.")
        else:
            await m.reply(f"⚠️ Likely phishing (score {verdict.score}): {verdict.summary()}.\n"
                          "Do not click it. If you already did: change that password, enable 2FA, and log out other sessions.")
        if escalate and suspect:
            await self.alert(f"**Possible compromised account**: {suspect} (`{suspect.id}`) reported by several "
                             f"people for sending: {verdict.summary()}. Links: "
                             f"{', '.join(defang(l) for l in verdict.links) or '-'}")

    async def handle_command(self, m: discord.Message) -> None:
        if not isinstance(m.author, discord.Member) or not m.author.guild_permissions.manage_guild:
            return
        parts = m.content.split()
        if len(parts) < 3 or not parts[2].strip("<@!>").isdigit():
            await m.reply(f"Usage: `{PREFIX} approve <user>` | `{PREFIX} compromised <user>`")
            return
        cmd, uid = parts[1], int(parts[2].strip("<@!>"))
        member = m.guild.get_member(uid)
        if cmd == "approve":
            self.engine.approve(str(uid))
            if member and self.hold_role_id:
                await member.remove_roles(discord.Object(self.hold_role_id), reason=f"TrustGuard approved by {m.author}")
            await m.reply(f"Approved `{uid}`.")
        elif cmd == "compromised":
            names = [member.name, member.display_name] if member else []
            self.engine.mark_compromised(str(uid), names, discord.utils.utcnow())
            if member:
                await member.kick(reason=f"TrustGuard: marked compromised by {m.author}")
            await m.reply(f"Marked `{uid}` as compromised. New joins are held for re-verification during lockdown.")

    async def on_member_ban(self, guild: discord.Guild, user: discord.User) -> None:
        self.engine.record_ban(str(user.id), [user.name, getattr(user, "display_name", "")], discord.utils.utcnow())

    async def on_member_join(self, member: discord.Member) -> None:
        decision = self.engine.process_join(JoinEvent(
            platform="discord", user_id=str(member.id), username=member.name,
            display_name=member.display_name, joined_at=member.joined_at or discord.utils.utcnow(),
            account_created_at=member.created_at))
        if not decision.hold:
            return
        if self.hold_role_id:
            try:
                await member.add_roles(discord.Object(self.hold_role_id), reason="TrustGuard re-verification")
            except discord.Forbidden:
                pass
        await self.alert(f"**Join held for re-verification**: {member} (`{member.id}`) - {'; '.join(decision.reasons)}.\n"
                         f"Confirm their identity out-of-band (call / in person), then `{PREFIX} approve {member.id}`.")


def main() -> None:
    load_env()
    require("DISCORD_TOKEN", "TRUSTGUARD_MOD_CHANNEL_ID")
    hold_role = os.environ.get("TRUSTGUARD_HOLD_ROLE_ID")
    config = EngineConfig.from_env()
    client = TrustGuardDiscord(
        TrustGuard(config),
        mod_channel_id=int(os.environ["TRUSTGUARD_MOD_CHANNEL_ID"]),
        hold_role_id=int(hold_role) if hold_role else None,
    )
    client.run(os.environ["DISCORD_TOKEN"])


if __name__ == "__main__":
    main()
