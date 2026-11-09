"""Discord adapter behaviour with fake message objects. Skipped when discord.py is not installed
(CI installs it). All ids are fictional."""

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

try:
    import discord
    from trustguard.adapters.discord_adapter import TrustGuardDiscord, to_message
except ImportError:   # pragma: no cover
    discord = None

from trustguard.core import TrustGuard

T0 = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
LURE = "steamcommunnity.com/gift-card/pay/50"


def fake_message(content, author_id=111, guild=True, snapshots=()):
    author = SimpleNamespace(id=author_id, bot=False, created_at=T0 - timedelta(days=400),
                             mention=f"<@{author_id}>", __str__=lambda self: "user")
    channel = SimpleNamespace(id=222, mention="<#222>", send=mock.AsyncMock())
    return SimpleNamespace(id=333, content=content, author=author, channel=channel, created_at=T0,
                           guild=SimpleNamespace(id=1) if guild else None, message_snapshots=list(snapshots),
                           delete=mock.AsyncMock(), reply=mock.AsyncMock())


@unittest.skipIf(discord is None, "discord.py not installed")
class DiscordAdapterTests(unittest.TestCase):
    def setUp(self):
        self.client = TrustGuardDiscord(TrustGuard(), mod_channel_id=999, hold_role_id=None)
        self.mod = SimpleNamespace(send=mock.AsyncMock())
        self.client.get_channel = lambda cid: self.mod if cid == 999 else None

    def run_async(self, coro):
        return asyncio.run(coro)

    def alerts(self):
        return [c.args[0] for c in self.mod.send.await_args_list]

    def test_to_message_includes_forwarded_snapshot_text(self):
        m = to_message(fake_message("fyi", snapshots=[SimpleNamespace(content=LURE)]))
        self.assertEqual((m.platform, m.sender_id, m.destination_id), ("discord", "111", "222"))
        self.assertIn(LURE, m.text)

    def test_incident_lure_is_deleted_and_alert_is_defanged(self):
        m = fake_message(LURE)
        self.run_async(self.client.on_message(m))
        m.delete.assert_awaited_once()
        m.channel.send.assert_awaited_once()
        self.assertEqual(len(self.alerts()), 1)
        self.assertIn("Quarantined", self.alerts()[0])
        self.assertNotIn("steamcommunnity.com/gift", self.alerts()[0].split("Text:")[1])

    def test_owner_cannot_be_timed_out_but_delete_still_reported_as_done(self):
        m = fake_message(LURE)
        owner = mock.MagicMock(spec=discord.Member)
        owner.id, owner.bot, owner.created_at, owner.mention = 111, False, T0 - timedelta(days=400), "<@111>"
        owner.timeout = mock.AsyncMock(side_effect=discord.Forbidden(
            SimpleNamespace(status=403, reason="Forbidden"), "Missing Permissions"))
        m.author = owner
        self.run_async(self.client.on_message(m))
        m.delete.assert_awaited_once()
        self.assertIn("could not time out the sender", self.alerts()[0])
        self.assertNotIn("could not delete", self.alerts()[0])

    def test_benign_message_untouched(self):
        m = fake_message("hey, standup moved to 10:30 today")
        self.run_async(self.client.on_message(m))
        m.delete.assert_not_awaited()
        self.assertEqual(self.alerts(), [])

    def test_edit_into_a_lure_is_quarantined_but_unchanged_edits_are_ignored(self):
        before, after = fake_message("see you at lunch"), fake_message(LURE)
        self.run_async(self.client.on_message_edit(before, after))
        after.delete.assert_awaited_once()
        same = fake_message(LURE)
        self.run_async(self.client.on_message_edit(fake_message(LURE), same))
        same.delete.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
