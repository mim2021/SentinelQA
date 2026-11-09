"""Slack adapter behaviour against a fake WebClient. No Slack SDK or network needed.
All user/channel ids are fictional."""

import unittest
from datetime import datetime, timezone

from trustguard.adapters.slack_adapter import SlackGuard, shared_messages, to_message, unwrap_links
from trustguard.core import EngineConfig, TrustGuard

MOD = "C0MODS"
TS = str(datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc).timestamp())
LURE = "<https://steamcommunnity.com/gift-card/pay/50|steamcommunnity.com/gift-card/pay/50>"


class FakeClient:
    def __init__(self, users=None):
        self.posts, self.kicks = [], []
        self.users = users or {}

    def chat_postMessage(self, **kw):
        self.posts.append(kw)

    def users_info(self, user):
        return {"user": self.users.get(user, {"id": user, "name": user.lower()})}

    def conversations_kick(self, channel, user):
        self.kicks.append((channel, user))

    def to(self, channel):
        return [p["text"] for p in self.posts if p["channel"] == channel]


def channel_msg(text, user="U0ALICE", channel="C0GENERAL", ts=TS, **extra):
    return dict(type="message", user=user, channel=channel, channel_type="channel", text=text, ts=ts, **extra)


def dm(text, user="U0BOB", **extra):
    return dict(type="message", user=user, channel="D0BOB", channel_type="im", text=text, ts=TS, **extra)


class NormalizationTests(unittest.TestCase):
    def test_unwrap_links(self):
        self.assertEqual(unwrap_links("<https://a.example/x>"), "https://a.example/x")
        self.assertEqual(unwrap_links("<https://a.example/x|https://a.example/x>"), "https://a.example/x")
        self.assertEqual(unwrap_links("<https://evil.example/x|steamcommunity.com>"),
                         "[steamcommunity.com](https://evil.example/x)")
        self.assertEqual(unwrap_links("<mailto:a@b.example|a@b.example>"), "mailto:a@b.example")

    def test_to_message_and_shares(self):
        m = to_message(channel_msg(LURE))
        self.assertEqual((m.platform, m.sender_id, m.destination_id), ("slack", "U0ALICE", "C0GENERAL"))
        self.assertEqual(m.text, "https://steamcommunnity.com/gift-card/pay/50")
        ev = dm("", attachments=[{"is_share": True, "author_id": "U0ALICE", "text": LURE}, {"text": "no author"}])
        self.assertEqual(shared_messages(ev), [("U0ALICE", "https://steamcommunnity.com/gift-card/pay/50")])


class MessageTests(unittest.TestCase):
    def setUp(self):
        self.guard = SlackGuard(TrustGuard(), MOD)
        self.client = FakeClient()

    def test_incident_lure_gets_thread_warning_and_defanged_alert(self):
        self.guard.on_message(channel_msg(LURE), self.client)
        warning = self.client.posts[0]
        self.assertEqual((warning["channel"], warning["thread_ts"]), ("C0GENERAL", TS))
        self.assertIn("Likely phishing", warning["text"])
        alert = self.client.to(MOD)[0]
        self.assertIn("QUARANTINE", alert)
        self.assertNotIn("steamcommunnity.com", alert)   # every link defanged
        self.assertIn("steamcommunnity[.]com", alert)

    def test_masked_link_is_flagged(self):
        self.guard.on_message(channel_msg("new policy doc <https://login-portal.example.net/x|docs.example.com>"),
                              self.client)
        self.assertIn("actually opens example[.]net", self.client.posts[0]["text"])

    def test_benign_and_bot_and_system_messages_ignored(self):
        self.guard.on_message(channel_msg("hey, standup moved to 10:30 today"), self.client)
        self.guard.on_message(channel_msg(LURE, bot_id="B0BOT"), self.client)
        self.guard.on_message(channel_msg(LURE, subtype="channel_join"), self.client)
        self.assertEqual(self.client.posts, [])

    def test_edit_that_adds_a_lure_is_scored_but_unfurl_edits_are_not(self):
        edit = dict(type="message", subtype="message_changed", channel="C0GENERAL", channel_type="channel",
                    message={"user": "U0ALICE", "text": LURE, "ts": TS},
                    previous_message={"user": "U0ALICE", "text": "see you at lunch", "ts": TS})
        self.guard.on_message(edit, self.client)
        self.assertEqual(len(self.client.to(MOD)), 1)
        unfurl = dict(edit, previous_message={"user": "U0ALICE", "text": LURE, "ts": TS})
        self.guard.on_message(unfurl, self.client)
        self.assertEqual(len(self.client.to(MOD)), 1)

    def test_warning_stays_in_existing_thread(self):
        self.guard.on_message(channel_msg(LURE, ts="1791374500.000200", thread_ts="1791374400.000100"), self.client)
        self.assertEqual(self.client.posts[0]["thread_ts"], "1791374400.000100")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.guard = SlackGuard(TrustGuard(), MOD)
        self.client = FakeClient()

    def share(self, reporter):
        return dm("got this from Alice", user=reporter,
                  attachments=[{"is_share": True, "author_id": "U0ALICE", "text": LURE}])

    def test_shared_dm_gets_verdict_and_two_reporters_escalate(self):
        self.guard.on_message(self.share("U0BOB"), self.client)
        self.assertIn("Likely phishing", self.client.posts[-1]["text"])
        self.assertEqual(self.client.to(MOD), [])
        self.guard.on_message(self.share("U0CAROL"), self.client)
        alert = self.client.to(MOD)
        self.assertEqual(len(alert), 1)
        self.assertIn("<@U0ALICE>", alert[0])

    def test_pasted_report_without_sender_gets_tip(self):
        self.guard.on_message(dm("$50 steam gift for you https://steam-giftcard.xyz/claim"), self.client)
        self.assertIn("Share message", self.client.posts[-1]["text"])


class CommandAndJoinTests(unittest.TestCase):
    def setUp(self):
        self.guard = SlackGuard(TrustGuard(EngineConfig()), MOD, admin_ids={"U0ADMIN"}, remove_held=True)
        self.client = FakeClient(users={
            "U0ALICE": {"id": "U0ALICE", "name": "alice.dev", "profile": {"display_name": "Alice", "real_name": "Alice Example"}},
            "U0OWNER": {"id": "U0OWNER", "name": "owner", "is_owner": True},
            "U0EVIL": {"id": "U0EVIL", "name": "alice_dev", "profile": {"display_name": "Alice"}},
            "U0NEWHIRE": {"id": "U0NEWHIRE", "name": "newhire"},
        })

    def cmd(self, text, user="U0ADMIN"):
        self.guard.on_message(channel_msg(text, user=user, channel=MOD), self.client)
        return self.client.posts[-1]["text"]

    def test_non_admin_cannot_run_commands(self):
        self.assertIn("Only workspace admins", self.cmd("!tg compromised <@U0ALICE>", user="U0BOB"))

    def test_workspace_owner_can_run_commands(self):
        self.assertIn("Marked <@U0ALICE>", self.cmd("!tg compromised <@U0ALICE>", user="U0OWNER"))

    def test_usage_on_bad_command(self):
        self.assertIn("Usage", self.cmd("!tg compromised alice"))

    def test_lookalike_account_joining_channel_is_held_and_removed(self):
        self.cmd("!tg compromised <@U0ALICE>")
        self.guard.on_member_joined_channel({"user": "U0EVIL", "channel": "C0GENERAL"}, self.client)
        self.assertEqual(self.client.kicks, [("C0GENERAL", "U0EVIL")])
        self.assertIn("resembles removed account", self.client.to(MOD)[-1])

    def test_lockdown_does_not_hold_ordinary_channel_joins_but_holds_new_members(self):
        self.cmd("!tg compromised <@U0ALICE>")
        self.guard.on_member_joined_channel({"user": "U0NEWHIRE", "channel": "C0GENERAL"}, self.client)
        self.assertEqual(self.client.kicks, [])
        self.guard.on_team_join({"user": self.client.users["U0NEWHIRE"]}, self.client)
        self.assertIn("post-compromise lockdown", self.client.to(MOD)[-1])

    def test_approve_releases_hold(self):
        self.cmd("!tg removed <@U0ALICE>")
        self.cmd("!tg approve <@U0EVIL>")
        self.guard.on_member_joined_channel({"user": "U0EVIL", "channel": "C0GENERAL"}, self.client)
        self.assertEqual(self.client.kicks, [])

    def test_deactivated_user_is_recorded_as_removed(self):
        self.guard.on_user_change({"user": dict(self.client.users["U0ALICE"], deleted=True)}, self.client)
        self.guard.on_member_joined_channel({"user": "U0EVIL", "channel": "C0GENERAL"}, self.client)
        self.assertEqual(self.client.kicks, [("C0GENERAL", "U0EVIL")])


if __name__ == "__main__":
    unittest.main()
