import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from trustguard.core import Action, EngineConfig, JoinEvent, Message, TrustGuard, defang, defang_text
from trustguard.core.mass_message import fingerprint
from trustguard.core.scoring import brand_impersonation, extract_links, score_text

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "messages.json").read_text(encoding="utf-8"))
T0 = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


def msg(text, sender="u1", dest="c1", at=T0, created=None):
    return Message("test", "m", sender, dest, text, at, sender_created_at=created)


class ScoringTests(unittest.TestCase):
    def test_extracts_scheme_and_bare_links(self):
        self.assertEqual(extract_links("go https://a.example.com/x."), ["https://a.example.com/x"])
        self.assertEqual(extract_links("steamcommunnity.com/gift-card/pay/50"), ["steamcommunnity.com/gift-card/pay/50"])
        self.assertEqual(extract_links("see file.txt or e.g this"), [])

    def test_brand_impersonation_matches_extension_rules(self):
        self.assertEqual(brand_impersonation("steamcommunnity.com"), ("Steam", "lookalike"))
        self.assertEqual(brand_impersonation("steam-giftcard.xyz"), ("Steam", "contains"))
        self.assertEqual(brand_impersonation("paypa1-secure.com")[0], "PayPal")
        self.assertIsNone(brand_impersonation("store.steampowered.com"))
        self.assertIsNone(brand_impersonation("stream.com"))

    def test_word_boundaries(self):
        reasons, _ = score_text("I know the gifted kids program")
        self.assertEqual([r.code for r in reasons], [])

    def test_masked_link_label_showing_another_domain(self):
        reasons, links = score_text("[steamcommunity.com](https://steam-gift.xyz/claim)")
        self.assertIn("masked_link", [r.code for r in reasons])
        self.assertEqual(links, ["https://steam-gift.xyz/claim"])
        honest, _ = score_text("[release notes](https://docs.example.com/r) and [example.com/x](https://www.example.com/x)")
        self.assertNotIn("masked_link", [r.code for r in honest])

    def test_trusted_domains_are_not_external(self):
        reasons, _ = score_text("https://docs.example-internal.com/x", {"example-internal.com"})
        self.assertNotIn("external_link", [r.code for r in reasons])


class EngineTests(unittest.TestCase):
    def test_incident_messages_are_flagged_and_benign_pass(self):
        tg = TrustGuard()
        for text in FIXTURES["phishing"]:
            self.assertNotEqual(tg.process_message(msg(text)).action, Action.ALLOW, text)
        for text in FIXTURES["benign"]:
            self.assertEqual(tg.process_message(msg(text, sender="u2")).action, Action.ALLOW, text)

    def test_exact_incident_link_is_quarantined(self):
        v = TrustGuard().process_message(msg("steamcommunnity.com/gift-card/pay/50"))
        self.assertEqual(v.action, Action.QUARANTINE)
        self.assertIn("brand_impersonation", [r.code for r in v.reasons])

    def test_mass_message_burst_escalates(self):
        tg = TrustGuard(EngineConfig(quarantine_at=200))  # isolate the burst signal
        text = "nice $20 gift https://example-shop.com/x"
        codes = []
        for i in range(3):
            v = tg.process_message(msg(text, dest=f"dm{i}", at=T0 + timedelta(minutes=i)))
            codes = [r.code for r in v.reasons]
        self.assertIn("mass_message", codes)

    def test_burst_window_expires(self):
        tg = TrustGuard()
        text = "$20 gift https://example-shop.com/x"
        for i in range(3):
            v = tg.process_message(msg(text, dest=f"dm{i}", at=T0 + timedelta(minutes=20 * i)))
        self.assertNotIn("mass_message", [r.code for r in v.reasons])

    def test_fingerprint_ignores_amounts_and_spacing(self):
        self.assertEqual(fingerprint("Gift  $50 now"), fingerprint("gift $100 now"))

    def test_new_account_signal(self):
        v = TrustGuard().process_message(msg("look https://example.org", created=T0 - timedelta(days=1)))
        self.assertIn("new_account", [r.code for r in v.reasons])

    def test_reports_escalate_after_two_reporters(self):
        tg = TrustGuard()
        text = "$50 steam gift https://steam-giftcard.xyz/claim"
        _, esc1 = tg.process_report("r1", "suspect", text, T0)
        _, esc_dup = tg.process_report("r1", "suspect", text, T0)
        _, esc2 = tg.process_report("r2", "suspect", text, T0 + timedelta(minutes=1))
        self.assertEqual((esc1, esc_dup, esc2), (False, False, True))

    def test_config_from_env(self):
        c = EngineConfig.from_env({"TRUSTGUARD_QUARANTINE_AT": "101", "TRUSTGUARD_TRUSTED_DOMAINS": "A.example, b.example"})
        self.assertEqual((c.warn_at, c.quarantine_at, c.state_path), (35, 101, None))
        self.assertEqual(c.trusted_domains, {"a.example", "b.example"})

    def test_defang(self):
        self.assertEqual(defang("https://evil.example/x"), "hxxps://evil[.]example/x")

    def test_defang_text_neutralises_every_link(self):
        out = defang_text("free gift steamcommunnity.com/gift and https://evil.example/x")
        self.assertNotIn("steamcommunnity.com", out)
        self.assertIn("hxxps://evil[.]example/x", out)


class RejoinTests(unittest.TestCase):
    def join(self, uid, name, at=T0, age_days=400):
        return JoinEvent("test", uid, name, name, at, account_created_at=at - timedelta(days=age_days))

    def test_attacker_rejoining_with_new_account_is_held(self):
        tg = TrustGuard()
        tg.mark_compromised("100", ["rahim.dev", "Rahim"], T0)
        d = tg.process_join(self.join("200", "rahim_dev", at=T0 + timedelta(days=5)))
        self.assertTrue(d.hold)
        self.assertTrue(any("resembles" in r for r in d.reasons))

    def test_lockdown_holds_everyone_then_expires(self):
        tg = TrustGuard()
        tg.mark_compromised("100", ["someone"], T0)
        self.assertTrue(tg.process_join(self.join("300", "unrelated", at=T0 + timedelta(hours=1))).hold)
        self.assertFalse(tg.process_join(self.join("301", "unrelated", at=T0 + timedelta(days=4))).hold)

    def test_same_id_rejoin_after_ban_held_until_approved(self):
        tg = TrustGuard()
        tg.record_ban("100", ["someone"], T0)
        self.assertTrue(tg.process_join(self.join("100", "someone", at=T0 + timedelta(days=10))).hold)
        tg.approve("100")
        self.assertFalse(tg.process_join(self.join("100", "someone", at=T0 + timedelta(days=10))).hold)

    def test_new_account_held(self):
        self.assertTrue(TrustGuard().process_join(self.join("400", "fresh", age_days=2)).hold)

    def test_normal_join_admitted(self):
        self.assertFalse(TrustGuard().process_join(self.join("500", "newhire")).hold)


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "state.db")
        self.engines = []

    def tearDown(self):
        for tg in self.engines:
            tg.close()
        self.tmp.cleanup()

    def engine(self):
        """A fresh engine on the same file, i.e. the bot after a restart."""
        for tg in self.engines:
            tg.close()
        self.engines.append(TrustGuard(EngineConfig(state_path=self.path)))
        return self.engines[-1]

    def join(self, uid, name, at):
        return JoinEvent("test", uid, name, name, at, account_created_at=at - timedelta(days=400))

    def test_removal_and_lockdown_survive_restart(self):
        self.engine().mark_compromised("100", ["rahim.dev"], T0)
        reasons = self.engine().process_join(self.join("200", "rahim_dev", T0 + timedelta(hours=1))).reasons
        self.assertTrue(any("resembles" in r for r in reasons))
        self.assertIn("community is in post-compromise lockdown", reasons)

    def test_approval_survives_restart_and_new_ban_revokes_it(self):
        tg = self.engine()
        tg.record_ban("100", ["someone"], T0)
        tg.approve("100")
        join = self.join("100", "someone", T0 + timedelta(days=10))
        tg = self.engine()
        self.assertFalse(tg.process_join(join).hold)
        tg.record_ban("100", ["someone"], T0 + timedelta(days=11))
        self.assertTrue(self.engine().process_join(join).hold)

    def test_store_holds_no_message_content(self):
        tg = self.engine()
        tg.process_message(msg("$50 steam gift https://steam-giftcard.xyz/claim"))
        tg.mark_compromised("100", ["someone"], T0)
        tg.close()
        db = sqlite3.connect(self.path)
        try:
            dump = "\n".join(db.iterdump())
            tables = {t for (t,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            db.close()
        self.assertNotIn("giftcard", dump)
        self.assertEqual(tables, {"removed", "approved", "lockdown"})


if __name__ == "__main__":
    unittest.main()
