import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from trustguard.adapters import load_env, require


class EnvTests(unittest.TestCase):
    def test_env_file_is_read_without_overriding_the_shell(self):
        with tempfile.TemporaryDirectory() as d:
            env = Path(d) / ".env"
            env.write_text('# comment\nTG_TEST_A="from-file"\nTG_TEST_B=from-file\n\nnot a setting\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {"TG_TEST_B": "from-shell"}):
                load_env(env)
                self.assertEqual(os.environ["TG_TEST_A"], "from-file")
                self.assertEqual(os.environ["TG_TEST_B"], "from-shell")
            os.environ.pop("TG_TEST_A", None)

    def test_missing_or_placeholder_settings_stop_with_a_clear_message(self):
        with mock.patch.dict(os.environ, {"SLACK_BOT_TOKEN": "xoxb-replace-me", "TRUSTGUARD_MOD_CHANNEL_ID": "000000"}, clear=False):
            os.environ.pop("SLACK_APP_TOKEN", None)
            with self.assertRaises(SystemExit) as e:
                require("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "TRUSTGUARD_MOD_CHANNEL_ID")
            self.assertIn("SLACK_BOT_TOKEN, SLACK_APP_TOKEN, TRUSTGUARD_MOD_CHANNEL_ID", str(e.exception))

    def test_real_looking_settings_pass(self):
        with mock.patch.dict(os.environ, {"TRUSTGUARD_MOD_CHANNEL_ID": "C0FAKEMODS"}):
            require("TRUSTGUARD_MOD_CHANNEL_ID")


if __name__ == "__main__":
    unittest.main()
