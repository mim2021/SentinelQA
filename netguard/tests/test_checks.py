"""Parser and decision tests on captured command output. MAC addresses are fictional
(locally administered 02:... range); IPs are private ranges or IANA's example.com addresses."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netguard import __main__ as cli
from netguard import checks

WIN_ARP = """
Interface: 192.168.1.23 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           02-11-22-33-44-55     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
MAC_ARP = "? (192.168.1.1) at 2:11:22:33:44:55 on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n"
LINUX_NEIGH = "192.168.1.1 dev wlan0 lladdr 02:11:22:33:44:55 REACHABLE\nfe80::1 dev wlan0 lladdr 02:11:22:33:44:55 router STALE\n"

WIN_ROUTE = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     10.10.0.1      10.10.0.50     50
          0.0.0.0          0.0.0.0    192.168.1.1     192.168.1.23     35
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
"""
MAC_ROUTE = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n"
LINUX_ROUTE = "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.23 metric 600\n"

WIN_WLAN = """
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : Cafe Free WiFi
    BSSID                  : 02:aa:bb:cc:dd:ee
"""

PUBLIC_A = ["93.184.215.14", "93.184.216.34"]


class ParserTests(unittest.TestCase):
    def test_neighbors_on_every_platform(self):
        for out in (WIN_ARP, MAC_ARP, LINUX_NEIGH):
            self.assertEqual(checks.parse_neighbors(out)["192.168.1.1"], "02:11:22:33:44:55")
        self.assertNotIn("192.168.1.9", checks.parse_neighbors(MAC_ARP))

    def test_default_gateway_on_every_platform(self):
        self.assertEqual(checks.parse_default_gateway(WIN_ROUTE), "192.168.1.1")   # lowest metric wins
        self.assertEqual(checks.parse_default_gateway(MAC_ROUTE), "192.168.1.1")
        self.assertEqual(checks.parse_default_gateway(LINUX_ROUTE), "192.168.1.1")
        self.assertIsNone(checks.parse_default_gateway(""))

    def test_ssid(self):
        self.assertEqual(checks.parse_ssid(WIN_WLAN), "Cafe Free WiFi")              # not the BSSID line
        self.assertEqual(checks.parse_ssid("no:Other\nyes:Office Net\n"), "Office Net")
        self.assertEqual(checks.parse_ssid("Current Wi-Fi Network: Home\n"), "Home")
        self.assertIsNone(checks.parse_ssid("There is no wireless interface on the system."))

    def test_network_id_hides_ssid(self):
        nid = checks.network_id("Cafe Free WiFi", "192.168.1.1")
        self.assertNotIn("Cafe", nid)
        self.assertNotEqual(nid, checks.network_id("Cafe Free WiFi", "192.168.1.254"))


class DecisionTests(unittest.TestCase):
    def test_gateway_change_is_critical(self):
        f = checks.gateway_finding("02:11:22:33:44:55", "02:66:77:88:99:00", "Cafe Free WiFi")
        self.assertEqual((f.severity, f.code), ("critical", "gateway_changed"))
        self.assertIsNone(checks.gateway_finding("02:11:22:33:44:55", "02:11:22:33:44:55", None))
        self.assertIsNone(checks.gateway_finding(None, "02:11:22:33:44:55", None))

    def test_private_answer_for_public_host_is_critical(self):
        f = checks.dns_finding("slack.com", ["192.168.1.1"], PUBLIC_A)
        self.assertEqual(f.code, "dns_private_answer")
        self.assertEqual(f.severity, "critical")

    def test_dns_same_block_is_consistent_disjoint_is_a_note_and_a_warning_with_cert_error(self):
        self.assertIsNone(checks.dns_finding("x.example", ["93.184.215.14"], ["93.184.216.34"]))
        self.assertEqual(checks.dns_finding("x.example", ["104.18.0.1"], PUBLIC_A).severity, "info")
        self.assertEqual(checks.dns_finding("x.example", ["104.18.0.1"], PUBLIC_A, cert_error=True).severity, "warn")
        self.assertIsNone(checks.dns_finding("x.example", [], PUBLIC_A))
        # a note alone keeps the overall verdict OK
        self.assertEqual(checks.overall([checks.dns_finding("x.example", ["104.18.0.1"], PUBLIC_A)]), "ok")

    def test_tls(self):
        self.assertIsNone(checks.tls_finding("slack.com", None, False))
        self.assertEqual(checks.tls_finding("slack.com", "self-signed certificate", True).severity, "critical")
        self.assertEqual(checks.tls_finding("slack.com", "TimeoutError", False).severity, "info")

    def test_overall(self):
        self.assertEqual(checks.overall([]), "ok")
        self.assertEqual(checks.overall([checks.Finding("info", "a", ""), checks.Finding("warn", "b", "")]), "warn")


class CliTests(unittest.TestCase):
    """End to end with the probes replaced: first visit records, a swapped router is flagged."""

    def run_check(self, state, mac):
        with mock.patch.object(cli.probes, "gateway_output", return_value=LINUX_ROUTE), \
             mock.patch.object(cli.probes, "ssid_output", return_value="yes:Cafe Free WiFi\n"), \
             mock.patch.object(cli.probes, "neighbors_output", return_value=f"192.168.1.1 dev wlan0 lladdr {mac} REACHABLE\n"), \
             mock.patch.object(cli.probes, "tls_probe", return_value=(None, False)), \
             mock.patch("builtins.print"):
            return cli.main(["check", "--no-doh", "--host", "slack.com", "--state", str(state)])

    def test_first_visit_then_evil_twin(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "baseline.json"
            self.assertEqual(self.run_check(state, "02:11:22:33:44:55"), 0)
            stored = json.loads(state.read_text())
            self.assertNotIn("Cafe", json.dumps(stored))                     # SSID never stored in clear
            self.assertEqual(self.run_check(state, "02:11:22:33:44:55"), 0)
            self.assertEqual(self.run_check(state, "02:66:77:88:99:00"), 2)


if __name__ == "__main__":
    unittest.main()
