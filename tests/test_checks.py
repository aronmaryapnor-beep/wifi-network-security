import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wifi_audit.checks import audit, check_security_mode, check_encryption, check_passphrase  # noqa: E402
from wifi_audit.passphrase import evaluate  # noqa: E402
from wifi_audit.report import to_html, to_markdown  # noqa: E402


def load(name):
    return json.loads((ROOT / "configs" / name).read_text(encoding="utf-8"))


class TestChecks(unittest.TestCase):
    def test_secure_config_scores_high(self):
        _, s = audit(load("sample_secure_config.json"))
        self.assertGreaterEqual(s["score"], 90)
        self.assertEqual(s["failed"], 0)

    def test_insecure_config_scores_low(self):
        _, s = audit(load("sample_insecure_config.json"))
        self.assertLess(s["score"], 25)
        self.assertGreater(s["failed"], 5)

    def test_mixed_config_has_unknowns(self):
        _, s = audit(load("sample_mixed_config.json"))
        self.assertGreater(s["unknown"], 0)
        self.assertGreater(s["warnings"], 0)

    def test_protocol_rules(self):
        self.assertEqual(check_security_mode({"security_mode": "WEP"}).status, "FAIL")
        self.assertEqual(check_security_mode({"security_mode": "Open"}).status, "FAIL")
        self.assertEqual(check_security_mode({"security_mode": "WPA-Personal"}).status, "FAIL")
        self.assertEqual(check_security_mode({"security_mode": "WPA2-Personal"}).status, "PASS")
        self.assertEqual(check_security_mode({"security_mode": "WPA3-Personal"}).status, "PASS")
        self.assertEqual(check_security_mode({"security_mode": "WPA2/WPA3-Personal"}).status, "WARN")
        self.assertEqual(check_security_mode({}).status, "UNKNOWN")

    def test_encryption_rules(self):
        self.assertEqual(check_encryption({"encryption": "TKIP"}).status, "FAIL")
        self.assertEqual(check_encryption({"encryption": "AES+TKIP"}).status, "WARN")
        self.assertEqual(check_encryption({"encryption": "AES"}).status, "PASS")
        self.assertEqual(check_encryption({"encryption": "CCMP"}).status, "PASS")

    def test_passphrase_length_rule(self):
        self.assertEqual(check_passphrase({"passphrase_length": 8}).status, "FAIL")
        self.assertEqual(check_passphrase({"passphrase_length": 14}).status, "WARN")
        self.assertEqual(check_passphrase({"passphrase_length": 20}).status, "PASS")

    def test_reports_render(self):
        cfg = load("sample_mixed_config.json")
        f, s = audit(cfg)
        self.assertIn("Wi-Fi Security Assessment Report", to_markdown(cfg, f, s))
        self.assertIn("<html", to_html(cfg, f, s))


class TestPassphrase(unittest.TestCase):
    def test_weak(self):
        self.assertEqual(evaluate("password")["rating"], "Weak")
        self.assertEqual(evaluate("12345678")["rating"], "Weak")

    def test_strong(self):
        self.assertEqual(evaluate("correct-Horse7battery!staple")["rating"], "Strong")


if __name__ == "__main__":
    unittest.main()
