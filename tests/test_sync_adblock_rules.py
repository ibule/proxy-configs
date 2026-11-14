import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import sync_adblock_rules as s  # noqa: E402

SAMPLE = """[General]
bypass-system = true
[Rule]
# comment
DOMAIN-SUFFIX,Ad.Example.com,Reject
DOMAIN-SUFFIX,ad.example.com,Reject
DOMAIN,track.example.net,Reject
DOMAIN-KEYWORD,adkw,Reject
IP-CIDR,1.2.3.4/24,Reject
IP-CIDR,2001:db8::/32,Reject
DOMAIN-SUFFIX,metrics.keep.org,Reject
FINAL,DIRECT
[URL Rewrite]
DOMAIN-SUFFIX,not-a-rule.com,Reject
"""


class ParseTest(unittest.TestCase):
    def test_parse(self):
        rules = s.parse_rules(SAMPLE, {"keep.org"})
        self.assertEqual(
            rules,
            [
                "DOMAIN-SUFFIX,ad.example.com",
                "DOMAIN,track.example.net",
                "IP-CIDR,1.2.3.0/24,no-resolve",
                "IP-CIDR6,2001:db8::/32,no-resolve",
            ],
        )

    def test_validate_min(self):
        with self.assertRaises(s.SyncError):
            s.validate(["DOMAIN,a.com"], [])

    def test_validate_mass_delete(self):
        old = [f"DOMAIN,a{i}.com" for i in range(20000)]
        new = old[:14000] + [f"DOMAIN,b{i}.com" for i in range(1000)]
        with self.assertRaises(s.SyncError):
            s.validate(new, old)

    def test_render_has_no_policy(self):
        out = s.render(["DOMAIN-SUFFIX,ad.example.com", "IP-CIDR,1.2.3.0/24,no-resolve"])
        self.assertIn("DOMAIN-SUFFIX,ad.example.com\n", out)
        self.assertNotIn("Reject", out)


if __name__ == "__main__":
    unittest.main()
