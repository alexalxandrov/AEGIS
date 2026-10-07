import unittest
from unittest.mock import patch
from aegis import db, runner, diff

class T(unittest.TestCase):
    def test_wayback_and_brute_and_email(self):
        c = db.connect(":memory:"); c.execute("INSERT INTO organization(name) VALUES('o')")
        c.execute("INSERT INTO asset(org_id,kind,value,scope,first_seen,last_seen) VALUES(1,'domain','x.test','VERIFIED',0,0)")
        c.execute("INSERT INTO seed(org_id,kind,value,verified) VALUES(1,'domain','x.test',1)")
        ctf = lambda c, a: []; dnf = lambda c, a: []
        ipf = lambda ip: []; domf = lambda d: []
        with patch("aegis.tentacles.wayback.hosts", return_value={"old.x.test"}), \
             patch("aegis.tentacles.dns.resolve", side_effect=lambda n, t, *a: {"values": ["1.2.3.4"], "agree": True} if n == "brute1.x.test" and t == "A" else {"values": [], "agree": True}), \
             patch("aegis.wordlist.WORDS", ["brute1", "brute2"]), \
             patch("aegis.tentacles.email.check", return_value={"spf": None, "dmarc": None, "dkim": []}):
            stats = runner.run_org(c, "o", log=lambda *_: 0, ct_fn=ctf, dns_fn=dnf, ip_fn=ipf, dom_fn=domf, brute=True, wb=True)
        names = {r["value"] for r in c.execute("SELECT value FROM asset WHERE kind='domain'")}
        self.assertIn("old.x.test", names); self.assertIn("brute1.x.test", names); self.assertNotIn("brute2.x.test", names)
        kinds = {e["kind"] for e in diff.static_checks(c, 1)}
        self.assertEqual(kinds, {"NO_SPF", "NO_DMARC"})
if __name__ == "__main__": unittest.main()
