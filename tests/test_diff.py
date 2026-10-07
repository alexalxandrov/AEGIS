import unittest, json
from aegis import db, store, diff
class T(unittest.TestCase):
    def test_diff(self):
        c = db.connect(":memory:"); c.execute("INSERT INTO organization(name) VALUES('o')")
        a, _ = store.upsert_asset(c, 1, "ip", "8.8.8.8")
        store.observe(c, a, "intel", "internetdb", {"ports": [80]})
        c.execute("UPDATE observation SET first_seen=1000"); c.execute("UPDATE asset SET first_seen=1000")
        store.observe(c, a, "intel", "internetdb", {"ports": [80, 3389]})
        ev = diff.compute(c, 1, 2000)
        self.assertEqual([e["kind"] for e in ev], ["NEW_PORT"]); self.assertEqual(len(diff.save(c, ev)), 1); self.assertEqual(len(diff.save(c, ev)), 0)
    def test_empty_no_history(self):
        c = db.connect(":memory:"); a, _ = store.upsert_asset(c, 1, "domain", "x.com")
        self.assertFalse(store.observe(c, a, "dns", "dns_MX", [])); self.assertTrue(store.observe(c, a, "dns", "dns_MX", ["m.x.com"]))
        self.assertTrue(store.observe(c, a, "dns", "dns_MX", []))  # исчезла запись — фиксируем
    def test_expiry(self):
        c = db.connect(":memory:"); a, _ = store.upsert_asset(c, 1, "domain", "x.com")
        store.observe(c, a, "intel", "rdap", {"expires": "2020-01-01T00:00:00Z", "ns": []})
        self.assertEqual(diff.static_checks(c, 1)[0]["severity"], "critical")
if __name__ == "__main__": unittest.main()
