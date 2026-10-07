import unittest
from aegis import db, store, diff
class T(unittest.TestCase):
    def test_flow(self):
        c = db.connect(":memory:"); c.execute("INSERT INTO organization(name) VALUES('o')")
        a, _ = store.upsert_asset(c, 1, "ip", "8.8.8.8", scope="VERIFIED")
        store.observe(c, a, "intel", "internetdb", {"ports": [80]}); diff.save(c, diff.compute(c, 1, 0))
        c.execute("UPDATE finding SET state='baseline'")
        self.assertEqual(diff.visible(c, diff.compute(c, 1, 0)), [])          # baseline скрыт
        store.observe(c, a, "intel", "internetdb", {"ports": [80, 23]})
        ev = diff.visible(c, diff.compute(c, 1, 0)); self.assertEqual([e["kind"] for e in ev], ["NEW_PORT"])
        diff.save(c, ev); self.assertEqual(diff.risk(c, 1)[0], 20)
        c.execute("UPDATE finding SET state='accepted' WHERE kind='NEW_PORT'"); self.assertEqual(diff.risk(c, 1)[0], 0)
    def test_third_party_zero(self):
        c = db.connect(":memory:"); a, _ = store.upsert_asset(c, 1, "ip", "1.1.1.1", scope="THIRD_PARTY")
        c.execute("INSERT INTO finding(asset_id,kind,severity,state) VALUES(?,?,?,?)", (a, "X", "critical", "open")); self.assertEqual(diff.risk(c, 1)[0], 0)
if __name__ == "__main__": unittest.main()
