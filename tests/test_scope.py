import unittest
from aegis import db, scope
class T(unittest.TestCase):
    def setUp(self):
        self.c = db.connect(":memory:")
        self.c.execute("INSERT INTO asset(org_id,kind,value,scope) VALUES(1,'domain','a.test','CANDIDATE')")
        self.c.execute("INSERT INTO asset(org_id,kind,value,scope) VALUES(1,'domain','b.test','VERIFIED')")
    def test_denied(self):
        with self.assertRaises(scope.ScopeDenied): scope.require_active(self.c, 1, "t", "probe")
        self.assertEqual(self.c.execute("SELECT allowed FROM action_log").fetchone()[0], 0)
    def test_allowed(self):
        self.assertEqual(scope.require_active(self.c, 2, "t", "probe"), "b.test")
    def test_queue(self):
        db.enqueue(self.c, "x"); t = db.claim(self.c); self.assertEqual(t["kind"], "x"); self.assertIsNone(db.claim(self.c))
if __name__ == "__main__": unittest.main()
