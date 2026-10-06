import unittest
from aegis import db, store, runner
from aegis.tentacles import ct, dns
ROWS=[{"id":1,"name_value":"a.test.com\n*.test.com","issuer_name":"X"},{"id":2,"name_value":"mail.test.com\nevil.com"}]
class T(unittest.TestCase):
    def test_names(self):
        n=ct.names_from_rows(ROWS,"test.com"); self.assertEqual(set(n),{"a.test.com","test.com","mail.test.com"})
    def test_resolve_disagree(self):
        f=lambda n,t,r:["1.1.1.1"] if r=="1.1.1.1" else ["2.2.2.2"]
        r=dns.resolve("x","A",["1.1.1.1","8.8.8.8"],f); self.assertFalse(r["agree"]); self.assertEqual(r["values"],["1.1.1.1","2.2.2.2"])
    def test_dedupe_run(self):
        c=db.connect(":memory:"); c.execute("INSERT INTO organization(name) VALUES('o')")
        store.upsert_asset(c,1,"domain","test.com",1,1,"VERIFIED")
        ctf=lambda c,a:[{"asset_value":n,"key":"ct_certs","value":sorted(v["certs"])} for n,v in ct.names_from_rows(ROWS,"test.com").items()]
        dnf=lambda c,a:[{"key":"dns_A","value":["9.9.9.9"],"agree":True}]
        s1=runner.run_org(c,"o",log=lambda *_:0,ct_fn=ctf,dns_fn=dnf); s2=runner.run_org(c,"o",log=lambda *_:0,ct_fn=ctf,dns_fn=dnf)
        self.assertGreater(s1["obs_new"],0); self.assertEqual(s2["obs_new"],0); self.assertEqual(s2["assets_new"],0)
        self.assertEqual(c.execute("SELECT count(*) FROM edge WHERE rel='resolves_to'").fetchone()[0],3)
if __name__=="__main__": unittest.main()
