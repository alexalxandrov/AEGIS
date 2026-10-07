import unittest
from aegis import db, store, runner
from aegis.tentacles import ct, dns
ROWS=[{"id":3,"name_value":"bad@a.test.com"},{"id":1,"name_value":"a.test.com\n*.test.com","issuer_name":"X"},{"id":2,"name_value":"mail.test.com\nevil.com"}]
class T(unittest.TestCase):
    def test_names(self):
        n=ct.names_from_rows(ROWS,"test.com"); self.assertEqual(set(n),{"a.test.com","test.com","mail.test.com"})
    def test_resolve_disagree(self):
        f=lambda n,t,r:["1.1.1.1"] if r=="1.1.1.1" else ["2.2.2.2"]
        r=dns.resolve("x","A",["1.1.1.1","8.8.8.8"],f); self.assertFalse(r["agree"]); self.assertEqual(r["values"],["1.1.1.1","2.2.2.2"])
    def test_dedupe_run(self):
        c=db.connect(":memory:"); c.execute("INSERT INTO organization(name) VALUES('o')")
        store.upsert_asset(c,1,"domain","test.com",1,1,"VERIFIED"); c.execute("INSERT INTO seed(org_id,kind,value,verified) VALUES(1,'domain','test.com',1)")
        ctf=lambda c,a:[{"asset_value":n,"key":"ct_certs","value":sorted(v["certs"])} for n,v in ct.names_from_rows(ROWS,"test.com").items()]
        dnf=lambda c,a:[{"key":"dns_A","value":["9.9.9.9"],"agree":True}]
        ipf=lambda ip:[{"key":"bgp","value":{"prefix":"9.9.9.0/24","asns":[{"asn":13335,"holder":"CLOUDFLARENET"}]}}]; domf=lambda d:[{"key":"rdap","value":{"ns":[]}}]
        kw=dict(log=lambda *_:0,ct_fn=ctf,dns_fn=dnf,ip_fn=ipf,dom_fn=domf)
        s1=runner.run_org(c,"o",**kw); s2=runner.run_org(c,"o",**kw)
        self.assertEqual(c.execute("SELECT scope FROM asset WHERE value='9.9.9.9'").fetchone()[0],"THIRD_PARTY")
        self.assertGreater(s1["obs_new"],0); self.assertEqual(s2["obs_new"],0); self.assertEqual(s2["assets_new"],0)
        self.assertEqual(c.execute("SELECT count(*) FROM edge WHERE rel='resolves_to'").fetchone()[0],3)


class T2(unittest.TestCase):
    def test_fallback_system(self):
        f=lambda n,t,r: None if r!="system" else ["5.5.5.5"]
        r=dns.resolve("x","A",["1.1.1.1","8.8.8.8"],f); self.assertEqual(r["values"],["5.5.5.5"])

class T3(unittest.TestCase):
    def test_registrable(self):
        from aegis.tentacles.intel import registrable, is_third_party
        self.assertEqual(registrable("scanme.nmap.org"), "nmap.org"); self.assertEqual(registrable("a.b.example.co.uk"), "example.co.uk")
        self.assertFalse(is_third_party(63949, "AKAMAI-LINODE-AP Akamai Connected Cloud")); self.assertTrue(is_third_party(13335, ""))
if __name__=="__main__": unittest.main()
