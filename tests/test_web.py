import unittest, threading, http.server
from aegis import db, store, runner, diff
from aegis.tentacles import web
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Server", "T/1"); self.send_header("X-Frame-Options", "DENY"); self.end_headers(); self.wfile.write(b"<title> Hi </title>")
    def log_message(self, *a): pass
class T(unittest.TestCase):
    def test_http(self):
        s = http.server.HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=s.serve_forever, daemon=True).start()
        r = web.probe_http("127.0.0.1", s.server_port, 3); s.shutdown()
        self.assertEqual((r["status"], r["title"], r["server"], r["sec"]["xfo"], r["sec"]["hsts"]), (200, "Hi", "T/1", True, False))
    def test_scope_blocks(self):
        c = db.connect(":memory:"); c.execute("INSERT INTO organization(name) VALUES('o')")
        store.upsert_asset(c, 1, "domain", "a.test"); store.upsert_asset(c, 1, "domain", "b.test", scope="VERIFIED")
        called = []
        runner.probe_org(c, "o", log=lambda *_: 0, web_fn=lambda cn, a: called.append(a["value"]) or [])
        self.assertEqual(called, ["b.test"]); self.assertEqual(c.execute("SELECT count(*) FROM action_log WHERE allowed=0").fetchone()[0], 1)
    def test_findings(self):
        c = db.connect(":memory:"); a, _ = store.upsert_asset(c, 1, "domain", "a.test")
        store.observe(c, a, "web", "tls", {"valid": False, "error": "expired"})
        store.observe(c, a, "web", "http_80", {"status": 200, "location": "", "sec": {}})
        self.assertEqual({e["kind"] for e in diff.static_checks(c, 1)}, {"TLS_INVALID", "NO_HTTPS_REDIRECT"})
    def test_header_removed(self):
        r = diff.classify({"value": "a"}, "http_443", {"sec": {"hsts": True}, "status": 200}, {"sec": {"hsts": False}, "status": 200})
        self.assertEqual(r[0], "HEADER_REMOVED")
if __name__ == "__main__": unittest.main()
