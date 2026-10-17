import unittest
from unittest.mock import patch
from aegis import db, runner, sources

class TestSourceQueryLoop(unittest.TestCase):
    def setUp(self):
        # Setup a minimal in-memory DB with one organization and one seed domain
        self.c = db.connect(":memory:")
        self.c.execute("INSERT INTO organization(name) VALUES('org1')")
        self.c.execute("INSERT INTO seed(org_id,kind,value,verified) VALUES(1,'domain','x.test',1)")

    def test_basic_source_invocation(self):
        # Counters for each external call
        counter = {
            "dns": 0,
            "email": 0,
            "archive": 0,
            "probe": 0,
            "http": 0,
            "binary": 0,
        }

        # Mock dns.resolve
        def dns_resolve(domain, record_type, *args, **kwargs):
            counter["dns"] += 1
            return {"values": ["1.2.3.4"], "agree": True}

        # Mock email check
        def email_check(domain):
            counter["email"] += 1
            return {"spf": None, "dmarc": None, "dkim": []}

        # Mock wayback.hosts
        def wayback_hosts(domain):
            counter["archive"] += 1
            return {"old.x.test"}

        # Mock web probe
        def web_probe_run(self, url, asset):
            counter["probe"] += 1
            return None

        # Mock urllib.request.urlopen
        class DummyResponse:
            def __init__(self):
                self.status = 200

        def urlopen(url, timeout=None):
            counter["http"] += 1
            return DummyResponse()

        # Mock shutil.which
        def which(name):
            counter["binary"] += 1
            return "/usr/bin/true"

        # Patch all external dependencies
        with patch("aegis.tentacles.dns.resolve", side_effect=dns_resolve), \
             patch("aegis.tentacles.email.check", side_effect=email_check), \
             patch("aegis.tentacles.wayback.hosts", side_effect=wayback_hosts), \
             patch("aegis.tentacles.web.Web.run", side_effect=web_probe_run), \
             patch("urllib.request.urlopen", side_effect=urlopen), \
             patch("shutil.which", side_effect=which):
            # Run the org with dummy functions for ct/dns/dns_intel
            runner.run_org(
                self.c,
                "org1",
                log=lambda *_, **__: None,
                ct_fn=lambda c, a: [],
                dns_fn=lambda c, a: [],
                ip_fn=lambda ip: [],
                dom_fn=lambda d: [],
                brute=False,
                wb=True,
            )

        # Assert each source type was invoked at least once
        self.assertGreater(counter["dns"], 0, "DNS query not called")
        self.assertGreater(counter["email"], 0, "Email check not called")
        self.assertGreater(counter["archive"], 0, "Wayback not called")
        self.assertGreater(counter["probe"], 0, "Active probe not called")
        self.assertGreater(counter["http"], 0, "HTTP source not called")
        self.assertGreater(counter["binary"], 0, "Binary check not called")

    def test_requires_key_source_skipped(self):
        # Add a fake source that requires an API key
        fake_source = {
            "name": "keyed_source",
            "category": "custom",
            "mode": "passive",
            "requires_key": 1,
            "check": "http",
            "url": "https://example.com/api",
        }
        original_registry = list(sources.REGISTRY)
        sources.REGISTRY.append(fake_source)

        try:
            # Patch urlopen to raise if called
            with patch("urllib.request.urlopen", side_effect=Exception("should not be called")):
                runner.run_org(
                    self.c,
                    "org1",
                    log=lambda *_, **__: None,
                    ct_fn=lambda c, a: [],
                    dns_fn=lambda c, a: [],
                    ip_fn=lambda ip: [],
                    dom_fn=lambda d: [],
                    brute=False,
                    wb=True,
                )
        finally:
            # Restore registry
            sources.REGISTRY[:] = original_registry
