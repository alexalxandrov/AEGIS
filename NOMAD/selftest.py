#!/usr/bin/env python3
"""Offline smoke tests for NOMAD. Does not perform network requests."""
import asyncio
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import start
from storage import SQLiteStorage


class NomadOfflineTests(unittest.TestCase):

    def test_sqlite_storage_roundtrip_integrity_and_external_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "start.py").write_text("first version", encoding="utf-8")
            (root / "index.html").write_text("<html>test</html>", encoding="utf-8")
            db_path = Path(directory) / "data" / "nomad.sqlite3"
            progress = []

            store = SQLiteStorage(db_path)
            first = store.initialize(root, lambda item: progress.append(dict(item)))
            self.assertTrue(first["integrity"]["ok"])
            self.assertTrue(first["hashes"]["baseline_established"])
            self.assertTrue(any(item["stage"] == "file_hash" for item in progress))
            self.assertTrue(any(item["stage"] == "integrity" for item in progress))
            self.assertTrue(any(item["stage"] == "restore" for item in progress))

            store.save_entity({"id": "IP:192.0.2.10", "kind": "ip", "label": "192.0.2.10", "first_seen": "2026-11-01T00:00:00+00:00"})
            store.save_route({"id": "route:test", "kind": "bgp", "observed_at": "2026-11-01T00:00:00+00:00"})
            store.save_observation({"id": "obs:test", "time": "2026-11-01T00:00:00+00:00", "subject": "test"})
            store.save_event({"id": "event:test", "time": "2026-11-01T00:00:00+00:00", "message": "persisted"})
            store.save_active_result({"id": "active:test", "time": "2026-11-01T00:00:00+00:00", "method": "ping", "target": "192.0.2.10"})
            store.close()

            # A second process/connection can read the same ordinary SQLite file.
            with sqlite3.connect(str(db_path)) as external:
                self.assertEqual(external.execute("SELECT COUNT(*) FROM entities").fetchone()[0], 1)
                self.assertEqual(external.execute("PRAGMA integrity_check").fetchone()[0], "ok")

            (root / "start.py").write_text("modified version", encoding="utf-8")
            reopened = SQLiteStorage(db_path)
            restored = reopened.initialize(root, lambda item: progress.append(dict(item)))
            self.assertIn("start.py", restored["hashes"]["changed"])
            self.assertEqual(restored["entities"]["IP:192.0.2.10"]["label"], "192.0.2.10")
            self.assertEqual(restored["routes"]["route:test"]["kind"], "bgp")
            self.assertEqual(restored["observations"][0]["subject"], "test")
            self.assertEqual(restored["events"][0]["message"], "persisted")
            self.assertEqual(restored["active_results"][0]["target"], "192.0.2.10")
            reopened.close()

    def test_no_map_markup_or_styles_remain(self):
        from pathlib import Path
        html = (Path(start.ROOT) / "index.html").read_text(encoding="utf-8").lower()
        for marker in ('id="map"', "map-wrap", "map-placeholder", "map-card", "leaflet", "tile.openstreetmap.org"):
            self.assertNotIn(marker, html)
        self.assertIn('id="ipinventory"', html)
        self.assertIn('id="activeprobecontrols"', html)

    def test_map_free_intelligence_ui(self):
        from pathlib import Path
        html = (Path(start.ROOT) / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="ipInventory"', html)
        self.assertIn("renderOrgIntelligence", html)
        self.assertIn("company-group", html)
        self.assertIn("ip-record", html)
        self.assertIn("statCompanies", html)
        self.assertIn("statIps", html)
        self.assertIn("Registered network", html)
        self.assertIn("Reverse DNS / hostname", html)
        self.assertIn("Ports and services", html)
        self.assertNotIn("renderTopology", html)
        self.assertNotIn("statRoutes", html)
        self.assertNotIn("statEntities", html)
        self.assertNotIn("asnFrontier", html)
        self.assertNotIn('id="routesBody"', html)
        self.assertNotIn('id="entitiesBody"', html)
        self.assertNotIn("leaflet.js", html.lower())
        self.assertNotIn("tile.openstreetmap.org", html.lower())
        self.assertNotIn("map-wrap", html.lower())
        self.assertNotIn("map-placeholder", html.lower())
        self.assertNotIn('id="map"', html.lower())
        self.assertIn('id="currentTargetValue"', html)
        self.assertIn('id="hostQueueProgress"', html)
        self.assertIn('id="hostPingProgress"', html)
        self.assertIn('id="hostEnrichProgress"', html)
        self.assertIn('id="startupProgressRow"', html)


    def test_public_host_scan_config_is_explicit_and_bounded(self):
        payload = {
            "ping": {"enabled": True, "approved_targets": ["8.8.8.8"]},
            "host_scan": {
                "enabled": True,
                "approved_subnets": ["8.8.8.0/24", "8.8.0.0/16", "10.0.0.0/24", "0.0.0.0/0"],
                "concurrency": 999,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(start, "CONFIG_PATH", config_path):
                cfg = start.load_config()
        self.assertTrue(cfg["host_scan"]["enabled"])
        self.assertEqual(cfg["host_scan"]["approved_subnets"], ["8.8.8.0/24"])
        self.assertEqual(cfg["host_scan"]["concurrency"], 32)
        self.assertTrue(cfg["ping"]["enabled"])
        self.assertEqual(cfg["ping"]["approved_targets"], ["8.8.8.8"])

    def test_authorized_host_sweep_pings_then_enriches_live_hosts_serially(self):
        original_state = start.STATE
        original_config = start.CONFIG
        original_which = start.shutil.which
        original_create = asyncio.create_subprocess_exec
        original_inspect = start.inspect_resource
        inspected = []
        inspected_batches = []
        ping_counts = {}
        in_inspect = False

        class FakeProcess:
            returncode = 0
            async def communicate(self):
                return (b"1 packets transmitted, 1 packets received, 0.0% packet loss", None)
            def kill(self):
                pass

        async def fake_create(*args, **kwargs):
            batch = start.STATE.host_scan.get("batch_index", 0)
            ping_counts[batch] = ping_counts.get(batch, 0) + 1
            return FakeProcess()

        async def fake_inspect(address):
            nonlocal in_inspect
            if in_inspect:
                raise AssertionError("live-host enrichment must be serial")
            in_inspect = True
            batch = start.STATE.host_scan.get("batch_index", 0)
            expected = 100 if batch < 3 else 54
            if ping_counts.get(batch, 0) != expected:
                raise AssertionError("the complete ping batch must finish before enrichment")
            inspected.append(address)
            inspected_batches.append(batch)
            await asyncio.sleep(0)
            in_inspect = False

        async def run():
            start.STATE = start.NomadState()
            start.STATE.stop_event = asyncio.Event()
            start.CONFIG = dict(original_config)
            start.CONFIG["host_scan"] = {
                "enabled": True, "approved_subnets": ["8.8.8.0/24"],
                "max_hosts_per_subnet": 256, "concurrency": 2, "timeout_seconds": 3,
            }
            start.shutil.which = lambda name: "/sbin/ping"
            asyncio.create_subprocess_exec = fake_create
            start.inspect_resource = fake_inspect
            result = await start.run_authorized_host_scan()
            self.assertEqual(result["status"], "COMPLETE")
            self.assertEqual(result["queue_total"], 254)
            self.assertEqual(result["queue_completed"], 254)
            self.assertEqual(result["batch_total"], 3)
            self.assertEqual(result["batch_index"], 3)
            self.assertEqual(result["alive"], 254)
            self.assertEqual(result["enriched_total"], 254)
            self.assertEqual(result["enrichment_completed"], 54)
            self.assertEqual(len(inspected), 254)
            self.assertEqual(inspected_batches, [1] * 100 + [2] * 100 + [3] * 54)
            self.assertIsNone(start.STATE.current_target)

        try:
            asyncio.run(run())
        finally:
            start.STATE = original_state
            start.CONFIG = original_config
            start.shutil.which = original_which
            asyncio.create_subprocess_exec = original_create
            start.inspect_resource = original_inspect

    def test_sqlite_rejects_corrupt_json_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "start.py").write_text("test", encoding="utf-8")
            db_path = Path(directory) / "data" / "nomad.sqlite3"
            store = SQLiteStorage(db_path)
            store.initialize(root, lambda item: None)
            store.save_entity({"id": "IP:8.8.8.8", "kind": "ip", "label": "8.8.8.8"})
            with sqlite3.connect(str(db_path)) as conn:
                conn.execute("UPDATE entities SET payload=? WHERE id=?", ("{broken", "IP:8.8.8.8"))
            store.close()
            reopened = SQLiteStorage(db_path)
            with self.assertRaisesRegex(RuntimeError, "content check failed"):
                reopened.initialize(root, lambda item: None)
            reopened.close()

    def test_active_config_allowlists_are_sanitized(self):
        payload = {
            "ping": {"enabled": True, "approved_targets": ["8.8.8.8", "192.168.1.5", "localhost", "127.0.0.1"]},
            "arp_scan": {"enabled": True, "approved_subnets": ["192.168.2.0/24", "10.20.30.0/24", "10.0.0.0/8", "169.254.0.0/24"], "interface": "eth0;bad"}
        }
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(start, "CONFIG_PATH", config_path):
                config = start.load_config()
        self.assertEqual(config["ping"]["approved_targets"], ["8.8.8.8", "192.168.1.5"])
        self.assertEqual(config["arp_scan"]["approved_subnets"], ["192.168.2.0/24", "10.20.30.0/24"])
        self.assertEqual(config["arp_scan"]["interface"], "")

    def test_active_probes_are_allowlist_gated(self):
        original = start.CONFIG
        try:
            start.CONFIG = dict(original)
            start.CONFIG["ping"] = {"enabled": False, "approved_targets": ["8.8.8.8"], "interval_seconds": 30, "timeout_seconds": 8}
            start.CONFIG["arp_scan"] = {"enabled": False, "approved_subnets": ["192.168.1.0/24"], "interface": "eth0", "interval_seconds": 3600, "timeout_seconds": 25}
            with self.assertRaises(PermissionError):
                asyncio.run(start.run_ping("8.8.8.8"))
            with self.assertRaises(PermissionError):
                asyncio.run(start.run_ping("8.8.4.4"))
            with self.assertRaises(PermissionError):
                asyncio.run(start.run_arp_scan("192.168.1.0/24"))
            with self.assertRaises(PermissionError):
                asyncio.run(start.run_arp_scan("10.0.0.0/8"))
        finally:
            start.CONFIG = original

    def test_evidence_correlator_explains_inputs(self):
        original = start.STATE
        try:
            start.STATE = start.NomadState()
            start.STATE.entities["AS64500"] = {"id": "AS64500", "kind": "asn", "asn": 64500, "holder": "Example Network"}
            start.STATE.entities["IP:8.8.8.8"] = {"id": "IP:8.8.8.8", "kind": "ip", "ip": "8.8.8.8", "asns": [64500], "prefix": "8.8.8.0/24", "source": "RIPEstat network-info"}
            start.STATE.routes["neighbour"] = {"kind": "asn-neighbour", "as_path": [64500, 64501]}
            start.STATE.routes["path"] = {"kind": "bgp", "as_path": [64500, 64501], "prefix": "8.8.8.0/24"}
            start.STATE.entities["PREFIX:8.8.8.0/24"] = {"id": "PREFIX:8.8.8.0/24", "kind": "prefix", "prefix": "8.8.8.0/24", "asns": [64500], "source": "RIPEstat network-info"}
            result = start.correlate_network_evidence()
            org = next(x for x in result if x["kind"] == "organization")
            prefix = next(x for x in result if x["kind"] == "prefix")
            self.assertEqual(org["score"], 100)
            self.assertIn("RIPEstat AS overview holder", org["evidence"])
            self.assertEqual(prefix["score"], 100)
            self.assertIn("BGP route observation", prefix["evidence"])
        finally:
            start.STATE = original

    def test_active_probe_routes_require_local_allowlist(self):
        from fastapi.testclient import TestClient
        with TestClient(start.app, base_url=f"http://127.0.0.1:{start.CONFIG['port']}") as client:
            self.assertEqual(client.post("/api/active/ping", json={"target": "8.8.8.8"}).status_code, 403)
            self.assertEqual(client.post("/api/active/arp", json={"subnet": "192.168.1.0/24"}).status_code, 403)
            # Deferred SQLite initialization begins only after the first browser page request.
            self.assertEqual(client.get("/").status_code, 200)
            status = {}
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status = client.get("/api/status").json()
                if status["storage"]["startup"]["status"] == "READY":
                    break
                time.sleep(0.02)
            self.assertEqual(status["storage"]["startup"]["status"], "READY")
            self.assertTrue(status["storage"]["database"]["ready"])
            backup = client.post("/api/storage/backup")
            self.assertEqual(backup.status_code, 200)
            self.assertTrue(backup.content.startswith(b"SQLite format 3\x00"))

    def test_ip_registry_source_catalogue(self):
        self.assertEqual(start.RIPE_ENDPOINTS["whois"], "whois")
        self.assertEqual(start.RIPE_ENDPOINTS["reverse-dns-ip"], "reverse-dns-ip")
        self.assertIn("whois", start.ROLE_SOURCES["resource-scout"])
        self.assertIn("reverse-dns-ip", start.ROLE_SOURCES["geo-scout"])

    def test_parse_whois_metadata(self):
        raw = {
            "data": {
                "authorities": ["ripe"],
                "query_time": "2026-10-31T20:00:00Z",
                "records": [[
                    {"key": "inetnum", "value": "192.0.2.0 - 192.0.2.255"},
                    {"key": "netname", "value": "EXAMPLE-NET"},
                    {"key": "org-name", "value": "Example Hosting Ltd"},
                    {"key": "country", "value": "DE"},
                    {"key": "status", "value": "ASSIGNED PA"},
                    {"key": "created", "value": "2020-01-01T00:00:00Z"},
                    {"key": "last-modified", "value": "2025-01-01T00:00:00Z"},
                    {"key": "source", "value": "RIPE"},
                ]]
            }
        }
        parsed = start.parse_whois_metadata(raw)
        self.assertEqual(parsed["registry_network"], "192.0.2.0 - 192.0.2.255")
        self.assertEqual(parsed["registry_name"], "EXAMPLE-NET")
        self.assertEqual(parsed["registry_org"], "Example Hosting Ltd")
        self.assertEqual(parsed["registry_country"], "DE")
        self.assertEqual(parsed["registry_status"], "ASSIGNED PA")
        self.assertEqual(parsed["registry_authorities"], ["ripe"])
        self.assertEqual(parsed["registry_records_count"], 1)

    def test_enrich_ip_profile_stores_whois_and_ptr(self):
        original_state = start.STATE
        original_fetch = start.fetch_ripestat

        async def fake_fetch(source_id, params=None):
            if source_id == "whois":
                return {"data": {
                    "authorities": ["test"],
                    "records": [[
                        {"key": "inetnum", "value": "8.8.8.0 - 8.8.8.255"},
                        {"key": "netname", "value": "EXAMPLE-NET"},
                        {"key": "org-name", "value": "Example Network Ltd"},
                    ]],
                    "query_time": "2026-10-31T20:00:00Z",
                }}
            if source_id == "reverse-dns-ip":
                return {"data": {"result": "dns.example.test", "error": ""}}
            raise AssertionError(source_id)

        async def run():
            start.STATE = start.NomadState()
            start.fetch_ripestat = fake_fetch
            await start.enrich_ip_profile("8.8.8.8")
            entity = start.STATE.entities["IP:8.8.8.8"]
            self.assertEqual(entity["registry_network"], "8.8.8.0 - 8.8.8.255")
            self.assertEqual(entity["registry_name"], "EXAMPLE-NET")
            self.assertEqual(entity["registry_org"], "Example Network Ltd")
            self.assertEqual(entity["rdns"], "dns.example.test")
            self.assertEqual(entity["rdns_status"], "FOUND")
            self.assertEqual(entity["port_status"], "NOT_SCANNED_BY_POLICY")
            self.assertEqual(entity["device_status"], "NOT_IDENTIFIED")
            self.assertEqual(entity["os_status"], "NOT_IDENTIFIED")

        try:
            asyncio.run(run())
        finally:
            start.STATE = original_state
            start.fetch_ripestat = original_fetch

    def test_entity_upsert_preserves_first_seen(self):
        original_state = start.STATE
        try:
            start.STATE = start.NomadState()
            start.entity_upsert("IP:192.0.2.1", "ip", "192.0.2.1", source="test")
            first = start.STATE.entities["IP:192.0.2.1"]["first_seen"]
            start.entity_upsert("IP:192.0.2.1", "ip", "192.0.2.1", rdns="host.example")
            current = start.STATE.entities["IP:192.0.2.1"]
            self.assertEqual(current["first_seen"], first)
            self.assertEqual(current["rdns"], "host.example")
            self.assertIn("last_seen", current)
        finally:
            start.STATE = original_state

    def test_parse_asns(self):
        self.assertEqual(start.parse_asns([{"asn": 13335}, "AS15169", "19281", 20326]), [13335, 15169, 19281, 20326])

    def test_parse_as_path(self):
        self.assertEqual(start.parse_as_path("6939 1299 AS13335"), [6939, 1299, 13335])

    def test_geo_parser(self):
        got = start.recursive_fields({"data": {"city": "Vilnius", "country": "LT", "latitude": 54.6872, "longitude": 25.2797}})
        self.assertEqual(got["city"], "Vilnius")
        self.assertAlmostEqual(got["lat"], 54.6872)
        self.assertAlmostEqual(got["lon"], 25.2797)

    def test_freshness_parser(self):
        self.assertEqual(start.classify_route_freshness("not-a-date"), "UNKNOWN")
        self.assertIn(start.classify_route_freshness(start.utcnow()), {"RECENT", "STALE"})

    def test_source_allowlist_is_closed(self):
        async def run():
            with self.assertRaises(PermissionError):
                await start.fetch_ripestat("arbitrary-url", {"resource": "127.0.0.1"})
        asyncio.run(run())

    def test_local_probe_process_lifecycle(self):
        manager = start.ProbeProcessManager()
        manager.start()
        try:
            current = manager.snapshot()
            self.assertEqual(current["total"], 7)
            self.assertEqual(current["alive"], 7)
            self.assertEqual(len({item["pid"] for item in current["items"]}), 7)
            self.assertTrue(all(item["pid"] for item in current["items"]))

            async def denied_private_target():
                with self.assertRaises(start.ProbeRemoteError):
                    await manager.request("network-info", {"resource": "127.0.0.1"})
            asyncio.run(denied_private_target())
        finally:
            manager.stop_all()
        stopped = manager.snapshot()
        self.assertEqual(stopped["total"], 7)
        self.assertEqual(stopped["alive"], 0)
        self.assertTrue(all(item["status"] == "STOPPED" for item in stopped["items"]))


    def test_discovery_only_uses_discovery_scout_before_other_probes(self):
        original_state = start.STATE
        original_fetch = start.fetch_ripestat
        calls = []

        async def fake_fetch(source_id, params=None):
            calls.append(source_id)
            if source_id == "network-info":
                return {"data": {"prefix": "8.8.8.0/24", "asns": [15169]}}
            raise AssertionError(f"Non-discovery source called during fast search: {source_id}")

        async def run():
            start.STATE = start.NomadState()
            start.STATE.stop_event = asyncio.Event()
            start.STATE.work_event = asyncio.Event()
            start.fetch_ripestat = fake_fetch
            await start.inspect_resource("8.8.8.8", discovery_only=True)
            self.assertEqual(calls, ["network-info"])
            self.assertIn("8.8.8.8", start.STATE.ip_queue)
            self.assertIn("8.8.8.1", start.STATE.ip_queue)
            self.assertNotIn("8.8.8.8", start.STATE.ip_inspected)
            self.assertEqual(start.STATE.workers["route-scout"]["count"], 0)
            self.assertEqual(start.STATE.workers["geo-scout"]["count"], 0)

        try:
            asyncio.run(run())
        finally:
            start.STATE = original_state
            start.fetch_ripestat = original_fetch

    def test_frontier_drains_multiple_asns_without_network(self):
        original_state = start.STATE
        original_fetch = start.fetch_ripestat
        async def fake_fetch(source_id, params=None):
            resource = (params or {}).get("resource", "")
            if source_id == "network-info":
                mapping = {"1.1.1.1": ("1.1.1.0/24", [13335]), "8.8.8.8": ("8.8.8.0/24", [15169]), "9.9.9.9": ("9.9.9.0/24", [19281]), "8.8.8.1": ("8.8.8.0/24", [15169])}
                prefix, asns = mapping[resource]
                return {"data": {"prefix": prefix, "asns": asns}}
            if source_id == "looking-glass":
                if resource == "1.1.1.1":
                    return {"data": {"rrcs": [{"rrc": "rrc00", "location": "test", "peers": [{"peer": "192.0.2.1", "prefix": "8.8.8.0/24", "as_path": "13335 15169"}]}]}}
                return {"data": {"rrcs": []}}
            if source_id == "maxmind-geo-lite":
                return {"data": {}}
            if source_id == "whois":
                return {"data": {"authorities": ["test"], "records": [[{"key": "netname", "value": "TEST-NET"}]], "query_time": "2026-10-31T20:00:00Z"}}
            if source_id == "reverse-dns-ip":
                return {"data": {"result": resource.replace(".", "-") + ".example.test", "error": ""}}
            if source_id == "as-overview":
                return {"data": {"holder": "Synthetic Test AS", "announced": True}}
            if source_id == "asn-neighbours":
                nmap = {"AS13335": [15169, 19281], "AS15169": [20473], "AS19281": [24940, 6939], "AS20473": [], "AS24940": [], "AS6939": []}
                return {"data": {"neighbours": [{"asn": n, "type": "left", "power": 10} for n in nmap.get(resource, [])]}}
            raise AssertionError(source_id)
        async def run():
            start.STATE = start.NomadState()
            start.STATE.stop_event = asyncio.Event()
            start.STATE.work_event = asyncio.Event()
            start.fetch_ripestat = fake_fetch
            await start.scan_cycle()
            self.assertGreater(start.STATE.asn_expansion_count, 1)
            self.assertEqual(len(start.STATE.asn_queue), 0)
            self.assertIn("8.8.8.1", start.STATE.ip_inspected)
            self.assertEqual(start.STATE.entities["IP:8.8.8.1"]["rdns_status"], "FOUND")
            self.assertEqual(start.STATE.entities["IP:8.8.8.1"]["registry_name"], "TEST-NET")
            self.assertEqual(len(start.STATE.ip_queue), 0)
        try:
            asyncio.run(run())
        finally:
            start.STATE = original_state
            start.fetch_ripestat = original_fetch

    def test_asn_frontier_has_no_fixed_count_ceiling(self):
        original_state = start.STATE
        try:
            start.STATE = start.NomadState()
            for asn in range(1, 1001):
                start.queue_asn(asn, 1, "synthetic test")
            self.assertEqual(len(start.STATE.asn_queue), 1000)
        finally:
            start.STATE = original_state

    def test_asn_frontier_batch_limit_yields_to_scheduler(self):
        original_state = start.STATE
        original_inspect = start.inspect_asn
        async def fake_inspect(asn, refresh=False):
            start.STATE.asn_expanded.add(asn)
        async def run():
            start.STATE = start.NomadState()
            start.STATE.stop_event = asyncio.Event()
            start.inspect_asn = fake_inspect
            for asn in (64500, 64501, 64502):
                start.queue_asn(asn, 1, "batch test")
            processed = await start.process_asn_frontier(max_items=1)
            self.assertEqual(processed, 1)
            self.assertEqual(len(start.STATE.asn_queue), 2)
        try:
            asyncio.run(run())
        finally:
            start.STATE = original_state
            start.inspect_asn = original_inspect

    def test_ip_frontier_batch_limit_yields_to_scheduler(self):
        original_state = start.STATE
        original_inspect = start.inspect_resource
        async def fake_inspect(resource):
            start.STATE.ip_inspected.add(resource)
        async def run():
            start.STATE = start.NomadState()
            start.STATE.stop_event = asyncio.Event()
            start.inspect_resource = fake_inspect
            for ip in ("8.8.8.1", "1.1.1.1", "9.9.9.9"):
                start.queue_ip(ip, 1, "batch test")
            processed = await start.process_ip_frontier(max_items=1)
            self.assertEqual(processed, 1)
            self.assertEqual(len(start.STATE.ip_queue), 2)
        try:
            asyncio.run(run())
        finally:
            start.STATE = original_state
            start.inspect_resource = original_inspect

    def test_prefix_discovery_queues_one_public_representative_ip(self):
        original_state = start.STATE
        try:
            start.STATE = start.NomadState()
            start.queue_prefix_sample("8.8.8.0/24", 10, "test prefix")
            self.assertIn("8.8.8.1", start.STATE.ip_queue)
            start.queue_prefix_sample("10.0.0.0/8", 10, "private test prefix")
            self.assertEqual(len(start.STATE.ip_queue), 1)
        finally:
            start.STATE = original_state

    def test_stale_asns_are_queued_for_refresh(self):
        original_state = start.STATE
        original_interval = start.CONFIG["asn_refresh_interval_seconds"]
        try:
            start.STATE = start.NomadState()
            start.CONFIG["asn_refresh_interval_seconds"] = 300
            start.STATE.asn_expanded.add(64500)
            start.STATE.asn_last_expanded[64500] = start.time.monotonic() - 301.0
            self.assertEqual(start.queue_stale_asn_refreshes(), 1)
            self.assertTrue(start.STATE.asn_queue[64500]["refresh"])
        finally:
            start.STATE = original_state
            start.CONFIG["asn_refresh_interval_seconds"] = original_interval

    def test_coordinator_repeats_discovery_passes(self):
        original_state = start.STATE
        original_scan = start.scan_cycle
        original_interval = start.CONFIG["discovery_interval_seconds"]
        calls = []
        async def fake_scan(drain_frontiers=True, discovery_only=False):
            calls.append(len(calls) + 1)
            start.STATE.work_event.set()
            if len(calls) >= 3:
                start.STATE.stop_event.set()
        async def run():
            start.STATE = start.NomadState()
            start.STATE.stop_event = asyncio.Event()
            start.CONFIG["discovery_interval_seconds"] = -1
            start.scan_cycle = fake_scan
            await start.worker_loop()
        try:
            asyncio.run(run())
            self.assertEqual(len(calls), 3)
            self.assertEqual(start.STATE.state, "STOPPED")
        finally:
            start.STATE = original_state
            start.scan_cycle = original_scan
            start.CONFIG["discovery_interval_seconds"] = original_interval

    def test_local_api(self):
        from fastapi.testclient import TestClient
        with TestClient(start.app, base_url=f"http://127.0.0.1:{start.CONFIG['port']}") as client:
            self.assertEqual(start.STARTUP_PROGRESS["status"], "PENDING")
            self.assertIsNone(start.STORE._connection)
            response = client.get("/api/status")
            self.assertEqual(response.status_code, 200)
            body = response.json()
            self.assertIn("probes_total", body["metrics"])
            self.assertIn("probes_alive", body["metrics"])
            self.assertEqual(client.get("/").status_code, 200)
            deadline = time.time() + 10
            while start.STARTUP_PROGRESS["status"] not in ("READY", "ERROR") and time.time() < deadline:
                time.sleep(0.02)
            self.assertEqual(start.STARTUP_PROGRESS["status"], "READY")
            location = client.post("/api/probe-location", json={"lat": 54.6872, "lon": 25.2797, "accuracy": 150})
            self.assertEqual(location.status_code, 200)
            self.assertAlmostEqual(location.json()["probe_location"]["lat"], 54.6872)
            self.assertAlmostEqual(start.STATE.probe_location["lon"], 25.2797)
            self.assertEqual(client.delete("/api/probe-location").status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
