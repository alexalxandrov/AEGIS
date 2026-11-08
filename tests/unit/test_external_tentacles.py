"""Unit tests for the minimal external API wrappers and caching logic.

These tests do not perform real network calls – the wrappers return
empty lists.  They mainly ensure that the public API exists and that the
TTL cache in :mod:`aegis.runner` behaves as expected.
"""

import builtins
import types
import pytest

import aegis.runner as runner
import aegis.config as config
from aegis.tentacles import virus_total, abuse_ipdb, shodan


def test_virus_total_lookup_returns_list():
    """The VirusTotal stub should return an empty list.
    The type and length are the only guarantees we can test.
    """
    result = virus_total.lookup_hash("dummyhash")
    assert isinstance(result, list)
    assert result == []


def test_abuse_ipdb_lookup_returns_list():
    result = abuse_ipdb.lookup_ip("1.2.3.4")
    assert isinstance(result, list)
    assert result == []


def test_shodan_lookup_returns_list():
    result = shodan.lookup_ip("1.2.3.4")
    assert isinstance(result, list)
    assert result == []


def test_cached_dns_uses_cache(monkeypatch):
    """Ensure that ``cached_dns`` calls the underlying resolver only once.
    We monkeypatch :func:`aegis.tentacles.dns.resolve` to record its usage.
    """
    call_count = 0

    def fake_resolve(name, rtype, resolvers):
        nonlocal call_count
        call_count += 1
        # return a deterministic structure mimicking dns.resolve
        return {"agree": True, "values": ["1.2.3.4"]}

    monkeypatch.setattr("aegis.tentacles.dns.resolve", fake_resolve)

    # First call – should hit the resolver
    result1 = runner.cached_dns("example.com", "A", tuple([]))
    assert result1["agree"] is True
    assert call_count == 1


def test_cached_dns_expiration(monkeypatch, capsys):
    """Verify that a cached entry expires after :data:`config.CACHE_TTL` seconds.

    The test temporarily overrides ``config.CACHE_TTL`` to a short value, performs a
    lookup, waits for the TTL to pass, and ensures that the resolver is invoked a
    second time.
    """
    import time

    call_count = 0

    def fake_resolve(name, rtype, resolvers):
        nonlocal call_count
        call_count += 1
        return {"agree": True, "values": ["10.0.0.1"]}

    monkeypatch.setattr("aegis.tentacles.dns.resolve", fake_resolve)

    # Use a very short TTL so we can wait without long delays.
    # ``cached_dns`` reads the TTL from the global ``_dns_resolver`` instance.
    monkeypatch.setattr(runner, "_dns_resolver", type("_Resolver", (), {"ttl": 1})(), raising=False)

    # First call – should invoke resolver
    first = runner.cached_dns("example.com", "A", tuple([]))
    assert first["agree"] is True
    assert call_count == 1

    # Immediate second call – should hit cache
    second = runner.cached_dns("example.com", "A", tuple([]))
    assert second is first
    assert call_count == 1

    # Wait for TTL to expire
    time.sleep(1.1)

    # Third call – should call resolver again
    third = runner.cached_dns("example.com", "A", tuple([]))
    assert third is not first
    assert call_count == 2

    # Second call with same args – should hit cache, not resolver
    result2 = runner.cached_dns("example.com", "A", tuple([]))
    assert result2 is result1  # same dict object from cache
    assert call_count == 1


def test_cached_email_uses_cache(monkeypatch):
    call_count = 0

    def fake_check(value):
        nonlocal call_count
        call_count += 1
        return [{"spam": False}]

    monkeypatch.setattr("aegis.tentacles.email.check", fake_check)

    res1 = runner.cached_email("test@example.com")
    assert res1[0]["spam"] is False
    assert call_count == 1

    res2 = runner.cached_email("test@example.com")
    assert res2 is res1
    assert call_count == 1
