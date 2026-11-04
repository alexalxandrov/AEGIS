import builtins
import types
import urllib.request
import urllib.error
import pytest

from aegis.tentacles.subtakeover import Subtakeover


def _mock_urlopen_factory(return_code=200, raise_exc=None):
    """Return a function that mimics urllib.request.urlopen.

    If *raise_exc* is supplied, it is raised instead of returning a
    response object.
    """

    class MockResponse:
        def __init__(self, code):
            self.code = code

        def getcode(self):
            return self.code

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

    def mock_urlopen(req, timeout=None):  # pragma: no cover – simple wrapper
        if raise_exc:
            raise raise_exc
        return MockResponse(return_code)

    return mock_urlopen


@pytest.fixture
def mock_dns(monkeypatch):
    """Patch the DNS.resolve method to return a deterministic target."""
    def _resolve(self, domain, rtype):  # noqa: D401
        return {"values": ["target.fake"]}

    monkeypatch.setattr("aegis.tentacles.subtakeover.DNS.resolve", _resolve, raising=False)


def test_takeover_https_404(monkeypatch, mock_dns):
    """HTTPS 404 should trigger a takeover flag."""
    monkeypatch.setattr(urllib.request, "urlopen", _mock_urlopen_factory(return_code=404))
    result = Subtakeover.check("example.com")
    assert result[0]["value"] is True


def test_takeover_fallback_http(monkeypatch, mock_dns):
    """HTTPS 200 but HTTP 404 should still trigger takeover."""
    # First call (HTTPS) returns 200, second call (HTTP) returns 404
    call_order = []

    def side_effect(req, timeout=None):
        url = req.full_url
        call_order.append(url)
        if url.startswith("https://"):
            return _mock_urlopen_factory(return_code=200)()(req)
        return _mock_urlopen_factory(return_code=404)()(req)

    monkeypatch.setattr(urllib.request, "urlopen", side_effect)
    result = Subtakeover.check("example.com")
    assert result[0]["value"] is True
    # Ensure the fallback was used
    assert any(url.startswith("http://") for url in call_order)


def test_no_takeover(monkeypatch, mock_dns):
    """Both HTTPS and HTTP 200 should result in no takeover."""
    monkeypatch.setattr(urllib.request, "urlopen", _mock_urlopen_factory(return_code=200))
    result = Subtakeover.check("example.com")
    assert result[0]["value"] is False