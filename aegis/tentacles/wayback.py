"""Пассивный источник: архивированные хосты из Wayback Machine CDX API."""
import json, time, urllib.request, urllib.parse
from .. import config
from ..tentacle import Tentacle

class Wayback(Tentacle):
    """Passive collection of archived hosts via Wayback Machine CDX API."""
    name = "wayback"
    active = False

    def run(self, conn, asset):
        """Return a list containing the set of archived hosts.

        The ``value`` of the asset is expected to be a domain name.
        """
        return [{"key": "wayback_hosts", "value": self.hosts(asset["value"])}]

    @staticmethod
    def hosts(domain, retries=2):
        url = (
            f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.quote('*.' + domain)}"
            "&output=json&fl=original&collapse=urlkey&limit=3000"
        )
        err = None
        for i in range(retries):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT})
                rows = json.load(urllib.request.urlopen(req, timeout=20))
                out = set()
                for r in rows[1:] if rows else []:
                    try:
                        h = urllib.parse.urlparse(r[0] if isinstance(r, list) else r).hostname
                    except Exception:
                        continue
                    if h and (h == domain or h.endswith("." + domain)):
                        out.add(h.lower())
                return out
            except Exception as e:
                err = e
                print(f"[wayback] hosts error: {e!r}")
                time.sleep(2 * (i + 1))
        # If all retries fail, return an empty set to avoid blocking the scan.
        return set()

# Compatibility shim: tests patch ``aegis.tentacles.wayback.hosts``
def hosts(*args, **kwargs):  # pragma: no cover
    """Proxy to :class:`Wayback.hosts`.

    The original API exposed ``hosts`` as a module‑level function.  The
    refactor moved it into the :class:`Wayback` class, but the test suite
    still patches the old location.  Providing this thin wrapper restores
    backwards compatibility without changing the public interface of the
    new implementation.
    """
    return Wayback.hosts(*args, **kwargs)
