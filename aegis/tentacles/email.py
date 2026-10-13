"""Пассивная проверка почтовой защиты домена: SPF, DMARC, DKIM-селекторы (частые)."""
from . import dns as dnsmod
from ..tentacle import Tentacle

DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "s1", "dkim"]

class Email(Tentacle):
    """Passive email security check: SPF, DMARC, DKIM selectors."""
    name = "email"
    active = False

    def run(self, conn, asset):
        """Return a list of observations for the supplied domain.

        Parameters
        ----------
        conn
            Connection object – unused for passive checks but kept for API
            compatibility.
        asset
            Asset record dictionary with ``value`` containing the domain.
        """
        return [self.check(asset["value"])]

    @staticmethod
    def check(name):
        out = {"spf": None, "dmarc": None, "dkim": []}
        for v in dnsmod.resolve(name, "TXT")["values"]:
            if v.strip('"').lower().startswith("v=spf1"):
                out["spf"] = v.strip('"')
        for v in dnsmod.resolve("_dmarc." + name, "TXT")["values"]:
            if v.strip('"').lower().startswith("v=dmarc1"):
                out["dmarc"] = v.strip('"')
        for sel in DKIM_SELECTORS:
            if dnsmod.resolve(f"{sel}._domainkey.{name}", "TXT")["values"]:
                out["dkim"].append(sel)
        return out

# Compatibility shim for the original module‑level ``check`` function.
def check(*args, **kwargs):  # pragma: no cover
    """Proxy to :meth:`Email.check`.

    The test suite patches ``aegis.tentacles.email.check`` expecting a
    function at the module level.  Providing this wrapper preserves that
    API contract while keeping the class‑based implementation.
    """
    return Email.check(*args, **kwargs)
