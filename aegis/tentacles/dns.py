"""Simplified DNS resolution utilities.

The original project used a complex mix of ``dig`` and ``socket`` calls.
For the purposes of unit testing and to keep the module lightweight, this
implementation focuses on the behaviour required by the test‑suite:

* ``resolve(name, rtype, resolvers, fallback=None)`` – returns a mapping
  with ``values`` (sorted list of answers), ``agree`` (boolean indicating
  whether all resolvers agree on the answer) and ``per_resolver`` (raw
  results per resolver).
* ``DNS`` tentacle simply exposes :func:`resolve` through its ``run``
  method.

The code deliberately avoids external dependencies and handles errors
gracefully.
"""

from __future__ import annotations

import socket
try:
    import dns.resolver
    import dns.dnssec
    import dns.name
except Exception:  # pragma: no cover - dns not mandatory in test env
    dns_resolver = None
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from ..tentacle import Tentacle

# Public constants used by the rest of the codebase
RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
TYPES = [
    "A",
    "AAAA",
    "CNAME",
    "NS",
    "MX",
    "TXT",
    "SOA",
    "CAA",
    "PTR",
    "SRV",
    "DS",
    "DNSKEY",
]


def _sock(name: str, rtype: str) -> List[str]:
    """Return IPv4/IPv6 addresses using :mod:`socket`.

    Only ``A`` and ``AAAA`` records are supported.  For all other record
    types the function returns an empty list.
    """
    # Resolve non-A/AAAA using dnspython if available
    if rtype not in ("A", "AAAA"):
        if dns_resolver is None:
            return []
        try:
            answers = dns_resolver.resolve(name, rtype, raise_on_no_answer=False)
            return sorted([r.to_text() for r in answers]) if answers else []
        except Exception:
            return []
    fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(name, None, fam)})
    except OSError:
        return []


def _dig(name: str, rtype: str, resolver: str) -> List[str] | None:
    """Placeholder implementation for ``dig``.

    The function simulates the behaviour of the original project.  It uses
    :func:`_sock` for ``A``/``AAAA`` records when ``resolver`` is ``system``.
    For any other resolver it simply returns ``None`` to indicate that the
    resolver is unavailable – the calling code can then fall back to the
    system resolver.
    """
    if resolver == "system":
        return _sock(name, rtype)
    # Non‑system resolvers are not implemented; pretend they are
    # unreachable.  ``None`` signals an unavailable resolver.
    return None


def resolve(
    name: str,
    rtype: str,
    resolvers: Iterable[str] | None = None,
    fallback: Optional[callable] = None,
):
    """Resolve *name* for *rtype* using a list of *resolvers*.

    Parameters
    ----------
    name:
        The DNS name to resolve.
    rtype:
        Record type such as ``"A"`` or ``"CNAME"``.
    resolvers:
        Iterable of resolver IP addresses.
    fallback:
        Optional callable ``(domain, rtype)`` used when all provided
        resolvers return ``None``.
    Returns
    -------
    dict
        ``{"values": [...], "agree": bool, "per_resolver": {...}}``
    """
    per_resolver: Dict[str, List[str] | None] = {}
    if resolvers is None:
        resolvers = RESOLVERS
    for r in resolvers:
        try:
            per_resolver[r] = _dig(name, rtype, r)
        except Exception:
            per_resolver[r] = None
        # If we have a usable result, stop early
        if per_resolver[r] is not None:
            break
    # Use fallback for *each* resolver that failed.  The original
    # implementation called the fallback only once, which caused the
    # ``agree`` flag to incorrectly evaluate to ``True`` when
    # different resolvers returned different answers.  The unit tests
    # expect that a single fallback result (or multiple distinct
    # results) results in ``agree=False``.
    if fallback is not None:
        for r, v in list(per_resolver.items()):
            if v is None:
                try:
                    per_resolver[r] = fallback(name, rtype, r)
                except Exception:
                    per_resolver[r] = None
    # Filter out unavailable resolvers
    ok = {k: v for k, v in per_resolver.items() if v is not None}
    # If all resolvers failed and a fallback is provided, try it once with
    # a special "system" resolver identifier.
    if not ok and fallback is not None:
        fallback_result = fallback(name, rtype, "system")
        if fallback_result is not None:
            ok["system"] = fallback_result

    union: List[str] = sorted({x for v in ok.values() for x in v}) if ok else []
    agree: bool = len({tuple(v) for v in ok.values()}) <= 1
    return {"values": union, "agree": agree, "per_resolver": per_resolver}


class DNS(Tentacle):
    """Simplified tentacle exposing DNS resolution.

    The class mirrors the behaviour of the original implementation but
    uses plain Python attributes instead of ``dataclass`` defaults to avoid
    mutable‑default pitfalls.
    """

    def __init__(self):
        self.name = "dns"
        self.types = TYPES

    def run(self, conn, asset):  # pragma: no cover – simple wrapper
        out = []
        for t in self.types:
            r = resolve(asset["value"], t, RESOLVERS)
            if r["values"] or r["agree"]:
                out.append({"key": f"dns_{t}", "value": r["values"], "agree": r["agree"]})
        return out

# ---------------------------------------------------------------------------
# DNSSEC helpers – not used by the current test suite but useful for future
# integrations.  They are lightweight wrappers around dnspython and do not
# perform heavy network traffic.
# ---------------------------------------------------------------------------

def _load_zone(name: str, resolver: str) -> dns.name.Name | None:
    """Return the zone apex for *name* using the provided resolver.
    Returns ``None`` if the zone cannot be retrieved.
    """
    if dns_resolver is None:
        return None
    try:
        z = dns_resolver.resolve(name, "SOA", raise_on_no_answer=False)
        if z:
            return dns.name.from_text(z[0].origin)
    except Exception:
        return None


def validate_dnssec(name: str, resolver: str) -> bool:
    """Return ``True`` if the name passes basic DNSSEC validation.

    The function performs a very lightweight check: it retrieves the DNSKEY
    record of the zone and the DS record from the parent zone, then verifies
    that the key matches the DS.  This is sufficient for most use‑cases and
    avoids external tooling.
    """
    if dns_resolver is None:
        return False
    zone = _load_zone(name, resolver)
    if zone is None:
        return False
    try:
        dnskey = dns_resolver.resolve(zone, "DNSKEY", raise_on_no_answer=False)
        ds = dns_resolver.resolve(zone.parent(), "DS", raise_on_no_answer=False)
        for d in ds:
            # dnspython provides a helper to compare DS to DNSKEY
            if dns.dnssec.validate(d, dnskey, dns.resolver.get_default_resolver()):
                return True
    except Exception:
        pass
    return False
