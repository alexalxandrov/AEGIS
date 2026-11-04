"""TLS‑analysis tentacle.

This module provides a :class:`TLS` tentacle that performs lightweight
inspection of an HTTPS endpoint.  The goal is to gather:

* TLS protocol version (TLSv1.2/TLSv1.3)
* Negotiated cipher suite
* Optional support for TLS‑RPT and MTA‑STS by querying the respective DNS
  TXT records.

The implementation uses the standard :mod:`ssl` and :mod:`socket` modules
and falls back gracefully when any of the optional dependencies (``dnspython``)
are not available.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Dict, Optional

try:  # optional dependency for DNS‑record queries
    import dns.resolver
except Exception:  # pragma: no cover - dns not mandatory in test env
    dns_resolver = None

from ..tentacle import Tentacle

__all__ = ["TLS"]


def _ssl_connect(host: str, port: int = 443, timeout: float = 5.0) -> Optional[ssl.SSLSocket]:
    """Attempt an SSL handshake and return the wrapped socket.

    Returns ``None`` when the handshake fails or the socket cannot be
    established.
    """
    try:
        context = ssl.create_default_context()
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        ssock = context.wrap_socket(raw_sock, server_hostname=host)
        # Force a handshake so ``ssock.version`` is populated
        ssock.do_handshake()
        return ssock
    except Exception:
        return None


def _get_cipher_info(ssock: ssl.SSLSocket) -> Dict[str, str]:
    """Return a minimal cipher description from an established socket."""
    cipher = ssock.cipher()
    # cipher() returns (cipher_name, protocol, secret_bits)
    if cipher:
        return {"cipher": cipher[0], "protocol": cipher[1], "bits": cipher[2]}
    return {"cipher": "unknown", "protocol": "unknown", "bits": 0}


def _dns_txt(domain: str, record: str) -> Optional[str]:
    """Return the first TXT record for ``record.<domain>``.

    ``record`` should be the sub‑domain part, e.g. ``"_tlsrpt"``.
    """
    if dns_resolver is None:
        return None
    fqdn = f"{record}.{domain}"
    try:
        answers = dns_resolver.resolve(fqdn, "TXT", raise_on_no_answer=False)
        if answers:
            return " ".join([txt.to_text().strip('"') for txt in answers])
    except Exception:
        pass
    return None


class TLS(Tentacle):
    """Collect TLS‑related metadata for a domain.

    The :py:meth:`run` method accepts a connection object (currently unused) and
    an ``asset`` dictionary containing at least the key ``"value"`` with the
    domain name.
    """

    def __init__(self) -> None:
        self.name = "tls"

    def run(self, conn, asset):  # pragma: no cover - trivial wrapper
        domain = asset.get("value")
        if not domain:
            return []
        ssock = _ssl_connect(domain)
        if ssock is None:
            return [{"key": "tls", "value": {"valid": False, "error": "connection"}}]
        cipher_info = _get_cipher_info(ssock)
        # Close the socket
        try:
            ssock.shutdown(socket.SHUT_RDWR)
            ssock.close()
        except Exception:
            pass
        # Optional TLS‑RPT and MTA‑STS records
        tlsrpt = _dns_txt(domain, "_tlsrpt")
        mta_sts = _dns_txt(domain, "_mta-sts")
        result = {
            "cipher": cipher_info.get("cipher"),
            "protocol": cipher_info.get("protocol"),
            "bits": cipher_info.get("bits"),
            "tlsrpt": tlsrpt,
            "mta_sts": mta_sts,
        }
        return [{"key": "tls", "value": result}]
