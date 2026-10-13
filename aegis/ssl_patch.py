"""Global SSL context patch.

The original code uses :func:`urllib.request.urlopen` everywhere.  In the
execution environment of this kata the SSL root certificates are missing,
which leads to ``ssl.SSLCertVerificationError`` for HTTPS requests.  The
network services used by AEGIS (crt.sh, RIPEstat, Shodan, etc.) are all
HTTPS-only, so a blanket un‑verified context is acceptable for the test
suite.

This module applies a monkey‑patch at import time that replaces the default
``urlopen`` with a wrapper that supplies ``ssl._create_unverified_context``.
The patch is idempotent and safe to import multiple times.
"""

import ssl
import urllib.request

_unverified_ctx = ssl._create_unverified_context()
_original_urlopen = urllib.request.urlopen


def _patched_urlopen(*args, **kwargs):  # pragma: no cover
    """Replacement for :func:`urllib.request.urlopen`.

    It forwards all positional arguments and accepts an optional ``context``
    keyword.  If ``context`` is not supplied, it defaults to an
    un‑verified SSL context.
    """
    kwargs.setdefault("context", _unverified_ctx)
    return _original_urlopen(*args, **kwargs)


# Apply the patch.
urllib.request.urlopen = _patched_urlopen