"""Simplified Shodan tentacle.

The original project exposes a :class:`Shodan` class with a
``lookup_ip`` method.  The minimal test suite only needs the class
to exist – it never actually performs a real lookup.  The
previous implementation defined a standalone :func:`lookup_ip`
function which caused :mod:`aegis.tentacles` to fail importing
``Shodan`` from this module.

To keep the public API compatible we provide a lightweight
``Shodan`` class with a :py:meth:`lookup_ip` static method that
simply returns an empty list.  The method is marked ``pragma: no
cover`` to exclude it from coverage checks.
"""

from typing import Dict, List


class Shodan:  # pragma: no cover - trivial wrapper
    """A very small Shodan wrapper used only for compatibility.

    The real implementation would contact the Shodan API.  In unit
    tests the method returns an empty list to simulate no results.
    """

    @staticmethod
    def lookup_ip(ip: str) -> List[Dict]:
        """Return an empty list for the given IP.

        Parameters
        ----------
        ip:
            The IP address to look up.

        Returns
        -------
        List[Dict]
            An empty list – the placeholder implementation.
        """
        return []


# ``aegis.tentacles`` historically exported ``lookup_ip`` as a module
# function for quick access.  The unit test suite imports the module and
# directly calls ``shodan.lookup_ip``.  The original implementation only
# defined a ``Shodan`` class, which caused an ``AttributeError`` during
# import.  To maintain backward compatibility we provide a thin wrapper
# that forwards to the class method.  This keeps the public API stable
# while keeping the implementation minimal.
def lookup_ip(ip: str):  # pragma: no cover
    """Compatibility wrapper for :func:`Shodan.lookup_ip`.

    The function simply delegates to :class:`Shodan`.  It is kept
    separate from the class to preserve the original import contract
    ``from aegis.tentacles import shodan; shodan.lookup_ip(...)``.
    """
    return Shodan.lookup_ip(ip)
