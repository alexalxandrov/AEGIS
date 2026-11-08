"""Public exports for :mod:`aegis.tentacles`.

The tentacles package contains a collection of passive enrichment modules
used by AEGIS.  To keep the import paths short, the most frequently
used classes are re‑exported from this package level.  Importing
``aegis.tentacles`` therefore provides direct access to
``Subtakeover`` and can be extended in the future as needed.
"""

# Export the public tentacles so that callers can use
# ``from aegis.tentacles import <name>`` without needing to know the
# internal module layout.
from .subtakeover import Subtakeover  # noqa: F401
from .tls import TLS  # noqa: F401
from .dns import DNS  # noqa: F401
from .email import Email  # noqa: F401
from .wayback import Wayback  # noqa: F401
from .web import Web  # noqa: F401
from .shodan import Shodan  # noqa: F401
# Newly added stubs – they are simple modules exposing functions or classes.
# Import them here to expose the module itself.
# Import the stub modules so they are available as submodules of
# ``aegis.tentacles``.  Using ``from . import <module>`` binds the module
# object itself under the given name.
# Import the stub modules as submodule objects so that callers can access the
# function attributes directly.  ``from . import <name>`` binds the module under
# the given name.
from . import ti  # noqa: F401
from . import passive_dns  # noqa: F401
from . import whois  # noqa: F401
from . import webscan  # noqa: F401
from . import cve  # noqa: F401
from . import subdomain  # noqa: F401
# Also expose the main tentacle modules as submodule objects.  These are used by
# ``aegis.runner`` which imports ``dns``, ``email``, ``wayback`` and ``web``.
from . import dns as dns  # noqa: F401
from . import email as email  # noqa: F401
from . import wayback as wayback  # noqa: F401
from . import web as web  # noqa: F401
from . import shodan as shodan  # noqa: F401
from .cve import cve  # noqa: F401
from .subdomain import subdomain  # noqa: F401