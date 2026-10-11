import importlib
import sys
import types
import unittest

class TestFastAPIImportGuard(unittest.TestCase):
    def test_create_app_without_fastapi(self):
        """Ensure that calling :func:`aegis.api.create_app` raises a
        :class:`RuntimeError` when the optional ``fastapi`` dependency is not
        available.

        The test temporarily removes the ``fastapi`` module from
        :pydata:`sys.modules` before invoking the function.  This mimics a
        runtime environment where the dependency is not installed, allowing us
        to verify the lazy‑import wrapper works as intended.
        """
        # Import the package to get the lazy wrapper.
        from aegis import api

        # Ensure fastapi is not already imported.
        if "fastapi" in sys.modules:
            del sys.modules["fastapi"]
        # Also remove any sub‑modules that might be cached.
        for mod in list(sys.modules):
            if mod.startswith("fastapi."):
                del sys.modules[mod]

        with self.assertRaises(RuntimeError) as excinfo:
            api.create_app()
        self.assertIn("fastapi", str(excinfo.exception))


if __name__ == "__main__":
    unittest.main()
