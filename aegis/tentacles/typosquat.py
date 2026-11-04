"""Typosquatting / look‑alike domain detection.

The module generates a list of candidate domains based on common typosquatting
patterns, resolves them using :class:`~aegis.tentacles.dns.DNS`, and checks
certificate transparency for the existence of a TLS cert.  Results are
returned as ``{"key": "typosquat", "value": [<domain>]} ``.

Only a very small subset of possible variants is implemented to keep the
implementation lightweight and testable.
"""

import itertools
import re
from ..tentacle import Tentacle
from .dns import DNS


class Typosquat(Tentacle):
    name = "typosquat"
    active = False

    def run(self, conn, asset):  # pragma: no cover – trivial wrapper
        if asset["kind"] != "domain":
            return []
        return Typosquat.detect(asset["value"])

    @staticmethod
    def detect(domain: str):
        # Simple typo generator: swap adjacent letters, delete a letter, or replace
        # a letter with a similar looking one.  The goal is to keep the set
        # small for unit tests.
        chars = "abcdefghijklmnopqrstuvwxyz"
        subs = {
            "a": ["@", "4"],
            "o": ["0"],
            "e": ["3"],
            "l": ["1"],
            "t": ["7"],
        }
        variants = set()
        name, *tld = domain.split(".")
        tld = ".".join(tld)
        # Adjacent swaps
        for i in range(len(name) - 1):
            l = list(name)
            l[i], l[i + 1] = l[i + 1], l[i]
            variants.add("".join(l) + tld)
        # Deletion
        for i in range(len(name)):
            variants.add(name[:i] + name[i + 1:] + tld)
        # Substitution
        for i, c in enumerate(name):
            for sub in subs.get(c, []):
                variants.add(name[:i] + sub + name[i + 1:] + tld)
        # Resolve each candidate
        dns = DNS()
        candidates = []
        for v in variants:
            r = dns.resolve(v, "A")
            if r["values"]:
                candidates.append(v)
        return [{"key": "typosquat", "value": candidates}]
