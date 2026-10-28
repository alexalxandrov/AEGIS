"""Unit tests for :mod:`aegis.tentacles.network_scan`.

The test suite verifies the behaviour of the helper functions that
normalise CIDR strings, truncate large networks, skip loopback scans and
handle timeouts.  The actual external scanners are only invoked if they
are available on the test runner; otherwise the tests are skipped.
"""

import os
import shutil
import sys
import time
from pathlib import Path
from typing import List, Dict

import pytest

from aegis.tentacles.network_scan import (
    detect_subnet,
    scan_subnet,
    run_network_scan,
)


def _scanner_available() -> bool:
    return shutil.which("naabu") or shutil.which("nmap")


@pytest.mark.skipif(not _scanner_available(), reason="naabu or nmap not installed")
def test_run_network_scan_single_ip() -> None:
    """Run a scan against the loopback interface.

    The test expects at least an empty list (no ports found).  The scan
    should not raise an exception.
    """

    results = run_network_scan("127.0.0.1")
    assert isinstance(results, list)
    # On a typical CI environment the scan will return no services.
    assert all(isinstance(r, dict) for r in results)


def test_detect_subnet_truncation() -> None:
    """Large networks are truncated to a /24 prefix when ``max_hosts`` is
    provided.
    """

    large_cidr = "10.0.0.0/8"
    truncated = detect_subnet(large_cidr, max_hosts=200)
    assert truncated == "10.0.0.0/24"
    # A normal CIDR remains unchanged.
    single_cidr = "192.168.1.0/24"
    assert detect_subnet(single_cidr) == single_cidr


def test_scan_subnet_loopback_avoidance() -> None:
    """Scanning the loopback range should return an empty list and skip
    invoking the external scanner.
    """

    # Use a small subnet that falls inside 127.0.0.0/8.
    loopback_subnet = "127.0.0.0/30"
    results = scan_subnet(loopback_subnet, max_hosts=2)
    assert results == []


@pytest.mark.skipif(not _scanner_available(), reason="naabu or nmap not installed")
def test_scan_subnet_timeout() -> None:
    """If a scan takes longer than the timeout, a RuntimeError should be
    raised.
    """

    # Use an IP that is unlikely to have any open ports to force a quick
    # completion.  We set an absurdly low timeout to trigger the
    # ``TimeoutExpired`` handling.
    with pytest.raises(RuntimeError):
        # Use a non‑loopback IP to exercise the scan logic; the zero timeout
        # will trigger the ``TimeoutExpired`` path.
        scan_subnet("8.8.8.8", timeout=0)
