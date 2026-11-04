import pytest
from aegis.tentacles.dns import TYPES


def test_dns_types_include_new_records():
    # Ensure the extended list contains the new DNSSEC and record types
    required = {"SOA", "CAA", "PTR", "SRV", "DS", "DNSKEY"}
    assert required.issubset(set(TYPES))