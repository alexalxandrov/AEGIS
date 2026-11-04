import pytest
from aegis.tentacles.baseline import calculate_baseline


def test_calculate_baseline_simple():
    records = [
        {"asset_kind": "domain", "asset_value": "example.com"},
        {"asset_kind": "domain", "asset_value": "sub.example.com"},
        {"asset_kind": "ip", "asset_value": "1.2.3.4", "key": "bgp", "value": {"asns": [{"asn": 64512}]}},
        {"asset_kind": "cert", "asset_value": "example.com", "key": "cert", "value": {"notBefore": "2024-01-01 00:00:00 +0000"}},
    ]
    baseline = calculate_baseline(records)
    assert baseline["median_cert_age_days"] is not None
    # The root domain derived from example.com should be "example".
    assert baseline["common_asn"].get("example") == 64512