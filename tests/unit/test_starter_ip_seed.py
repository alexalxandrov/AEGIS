import os
import pathlib
import importlib
import pytest


def _setup_env(tmp_path: pathlib.Path):
    # Ensure AEGIS_DATA points to a temporary directory
    os.environ["AEGIS_DATA"] = str(tmp_path)
    # Invalidate caches and import modules so that they pick up the new environment variable
    importlib.invalidate_caches()
    import aegis.config
    import aegis.db
    import starter
    return starter


def test_ip_seed_insert(tmp_path: pathlib.Path):
    starter = _setup_env(tmp_path)
    # Create a fresh database connection
    conn = starter.db.connect()
    # Ensure organization exists
    org_id = starter._ensure_organization(conn, "TestOrg")
    assert org_id is not None
    # Prepare info dict with domain and IP
    info = {
        "site": "example.com",
        "ip": "8.8.8.8",
        "url": "https://example.com",
        "nick": "ex",
        "company": "Example Inc",
    }
    # Seed data as in starter.main
    conn.execute(
        "INSERT OR IGNORE INTO seed(org_id,kind,value,verified) VALUES(?,?,?,?)",
        (org_id, "domain", info["site"], 1),
    )
    conn.execute(
        "INSERT OR IGNORE INTO asset(org_id,kind,value,scope,first_seen,last_seen) VALUES(?,?,?,?,strftime('%s','now'),strftime('%s','now'))",
        (org_id, "domain", info["site"], "verified",),
    )
    ip_addr = info.get("ip")
    if ip_addr:
        conn.execute(
            "INSERT OR IGNORE INTO asset(org_id,kind,value,scope,first_seen,last_seen) VALUES(?,?,?,?,strftime('%s','now'),strftime('%s','now'))",
            (org_id, "ip", ip_addr, "candidate",),
        )
    # Verify that both records exist
    domain_rows = conn.execute(
        "SELECT * FROM asset WHERE org_id=? AND kind='domain' AND value=?", (org_id, info["site"])
    ).fetchall()
    ip_rows = conn.execute(
        "SELECT * FROM asset WHERE org_id=? AND kind='ip' AND value=?", (org_id, ip_addr)
    ).fetchall()
    assert len(domain_rows) == 1
    assert len(ip_rows) == 1
    # Check the scope of the IP asset
    assert ip_rows[0]["scope"] == "candidate"