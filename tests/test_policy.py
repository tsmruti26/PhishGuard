import json
from contextlib import closing
from pathlib import Path

import pytest

from src.db import store
from src.mcp_server.policy import PolicyDenied, PolicyEngine

POLICY = Path(__file__).resolve().parents[1] / "policy" / "mcp_policy.json"


@pytest.fixture
def engine():
    return PolicyEngine(POLICY)


def test_unknown_role_denied(engine):
    with pytest.raises(PolicyDenied):
        engine.authorize_tool("hacker", "list_scans")


def test_readonly_cannot_use_write_tools(engine):
    with pytest.raises(PolicyDenied):
        engine.authorize_tool("analyst_readonly", "create_incident")


def test_column_allowlist(engine):
    role = engine.role("analyst_readonly")
    with pytest.raises(PolicyDenied):
        engine.allowed_columns(role, "scans", ["raw_payload"])


def test_row_cap(engine):
    assert engine.max_rows(engine.role("analyst_readonly"), "scans", 10_000) == 50


def test_rate_limit(engine):
    for _ in range(30):
        engine.authorize_tool("analyst_readonly", "list_scans")
    with pytest.raises(PolicyDenied):
        engine.authorize_tool("analyst_readonly", "list_scans")


def test_status_transitions(engine):
    role = engine.role("incident_responder")
    engine.check_transition(role, "open", "investigating")
    with pytest.raises(PolicyDenied):
        engine.check_transition(role, "open", "closed")


def test_sql_identifier_injection_rejected():
    with pytest.raises(ValueError):
        store.select("scans", ["id; DROP TABLE scans"])
    with pytest.raises(ValueError):
        store.select("scans; DROP TABLE scans", ["id"])


def test_audit_chain_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_DB", str(tmp_path / "t.db"))
    store.init_db()
    store.audit("analyst_readonly", "list_scans", "allow", "a")
    store.audit("analyst_readonly", "create_incident", "deny", "b")
    assert store.verify_audit_chain()
    with closing(store.connect()) as conn:
        conn.execute("UPDATE audit_log SET decision = 'allow' WHERE id = 2")
        conn.commit()
    assert not store.verify_audit_chain()


def test_mcp_server_enforces_policy(tmp_path, monkeypatch):
    pytest.importorskip("mcp")
    monkeypatch.setenv("PHISHGUARD_DB", str(tmp_path / "t.db"))
    store.init_db()
    sid = store.insert_scan("http://evil.test", "qr", 90, "malicious", "secret-payload")
    from src.mcp_server import db_server as s

    monkeypatch.setattr(s, "ROLE", "analyst_readonly")
    res = s.get_scan(sid)
    assert "raw_payload" not in res
    assert "hxxp" in res["target"]
    assert "error" in s.create_incident(sid, "t", "high", "testing reason")
    assert "error" in s.list_scans(verdict="x'; DROP TABLE scans;--")
    assert store.verify_audit_chain()