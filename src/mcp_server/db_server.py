"""Policy-controlled MCP server for the PhishGuard database.

Never print() to stdout here: with the stdio transport, stdout is the protocol channel.
"""
import functools
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _McpServer
except ModuleNotFoundError:  # mcp 2.x renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as _McpServer

from src.db import store
from src.mcp_server.policy import PolicyDenied, PolicyEngine
from src.utils.defang import defang_all

ROLE = os.environ.get("PHISHGUARD_MCP_ROLE", "analyst_readonly")  # least privilege default
POLICY_PATH = Path(os.environ.get(
    "PHISHGUARD_MCP_POLICY",
    Path(__file__).resolve().parents[2] / "policy" / "mcp_policy.json",
))

policy = PolicyEngine(POLICY_PATH)
mcp = _McpServer("phishguard-db")

VERDICTS = {"safe", "suspicious", "malicious"}
KINDS = {"domain", "qr"}
SEVERITIES = {"low", "medium", "high", "critical"}
STATUSES = {"open", "investigating", "contained", "resolved", "closed"}
INCIDENT_ID_RE = re.compile(r"^INC-\d{8}-[0-9A-F]{8}$")


def guarded(tool_name):
    """Authorize, rate-limit and audit every call. Policy checks live here, not in the model."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            detail = json.dumps(kwargs, default=str)[:300]
            try:
                policy.authorize_tool(ROLE, tool_name)
                result = fn(*args, **kwargs)
            except PolicyDenied as exc:
                store.audit(ROLE, tool_name, "deny", f"{exc} | {detail}")
                return {"error": f"Denied by policy: {exc}"}
            except ValueError as exc:
                store.audit(ROLE, tool_name, "invalid", f"{exc} | {detail}")
                return {"error": f"Invalid request: {exc}"}
            except Exception:
                store.audit(ROLE, tool_name, "error", detail)
                return {"error": "Internal error"}
            store.audit(ROLE, tool_name, "allow", detail)
            return result
        return wrapper
    return decorator


def _enum(value, allowed, name):
    if value not in allowed:
        raise ValueError(f"{name} must be one of {sorted(allowed)}")


def _clean(text, max_len):
    return "".join(ch for ch in str(text) if ch.isprintable()).strip()[:max_len]


def _reason(reason):
    if len(_clean(reason, 200)) < 5:
        raise ValueError("a reason of at least 5 characters is required for write actions")


def _incident_id(value):
    if not INCIDENT_ID_RE.match(str(value)):
        raise ValueError("invalid incident id format")


def _out(rows):
    """Defang scanned targets so stored attacker content is inert in clients and LLM context."""
    for row in rows:
        if "target" in row:
            row["target"] = defang_all(row["target"])
    return rows


@mcp.tool()
@guarded("list_scans")
def list_scans(verdict: str | None = None, kind: str | None = None,
               min_risk: float | None = None, limit: int = 20) -> dict:
    """List recent scans. Columns and row count are limited by policy."""
    role = policy.role(ROLE)
    filters = []
    if verdict is not None:
        _enum(verdict, VERDICTS, "verdict")
        filters.append(("verdict", "=", verdict))
    if kind is not None:
        _enum(kind, KINDS, "kind")
        filters.append(("kind", "=", kind))
    if min_risk is not None:
        filters.append(("risk_score", ">=", float(min_risk)))
    policy.allowed_columns(role, "scans", [f[0] for f in filters])
    cols = policy.allowed_columns(role, "scans")
    rows = store.select("scans", cols, filters, policy.max_rows(role, "scans", limit))
    return {"count": len(rows), "rows": _out(rows)}


@mcp.tool()
@guarded("get_scan")
def get_scan(scan_id: int) -> dict:
    """Get one scan by id."""
    role = policy.role(ROLE)
    policy.allowed_columns(role, "scans", ["id"])
    cols = policy.allowed_columns(role, "scans")
    rows = store.select("scans", cols, [("id", "=", int(scan_id))], 1)
    if not rows:
        raise ValueError("scan not found")
    return _out(rows)[0]


@mcp.tool()
@guarded("list_incidents")
def list_incidents(status: str | None = None, severity: str | None = None, limit: int = 20) -> dict:
    """List incidents (without full report bodies)."""
    role = policy.role(ROLE)
    filters = []
    if status is not None:
        _enum(status, STATUSES, "status")
        filters.append(("status", "=", status))
    if severity is not None:
        _enum(severity, SEVERITIES, "severity")
        filters.append(("severity", "=", severity))
    policy.allowed_columns(role, "incidents", [f[0] for f in filters])
    cols = [c for c in policy.allowed_columns(role, "incidents") if c != "report_json"]
    rows = store.select("incidents", cols, filters, policy.max_rows(role, "incidents", limit))
    return {"count": len(rows), "rows": rows}


@mcp.tool()
@guarded("get_incident_report")
def get_incident_report(incident_id: str) -> dict:
    """Get the stored incident report for one incident id."""
    role = policy.role(ROLE)
    _incident_id(incident_id)
    policy.allowed_columns(role, "incidents", ["incident_id", "report_json"])
    rows = store.select("incidents", ["incident_id", "report_json"],
                        [("incident_id", "=", incident_id)], 1)
    if not rows:
        raise ValueError("incident not found")
    return rows[0]


@mcp.tool()
@guarded("create_incident")
def create_incident(scan_id: int, title: str, severity: str, reason: str) -> dict:
    """Open a new incident for a scan. Requires a reason, which is written to the audit log."""
    role = policy.role(ROLE)
    policy.check_write(role, "incidents")
    _reason(reason)
    _enum(severity, SEVERITIES, "severity")
    title = _clean(title, 120)
    if not title:
        raise ValueError("title is required")
    policy.allowed_columns(role, "scans", ["id"])
    if not store.select("scans", ["id"], [("id", "=", int(scan_id))], 1):
        raise ValueError("scan not found")
    incident_id = f"INC-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(4).upper()}"
    store.insert_incident(incident_id, int(scan_id), title, severity)
    return {"incident_id": incident_id, "status": "open"}


@mcp.tool()
@guarded("update_incident_status")
def update_incident_status(incident_id: str, new_status: str, reason: str) -> dict:
    """Move an incident to a new status. Allowed transitions are defined per role in the policy."""
    role = policy.role(ROLE)
    policy.check_write(role, "incidents")
    _reason(reason)
    _incident_id(incident_id)
    _enum(new_status, STATUSES, "status")
    policy.allowed_columns(role, "incidents", ["incident_id", "status"])
    rows = store.select("incidents", ["status"], [("incident_id", "=", incident_id)], 1)
    if not rows:
        raise ValueError("incident not found")
    policy.check_transition(role, rows[0]["status"], new_status)
    store.update_incident_status(incident_id, new_status)
    return {"incident_id": incident_id, "status": new_status}


if __name__ == "__main__":
    store.init_db()
    mcp.run()
