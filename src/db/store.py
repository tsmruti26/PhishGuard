import hashlib
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "phishguard.db"

COLUMNS = {
    "scans": ["id", "target", "kind", "risk_score", "verdict", "raw_payload", "created_at"],
    "incidents": ["id", "incident_id", "scan_id", "title", "severity", "status",
                  "report_json", "created_at", "updated_at"],
}
FILTER_OPS = {"=", ">="}
GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('domain','qr')),
  risk_score REAL NOT NULL DEFAULT 0,
  verdict TEXT NOT NULL CHECK (verdict IN ('safe','suspicious','malicious')),
  raw_payload TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT UNIQUE NOT NULL,
  scan_id INTEGER REFERENCES scans(id),
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  status TEXT NOT NULL CHECK (status IN ('open','investigating','contained','resolved','closed')),
  report_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  role TEXT NOT NULL,
  tool TEXT NOT NULL,
  decision TEXT NOT NULL,
  detail TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
"""


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def db_path() -> Path:
    override = os.environ.get("PHISHGUARD_DB")
    return Path(override) if override else DEFAULT_DB


def connect(readonly=False):
    path = db_path()
    if readonly:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        conn.execute("PRAGMA query_only=ON")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with closing(connect()) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def select(table, columns, filters=None, limit=20):
    """Identifiers are checked against COLUMNS; all values are bound parameters."""
    if table not in COLUMNS:
        raise ValueError("unknown table")
    if not columns or any(c not in COLUMNS[table] for c in columns):
        raise ValueError("unknown column")
    clauses, params = [], []
    for col, op, val in (filters or []):
        if col not in COLUMNS[table] or op not in FILTER_OPS:
            raise ValueError("invalid filter")
        clauses.append(f"{col} {op} ?")
        params.append(val)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT {', '.join(columns)} FROM {table}{where} ORDER BY id DESC LIMIT ?"  # nosec B608 - identifiers allowlisted above
    params.append(int(limit))
    with closing(connect(readonly=True)) as conn:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


def insert_scan(target, kind, risk_score, verdict, raw_payload=None):
    with closing(connect()) as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, kind, risk_score, verdict, raw_payload, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (target, kind, float(risk_score), verdict, raw_payload, _now()),
        )
        conn.commit()
        return cur.lastrowid


def insert_incident(incident_id, scan_id, title, severity, status="open", report=None):
    now = _now()
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO incidents (incident_id, scan_id, title, severity, status, report_json, "
            "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (incident_id, scan_id, title, severity, status,
             json.dumps(report) if report else None, now, now),
        )
        conn.commit()


def update_incident_status(incident_id, new_status):
    with closing(connect()) as conn:
        cur = conn.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
            (new_status, _now(), incident_id),
        )
        conn.commit()
        return cur.rowcount > 0


def _hash(*parts):
    return hashlib.sha256(json.dumps(parts).encode("utf-8")).hexdigest()


def audit(role, tool, decision, detail=""):
    """Append-only, hash-chained audit entry (each row commits to the previous one)."""
    ts, detail = _now(), str(detail)[:500]
    with closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        conn.execute(
            "INSERT INTO audit_log (ts, role, tool, decision, detail, prev_hash, hash) "
            "VALUES (?,?,?,?,?,?,?)",
            (ts, role, tool, decision, detail, prev, _hash(prev, ts, role, tool, decision, detail)),
        )
        conn.commit()


def verify_audit_chain() -> bool:
    prev = GENESIS
    with closing(connect(readonly=True)) as conn:
        for r in conn.execute("SELECT * FROM audit_log ORDER BY id"):
            expected = _hash(prev, r["ts"], r["role"], r["tool"], r["decision"], r["detail"])
            if r["prev_hash"] != prev or r["hash"] != expected:
                return False
            prev = r["hash"]
    return True