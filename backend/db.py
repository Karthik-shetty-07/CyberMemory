import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get(
    "CM_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cybermemory.db"),
)


def _run(sql, params=(), fetch=False):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(sql, params)
        rows = cur.fetchall() if fetch else None
        conn.commit()
        return rows
    finally:
        conn.close()


def _now():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    _run("""CREATE TABLE IF NOT EXISTS incidents (
        tenant TEXT NOT NULL,
        incident_id TEXT NOT NULL,
        severity TEXT,
        alert_type TEXT,
        data TEXT NOT NULL,
        hindsight_status TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (tenant, incident_id))""")


def save_incident(tenant, inc, hindsight_status="pending"):
    now = _now()
    _run("""INSERT INTO incidents
            (tenant, incident_id, severity, alert_type, data, hindsight_status, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(tenant, incident_id) DO UPDATE SET
              severity=excluded.severity, alert_type=excluded.alert_type,
              data=excluded.data, hindsight_status=excluded.hindsight_status,
              updated_at=excluded.updated_at""",
         (tenant, inc["incident_id"], str(inc.get("severity", "")),
          str(inc.get("alert_type", "")), json.dumps(inc), hindsight_status, now, now))


def set_hindsight_status(tenant, incident_id, status):
    _run("UPDATE incidents SET hindsight_status=?, updated_at=? WHERE tenant=? AND incident_id=?",
         (status, _now(), tenant, incident_id))


def _summary(row):
    d = json.loads(row["data"])
    return {"incident_id": row["incident_id"], "title": d.get("title", ""),
            "severity": row["severity"], "alert_type": row["alert_type"],
            "host": d.get("host", ""), "outcome": d.get("outcome", ""),
            "hindsight_status": row["hindsight_status"], "updated_at": row["updated_at"]}


def list_incidents(tenant, severity=None, q=None, limit=100):
    sql, params = "SELECT * FROM incidents WHERE tenant=?", [tenant]
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    if q:
        sql += " AND data LIKE ?"
        params.append(f"%{q}%")
    sql += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)
    return [_summary(r) for r in _run(sql, params, fetch=True)]


def get_incident(tenant, incident_id):
    rows = _run("SELECT * FROM incidents WHERE tenant=? AND incident_id=?",
                (tenant, incident_id), fetch=True)
    if not rows:
        return None
    out = json.loads(rows[0]["data"])
    out["hindsight_status"] = rows[0]["hindsight_status"]
    return out