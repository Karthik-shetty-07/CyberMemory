
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
        PRIMARY KEY (tenant, incident_id)
    )""")

    _run("""CREATE TABLE IF NOT EXISTS analyst_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant TEXT NOT NULL,
        incident_id TEXT NOT NULL,
        rating TEXT NOT NULL CHECK(rating IN ('positive', 'negative')),
        comment TEXT DEFAULT '',
        created_at TEXT NOT NULL
    )""")

    # Tracks successful and unsuccessful recall requests
    _run("""CREATE TABLE IF NOT EXISTS memory_retrievals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")


def save_incident(tenant, inc, hindsight_status="pending"):
    now = _now()

    _run("""INSERT INTO incidents
            (tenant, incident_id, severity, alert_type, data,
             hindsight_status, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(tenant, incident_id) DO UPDATE SET
              severity=excluded.severity,
              alert_type=excluded.alert_type,
              data=excluded.data,
              hindsight_status=excluded.hindsight_status,
              updated_at=excluded.updated_at""",
         (tenant, inc["incident_id"], str(inc.get("severity", "")),
          str(inc.get("alert_type", "")), json.dumps(inc),
          hindsight_status, now, now))


def set_hindsight_status(tenant, incident_id, status):
    _run("""UPDATE incidents
            SET hindsight_status=?, updated_at=?
            WHERE tenant=? AND incident_id=?""",
         (status, _now(), tenant, incident_id))


def _summary(row):
    d = json.loads(row["data"])

    return {
        "incident_id": row["incident_id"],
        "title": d.get("title", ""),
        "severity": row["severity"],
        "alert_type": row["alert_type"],
        "host": d.get("host", ""),
        "outcome": d.get("outcome", ""),
        "hindsight_status": row["hindsight_status"],
        "updated_at": row["updated_at"]
    }


def list_incidents(tenant, severity=None, q=None, limit=100):
    sql = "SELECT * FROM incidents WHERE tenant=?"
    params = [tenant]

    if severity:
        sql += " AND severity=?"
        params.append(severity)

    if q:
        sql += " AND data LIKE ?"
        params.append(f"%{q}%")

    sql += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)

    return [
        _summary(r)
        for r in _run(sql, params, fetch=True)
    ]


def get_incident(tenant, incident_id):
    rows = _run(
        "SELECT * FROM incidents WHERE tenant=? AND incident_id=?",
        (tenant, incident_id),
        fetch=True
    )

    if not rows:
        return None

    out = json.loads(rows[0]["data"])
    out["hindsight_status"] = rows[0]["hindsight_status"]

    return out


# ---------------- ANALYST FEEDBACK ----------------

def save_feedback(tenant, incident_id, rating, comment=""):
    _run(
        """INSERT INTO analyst_feedback
           (tenant, incident_id, rating, comment, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (tenant, incident_id, rating, comment, _now())
    )


def list_feedback(tenant):
    rows = _run(
        """SELECT * FROM analyst_feedback
           WHERE tenant=?
           ORDER BY created_at DESC""",
        (tenant,),
        fetch=True
    )

    return [dict(r) for r in rows]


def feedback_counts(tenant):
    rows = _run(
        """SELECT rating, COUNT(*) AS total
           FROM analyst_feedback
           WHERE tenant=?
           GROUP BY rating""",
        (tenant,),
        fetch=True
    )

    return {
        r["rating"]: r["total"]
        for r in rows
    }


# ---------------- MEMORY RETRIEVAL TRACKING ----------------

def record_retrieval(tenant, status):
    _run(
        """INSERT INTO memory_retrievals
           (tenant, status, created_at)
           VALUES (?, ?, ?)""",
        (tenant, status, _now())
    )


def retrieval_count(tenant):
    rows = _run(
        """SELECT COUNT(*) AS total
           FROM memory_retrievals
           WHERE tenant=?""",
        (tenant,),
        fetch=True
    )

    return rows[0]["total"]


# ---------------- DASHBOARD STATISTICS ----------------

def dashboard_stats(tenant):

    rows = _run(
        """SELECT severity, COUNT(*) AS total
           FROM incidents
           WHERE tenant=?
           GROUP BY severity""",
        (tenant,),
        fetch=True
    )

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for row in rows:
        key = (row["severity"] or "").lower()

        if key in severity_counts:
            severity_counts[key] = row["total"]

    outcome_rows = _run(
        """SELECT data FROM incidents WHERE tenant=?""",
        (tenant,),
        fetch=True
    )

    outcome_counts = {
        "confirmed_malicious": 0,
        "false_positive": 0,
        "other": 0
    }

    for row in outcome_rows:
        data = json.loads(row["data"])
        outcome = data.get("outcome", "").lower()

        if "false positive" in outcome:
            outcome_counts["false_positive"] += 1
        elif "confirmed malicious" in outcome:
            outcome_counts["confirmed_malicious"] += 1
        else:
            outcome_counts["other"] += 1

    status_rows = _run(
        """SELECT hindsight_status, COUNT(*) AS total
           FROM incidents
           WHERE tenant=?
           GROUP BY hindsight_status""",
        (tenant,),
        fetch=True
    )

    hindsight_counts = {
        row["hindsight_status"] or "unknown": row["total"]
        for row in status_rows
    }

    feedback = feedback_counts(tenant)

    return {
        "total_incidents": len(outcome_rows),
        "severity_counts": severity_counts,
        "outcome_counts": outcome_counts,
        "feedback_counts": {
            "positive": feedback.get("positive", 0),
            "negative": feedback.get("negative", 0)
        },
        "hindsight_counts": hindsight_counts,
        "total_retrievals": retrieval_count(tenant)
    }
