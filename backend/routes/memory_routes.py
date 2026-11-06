
import re
from datetime import datetime

from flask import Blueprint, jsonify, request

from backend import db
from backend.services import hindsight_service as hs


memory_bp = Blueprint("memory", __name__)

TENANT_RE = re.compile(r"^[a-z0-9-]{1,32}$")
INCIDENT_RE = re.compile(r"^INC-\d+$")

MAX_TEXT = 5000

ALLOWED_STATES = {"valid", "invalidated"}

ALLOWED_TIME_FIELDS = {
    "created_at",
    "updated_at",
    "mentioned_at",
    "occurred_start",
    "occurred_end"
}


# ---------------- HELPER FUNCTIONS ----------------

def _tenant():
    tenant = request.headers.get(
        "X-Tenant-ID", "default"
    ).strip().lower()

    return tenant if TENANT_RE.match(tenant) else None


def _bad(msg):
    return jsonify({
        "status": "error",
        "error": msg
    }), 400


def _respond(result):
    return jsonify(result), (
        503 if result.get("status") == "unavailable" else 200
    )


def _str_list(value):
    return (
        isinstance(value, list)
        and all(isinstance(item, str) for item in value)
    )


def _valid_iso_date(value):
    if not value:
        return True

    try:
        datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
        return True

    except (ValueError, AttributeError):
        return False


# ---------------- HEALTH API ----------------

@memory_bp.get("/health")
def health():
    return _respond(hs.health())


# ---------------- DASHBOARD STATS API ----------------

@memory_bp.get("/stats")
def stats():
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    result = db.dashboard_stats(tenant)

    return jsonify({
        "status": "ok",
        "stats": result
    })


# ---------------- RETAIN API ----------------

@memory_bp.post("/retain")
def retain():
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return _bad("JSON body required")

    if not INCIDENT_RE.match(
        str(data.get("incident_id", ""))
    ):
        return _bad("incident_id must look like INC-001")

    if not str(data.get("description", "")).strip():
        return _bad("description is required")

    for field in ("iocs", "steps"):
        if field in data and not _str_list(data[field]):
            return _bad(f"{field} must be a list of strings")

    for field, value in data.items():
        if isinstance(value, str) and len(value) > MAX_TEXT:
            return _bad(f"{field} too long")

    db.save_incident(tenant, data, "pending")

    result = hs.retain_incident(data, tenant=tenant)

    db.set_hindsight_status(
        tenant,
        data["incident_id"],
        result["status"]
    )

    result["saved_locally"] = True

    return _respond(result)


# ---------------- RECALL API ----------------

@memory_bp.post("/recall")
def recall():
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return _bad("JSON body required")

    query = str(data.get("query", "")).strip()

    if not query:
        return _bad("query is required")

    if len(query) > MAX_TEXT:
        return _bad("query too long")

    result = hs.recall_similar(
        query,
        tenant=tenant
    )

    db.record_retrieval(
        tenant,
        result.get("status", "unknown")
    )

    return _respond(result)


# ---------------- REFLECT API ----------------

@memory_bp.post("/reflect")
def reflect():
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return _bad("JSON body required")

    query = str(data.get("query", "")).strip()

    if not query:
        return _bad("query is required")

    if len(query) > MAX_TEXT:
        return _bad("query too long")

    result = hs.reflect_lessons(
        query,
        tenant=tenant
    )

    return _respond(result)


# ---------------- INCIDENT HISTORY API ----------------

@memory_bp.get("/incidents")
def incidents():
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    items = db.list_incidents(
        tenant,
        severity=request.args.get("severity"),
        q=request.args.get("q")
    )

    return jsonify({
        "status": "ok",
        "count": len(items),
        "incidents": items
    })


# ---------------- INCIDENT DETAILS API ----------------

@memory_bp.get("/incidents/<incident_id>")
def incident_detail(incident_id):
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    if not INCIDENT_RE.match(incident_id):
        return _bad("invalid incident id")

    incident = db.get_incident(
        tenant,
        incident_id
    )

    if incident is None:
        return jsonify({
            "status": "error",
            "error": "not found"
        }), 404

    return jsonify({
        "status": "ok",
        "incident": incident
    })


# ---------------- ANALYST FEEDBACK API ----------------

@memory_bp.post("/feedback")
def feedback():
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return _bad("JSON body required")

    incident_id = str(
        data.get("incident_id", "")
    ).strip()

    rating = data.get("rating")
    comment = data.get("comment", "")

    if not INCIDENT_RE.match(incident_id):
        return _bad("invalid incident_id")

    if rating not in ("positive", "negative"):
        return _bad("rating must be positive or negative")

    if not isinstance(comment, str):
        return _bad("comment must be a string")

    if len(comment) > MAX_TEXT:
        return _bad("comment too long")

    incident = db.get_incident(
        tenant,
        incident_id
    )

    if incident is None:
        return jsonify({
            "status": "error",
            "error": "incident not found"
        }), 404

    db.save_feedback(
        tenant,
        incident_id,
        rating,
        comment.strip()
    )

    return jsonify({
        "status": "ok",
        "message": "Feedback saved successfully",
        "incident_id": incident_id,
        "rating": rating
    }), 201


# ---------------- MEMORY EXPLORER API ----------------

@memory_bp.get("/explorer")
def memory_explorer():
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    memory_type = request.args.get(
        "type", ""
    ).strip() or None

    search_query = request.args.get(
        "q", ""
    ).strip() or None

    state = request.args.get(
        "state", ""
    ).strip() or None

    time_field = request.args.get(
        "time_field", ""
    ).strip() or None

    start_date = request.args.get(
        "start_date", ""
    ).strip() or None

    end_date = request.args.get(
        "end_date", ""
    ).strip() or None

    # Pagination validation
    try:
        limit = int(request.args.get("limit", 20))
        offset = int(request.args.get("offset", 0))

    except (TypeError, ValueError):
        return _bad("limit and offset must be integers")

    if limit < 1 or limit > 100:
        return _bad("limit must be between 1 and 100")

    if offset < 0:
        return _bad("offset cannot be negative")

    # Memory type validation
    if memory_type and len(memory_type) > 100:
        return _bad("memory type too long")

    # Search validation
    if search_query and len(search_query) > MAX_TEXT:
        return _bad("search query too long")

    # State validation
    if state and state not in ALLOWED_STATES:
        return _bad("state must be valid or invalidated")

    # Time field validation
    if time_field and time_field not in ALLOWED_TIME_FIELDS:
        return _bad("invalid time_field")

    # Date filters require a time field
    if (start_date or end_date) and not time_field:
        return _bad(
            "time_field is required when using date filters"
        )

    # ISO date validation
    if start_date and not _valid_iso_date(start_date):
        return _bad("invalid start_date")

    if end_date and not _valid_iso_date(end_date):
        return _bad("invalid end_date")

    # Date range validation
    if start_date and end_date:
        try:
            start = datetime.fromisoformat(
                start_date.replace("Z", "+00:00")
            )

            end = datetime.fromisoformat(
                end_date.replace("Z", "+00:00")
            )

            # Prevent comparing timezone-aware and naive dates
            if (start.tzinfo is None) != (end.tzinfo is None):
                return _bad(
                    "start_date and end_date must both include "
                    "a timezone or both omit it"
                )

            if start >= end:
                return _bad(
                    "start_date must be earlier than end_date"
                )

        except (ValueError, TypeError):
            return _bad(
                "start_date and end_date must use valid, compatible dates"
            )

    # Retrieve memories from Hindsight
    result = hs.list_memory_units(
        tenant=tenant,
        memory_type=memory_type,
        search_query=search_query,
        limit=limit,
        offset=offset,
        state=state,
        time_field=time_field,
        start_date=start_date,
        end_date=end_date
    )

    return _respond(result)
