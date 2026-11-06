
import re
from flask import Blueprint, jsonify, request
from backend import db
from backend.services import hindsight_service as hs

memory_bp = Blueprint("memory", __name__)

TENANT_RE = re.compile(r"^[a-z0-9-]{1,32}$")
INCIDENT_RE = re.compile(r"^INC-\d+$")
MAX_TEXT = 5000


def _tenant():
    t = request.headers.get("X-Tenant-ID", "default").strip().lower()
    return t if TENANT_RE.match(t) else None


def _bad(msg):
    return jsonify({"status": "error", "error": msg}), 400


def _respond(result):
    return jsonify(result), (
        503 if result.get("status") == "unavailable" else 200
    )


def _str_list(v):
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


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

    d = request.get_json(silent=True)

    if not isinstance(d, dict):
        return _bad("JSON body required")

    if not INCIDENT_RE.match(str(d.get("incident_id", ""))):
        return _bad("incident_id must look like INC-001")

    if not str(d.get("description", "")).strip():
        return _bad("description is required")

    for f in ("iocs", "steps"):
        if f in d and not _str_list(d[f]):
            return _bad(f"{f} must be a list of strings")

    for f, v in d.items():
        if isinstance(v, str) and len(v) > MAX_TEXT:
            return _bad(f"{f} too long")

    db.save_incident(tenant, d, "pending")

    result = hs.retain_incident(d, tenant=tenant)

    db.set_hindsight_status(
        tenant, d["incident_id"], result["status"]
    )

    result["saved_locally"] = True

    return _respond(result)


# ---------------- RECALL API ----------------

@memory_bp.post("/recall")
def recall():
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    d = request.get_json(silent=True)

    if not isinstance(d, dict):
        return _bad("JSON body required")

    q = str(d.get("query", "")).strip()

    if not q:
        return _bad("query is required")

    if len(q) > MAX_TEXT:
        return _bad("query too long")

    result = hs.recall_similar(q, tenant=tenant)

    # Track this valid recall request, even if Hindsight is unavailable.
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

    d = request.get_json(silent=True)

    if not isinstance(d, dict):
        return _bad("JSON body required")

    q = str(d.get("query", "")).strip()

    if not q:
        return _bad("query is required")

    if len(q) > MAX_TEXT:
        return _bad("query too long")

    return _respond(
        hs.reflect_lessons(q, tenant=tenant)
    )


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


@memory_bp.get("/incidents/<incident_id>")
def incident_detail(incident_id):
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    if not INCIDENT_RE.match(incident_id):
        return _bad("invalid incident id")

    inc = db.get_incident(tenant, incident_id)

    if inc is None:
        return jsonify({
            "status": "error",
            "error": "not found"
        }), 404

    return jsonify({
        "status": "ok",
        "incident": inc
    })


# ---------------- ANALYST FEEDBACK API ----------------

@memory_bp.post("/feedback")
def feedback():
    tenant = _tenant()

    if not tenant:
        return _bad("invalid X-Tenant-ID")

    d = request.get_json(silent=True)

    if not isinstance(d, dict):
        return _bad("JSON body required")

    incident_id = str(d.get("incident_id", "")).strip()
    rating = d.get("rating")
    comment = d.get("comment", "")

    if not INCIDENT_RE.match(incident_id):
        return _bad("invalid incident_id")

    if rating not in ("positive", "negative"):
        return _bad("rating must be positive or negative")

    if not isinstance(comment, str):
        return _bad("comment must be a string")

    if len(comment) > MAX_TEXT:
        return _bad("comment too long")

    # Ensure the incident belongs to this tenant.
    incident = db.get_incident(tenant, incident_id)

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

    memory_type = request.args.get("type", "").strip() or None
    search_query = request.args.get("q", "").strip() or None

    try:
        limit = int(request.args.get("limit", 20))
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        return _bad("limit and offset must be integers")

    if limit < 1 or limit > 100:
        return _bad("limit must be between 1 and 100")

    if offset < 0:
        return _bad("offset cannot be negative")

    if memory_type and len(memory_type) > 100:
        return _bad("memory type too long")

    if search_query and len(search_query) > MAX_TEXT:
        return _bad("search query too long")

    result = hs.list_memory_units(
        tenant=tenant,
        memory_type=memory_type,
        search_query=search_query,
        limit=limit,
        offset=offset
    )

    return _respond(result)
