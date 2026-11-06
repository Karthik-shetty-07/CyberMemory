"""Only module that talks to Hindsight. Never raises: returns status dicts."""
import logging
import re

import json
import os
import threading
import uuid
from datetime import datetime, timezone

from backend import config

try:  # The SDK is optional: without it (or without HINDSIGHT_URL) a local bank is used.
    from hindsight_client import Hindsight
except ImportError:  # pragma: no cover - depends on environment
    Hindsight = None

log = logging.getLogger(__name__)
INCIDENT_ID_RE = re.compile(r"INC-\d+(?:-\d+)*")
MISSION = (
    "SOC investigation memory: remember security incidents, indicators, "
    "investigation steps, root causes, remediation and outcomes."
)


def bank_id_for(tenant="default"):
    return f"{config.BANK_PREFIX}-{tenant}"


def use_live():
    """True only when the SDK is installed and a Hindsight URL is configured."""
    return Hindsight is not None and bool(config.HINDSIGHT_URL)


def _client():
    if not use_live():
        raise RuntimeError("Hindsight not configured")
    return Hindsight(
        base_url=config.HINDSIGHT_URL,
        api_key=config.HINDSIGHT_API_KEY or None,
        timeout=config.HINDSIGHT_TIMEOUT
    )


def _unavailable(e):
    # Log only the exception class: never expose keys or full URLs.
    log.warning("Hindsight call failed: %s", type(e).__name__)
    return {"status": "unavailable", "error": type(e).__name__}


def _is_missing_bank(e):
    return type(e).__name__ == "NotFoundException"


def _ensure_bank(client, bank_id):
    try:
        client.create_bank(bank_id=bank_id, name=bank_id, mission=MISSION)
    except Exception as e:
        # The bank may already exist. A real failure will surface on the next call.
        log.debug("create_bank skipped: %s", type(e).__name__)


def build_incident_text(inc):
    lines = [
        f"Incident {inc['incident_id']}: {inc.get('title', '')}",
        f"Alert type: {inc.get('alert_type', 'unknown')}; severity: {inc.get('severity', 'unknown')}",
        f"Affected host: {inc.get('host', 'unknown')}",
        f"Description: {inc.get('description', '')}",
        f"Indicators of compromise: {', '.join(inc.get('iocs', []))}",
        f"Investigation steps: {'; '.join(inc.get('steps', []))}",
        f"Root cause: {inc.get('root_cause', '')}",
        f"Remediation: {inc.get('remediation', '')}",
        f"Final outcome: {inc.get('outcome', '')}",
        f"Analyst feedback: {inc.get('feedback', '')}",
        f"Lessons learned: {inc.get('lessons', '')}"
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Local memory bank: an honest offline fallback (clearly labelled mode="local").
# ---------------------------------------------------------------------------
_LOCK = threading.Lock()
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9.\-_]{2,}")


def _local_path(bank):
    root = os.environ.get("LOCAL_BANK_DIR") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "local_banks")
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, f"{re.sub(r'[^A-Za-z0-9_-]', '_', bank)}.json")


def _local_load(bank):
    try:
        with open(_local_path(bank), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def _local_save(bank, items):
    path = _local_path(bank)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)
    os.replace(tmp, path)


def _local_retain(bank, content, context, document_id=None, metadata=None, fact_type="world"):
    with _LOCK:
        items = _local_load(bank)
        if document_id:  # same document id replaces the earlier version, like Hindsight
            items = [i for i in items if i.get("document_id") != document_id]
        items.append({
            "id": uuid.uuid4().hex, "text": content, "context": context,
            "document_id": document_id, "metadata": metadata or {},
            "fact_type": fact_type, "tags": [], "state": "active",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        _local_save(bank, items)


def _tokens(text):
    return set(_WORD_RE.findall((text or "").lower()))


def _local_rank(bank, query):
    q = _tokens(query)
    scored = []
    for item in _local_load(bank):
        t = _tokens(item["text"])
        if q and t:
            overlap = len(q & t) / len(q)
            if overlap > 0:
                scored.append((overlap, item))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored


def health():
    if not use_live():
        return {"status": "ok", "mode": "local", "api_version": None}
    try:
        with _client() as c:
            return {"status": "ok", "api_version": c.get_version().api_version}
    except Exception as e:
        return _unavailable(e)


def retain_incident(inc, tenant="default"):
    bank = bank_id_for(tenant)
    if not use_live():
        _local_retain(bank, build_incident_text(inc), "security incident report",
                      document_id=inc["incident_id"],
                      metadata={"severity": str(inc.get("severity", "")),
                                "alert_type": str(inc.get("alert_type", ""))})
        return {"status": "ok", "incident_id": inc["incident_id"], "mode": "local"}
    try:
        with _client() as c:
            _ensure_bank(c, bank)
            c.retain(
                bank_id=bank,
                content=build_incident_text(inc),
                context="security incident report",
                document_id=inc["incident_id"],
                metadata={
                    "severity": str(inc.get("severity", "")),
                    "alert_type": str(inc.get("alert_type", ""))
                },
                retain_async=False
            )
        return {"status": "ok", "incident_id": inc["incident_id"]}
    except Exception as e:
        return _unavailable(e)


def retain_feedback(incident, rating, comment, tenant="default"):
    """Retain analyst feedback as a separate searchable Hindsight memory."""
    bank = bank_id_for(tenant)
    incident_id = incident["incident_id"]

    content = "\n".join([
        f"Analyst feedback for security incident {incident_id}",
        f"Incident title: {incident.get('title', '')}",
        f"Severity: {incident.get('severity', '')}",
        f"Alert type: {incident.get('alert_type', '')}",
        f"Analyst rating: {rating}",
        f"Analyst comments and confirmed findings: {comment}",
        f"Original root cause: {incident.get('root_cause', '')}",
        f"Original remediation: {incident.get('remediation', '')}"
    ])

    if not use_live():
        _local_retain(bank, content, "SOC analyst feedback and confirmed incident findings",
                      metadata={"incident_id": incident_id, "rating": rating,
                                "type": "analyst_feedback"}, fact_type="experience")
        return {"status": "ok", "incident_id": incident_id, "mode": "local"}
    try:
        with _client() as c:
            _ensure_bank(c, bank)
            c.retain(
                bank_id=bank,
                content=content,
                context="SOC analyst feedback and confirmed incident findings",
                metadata={
                    "incident_id": incident_id,
                    "rating": rating,
                    "type": "analyst_feedback"
                },
                retain_async=False
            )
        return {"status": "ok", "incident_id": incident_id}
    except Exception as e:
        return _unavailable(e)


def recall_similar(query, tenant="default", max_tokens=2048):
    bank = bank_id_for(tenant)
    if not use_live():
        memories = [
            {"text": i["text"], "type": i.get("fact_type"), "score": round(sc, 3),
             "incident_ids": INCIDENT_ID_RE.findall(i["text"])}
            for sc, i in _local_rank(bank, query)[:8]
        ]
        return {"status": "ok" if memories else "empty", "memories": memories, "mode": "local"}
    try:
        with _client() as c:
            res = c.recall(bank_id=bank, query=query, budget="mid", max_tokens=max_tokens)
        memories = [
            {"text": r.text, "type": r.type, "incident_ids": INCIDENT_ID_RE.findall(r.text)}
            for r in res.results
        ]
        return {"status": "ok" if memories else "empty", "memories": memories}
    except Exception as e:
        if _is_missing_bank(e):
            return {"status": "empty", "memories": []}
        out = _unavailable(e)
        out["memories"] = []
        return out


def reflect_lessons(query, tenant="default"):
    bank = bank_id_for(tenant)
    if not use_live():
        ranked = _local_rank(bank, query)[:5]
        if not ranked:
            return {"status": "empty", "text": "", "mode": "local"}
        lines = []
        for _, i in ranked:
            rc = re.search(r"Root cause:\s*([^\n]+)", i["text"])
            le = re.search(r"Lessons learned:\s*([^\n]+)", i["text"])
            ids = INCIDENT_ID_RE.findall(i["text"])
            parts = [p for p in [rc and f"root cause: {rc.group(1)}",
                                 le and f"lesson: {le.group(1)}"] if p]
            if parts:
                lines.append(f"- {ids[0] if ids else 'memory'}: " + "; ".join(parts))
        text = ("Local bank synthesis (keyword match, no LLM reflection):\n" + "\n".join(lines)) if lines \
            else "Related memories exist but none record root causes or lessons yet."
        return {"status": "ok", "text": text, "mode": "local"}
    try:
        with _client() as c:
            ans = c.reflect(bank_id=bank, query=query, budget="low")
        return {"status": "ok", "text": ans.text}
    except Exception as e:
        if _is_missing_bank(e):
            return {"status": "empty", "text": ""}
        out = _unavailable(e)
        out["text"] = ""
        return out


def list_memory_units(
    tenant="default", memory_type=None, search_query=None, limit=20, offset=0,
    state=None, time_field=None, start_date=None, end_date=None
):
    bank = bank_id_for(tenant)
    if not use_live():
        items = _local_load(bank)
        if memory_type:
            items = [i for i in items if i.get("fact_type") == memory_type]
        if state:
            items = [i for i in items if i.get("state") == state]
        if search_query:
            ql = search_query.lower()
            items = [i for i in items if ql in i["text"].lower()]
        items = sorted(items, key=lambda i: i.get("updated_at", ""), reverse=True)
        page = items[offset:offset + limit]
        memories = [{
            "id": i["id"], "text": i["text"], "context": i.get("context"),
            "type": i.get("fact_type"), "document_id": i.get("document_id"),
            "incident_ids": INCIDENT_ID_RE.findall(i["text"]), "entities": None,
            "tags": i.get("tags", []), "date": i.get("updated_at"), "state": i.get("state"),
            "proof_count": None, "updated_at": i.get("updated_at"),
        } for i in page]
        return {"status": "ok" if memories else "empty", "memories": memories,
                "total": len(items), "limit": limit, "offset": offset, "mode": "local"}
    try:
        with _client() as c:
            res = c.list_memories(
                bank_id=bank,
                type=memory_type,
                search_query=search_query,
                limit=limit,
                offset=offset,
                state=state,
                time_field=time_field,
                start_date=start_date,
                end_date=end_date
            )

        memories = []
        for item in res.items:
            document_id = getattr(item, "document_id", None)
            text = getattr(item, "text", "") or ""
            incident_ids = []
            if document_id and INCIDENT_ID_RE.fullmatch(document_id):
                incident_ids.append(document_id)
            incident_ids.extend(
                incident_id for incident_id in INCIDENT_ID_RE.findall(text)
                if incident_id not in incident_ids
            )
            memories.append({
                "id": item.id,
                "text": text,
                "context": getattr(item, "context", None),
                "type": getattr(item, "fact_type", None),
                "document_id": document_id,
                "incident_ids": incident_ids,
                "entities": getattr(item, "entities", None),
                "tags": getattr(item, "tags", None) or [],
                "date": getattr(item, "var_date", None),
                "state": getattr(item, "state", None),
                "proof_count": getattr(item, "proof_count", None),
                "updated_at": getattr(item, "updated_at", None)
            })

        return {
            "status": "ok" if memories else "empty",
            "memories": memories,
            "total": res.total,
            "limit": res.limit,
            "offset": res.offset
        }
    except Exception as e:
        if _is_missing_bank(e):
            return {"status": "empty", "memories": [], "total": 0, "limit": limit, "offset": offset}
        out = _unavailable(e)
        out.update({"memories": [], "total": 0, "limit": limit, "offset": offset})
        return out
