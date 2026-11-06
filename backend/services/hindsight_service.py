"""Only module that talks to Hindsight. Never raises: returns status dicts."""
import logging
import re
from hindsight_client import Hindsight
from backend import config

log = logging.getLogger(__name__)
INCIDENT_ID_RE = re.compile(r"INC-\d+")
MISSION = ("SOC investigation memory: remember security incidents, indicators, "
           "investigation steps, root causes, remediation and outcomes.")


def bank_id_for(tenant="default"):
    return f"{config.BANK_PREFIX}-{tenant}"


def _client():
    return Hindsight(base_url=config.HINDSIGHT_URL,
                     api_key=config.HINDSIGHT_API_KEY or None,
                     timeout=config.HINDSIGHT_TIMEOUT)


def _unavailable(e):
    # exception class name only: never log keys or full URLs
    log.warning("Hindsight call failed: %s", type(e).__name__)
    return {"status": "unavailable", "error": type(e).__name__}


def _is_missing_bank(e):
    # A tenant that has never retained anything has no bank yet: empty memory, not an outage
    return type(e).__name__ == "NotFoundException"


def _ensure_bank(client, bank_id):
    try:
        client.create_bank(bank_id=bank_id, name=bank_id, mission=MISSION)
    except Exception as e:  # bank may already exist; real failures surface on the next call
        log.debug("create_bank skipped: %s", type(e).__name__)


def build_incident_text(inc):
    lines = [f"Incident {inc['incident_id']}: {inc.get('title', '')}",
             f"Alert type: {inc.get('alert_type', 'unknown')}; severity: {inc.get('severity', 'unknown')}",
             f"Affected host: {inc.get('host', 'unknown')}",
             f"Description: {inc.get('description', '')}",
             f"Indicators of compromise: {', '.join(inc.get('iocs', []))}",
             f"Investigation steps: {'; '.join(inc.get('steps', []))}",
             f"Root cause: {inc.get('root_cause', '')}",
             f"Remediation: {inc.get('remediation', '')}",
             f"Final outcome: {inc.get('outcome', '')}",
             f"Analyst feedback: {inc.get('feedback', '')}",
             f"Lessons learned: {inc.get('lessons', '')}"]
    return "\n".join(lines)


def health():
    try:
        with _client() as c:
            return {"status": "ok", "api_version": c.get_version().api_version}
    except Exception as e:
        return _unavailable(e)


def retain_incident(inc, tenant="default"):
    bank = bank_id_for(tenant)
    try:
        with _client() as c:
            _ensure_bank(c, bank)
            c.retain(bank_id=bank, content=build_incident_text(inc),
                     context="security incident report",
                     document_id=inc["incident_id"],
                     metadata={"severity": str(inc.get("severity", "")),
                               "alert_type": str(inc.get("alert_type", ""))},
                     retain_async=False)
        return {"status": "ok", "incident_id": inc["incident_id"]}
    except Exception as e:
        return _unavailable(e)


def recall_similar(query, tenant="default", max_tokens=2048):
    bank = bank_id_for(tenant)
    try:
        with _client() as c:
            res = c.recall(bank_id=bank, query=query, budget="mid", max_tokens=max_tokens)
        memories = [{"text": r.text, "type": r.type,
                     "incident_ids": INCIDENT_ID_RE.findall(r.text)} for r in res.results]
        return {"status": "ok" if memories else "empty", "memories": memories}
    except Exception as e:
        if _is_missing_bank(e):
            return {"status": "empty", "memories": []}
        out = _unavailable(e)
        out["memories"] = []
        return out


def reflect_lessons(query, tenant="default"):
    bank = bank_id_for(tenant)
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
    tenant="default",
    memory_type=None,
    search_query=None,
    limit=20,
    offset=0,
    state=None,
    time_field=None,
    start_date=None,
    end_date=None
):
    bank = bank_id_for(tenant)

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
                incident_id
                for incident_id in INCIDENT_ID_RE.findall(text)
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
            return {
                "status": "empty",
                "memories": [],
                "total": 0,
                "limit": limit,
                "offset": offset
            }

        out = _unavailable(e)
        out.update({
            "memories": [],
            "total": 0,
            "limit": limit,
            "offset": offset
        })
        return out
