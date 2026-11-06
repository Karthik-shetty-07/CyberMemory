# CyberMemory AI

CyberMemory combines a SOC investigation dashboard with a Flask API for security incident analysis and persistent Hindsight memory. The API applies defensive input handling and read-only analysis guardrails; containment recommendations require human review.

## Applications

| Service | Local URL | Start command |
|---|---|---|
| SOC dashboard | `http://localhost:5000` | `python app.py` |
| Investigation API | `http://localhost:5001` | `python -m cybermemory.api.app` |

The dashboard includes:

1. `/` or `/dashboard` — SOC metrics, severity charts, and activity.
2. `/investigate` — alert submission and investigation progress.
3. `/investigation/<id>` — investigation results, recommendations, and analyst feedback.
4. `/history` — searchable incident archive.
5. `/memory` — memory explorer.
6. `/analytics` — learning and triage analytics.

The dashboard can run in standalone mode with its bundled demo data. The investigation API is a separate service with its own API contract; see `docs/API_CONTRACT.md` for the dashboard contract and `docs/API_SPECIFICATION.md` for the backend API.

## Architecture

```
Browser ──> app.py (SOC dashboard, Flask :5000)
              │  memory calls go through try_backend_proxy()
              ├─ BACKEND_API_URL set   → HTTP to a separate backend service
              └─ BACKEND_API_URL unset → bundled backend/ app, called in-process
                                          (seeded from static/data/synthetic_incidents.json)
backend/ (memory API: /api/memory/retain|recall|reflect|feedback|stats|explorer)
  ├─ SQLite (incidents, feedback, stats)   CM_DB_PATH
  └─ services/hindsight_service.py
        ├─ live Hindsight  when hindsight-client is installed AND HINDSIGHT_URL is set
        └─ local bank      otherwise: JSON files in backend/data/local_banks/ (mode="local")

cybermemory/ (investigation engine + API, :5001)
  agent/investigator.py  IncidentInvestigator — the single authoritative pipeline:
                         sanitize → extract IOCs → recall memory → Groq LLM or
                         deterministic fallback → report
  memory/hindsight_service.py  live SDK (recall .results[].text, reflect .text)
                               with local mock fallback
  api/app.py             /api/health, /api/investigate, /api/reflect, /api/feedback, ...
```

**Memory bank modes.** Every memory response reports its mode. Live Hindsight is used only after a real
connectivity check (`get_version()`); otherwise the local bank is used and labelled as such. The local
bank uses keyword overlap, not semantic search, and its reflect output is a keyword-matched summary,
not an LLM synthesis.

**Confidence.** Deterministic-fallback confidence is derived from the top historical match's
similarity score. With no matches it is reported as "not scored".

**Analyst feedback.** Fields the analyst did not provide are stored as "Not provided by analyst";
nothing is fabricated.

## Local setup

Requires Python 3.10 or newer.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate
python -m pip install -r requirements.txt
```

The dashboard alone runs the whole stack: `python app.py`. No Hindsight server is required (the local bank is used).
To use live Hindsight, set `HINDSIGHT_URL` (and `HINDSIGHT_API_KEY` if needed) and install `hindsight-client`.

Copy `.env.example` to `.env` and set credentials for any external services you use. Start the dashboard and API in separate terminals:

```bash
python app.py
```

```bash
python -m cybermemory.api.app
```

The API listens on port 5000 by default, so set `PORT=5001` in its terminal when running it alongside the dashboard on the same machine.

## Docker

The Compose stack starts the dashboard, backend API, and Hindsight memory service:

```bash
docker compose up --build
```

The dashboard is available on port 5000, the API on port 5001, and Hindsight on port 8888. Configure service credentials in `.env` before connecting to hosted services.

## Tests

All suites use the standard library (no pytest required):

```bash
python -m unittest discover -s tests -t . -v
python -m unittest discover -s backend/tests -t . -v
```

`backend/tests/smoke_service.py`, `probe_hindsight.py` and `smoke_hindsight.py` are manual scripts against a live Hindsight server.

## Backend API

- `GET /api/health` — service and operational-mode status.
- `POST /api/investigate` — analyze a security alert.
- `POST /api/reflect` — `{"query": "..."}` → synthesis of lessons across stored incidents.
- `POST /api/feedback` — record analyst feedback and incident outcome.
- `GET /api/incidents` and `GET /api/incidents/<id>` — query incident records.
- `POST /api/memory/seed` — seed the memory bank with sample incidents.
- `POST /api/upload` — validate and process an uploaded file.

Investigation and safety behavior is documented in `docs/ARCHITECTURE.md`, `docs/SECURITY_AUDIT.md`, and `docs/DEMO_GUIDE.md`.
