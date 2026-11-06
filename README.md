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

Run the frontend integration tests and backend test suite with:

```bash
python -m pytest tests/ -v
```

The backend tests can also be run with the standard library:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

## Backend API

- `GET /api/health` — service and operational-mode status.
- `POST /api/investigate` — analyze a security alert.
- `POST /api/feedback` — record analyst feedback and incident outcome.
- `GET /api/incidents` and `GET /api/incidents/<id>` — query incident records.
- `POST /api/memory/seed` — seed the memory bank with sample incidents.
- `POST /api/upload` — validate and process an uploaded file.

Investigation and safety behavior is documented in `docs/ARCHITECTURE.md`, `docs/SECURITY_AUDIT.md`, and `docs/DEMO_GUIDE.md`.
