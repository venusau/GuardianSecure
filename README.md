# GuardianSecure

**GuardianSecure** is an enterprise-grade web-security platform that lets users
run **OWASP Top-10 vulnerability scans**, check password strength, and convert
text to digests — all behind a secure, rate-limited authentication layer.

> **ZAP dependency removed.** The original app drove OWASP ZAP (`ZAPv2`) for
> scanning. That dependency is gone. Scanning is now performed by a fully
> **in-house engine** (`scanner/`) — crawl → passive analysis → active probing —
> with no external scanning daemon.

---

## Architecture (built to scale to ~1M users)

```
                ┌──────────────┐
   Browser ───► │ API Gateway  │  Flask, rate-limited, Redis-backed sessions
                │  (gateway)   │
                └──────┬───────┘
                       │  POST /api/scans
                       ▼
                ┌──────────────┐      scan-requests      ┌─────────────────┐
                │   Temporal   │ ───────────────────────► │  Scan Workers   │
                │  Workflow    │                          │  (scanner/)     │
                └──────────────┘                          └────────┬────────┘
                       ▲                                           │ ScanResult
                       │                                           ▼
                ┌──────────────┐      scan-results       ┌─────────────────┐
                │    Redis     │ ◄───────(cache)──────── │  Notification   │
                │ (status/RL)  │                         │  Worker (email) │
                └──────────────┘                         └─────────────────┘
                       ▲
                       │ persist
                ┌──────┴───────┐
                │   Postgres   │  (users + scans, Alembic migrations)
                └──────────────┘
```

| Concern            | Technology |
|--------------------|------------|
| Web framework      | Flask (API gateway) |
| Scan orchestration | **Temporal** (`ScanWorkflow` + activity) |
| Event streaming    | **Kafka** (`scan-requests`, `scan-results`) |
| Cache / rate-limit | **Redis** |
| Database           | **Postgres** + Alembic migrations |
| Scanner engine     | In-house `scanner/` package (no ZAP) |
| Containerization   | Docker + `docker-compose.yml` |

The gateway enqueues a scan, immediately returns a `scan_id`, and the SPA-style
UI polls `GET /api/scans/<id>`. When `USE_TEMPORAL=true` scans are driven by
durable Temporal workflows; otherwise a local worker thread runs the same
engine. Both paths share `project/scan_service.py`.

---

## The in-house scanner (OWASP Top-10)

Located in `scanner/`:

- `spider.py` — bounded BFS crawler (same-host only).
- `checks/` — one module per category:
  - **A01** Broken Access Control — probes sensitive paths.
  - **A02** Cryptographic Failures — HTTPS/HSTS, cookie flags.
  - **A03** Injection — reflected XSS & SQLi payload probing.
  - **A05** Security Misconfiguration — missing security headers, server banner.
  - **A06** Vulnerable Components — outdated-tech signature + missing SRI.
  - **A07** Auth Failures — login brute-force protection check.
  - **A10** SSRF — internal/metadata endpoint probing.
- `report.py` — JSON + HTML report (replaces the old ZAP PDF).
- `scanner.py` — orchestrator (passive by default, active on demand).

Run the tests: `make test-scan`.

---

## Local development

```bash
cp .env.example .env          # fill SECRET_KEY, MAIL_*, DATABASE_URI
make install                  # install dependencies
make migrate                  # create Postgres schema (Alembic)
make run-gateway              # http://localhost:5500
```

The app also calls `db.create_all()` for zero-config dev when no migrations
exist yet; **production must use Alembic** (`make migrate`).

### Run the full stack (recommended)

```bash
cp .env.example .env
docker compose up -d          # or: make docker-up
```

This starts gateway, Postgres, Redis, Kafka, Temporal, 3 scan-workers and the
notification worker.

### Components

| Command | What it runs |
|---------|--------------|
| `make run-gateway` | Flask API gateway |
| `make run-worker`  | Temporal scan worker (scale horizontally) |
| `make run-notifier`| Kafka → email notification worker |
| `make migrate`     | Apply Alembic DB migrations |

---

## Security hardening applied

- Secrets via env (`SECRET_KEY`, DB, mail) — no hardcoded keys.
- **Removed plaintext password comparisons** for admin checks (`auth.py`,
  `main.py`, `crud_user.py`); admin is now a `role` column.
- Per-user **rate limiting** on the scan API via Redis.
- `delete_user` now requires auth + admin.
- Report/scan access is ownership-checked (`current_user.id`).

---

## Project layout

```
project/            Flask app (auth, tools, api, models, scan_service)
scanner/            In-house OWASP Top-10 scanner (no ZAP)
libs/               Redis + Kafka clients
temporal/           Workflow + activity + worker
services/notification/   Kafka consumer -> email
migrations/         Alembic migrations
deploy/             Dockerfiles
docker-compose.yml  Full stack
Makefile            Dev & ops commands
tests/              Scanner pytest suite
```
