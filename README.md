# DoomScanner — v2.0 Platform

Post-Quantum Cryptography readiness scanner with full web UI, PostgreSQL database,
user authentication, analytics dashboards, scheduled reports, and Docker deployment.

---

## Quick Start

### Prerequisites
- Docker Desktop (Windows/Mac) or Docker + Docker Compose (Linux)
- Your `Final_Script.py` renamed to `scanner.py` and placed in `backend/app/`

### 1. Configure environment

Edit `.env` with your actual values:

```env
POSTGRES_PASSWORD=choose-a-strong-password
SECRET_KEY=run-python-c-import-secrets-print-secrets.token_hex-32

# Email (Gmail example)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-16-char-app-password    # Google Account → Security → App Passwords
FROM_EMAIL=your-email@gmail.com

# Optional API keys for extra subdomain discovery
SHODAN_API_KEY=
SECURITYTRAILS_API_KEY=
VIRUSTOTAL_API_KEY=
```

**Gmail App Password:** Google Account → Security → 2-Step Verification → App Passwords → create one for "Mail"

### 2. Start the platform

```bash
cd pqc-platform
docker compose up --build
```

Wait for all 3 containers to be healthy (~60 seconds first time).

### 3. Access

| Service       | URL                          |
|---------------|------------------------------|
| Web UI        | http://localhost             |
| API docs      | http://localhost/api/docs    |
| API direct    | http://localhost:8000        |

### 4. First login

Open http://localhost → click **Register** → create your account.
The **first registered user** is automatically made admin.

---

## File Structure

```
pqc-platform/
├── docker-compose.yml         — orchestrates all services
├── .env                       — configuration (never commit this)
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py            — FastAPI routes (auth, scans, analytics, reports, jobs)
│       ├── models.py          — PostgreSQL schema (SQLAlchemy)
│       ├── database.py        — DB engine + session
│       ├── schemas.py         — Pydantic request/response models
│       ├── auth.py            — JWT + bcrypt authentication
│       ├── discovery.py       — Enhanced subdomain discovery (9 sources)
│       ├── scan_manager.py    — Scan orchestration + DB persistence
│       ├── report_manager.py  — Report generation (HTML/JSON/CBOM)
│       ├── scheduler.py       — APScheduler job engine
│       ├── email_service.py   — SMTP delivery (reads from .env only)
│       └── scanner.py         — Your original Final_Script.py (unchanged)
├── frontend/
│   ├── Dockerfile
│   ├── nginx.conf
│   └── index.html             — Complete single-file React-less frontend
└── nginx/
    └── default.conf           — Reverse proxy config
```

---

## Features

### Authentication
- Full user registration + JWT login
- First user auto-promoted to admin
- 24-hour token expiry

### Scanning
- 9 subdomain discovery sources: crt.sh, HackerTarget, AlienVault, RapidDNS, cert SANs, Shodan, SecurityTrails, VirusTotal, DNS brute-force
- Real-time SSE progress stream
- Full TLS cipher enumeration via sslyze
- PQC key exchange detection (raw TLS ServerHello parser)
- PQC label assignment: FULLY QUANTUM SAFE / PQC READY / PQC NOT READY / NOT QUANTUM SAFE
- CycloneDX 1.6 CBOM JSON export

### Database (PostgreSQL)
- All scans, hosts, reports, jobs persisted
- Full scan history with dates, summaries, elapsed times
- Per-host TLS/cipher data stored as JSONB

### Analytics
- Quantum Risk Score trend over time (line chart)
- PQC status distribution donut chart
- TLS version breakdown bar chart
- Open port frequency heatmap
- Top cipher suites horizontal bar chart
- Scan timeline table

### Reports
- **On-Demand**: generate HTML/JSON/CBOM from any completed scan
- **Scheduled**: fresh scan + report at a specific future datetime (one-shot)
- **Frequency**: recurring scan every N hours/days/weeks, optional max runs
- Download link for all report formats
- Email delivery to any recipient — SMTP configured in `.env` only

### Email
- Recipients specified in frontend (comma separated)
- SMTP credentials never exposed to frontend — stored in `.env` on server
- Branded HTML email with scan summary table

---

## Production Deployment (Render.com)

1. Push to GitHub
2. Create a **PostgreSQL** database on Render → copy the Internal Database URL
3. Create a **Web Service** pointing to your repo
   - Build command: `docker build -t pqc backend/`
   - Set all env vars from `.env` in Render's Environment tab
   - Set `DATABASE_URL` to the Render PostgreSQL internal URL
4. Create a second Web Service for the frontend (static site or nginx)

---

## API Reference

Full interactive docs at `/api/docs` (Swagger UI) after startup.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Login, get JWT |
| POST | `/scan` | Start scan |
| GET | `/scan/{id}` | Full results |
| GET | `/scan/{id}/stream?token=` | SSE live feed |
| GET | `/scans` | Scan history |
| GET | `/analytics/overview` | Aggregated analytics |
| POST | `/report/on-demand` | Generate report |
| POST | `/report/scheduled` | Schedule one-shot |
| POST | `/report/frequency` | Recurring monitor |
| GET | `/report/{id}/download?token=` | Download file |
| GET | `/jobs` | List jobs |
| DELETE | `/jobs/{id}` | Cancel job |
| GET | `/health` | Health check |

---

## Quantum Risk Score

```
score = ((not_safe × 1.0 + pqc_not_ready × 0.6) / total_tls_endpoints) × 100

0–20   Low Risk    (green)
21–60  Medium Risk (amber)
61–100 High Risk   (red)
```
