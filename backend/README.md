# CyberTrust Decision Engine (CTDE) — Backend

AI-powered Digital Trust and Forensics platform.

## Quick Start

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The frontend expects the backend at `http://localhost:8000`.

---

## Environment Variables

Create a `.env` file in the `backend/` directory:

```env
# Optional — AI Explanations (rule-based fallback if absent)
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini

GOOGLE_API_KEY=AIza...
GOOGLE_MODEL=gemini-1.5-flash

# Optional — Threat Intelligence (graceful fallback if absent)
VIRUSTOTAL_API_KEY=...
GOOGLE_SAFE_BROWSING_API_KEY=...
URLSCAN_API_KEY=...
ABUSEIPDB_API_KEY=...

# JWT (change in production)
SECRET_KEY=change-this-secret-key-in-production

# Database (default: SQLite)
DATABASE_URL=sqlite:///./ctde.db
```

**All API keys are optional.** The backend performs real forensic analysis (DNS, WHOIS, SSL, HTTP) without any keys. API keys unlock additional threat intelligence layers.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/analyze` | Main investigation endpoint |
| POST | `/ask-ai` | AI assistant chat |
| GET | `/health` | Server status & API key status |
| POST | `/users/register` | Create account |
| POST | `/users/login` | Get JWT token |
| GET | `/users/me` | Current user profile |
| GET | `/reports` | List investigations (auth required) |
| GET | `/reports/{id}` | Get investigation JSON |
| POST | `/reports/{id}/pdf` | Download PDF report |

### POST /analyze

```json
{
  "evidenceType": "url",
  "evidenceValue": "https://suspicious-site.com"
}
```

Evidence types: `url`, `email`, `apk`, `qr`, `sender`

### POST /ask-ai

```json
{
  "question": "Why is this site dangerous?",
  "investigation": { ...investigation result object... }
}
```

---

## What the Backend Actually Does

### Without any API keys (free)
- Real DNS lookups (A, AAAA, MX, TXT, NS, CNAME)
- Real WHOIS domain registration data
- Real SSL/TLS certificate inspection
- Real HTTP header collection and redirect following
- SPF / DMARC / DKIM selector detection
- Brand impersonation heuristics
- URL analysis (redirects, encoding, IP detection)
- Deterministic trust score from 10+ evidence factors
- Rule-based AI explanations from collected evidence

### With API keys
- VirusTotal: multi-vendor malware/phishing scan
- Google Safe Browsing: real-time threat database
- URLScan.io: URL sandbox scan
- AbuseIPDB: IP reputation database
- OpenAI / Gemini: natural language AI explanations

---

## Trust Score Logic

| Score | Risk Level |
|-------|-----------|
| 0–40 | Dangerous |
| 41–60 | Suspicious |
| 61–100 | Safe |

The score is deterministic — calculated from weighted evidence factors. It is never randomly generated.

---

## Production Notes

1. Change `SECRET_KEY` in `.env`
2. Replace `DATABASE_URL` with PostgreSQL: `postgresql+psycopg2://user:pass@host/db`
3. Remove `"*"` from CORS `allow_origins` in `main.py` — list explicit frontend origins
4. Run behind a reverse proxy (nginx/caddy) with HTTPS
5. Use `uvicorn main:app --workers 4` for production

---

## Project Structure

```
backend/
├── main.py               # FastAPI app, CORS, lifespan
├── config.py             # Settings via pydantic-settings
├── database.py           # SQLAlchemy engine + session
├── models.py             # DB models (User, Investigation, Report)
├── schemas.py            # Pydantic request/response schemas
├── auth.py               # JWT creation + dependency
├── security.py           # bcrypt password hashing
├── services/
│   ├── website.py        # HTTP fetch, headers, redirects, brand detection
│   ├── domain.py         # Domain intelligence aggregator
│   ├── ssl.py            # TLS certificate inspection
│   ├── dns.py            # DNS record lookups
│   ├── whois_svc.py      # WHOIS registration data
│   ├── reputation.py     # VirusTotal, GSB, URLScan, AbuseIPDB
│   ├── email_svc.py      # SPF, DKIM, DMARC, spoofing
│   ├── qr_svc.py         # QR decoding + URL investigation
│   ├── apk_svc.py        # APK static analysis (androguard)
│   ├── risk_engine.py    # Deterministic trust score calculator
│   ├── ai.py             # AI explanation (LLM + rule-based fallback)
│   └── report.py         # PDF + JSON report generation
├── routers/
│   ├── investigation.py  # POST /analyze
│   ├── assistant.py      # POST /ask-ai
│   ├── reports.py        # GET /reports
│   └── users.py          # Auth endpoints
└── utils/
    ├── validators.py     # URL/email/domain validation
    └── helpers.py        # SHA256, IP resolution, helpers
```
