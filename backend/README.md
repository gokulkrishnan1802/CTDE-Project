# CyberTrust Decision Engine (CTDE) — Backend

Digital trust and forensics platform with evidence processing, heuristic risk scoring, optional AI explanations, and investigation reports.

## Quick Start

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The frontend expects the backend at `http://localhost:8000`.

## Environment Variables

Create a `.env` file in the `backend/` directory. AI and threat intelligence keys are optional; without an AI key, the backend uses its rule-based explanation.

```env
# Optional AI providers
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
GOOGLE_API_KEY=
GOOGLE_MODEL=gemini-3.8-flash

# Optional threat intelligence
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
URLSCAN_API_KEY=
ABUSEIPDB_API_KEY=

# Change this in production
SECRET_KEY=change-this-secret-key-in-production

# Database (SQLite default)
DATABASE_URL=sqlite:///./ctde.db
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/analyze` | Analyze submitted evidence |
| POST | `/analyze/email` | Analyze raw email headers |
| POST | `/analyze/apk` | Analyze an uploaded APK |
| POST | `/ask-ai` | Ask about an investigation; authentication required |
| GET | `/health` | Backend status and configured API-key status |
| POST | `/users/register` | Create an account |
| POST | `/users/login` | Get an authentication token |
| GET | `/users/me` | Get the signed-in user profile |
| GET | `/reports` | List the signed-in user's investigations |
| GET | `/reports/{id}` | Get an investigation result |
| GET | `/reports/{id}/download` | Download a PDF report |
| GET | `/reports/{id}/download.json` | Download a JSON report |
| POST | `/reports/{id}/pdf` | Existing PDF download endpoint |

Report endpoints require authentication and only return investigations belonging to the signed-in user.

### Analyze evidence

```json
{
  "evidenceType": "url",
  "evidenceValue": "https://example.com"
}
```

Supported evidence types include `url`, `email`, `apk`, `qr`, and `sender`.

### Ask the assistant

```json
{
  "question": "What evidence contributed to this result?",
  "investigation": {
    "evidenceType": "url",
    "trustScore": 60,
    "riskLevel": "Suspicious"
  }
}
```

The endpoint requires the user's bearer token. Investigation context is size-limited.

## Analysis and Score Limitations

The trust score is a heuristic based on collected evidence. It is not a probability, independently measured accuracy, or a confirmed malware verdict. The project has not been calibrated against a representative labelled dataset.

External reputation checks only run when their API keys are configured. Reports and explanations should be interpreted using the findings and sources shown for that investigation.

## What the Backend Checks

Depending on evidence type and available services, the backend can collect DNS, WHOIS, TLS, HTTP, email-authentication, QR, and APK evidence. Evidence processing normalizes indicators and correlates relationships. Optional API keys enable additional threat-intelligence lookups. An optional OpenAI or Gemini key enables generated explanations; otherwise a rule-based explanation is used.

## Production Notes

1. Set a strong, private `SECRET_KEY`.
2. Use a managed PostgreSQL database for production.
3. Configure CORS in `main.py` for the exact frontend origin.
4. Keep API keys in the deployment platform's secret environment variables.
5. Set appropriate upload and request limits for the hosting plan.

## Project Structure

```text
backend/
├── main.py
├── config.py
├── database.py
├── models.py
├── schemas.py
├── auth.py
├── security.py
├── services/
│   ├── website.py
│   ├── domain.py
│   ├── ssl.py
│   ├── dns.py
│   ├── whois_svc.py
│   ├── reputation.py
│   ├── email_svc.py
│   ├── qr_svc.py
│   ├── apk_svc.py
│   ├── evidence.py
│   ├── evidence_processing.py
│   ├── risk_engine.py
│   ├── ai.py
│   └── report.py
├── routers/
│   ├── investigation.py
│   ├── assistant.py
│   ├── reports.py
│   └── users.py
└── utils/
    ├── validators.py
    └── helpers.py
```