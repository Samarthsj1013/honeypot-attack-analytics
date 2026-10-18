# Honeypot Attack Analytics Platform

A cybersecurity analytics platform for analyzing honeypot activity, investigating attacker behavior, identifying suspicious patterns, and exploring potential attack campaigns.

**Live Demo:** https://honeypot-attack-analytics-3gxv.onrender.com/

**Repository:** https://github.com/Samarthsj1013/honeypot-attack-analytics

## Overview

The Honeypot Attack Analytics Platform transforms Cowrie honeypot logs into structured event and session data. It combines behavioral analysis, risk scoring, geographic enrichment, threat detection, and interactive investigation tools in a unified dashboard.

The application uses a FastAPI backend, SQLite database, and React frontend to help security analysts explore recorded honeypot activity, investigate suspicious sources, and understand relationships between observed behaviors.

**Important:** The deployed application uses sanitized demonstration data. IP addresses are anonymized, and geographic metadata is approximate. The dashboard is intended for demonstration and analysis, not definitive attacker attribution.

## Key Features

- **Security Overview:** Monitor event counts, attacker sources, sessions, and risk indicators.
- **Attacker Origin Map:** Visualize available approximate geographic coordinates.
- **Source Intelligence:** Explore source records, event counts, login attempts, and risk scores.
- **Behavioral Clustering:** Group sessions into behavior categories using machine learning.
- **Attack Timeline:** Examine activity over time and reconstruct attacker-specific sequences.
- **Threat Hunting:** Filter recorded events using source IP, username, command, event type, and risk level.
- **Automated Threat Alerts:** Identify repeated failed logins, successful honeypot logins, suspicious command patterns, and download-tool activity.
- **MITRE ATT&CK Intelligence:** Explore technique-related evidence associated with observed activity.
- **Attack Campaign Correlation:** Investigate candidate campaigns and related activity.
- **Attack Relationship Graph:** Explore relationships between attackers and sessions.
- **Attacker Intent Analysis:** Review explainable behavioral indicators.
- **Behavioral Similarity:** Compare attackers using multiple behavioral characteristics.
- **Incident Reconstruction:** Investigate attacker-specific events and activity sequences.
- **CSV Export:** Export threat-hunting results for further analysis.
- **Interactive Filtering:** Apply supported date and behavior filters across relevant views.

## Technology Stack

### Backend
- Python
- FastAPI
- Uvicorn
- SQLite
- Pandas
- NumPy
- Scikit-learn
- GeoIP2

### Frontend
- React
- Vite
- JavaScript
- Recharts
- Leaflet
- React Leaflet
- Lucide React

### Deployment
- Docker
- Render

## System Architecture

```text
Cowrie Honeypot Logs
        |
        v
    Log Parser
        |
        v
 Session Construction
        |
        v
Behavioral Clustering
 and Risk Analysis
        |
        v
    SQLite Database
        |
        v
     FastAPI
    REST API
        |
        v
    React UI
        |
        v
Interactive Security
 Analytics Dashboard
```

The pipeline parses events, groups activity into sessions, derives behavioral and risk information, and makes the results available through API endpoints and dashboard visualizations.

## Live Application

**Dashboard:** https://honeypot-attack-analytics-3gxv.onrender.com/

**API Documentation:** https://honeypot-attack-analytics-3gxv.onrender.com/docs

**Health Check:** https://honeypot-attack-analytics-3gxv.onrender.com/health

The application is hosted on Render. Free instances may spin down after inactivity, so the first request after a period of inactivity can take longer than usual.

## Installation and Local Setup

### Prerequisites

- Python 3.12 recommended
- Node.js and npm
- Git

### 1. Clone the repository

```bash
git clone https://github.com/Samarthsj1013/honeypot-attack-analytics.git
cd honeypot-attack-analytics
```

### 2. Create a Python virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### 3. Install frontend dependencies

```bash
cd frontend
npm install
cd ..
```

### 4. Start the backend

From the project root:

```bash
python run_api.py
```

The API runs at:

`http://127.0.0.1:8000`

Interactive API documentation:

`http://127.0.0.1:8000/docs`

### 5. Start the frontend

Open a second terminal:

```bash
cd frontend
npm run dev
```

Open the local URL printed by Vite, usually:

`http://localhost:5173`

For local development, the frontend API configuration defaults to `http://127.0.0.1:8000`. Use `VITE_API_URL` if the backend runs at a different address.

## Data Processing

The project includes modules for parsing Cowrie logs, constructing sessions, clustering behavior, and computing risk indicators.

The repository includes these pipeline commands:

```bash
python run_pipeline.py
python run_analysis.py
```

Use the sample dataset for initial testing. When using other datasets, ensure their schema is compatible with the parser and session-building logic.

GeoIP enrichment uses a local MaxMind GeoLite2 City database when available. If the database is missing or an address has no matching record, geographic information may be unavailable.

## API Endpoints

The complete API specification is available at `/docs`.

| Endpoint | Description |
|---|---|
| `GET /health` | Application and database readiness |
| `GET /api/meta` | Active dataset metadata |
| `GET /api/overview` | Dashboard summary metrics |
| `GET /api/timeline` | Activity timeline |
| `GET /api/hourly` | Hourly activity summary |
| `GET /api/behaviors` | Behavior category summary |
| `GET /api/countries` | Country-level summary |
| `GET /api/map` | Map points with available coordinates |
| `GET /api/attackers` | Attacker source listing |
| `GET /api/source-intelligence` | Filterable source intelligence |
| `GET /api/threat-hunt` | Threat-hunting query |
| `GET /api/threat-hunt/export` | CSV export |
| `GET /api/alerts` | Rule-based threat alerts |
| `GET /api/alerts/{alert_id}` | Alert details |
| `GET /api/attack-graph` | Attack relationship graph data |
| `GET /api/campaigns` | Candidate attack campaigns |
| `GET /api/campaigns/{campaign_id}` | Campaign details |
| `GET /api/mitre/techniques` | MITRE ATT&CK technique intelligence |
| `GET /api/mitre/techniques/{technique_id}` | Technique evidence details |
| `GET /api/attackers/{src_ip}` | Attacker profile |
| `GET /api/attackers/{src_ip}/dna` | Attacker behavioral profile |
| `GET /api/attackers/{src_ip}/similar` | Similar attacker analysis |
| `GET /api/attackers/{src_ip}/intent` | Attacker intent indicators |
| `GET /api/attackers/{src_ip}/timeline` | Attacker-specific timeline |
| `GET /api/attackers/{src_ip}/incident` | Incident reconstruction |
| `GET /api/risk-levels` | Risk-level summary |
| `GET /api/credentials` | Aggregated username, password, or command values |

Supported endpoints accept applicable query parameters for date ranges, behaviors, pagination, and other filters. Refer to `/docs` for exact parameter definitions and response schemas.

## Testing

Run the backend unit tests:

```bash
python -m unittest discover -s tests -v
```

Build the frontend for production:

```bash
cd frontend
npm run build
```

During development, the project passed **115 backend unit tests**, and the Vite production build completed successfully. Run these checks again after making changes to verify your current version.

## Docker Deployment

The project includes a root-level `Dockerfile` that builds the React frontend and packages it with the FastAPI backend in one container.

To deploy, configure the hosting service to build from the repository's root Dockerfile. The server uses the `PORT` environment variable for its listening port.

The deployed demo database should contain only sanitized data intended for publication. Never include raw honeypot logs, original IP mappings, credentials, or secrets in a public repository.

## Configuration

| Variable | Purpose |
|---|---|
| `HONEYPOT_DB_PATH` | Overrides the SQLite database path |
| `CORS_ORIGINS` | Adds comma-separated allowed frontend origins |
| `VITE_API_URL` | Configures the frontend API base URL |
| `PORT` | Configures the web server port |

## Privacy and Security

- The public demo uses anonymized IP addresses from the documentation-reserved `198.51.100.0/24` range.
- The IP addresses shown in the demo are placeholders, not live attacker IPs.
- Geographic metadata is approximate source-record metadata retained before IP anonymization; it is not verified attribution.
- GeoIP coordinates can be missing or inaccurate and do not identify an attacker's physical location.
- Risk scores, behavioral classifications, intent indicators, and campaign correlations are analytical signals, not definitive conclusions.
- Never commit `.env` files, API keys, raw logs, local databases, `.mmdb` files, or other sensitive data.
- Review data sanitization before publishing new datasets.

## Limitations

- GeoIP results depend on database coverage.
- The demo dataset is sanitized and does not represent a live threat feed.
- Model-derived behavior labels and risk scores should be interpreted as investigative aids.
- Render's free service may sleep after inactivity, and ephemeral filesystem changes should not be treated as durable storage.

## Future Enhancements

Potential improvements include additional honeypot integrations, persistent production storage, configurable detection thresholds, expanded investigation workflows, and more automated validation of incoming datasets.

## License

No license is specified in this repository documentation. Add a `LICENSE` file if you intend to grant explicit permissions for reuse or redistribution.

## Author

**Samarth Jayant**

**GitHub:** https://github.com/Samarthsj1013

**Project Repository:** https://github.com/Samarthsj1013/honeypot-attack-analytics

**Live Demo:** https://honeypot-attack-analytics-3gxv.onrender.com/
