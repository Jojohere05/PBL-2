# FinGuard - Security Scanner & Compliance Tool

A comprehensive security scanning and compliance checking tool for financial applications.

## Features

- **Secret Detection**: Scans code for hardcoded secrets, API keys, and credentials
- **Dependency Scanning**: Identifies vulnerable dependencies using OSV database
- **Terraform Analysis**: Detects security misconfigurations in infrastructure code
- **Real-time Updates**: WebSocket-based live scan progress
- **GitHub Integration**: Works as a GitHub App for automated PR checks
- **RAG-powered Explanations**: AI-generated explanations for findings
- **Feedback Learning**: Adjusts rule weights based on user feedback
- **PDF Reports**: Generate detailed security reports

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker (optional)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/finguard.git
cd finguard
```

2. Set up the backend:
```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your configuration
```

3. Set up the frontend:
```bash
cd frontend
npm install
```

4. Prepare your data:
   - Place `compliance.xlsx` in `data/raw/`
   - Place `gitleaks.toml` in `data/raw/`
   - Place OSV JSON files in `data/raw/osv/`

5. Convert data files:
```bash
python scripts/convert_excel.py
python scripts/convert_gitleaks.py
python scripts/validate_datasets.py
```

### Running the Application

**Development:**

Backend:
```bash
cd api
uvicorn main:app --reload
```

Frontend:
```bash
cd frontend
npm run dev
```

**Docker:**
```bash
docker-compose up --build
```

## Project Structure

```
finguard/
├── data/                    # Data files
│   ├── raw/                 # Original source files
│   ├── rules/               # Converted compliance rules
│   ├── gitleaks/            # Converted gitleaks rules
│   ├── osv/                 # OSV vulnerability data
│   └── feedback/            # User feedback weights
├── api/                     # FastAPI backend
│   ├── routes/              # API endpoints
│   ├── adk_agents/          # Scanning agents
│   ├── github_app/          # GitHub integration
│   ├── rag/                 # RAG for explanations
│   └── report/              # PDF generation
├── scripts/                 # Utility scripts
├── frontend/                # React frontend
└── .github/workflows/       # GitHub Actions
```

## API Endpoints

- `POST /api/scan/start` - Start a new scan
- `GET /api/scan/status/{id}` - Get scan status
- `GET /api/scan/results/{id}` - Get scan results
- `GET /api/dashboard/summary` - Dashboard data
- `POST /api/feedback/submit` - Submit finding feedback
- `WS /api/ws/scan/{id}` - Real-time scan updates

## Configuration

See `.env.example` for all configuration options.

## License

MIT
