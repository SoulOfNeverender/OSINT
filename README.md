# OSINT AI Tool — Starter Backend

A minimal, **ready-to-run** FastAPI backend for an AI-enabled OSINT tool.
Day 0 goal: enrich a **domain** using **RDAP** and **crt.sh**, return a **transparent threat score**, and expose `/enrich`.

---

## 0) Prereqs
- Python 3.10+
- Git (optional but recommended)

---

## 1) Get the code
```bash
# Linux / macOS / WSL
unzip osint-ai-tool-starter.zip -d .
cd osint-ai-tool/backend
```

On Windows (PowerShell):
```powershell
Expand-Archive -Path .\osint-ai-tool-starter.zip -DestinationPath .
cd .\osint-ai-tool\backend
```

> If you cloned from GitHub instead of the zip, just `cd` into `backend`.

---

## 2) Create a virtual environment & install deps
**Linux/macOS/WSL:**
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r ../requirements.txt
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r ..\requirements.txt
```

---

## 3) Run the API
```bash
uvicorn main:app --reload --port 8000
```

Health check:
```bash
curl http://127.0.0.1:8000/health
```

Enrich a domain:
```bash
curl -X POST http://127.0.0.1:8000/enrich ^
  -H "Content-Type: application/json" ^
  -d "{\"type\":\"domain\",\"value\":\"example.com\"}"
```

Linux/macOS equivalent:
```bash
curl -X POST http://127.0.0.1:8000/enrich   -H "Content-Type: application/json"   -d '{"type":"domain","value":"example.com"}'
```

You should see JSON with `data.rdap`, `data.crtsh`, a `score`, and `factors`.

---

## 4) Next Steps (today)
- Add a new collector (AbuseIPDB or OTX) to `backend/collectors/` and wire it in `main.py`.
- Commit to Git: `git init && git add . && git commit -m "starter backend"`
- Push to GitHub.

---

## File Tree
```
osint-ai-tool/
├── .gitignore
├── .env.example
├── README.md
├── requirements.txt
└── backend/
    ├── main.py
    ├── scoring.py
    └── collectors/
        ├── __init__.py
        ├── rdap.py
        └── crtsh.py
```