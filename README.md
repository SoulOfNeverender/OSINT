# 🔎 OSINT AI Dashboard  

An **intelligent, full-stack OSINT (Open-Source Intelligence) platform** for enriching and analyzing domain names.  
The system aggregates intelligence from multiple trusted sources, computes a **dynamic risk score**, and presents insights in a **clean, interactive dashboard**.  

---

## 🚩 Key Features  

- **Multi-Source Intelligence Collection**  
  - **WHOIS**: Domain registration and ownership data  
  - **crt.sh**: SSL/TLS certificate transparency logs  
  - **AlienVault OTX**: Malware and threat campaign associations  
  - **AbuseIPDB**: IP reputation and abuse reports  

- **Dynamic Risk Scoring**  
  - Weighted scoring engine (0–100)  
  - Transparent breakdown of contributing risk factors  

- **Interactive Dashboard**  
  - Built with **React + Tailwind CSS**  
  - Real-time enrichment results  
  - Context-aware tooltips & documentation  

- **Robust Backend**  
  - Asynchronous API layer powered by **FastAPI**  
  - High-performance event loop with **Uvicorn**  
  - Modular design for integrating future data sources  

---

## 🛠️ Technology Stack  

| Layer        | Technology / Tools |
|--------------|---------------------|
| **Frontend** | React, Tailwind CSS |
| **Backend**  | FastAPI (Python), Uvicorn |
| **Libraries**| httpx, python-whois |
| **Data Sources** | crt.sh, AlienVault OTX, AbuseIPDB |

---

## ⚡ Installation & Setup  

### Backend (FastAPI)  

```bash
# Navigate to backend
cd backend

# Install dependencies
pip install fastapi "uvicorn[standard]" httpx python-whois
Configuration
Edit main.py and provide your API keys:

python
Copy
Edit
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
OTX_API_KEY = "YOUR_ALIENVAULT_OTX_API_KEY"
Run the server

bash
Copy
Edit
uvicorn main:app --reload
Backend runs at: http://127.0.0.1:8000

Frontend (React)
bash
Copy
Edit
# Navigate to frontend
cd frontend

# Install dependencies
npm install   # or yarn install
Run the application

bash
Copy
Edit
npm start     # or yarn start
Frontend runs at: http://localhost:3000

🚀 Usage Workflow
Start both backend and frontend services

Access dashboard via http://localhost:3000

Input a domain (e.g., example.com)

Trigger enrichment → system fetches & analyzes data

View:

Domain WHOIS details

SSL/TLS certificate logs

Threat intelligence (OTX, AbuseIPDB)

Risk Score (0–100) with contributing factors

Use ❓ icons for in-app context explanations

📸 Demo (Recommended to Add)
Add screenshots or a short GIF walkthrough of:

Domain input

Data cards loading

Risk scoring visualization

📐 Architecture Overview
markdown
Copy
Edit
User (Browser)
      │
      ▼
Frontend (React + Tailwind)
      │ (REST API calls)
      ▼
Backend (FastAPI + Uvicorn)
      │
 ┌────┴───────────────────────────┐
 │   WHOIS    |   crt.sh          │
 │ AlienVault |   AbuseIPDB       │
 └────────────┴───────────────────┘
      │
      ▼
Risk Scoring Engine → Dashboard Results
📄 License
This project is distributed under the MIT License.

✅ Future Enhancements
🔐 Integration with additional OSINT sources (Shodan, VirusTotal)

📊 Risk trend analysis & reporting

📥 Export results (PDF/CSV)

🤖 AI-assisted remediation suggestions

🏢 Team & multi-user support















