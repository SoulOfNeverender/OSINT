# OSINT AI Dashboard

An **intelligent, full-stack OSINT (Open-Source Intelligence) tool** designed to enrich and analyze domain names. This dashboard aggregates data from multiple intelligence sources, computes a **dynamic risk score**, and presents it in a clear, user-friendly interface.

---

##  Features

- **Multi-Source Data Collection**
  - **WHOIS**: Public domain registration data.
  - **crt.sh**: SSL/TLS certificate transparency logs.
  - **AlienVault OTX**: Malware and malicious campaign associations.
  - **AbuseIPDB**: IP reputation and abuse reports.

- **Dynamic Risk Scoring**
  - Intelligent scoring engine generates a **0–100 risk score**.
  - Transparent scoring with **clear contributing factors**.

- **Interactive Frontend**
  - Built with **React + Tailwind CSS**.
  - Modern, responsive UI with intuitive workflows.

- **Context-Aware Help**
  - In-app **popups/tooltips** explaining what each intelligence tool does.

- **Robust Backend**
  - High-performance, asynchronous backend using **FastAPI + Uvicorn**.

---

##  Tech Stack

| Layer       | Technology                                  |
|-------------|----------------------------------------------|
| **Frontend** | React, Tailwind CSS                         |
| **Backend**  | FastAPI (Python), Uvicorn                   |
| **Libraries**| httpx, python-whois                         |
| **APIs**     | crt.sh, AlienVault OTX, AbuseIPDB           |

---

##  Setup & Installation

### Backend Setup (FastAPI)

```bash
# Navigate to backend directory
cd path/to/your/backend

# (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate  # For Linux/Mac
venv\Scripts\activate     # For Windows

# Install dependencies
pip install fastapi "uvicorn[standard]" httpx python-whois
```

#### Configure API Keys

Edit `main.py` and replace placeholders with your keys:

```python
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
OTX_API_KEY       = "YOUR_ALIENVAULT_OTX_API_KEY"
```

#### Run the Backend Server

```bash
uvicorn main:app --reload
```

Backend runs at: [http://127.0.0.1:8000](http://127.0.0.1:8000)

---

### Frontend Setup (React)

```bash
# Navigate to frontend directory
cd path/to/your/frontend

# Install dependencies
npm install   # or yarn install

# Run development server
npm start     # or yarn start
```

Frontend runs at: [http://localhost:3000](http://localhost:3000)

---

##  Usage

1. Ensure **both frontend and backend** are running.
2. Open your browser at `http://localhost:3000`.
3. Enter a domain name (e.g., `google.com`, `x.com`).
4. Click **Enrich Domain** to fetch and analyze intelligence.
5. Use the **info icons (?)** for explanations of each data source.

---

##  Preview

<img width="1080" height="606" alt="image" src="https://github.com/user-attachments/assets/92276d1f-78e4-4082-8707-261ea8c56e47" />

<img width="1094" height="639" alt="image" src="https://github.com/user-attachments/assets/eefbe436-f22d-4b20-b6dd-822048572c62" />

<img width="1049" height="654" alt="image" src="https://github.com/user-attachments/assets/34e2d5c2-8cb4-4e97-b2d9-f7de235925f3" />

<img width="1094" height="639" alt="image" src="https://github.com/user-attachments/assets/dddd70ca-b2bf-41c2-8c79-4b64378ba7b7" />




---

##  Contributions

Contributions, feature requests, and issues are welcome! Feel free to open a PR or raise an issue.

---















