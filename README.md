#  OSINT AI Dashboard  

An intelligent, full-stack **OSINT (Open-Source Intelligence) tool** designed to enrich and analyze domain names.  
This dashboard collects data from multiple sources, computes a dynamic risk score, and provides a clear, user-friendly interface for analysis.  

---

##  Features  

- **Multi-Source Data Collection**: Gathers intelligence from four distinct sources:  
  - **WHOIS**: Public domain registration data.  
  - **crt.sh**: SSL/TLS certificate transparency logs.  
  - **AlienVault OTX**: Malware and malicious campaign associations.  
  - **AbuseIPDB**: IP address reputation and abuse reports.  

- **Dynamic Risk Scoring**: An intelligent scoring engine that analyzes the collected data to produce a **risk score (0–100)**, with clear factors explaining the score.  

- **Interactive Frontend**: A responsive, intuitive UI built with **React + Tailwind CSS**.  

- **Context-Aware Help**: In-app popups explaining what each intelligence tool does and what its results mean.  

- **Robust Backend**: A high-performance, asynchronous backend built with **FastAPI (Python)**.  

---

##  Tech Stack  

| Area       | Technology |
|------------|------------|
| **Frontend** | React, Tailwind CSS |
| **Backend**  | FastAPI (Python), Uvicorn |
| **Libraries** | httpx, python-whois |
| **APIs**     | crt.sh, AlienVault OTX, AbuseIPDB |

---

##  Setup and Installation  

### 1. Backend Setup (FastAPI)  

```bash
# Navigate to backend folder
cd path/to/your/backend

# Install dependencies
pip install fastapi "uvicorn[standard]" httpx python-whois
Add API Keys:
Open main.py and replace placeholders with your keys:

python
Copy
Edit
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
OTX_API_KEY = "YOUR_ALIENVAULT_OTX_API_KEY"
Run the server:

bash
Copy
Edit
uvicorn main:app --reload
Backend will now be live at: http://127.0.0.1:8000

2. Frontend Setup (React)
bash
Copy
Edit
# Navigate to frontend folder
cd path/to/your/frontend

# Install dependencies
npm install
# or
yarn install
Run the application:

bash
Copy
Edit
npm start
# or
yarn start
Frontend will be live at: http://localhost:3000

🚀 Usage
Ensure both backend & frontend servers are running.

Open your browser at http://localhost:3000.

Enter a domain name (e.g., google.com, x.com) in the input field.

Click “Enrich Domain” to fetch and display the intelligence data.

Click the ❓ icon on any card to learn more about that data source.

📸 Demo (Optional)
(Insert screenshots or GIFs of dashboard here)












