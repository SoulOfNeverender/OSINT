OSINT AI Dashboard
An intelligent, full-stack OSINT (Open-Source Intelligence) tool designed to enrich and analyze domain names. This dashboard collects data from multiple sources, computes a dynamic risk score, and provides a clear, user-friendly interface for analysis.

Features
Multi-Source Data Collection: Gathers intelligence from four distinct sources:

WHOIS: Public domain registration data.

crt.sh: SSL/TLS certificate transparency logs.

AlienVault OTX: Malware and malicious campaign associations.

AbuseIPDB: IP address reputation and abuse reports.

Dynamic Risk Scoring: An intelligent scoring engine that analyzes the collected data to produce a risk score from 0-100, with clear factors explaining the score.

Interactive Frontend: A responsive and intuitive user interface built with React and Tailwind CSS.

Context-Aware Help: In-app popups explaining what each intelligence tool does and what its results mean.

Robust Backend: A high-performance, asynchronous backend built with FastAPI (Python).

Tech Stack
Area

Technology

Frontend

React, Tailwind CSS

Backend

FastAPI (Python), Uvicorn

Libraries

httpx, python-whois

APIs

crt.sh, AlienVault OTX, AbuseIPDB

Setup and Installation
To get this project running locally, you'll need to set up both the backend server and the frontend application.

1. Backend Setup (FastAPI)
First, navigate to your backend directory.

cd path/to/your/backend

Install Dependencies:

Create a virtual environment (optional but recommended) and install the required Python libraries.

pip install fastapi "uvicorn[standard]" httpx python-whois

Add API Keys:

Open the main.py file and replace the placeholder API keys with your own:

# main.py

ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
OTX_API_KEY = "YOUR_ALIENVAULT_OTX_API_KEY"

Run the Server:

Start the backend server.

uvicorn main:app --reload

The backend will now be running at http://127.0.0.1:8000.

2. Frontend Setup (React)
Next, navigate to your frontend directory in a new terminal.

cd path/to/your/frontend

Install Dependencies:

If you are using a standard React setup with npm or yarn, install the project dependencies.

npm install
# or
yarn install

Run the Application:

Start the frontend development server.

npm start
# or
yarn start

The frontend application will now be running, typically at http://localhost:3000, and will be able to communicate with your backend server.

Usage
Ensure both the backend and frontend servers are running.

Open your web browser and navigate to the frontend application's URL.

Enter a domain name (e.g., google.com, x.com) into the input field.

Click the "Enrich Domain" button to fetch and display the intelligence data.

Click the question mark icon (?) on any card to learn more about that specific data source.
