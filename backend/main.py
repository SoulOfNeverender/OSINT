# main.py
# To run this backend:
# 1. Install libraries: pip install fastapi "uvicorn[standard]" httpx python-whois
# 2. Run the server: uvicorn main:app --reload

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import httpx
import asyncio
import whois
from datetime import datetime
import socket
import json

# --- Configuration ---
# In a real app, use environment variables for API keys
ABUSEIPDB_API_KEY = "c0ffb2fc92f6fe811b2036c75f77c1a94e562b5aad9176d9dee04a313bd88ac8188915c831fed108"
OTX_API_KEY = "440bdebb81cc773652acc99abb85d5a371cc153c4b5f3e60f0948fc090421c53"

# --- Pydantic Models ---
class EnrichRequest(BaseModel):
    type: str = Field(..., examples=["domain"])
    value: str = Field(..., examples=["example.com"])

class Factor(BaseModel):
    factor: str
    delta: int

# --- FastAPI App Initialization ---
app = FastAPI(
    title="OSINT AI Tool — Multi-Page Backend",
    version="0.3.0",
    description="An enhanced backend that provides detailed data for multi-page frontend.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Data Collectors ---

async def fetch_rdap_whois(domain: str) -> Dict[str, Any]:
    """Fetches domain registration data using python-whois as a fallback for RDAP."""
    try:
        loop = asyncio.get_running_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        
        if not w or not w.creation_date:
            error_message = "No registration data found."
            if domain.endswith('.edu'):
                error_message += " (.edu domains use a specific registrar which can cause lookup issues.)"
            return {"error": error_message}
            
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date

        return {
            "registrar": w.registrar,
            "creation_date": creation_date.isoformat() if creation_date else None,
            "expiration_date": expiration_date.isoformat() if expiration_date else None,
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "status": list(w.status) if w.status else [],
        }
    except Exception as e:
        error_message = f"WHOIS lookup failed."
        if domain.endswith('.edu'):
            error_message += " This may be due to the specialized .edu WHOIS server."
        return {"error": error_message}

async def fetch_crtsh(domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetches certificate transparency logs from crt.sh."""
    try:
        response = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25.0)
        response.raise_for_status()
        
        if 'application/json' not in response.headers.get('content-type', ''):
             return {"error": "crt.sh returned non-JSON response."}

        certs = response.json()
        # ENHANCEMENT: Return the actual certificate data for the detail page
        return {
            "count": len(certs), 
            "certs": certs
        }
    except httpx.TimeoutException:
        return {"error": "Lookup timed out. This can happen with very large domains."}
    except json.JSONDecodeError:
        return {"error": "Failed to decode JSON response from crt.sh."}
    except Exception as e:
        return {"error": f"crt.sh lookup failed: {str(e)}"}


async def fetch_otx(domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetches threat intelligence from AlienVault OTX."""
    if not OTX_API_KEY or OTX_API_KEY == "YOUR_ALIENVAULT_OTX_API_KEY":
        return {"error": "OTX API key not configured."}
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        response = await client.get(url, headers=headers, timeout=10.0)
        response.raise_for_status()
        data = response.json()
        return {
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "pulses": data.get("pulse_info", {}).get("pulses", []) # For detail page
        }
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {"pulse_count": 0, "pulses": []}
        return {"error": f"OTX lookup failed: {str(e)}"}
    except Exception as e:
        return {"error": f"OTX lookup failed: {str(e)}"}

async def fetch_abuseipdb(domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetches IP reputation from AbuseIPDB."""
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY":
        return {"error": "AbuseIPDB API key not configured."}
    try:
        ip_address = (await asyncio.get_event_loop().getaddrinfo(domain, None))[0][4][0]
        
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": True} # verbose for more details
        response = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10.0)
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "ip_address": ip_address,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "report_count": data.get("totalReports", 0),
            "reports": data.get("reports", []) # For detail page
        }
    except Exception as e:
        return {"error": f"AbuseIPDB lookup failed: {str(e)}"}

# --- Scoring Logic ---

def score_domain(features: Dict[str, Any]) -> (int, List[Dict[str, Any]]):
    """Calculates a risk score based on collected data."""
    score = 0
    factors = []

    if features.get("rdap") and not features["rdap"].get("error"):
        created_str = features["rdap"].get("creation_date")
        if created_str:
            created_date = datetime.fromisoformat(created_str)
            age_days = (datetime.now() - created_date).days
            if age_days < 90:
                score += 30
                factors.append({"factor": "Domain is less than 90 days old", "delta": 30})

    if features.get("crtsh") and not features["crtsh"].get("error"):
        if features["crtsh"].get("count", 0) < 1:
            score += 10
            factors.append({"factor": "No SSL certificates found", "delta": 10})

    if features.get("otx") and not features["otx"].get("error"):
        if features["otx"].get("pulse_count", 0) > 0:
            score += 40
            factors.append({"factor": "Associated with malware campaigns (OTX)", "delta": 40})
            
    if features.get("abuseipdb") and not features["abuseipdb"].get("error"):
        abuse_score = features["abuseipdb"].get("abuse_score", 0)
        if abuse_score > 50:
            score += abuse_score
            factors.append({"factor": f"High IP abuse score: {abuse_score}%", "delta": int(abuse_score)})

    return min(score, 100), factors


# --- API Endpoints ---

@app.get("/")
def read_root():
    return {"message": "OSINT Tool API is running!"}

@app.post("/enrich")
async def enrich(req: EnrichRequest) -> Dict[str, Any]:
    t = req.type.lower().strip()
    v = req.value.strip()

    if t != "domain":
        raise HTTPException(status_code=400, detail="Only type='domain' is supported.")

    async with httpx.AsyncClient() as client:
        tasks = [
            fetch_rdap_whois(v),
            fetch_crtsh(v, client),
            fetch_otx(v, client),
            fetch_abuseipdb(v, client),
        ]
        results = await asyncio.gather(*tasks)

    rdap, crt, otx, abuseipdb = results
    
    features = { "rdap": rdap, "crtsh": crt, "otx": otx, "abuseipdb": abuseipdb }
    score, factors = score_domain(features)

    return {
        "indicator": v,
        "type": t,
        "data": { "rdap": rdap, "crtsh": crt, "otx": otx, "abuseipdb": abuseipdb },
        "score": score,
        "factors": factors,
    }