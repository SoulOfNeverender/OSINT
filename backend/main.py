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
    title="OSINT AI Tool — Enhanced Backend",
    version="0.2.1",
    description="An enhanced backend with multiple data collectors and improved scoring.",
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
        # Use a thread to run the synchronous whois library without blocking asyncio
        loop = asyncio.get_running_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        
        if not w or not w.creation_date:
            return {"error": "No registration data found."}
            
        # Handle cases where creation_date is a list
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date

        return {
            "registrar": w.registrar,
            "creation_date": creation_date.isoformat() if creation_date else None,
            "expiration_date": expiration_date.isoformat() if expiration_date else None,
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}

async def fetch_crtsh(domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetches certificate transparency logs from crt.sh."""
    try:
        # OPTIMIZED: Increased timeout for large domains and added specific error handling.
        response = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25.0)
        response.raise_for_status()
        
        if 'application/json' not in response.headers.get('content-type', ''):
             return {"error": "crt.sh returned non-JSON response."}

        certs = response.json()
        return {"count": len(certs), "issuers": list(set(c['issuer_name'] for c in certs))}
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
        return {"pulse_count": data.get("pulse_info", {}).get("count", 0)}
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {"pulse_count": 0} # Not found is not an error
        return {"error": f"OTX lookup failed: {str(e)}"}
    except Exception as e:
        return {"error": f"OTX lookup failed: {str(e)}"}

async def fetch_abuseipdb(domain: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetches IP reputation from AbuseIPDB."""
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY":
        return {"error": "AbuseIPDB API key not configured."}
    try:
        # Resolve domain to IP first
        ip_address = (await asyncio.get_event_loop().getaddrinfo(domain, None))[0][4][0]
        
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
        response = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10.0)
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "ip_address": ip_address,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "report_count": data.get("totalReports", 0),
        }
    except Exception as e:
        return {"error": f"AbuseIPDB lookup failed: {str(e)}"}

# --- Scoring Logic ---

def score_domain(features: Dict[str, Any]) -> (int, List[Dict[str, Any]]):
    """Calculates a risk score based on collected data."""
    score = 0
    factors = []

    # RDAP/WHOIS scoring
    if features.get("rdap") and not features["rdap"].get("error"):
        created_str = features["rdap"].get("creation_date")
        if created_str:
            created_date = datetime.fromisoformat(created_str)
            age_days = (datetime.now() - created_date).days
            if age_days < 90:
                score += 30
                factors.append({"factor": "Domain is less than 90 days old", "delta": 30})

    # crt.sh scoring
    if features.get("crtsh") and not features["crtsh"].get("error"):
        if features["crtsh"].get("count", 0) < 1:
            score += 10
            factors.append({"factor": "No SSL certificates found", "delta": 10})

    # OTX scoring
    if features.get("otx") and not features["otx"].get("error"):
        if features["otx"].get("pulse_count", 0) > 0:
            score += 40
            factors.append({"factor": "Associated with malware campaigns (OTX)", "delta": 40})
            
    # AbuseIPDB scoring
    if features.get("abuseipdb") and not features["abuseipdb"].get("error"):
        abuse_score = features["abuseipdb"].get("abuse_score", 0)
        if abuse_score > 50:
            score += abuse_score
            factors.append({"factor": f"High IP abuse score: {abuse_score}%", "delta": abuse_score})

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
    
    features = {
        "rdap": rdap,
        "crtsh": crt,
        "otx": otx,
        "abuseipdb": abuseipdb,
    }
    score, factors = score_domain(features)

    return {
        "indicator": v,
        "type": t,
        "data": {
            "rdap": rdap,
            "crtsh": crt,
            "otx": otx,
            "abuseipdb": abuseipdb,
        },
        "score": score,
        "factors": factors,
    }