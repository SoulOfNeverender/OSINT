from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any

from collectors.rdap import fetch_rdap
from collectors.crtsh import fetch_crtsh
from scoring import score_domain

app = FastAPI(title="OSINT AI Tool — Starter Backend", version="0.1.0")

# Enable CORS for future frontend use
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EnrichRequest(BaseModel):
    type: str = Field(..., examples=["domain"])
    value: str = Field(..., examples=["example.com"])

@app.get("/health")
def health() -> dict:
    return {"status": "ok"}

@app.get("/")
def read_root():
    return {"message": "OSINT Tool API is running!"}

@app.post("/enrich")
def enrich(req: EnrichRequest) -> Dict[str, Any]:
    t = req.type.lower().strip()
    v = req.value.strip()

    if t not in {"domain"}:
        raise HTTPException(status_code=400, detail="Only type='domain' is supported in the starter.")

    # Collect data
    rdap = fetch_rdap(v)
    crt = fetch_crtsh(v)

    # Compute basic score
    features = {
        "rdap": rdap if isinstance(rdap, dict) and "error" not in rdap else None,
        "crt_count": crt.get("count") if isinstance(crt, dict) and "count" in crt else 0,
    }
    score, factors = score_domain(features)

    return {
        "indicator": v,
        "type": t,
        "data": {
            "rdap": rdap,
            "crtsh": crt,
        },
        "score": score,
        "factors": factors,
        "notes": "Starter build. Add more collectors (OTX, AbuseIPDB, Shodan) and expand scoring."
    }