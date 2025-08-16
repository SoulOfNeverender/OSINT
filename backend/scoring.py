from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any

def _parse_rdap_registration_date(rdap: dict):
    """
    Extract earliest registration date from RDAP 'events' if present.
    """
    try:
        events = rdap.get("events", [])
        dates = []
        for ev in events:
            if ev.get("eventAction") in {"registration"}:
                ts = ev.get("eventDate")
                if ts:
                    # Ensure timezone-aware parsing
                    if ts.endswith("Z"):
                        ts = ts.replace("Z", "+00:00")
                    dates.append(datetime.fromisoformat(ts))
        if dates:
            return min(dates)
    except Exception:
        pass
    return None

def _years_between(d1: datetime, d2: datetime) -> float:
    return (d2 - d1).days / 365.25

def score_domain(features: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Simple transparent scoring v0 for a domain.
    Inputs (features) expected:
      - rdap (dict or None)
      - crt_count (int)
    Returns: (score:int 0-100, factors:list)
    """
    now = datetime.now(timezone.utc)
    factors = []
    score = 0

    rdap = features.get("rdap") or {}
    reg_date = _parse_rdap_registration_date(rdap) if rdap else None
    if reg_date:
        age_years = _years_between(reg_date, now)
        if age_years < 0.2:
            score += 15; factors.append({"factor": "Newly registered domain (<~2.5 months)", "delta": +15})
        elif age_years < 1:
            score += 8; factors.append({"factor": "Young domain (<1y)", "delta": +8})
        else:
            score -= 5; factors.append({"factor": "Older domain (>=1y)", "delta": -5})
    else:
        factors.append({"factor": "No registration date found", "delta": 0})

    crt_count = int(features.get("crt_count") or 0)
    if crt_count == 0:
        score += 5; factors.append({"factor": "No CT entries (could be suspicious for active domain)", "delta": +5})
    elif crt_count < 5:
        score += 3; factors.append({"factor": "Few CT entries", "delta": +3})
    elif crt_count > 100:
        score -= 5; factors.append({"factor": "Many CT entries (likely common/benign infra)", "delta": -5})
    else:
        factors.append({"factor": "Moderate CT activity", "delta": 0})

    score = max(0, min(100, score))
    return score, factors