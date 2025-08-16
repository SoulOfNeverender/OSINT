import requests

def fetch_rdap(domain: str) -> dict:
    """
    Fetch RDAP data for a domain from rdap.org.
    Returns a dict with either the RDAP JSON, or {"error": "..."}.
    """
    try:
        url = f"https://rdap.org/domain/{domain}"
        headers = {"User-Agent": "osint-ai-tool/0.1"}
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"rdap_status_{resp.status_code}"}
    except Exception as e:
        return {"error": f"rdap_exception: {e}"}