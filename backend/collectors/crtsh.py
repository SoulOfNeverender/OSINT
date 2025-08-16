import requests

def fetch_crtsh(domain: str) -> dict:
    """
    Fetch certificate transparency entries from crt.sh for a domain.
    Returns {"count": int, "entries": [...]} or {"error": "..."}.
    """
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        headers = {"User-Agent": "osint-ai-tool/0.1"}
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return {"error": f"crtsh_status_{resp.status_code}"}
        try:
            data = resp.json()
        except Exception as je:
            return {"error": f"crtsh_json_error: {je}"}
        keep = ("issuer_name", "common_name", "name_value", "not_before", "not_after", "id")
        entries = []
        for item in data:
            entries.append({k: item.get(k) for k in keep})
        return {"count": len(entries), "entries": entries}
    except Exception as e:
        return {"error": f"crtsh_exception: {e}"}