# backend/cve_api.py
import requests
import urllib.parse

CIRCL_SEARCH_URL = "https://cve.circl.lu/api/search/"

def query_cve_for(term, max_results=5):
    """
    Query the CIRCL CVE API for a given search term
    (e.g. "mysql 8.0.35" or "apache 2.4.41").
    Returns up to max_results vulnerabilities,
    each as dict with keys: id, cvss, summary.
    """
    encoded = urllib.parse.quote(term)
    url = f"{CIRCL_SEARCH_URL}{encoded}"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    results = resp.json().get("results", [])
    # sort by descending CVSS and take top N
    sorted_by_cvss = sorted(
        [r for r in results if r.get("cvss") is not None],
        key=lambda r: r["cvss"],
        reverse=True
    )
    out = []
    for entry in sorted_by_cvss[:max_results]:
        out.append({
            "cve": entry.get("id"),
            "cvss": entry.get("cvss"),
            "summary": entry.get("summary")[:200]  # truncate
        })
    return out
