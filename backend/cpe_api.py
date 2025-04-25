import time
import requests
import logging
import sys

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

# NVD v2.0 endpoints & your API key
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "5b8ed342-47cb-4a2c-a4d2-90d4e1f0a5f9"

# The header name should be 'apiKey' (case sensitive)
HEADERS = {
    "apiKey": API_KEY,
    "User-Agent": "NetworkScanner/1.0",
    "Accept": "application/json"
}

def test_api_key():
    """Test if the API key is working."""
    try:
        # Make sure to use the correct endpoint
        resp = requests.get(
            f"{CVE_URL}",
            headers=HEADERS,
            params={"resultsPerPage": 1},
            timeout=10
        )
        
        if resp.status_code == 200:
            logging.info("API key test successful")
            return True
        elif resp.status_code in (403, 401, 404):
            logging.error(f"API key invalid or unauthorized (status {resp.status_code})")
            logging.error(f"Response headers: {dict(resp.headers)}")
            return False
        else:
            logging.error(f"API test failed with status {resp.status_code}")
            logging.error(f"Response headers: {dict(resp.headers)}")
            return False
    except Exception as e:
        logging.error(f"API test failed with error: {e}")
        return False

def search_cpes(keyword: str, max_results: int = 5) -> list[str]:
    """Look up up to `max_results` CPE URIs matching `keyword`."""
    if not keyword:
        return []

    try:
        # Clean up the keyword
        keyword = keyword.strip().lower()
        
        # If it's already a CPE URI
        if keyword.startswith("cpe:2.3:"):
            params = {
                "cpeMatchString": keyword,
                "resultsPerPage": max_results,
                "startIndex": 0
            }
        else:
            # Try to make the keyword more specific
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results * 2,  # Get more results to filter
                "startIndex": 0
            }
        
        logging.info(f"Searching CPEs for: {keyword}")
        resp = requests.get(CPE_URL, headers=HEADERS, params=params, timeout=10)
        
        if resp.status_code == 403:
            logging.error("API key unauthorized")
            return []
            
        if resp.status_code != 200:
            logging.error(f"CPE API error {resp.status_code}: {resp.text[:500]}")
            return []
        
        data = resp.json()
        cpe_entries = data.get("products", [])
        logging.info(f"Found {len(cpe_entries)} CPE entries for '{keyword}'")
        
        # Filter and sort CPEs by relevance
        filtered_cpes = []
        for entry in cpe_entries:
            cpe = entry.get("cpe", {}).get("cpeName", "")
            if not cpe:
                continue
                
            # Calculate relevance score
            score = 0
            cpe_lower = cpe.lower()
            
            # Exact match gets highest score
            if keyword in cpe_lower:
                score += 10
            
            # Version match gets high score
            if any(v in cpe_lower for v in keyword.split()):
                score += 5
                
            filtered_cpes.append((cpe, score))
            
        # Sort by relevance score and take top results
        filtered_cpes.sort(key=lambda x: x[1], reverse=True)
        return [cpe for cpe, _ in filtered_cpes[:max_results]]
        
    except Exception as e:
        logging.error(f"CPE search failed: {e}")
        return []

def query_cves_by_cpe(cpe_uri: str, max_results: int = 5) -> list[dict]:
    """
    Given a CPE URI, return up to `max_results` CVEs (with id, cvss, summary).
    """
    if not cpe_uri:
        return []

    try:
        params = {
            "cpeName": cpe_uri,
            "resultsPerPage": max_results * 2,  # Get more to filter by CVSS
            "startIndex": 0
        }
        
        logging.info(f"Querying CVEs for CPE: {cpe_uri}")
        resp = requests.get(CVE_URL, headers=HEADERS, params=params, timeout=10)
        
        if resp.status_code == 403:
            logging.error("API key unauthorized")
            return []
            
        if resp.status_code != 200:
            logging.error(f"CVE API error {resp.status_code}: {resp.text[:500]}")
            return []

        data = resp.json()
        items = data.get("vulnerabilities", [])
        logging.info(f"Found {len(items)} vulnerabilities for CPE '{cpe_uri}'")

        vulns = []
        for item in items:
            try:
                cve = item.get("cve", {})
                if not cve:
                    continue
                    
                cve_id = cve.get("id")
                if not cve_id:
                    continue

                # Get CVSS score - try v3.1 first, then v3.0, then v2
                metrics = item.get("metrics", {})
                score = None
                severity = None
                vector = None
                
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric = metrics.get(metric_key, [{}])[0] if metric_key in metrics else {}
                    cvss_data = metric.get("cvssData", {})
                    if cvss_data:
                        score = cvss_data.get("baseScore")
                        severity = metric.get("baseSeverity", "").upper()
                        vector = cvss_data.get("vectorString", "")
                        break

                # Get English description
                descs = cve.get("descriptions", [])
                summary = next((
                    d.get("value", "")
                    for d in descs
                    if d.get("lang", "").lower() == "en"
                ), "")

                if len(summary) > 200:
                    summary = summary[:197] + "..."

                vulns.append({
                    "id": cve_id,
                    "cvss": score,
                    "severity": severity,
                    "vector": vector,
                    "summary": summary,
                    "cpe": cpe_uri
                })

            except Exception as e:
                logging.error(f"Error processing CVE {cve_id if cve_id else 'unknown'}: {e}")
                continue

        # Sort by CVSS score (highest first)
        vulns.sort(key=lambda x: float(x["cvss"] or 0), reverse=True)
        return vulns[:max_results]

    except Exception as e:
        logging.error(f"CVE query failed: {e}")
        return []

def get_top_vulns(term: str, max_results: int = 5) -> list[dict]:
    """
    High-level: given a term (e.g. "mysql 8.0.35" or "Windows 10"),
    1) find matching CPEs
    2) fetch CVEs for each CPE
    3) dedupe & sort by CVSS, return up to max_results
    """
    if not term:
        return []

    try:
        term = term.strip()
        seen = set()
        vulns = []

        # Test API key first
        if not test_api_key():
            logging.error("API key validation failed")
            return []

        # Rate limit
        time.sleep(1)
        
        # Get CPEs
        cpes = search_cpes(term, max_results=3)
        if not cpes:
            logging.warning(f"No CPEs found for term: {term}")
            return []

        # Get CVEs for each CPE
        for cpe in cpes:
            time.sleep(1)  # Rate limit
            for v in query_cves_by_cpe(cpe, max_results):
                if v["id"] not in seen:
                    seen.add(v["id"])
                    vulns.append(v)

        # Sort by CVSS score and return top results
        vulns.sort(key=lambda x: float(x["cvss"] or 0), reverse=True)
        return vulns[:max_results]

    except Exception as e:
        logging.error(f"get_top_vulns failed for {term}: {e}")
        return []
