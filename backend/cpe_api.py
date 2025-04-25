import time
import requests
import logging
import sys
import re

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

def normalize_version(version_str):
    """Convert version string to a normalized format."""
    if not version_str:
        return ""
    # Extract version numbers
    matches = re.findall(r'\d+(?:\.\d+)*', version_str)
    if matches:
        return matches[0]
    return version_str

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
        else:
            logging.error(f"API key test failed with status code {resp.status_code}: {resp.text[:500]}")
            return False
            
    except Exception as e:
        logging.error(f"API key test failed with error: {e}")
        return False

def search_cpes(keyword: str, max_results: int = 5) -> list[str]:
    """Look up up to `max_results` CPE URIs matching `keyword`."""
    if not keyword:
        return []

    try:
        # Clean up and normalize the keyword
        keyword = keyword.strip().lower()
        version = ""
        
        # Try to extract version if present
        version_match = re.search(r'[\d.]+', keyword)
        if version_match:
            version = version_match.group()
            keyword = keyword.replace(version, '').strip()
        
        logging.info(f"Searching CPEs for term '{keyword}' version '{version}'")
        
        # If it's already a CPE URI
        if keyword.startswith("cpe:2.3:"):
            params = {
                "cpeMatchString": keyword,
                "resultsPerPage": max_results * 2
            }
        else:
            # Try to make the keyword more specific
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results * 3
            }
        
        resp = requests.get(CPE_URL, headers=HEADERS, params=params, timeout=10)
        
        if resp.status_code != 200:
            logging.error(f"CPE API error {resp.status_code}: {resp.text[:500]}")
            return []
        
        data = resp.json()
        products = data.get("products", [])
        logging.info(f"Found {len(products)} initial CPE matches for '{keyword}'")
        
        # Score and filter CPEs
        scored_cpes = []
        for product in products:
            cpe = product.get("cpe", {}).get("cpeName", "")
            if not cpe:
                continue
            
            # Calculate relevance score
            score = 0
            cpe_lower = cpe.lower()
            
            # Exact keyword match
            if keyword in cpe_lower:
                score += 10
            
            # Version match if we have one
            if version:
                cpe_version = normalize_version(cpe_lower)
                if version == cpe_version:
                    score += 15
                elif version in cpe_version or cpe_version in version:
                    score += 10
            
            # Prefer more specific CPEs
            parts = cpe.split(':')
            if len(parts) > 6 and parts[6] != '*':
                score += 5
            
            if score > 0:
                scored_cpes.append((cpe, score))
                logging.info(f"CPE match: {cpe} (score: {score})")
        
        # Sort by score and return top matches
        scored_cpes.sort(key=lambda x: x[1], reverse=True)
        results = [cpe for cpe, _ in scored_cpes[:max_results]]
        logging.info(f"Returning top {len(results)} CPE matches")
        return results
        
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
            "resultsPerPage": max_results * 2
        }
        
        logging.info(f"Querying CVEs for CPE: {cpe_uri}")
        resp = requests.get(CVE_URL, headers=HEADERS, params=params, timeout=10)
        
        if resp.status_code != 200:
            logging.error(f"CVE API error {resp.status_code}: {resp.text[:500]}")
            return []

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        logging.info(f"Found {len(vulns)} initial vulnerabilities for CPE '{cpe_uri}'")

        results = []
        for item in vulns:
            try:
                cve = item.get("cve", {})
                if not cve:
                    continue
                
                cve_id = cve.get("id")
                if not cve_id:
                    continue

                # Get metrics - try v31 first, then v30, then v2
                metrics = item.get("metrics", {})
                score = None
                severity = None
                vector = None
                
                for metric_type in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metric_type in metrics and metrics[metric_type]:
                        metric = metrics[metric_type][0]
                        cvss_data = metric.get("cvssData", {})
                        if cvss_data:
                            score = cvss_data.get("baseScore")
                            severity = metric.get("baseSeverity", "")
                            vector = cvss_data.get("vectorString", "")
                            logging.info(f"Found {metric_type} score {score} for {cve_id}")
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

                results.append({
                    "id": cve_id,
                    "cvss": score,
                    "severity": severity,
                    "vector": vector,
                    "summary": summary,
                    "cpe": cpe_uri
                })

            except Exception as e:
                logging.error(f"Error processing CVE {cve_id if 'cve_id' in locals() else 'unknown'}: {e}")
                continue

        # Sort by CVSS score
        results.sort(key=lambda x: float(x["cvss"] or 0), reverse=True)
        final_results = results[:max_results]
        logging.info(f"Returning top {len(final_results)} vulnerabilities")
        return final_results

    except Exception as e:
        logging.error(f"CVE query failed: {e}")
        return []

def get_top_vulns(term, max_results=10):
    """Get top vulnerabilities for a given CPE term."""
    try:
        # Ensure term is properly formatted
        if not term.startswith('cpe:'):
            term = f'cpe:2.3:*:{term}:*:*:*:*:*:*:*:*'
            
        params = {
            'cpeName': term,
            'resultsPerPage': max_results
        }
        
        logging.info(f"Querying NVD for CPE: {term}")
        resp = requests.get(
            f"{CVE_URL}",
            headers=HEADERS,
            params=params,
            timeout=10
        )
        
        if resp.status_code != 200:
            logging.error(f"Failed to get vulnerabilities: {resp.status_code} - {resp.text[:200]}")
            return []
            
        data = resp.json()
        vulnerabilities = []
        
        for vuln in data.get('vulnerabilities', []):
            try:
                cve = vuln.get('cve', {})
                if not cve:
                    continue

                # Get CVE ID
                cve_id = cve.get('id')
                if not cve_id:
                    continue

                # Get English description
                description = None
                for desc in cve.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value')
                        break
                
                if not description:
                    continue

                # Get CVSS score and severity
                metrics = cve.get('metrics', {})
                cvss_score = None
                cvss_severity = None
                cvss_vector = None

                # Try CVSS v3.1 first
                if 'cvssMetricV31' in metrics:
                    metric = metrics['cvssMetricV31'][0]
                    cvss_data = metric.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    cvss_severity = metric.get('baseSeverity')
                    cvss_vector = cvss_data.get('vectorString')
                
                # Try CVSS v3.0 next
                elif 'cvssMetricV30' in metrics:
                    metric = metrics['cvssMetricV30'][0]
                    cvss_data = metric.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    cvss_severity = metric.get('baseSeverity')
                    cvss_vector = cvss_data.get('vectorString')
                
                # Finally try CVSS v2
                elif 'cvssMetricV2' in metrics:
                    metric = metrics['cvssMetricV2'][0]
                    cvss_data = metric.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    cvss_severity = metric.get('baseSeverity', 'Unknown')
                    cvss_vector = cvss_data.get('vectorString')

                # Get references
                references = []
                for ref in cve.get('references', [])[:3]:  # Get up to 3 references
                    ref_url = ref.get('url')
                    if ref_url:
                        references.append(ref_url)

                # Get published and modified dates
                published = cve.get('published', '').split('T')[0]  # Just get the date part
                last_modified = cve.get('lastModified', '').split('T')[0]

                vuln_data = {
                    'id': cve_id,
                    'description': description,
                    'cvss': cvss_score,
                    'severity': cvss_severity or 'Unknown',
                    'vector': cvss_vector,
                    'published': published,
                    'lastModified': last_modified,
                    'references': references
                }
                
                vulnerabilities.append(vuln_data)
                logging.info(f"Found vulnerability {cve_id} with CVSS score {cvss_score}")

            except Exception as e:
                logging.error(f"Error processing vulnerability: {e}")
                continue
        
        # Sort by CVSS score (highest first)
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: float(x['cvss'] or 0),
            reverse=True
        )
        
        # Log results
        if sorted_vulns:
            logging.info(f"Found {len(sorted_vulns)} vulnerabilities for {term}")
            for v in sorted_vulns[:3]:  # Log first 3 for debugging
                logging.info(f"CVE: {v['id']}, CVSS: {v['cvss']}, Severity: {v['severity']}")
        else:
            logging.warning(f"No vulnerabilities found for {term}")
        
        return sorted_vulns[:max_results]
        
    except Exception as e:
        logging.error(f"Error getting vulnerabilities: {e}")
        return []
