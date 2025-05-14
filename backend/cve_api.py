import requests
import time
import os

class CVEAPI:
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.headers = {"User-Agent": "Mozilla/5.0"}
        if self.api_key:
            self.headers["apiKey"] = self.api_key
        self.last_request_time = 0
        self.min_request_interval = 6  # seconds

    def search_cves(self, cpe_name):
        # Rate limiting
        now = time.time()
        if now - self.last_request_time < self.min_request_interval:
            time.sleep(self.min_request_interval - (now - self.last_request_time))
        params = {"cpeName": cpe_name, "resultsPerPage": 20}
        response = requests.get(self.base_url, headers=self.headers, params=params)
        self.last_request_time = time.time()
        if response.status_code != 200:
            return []
        data = response.json()
        vulns = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            # Try CVSS v3.1, then v2, then unknown
            severity = "unknown"
            score = None
            if "metrics" in cve and "cvssMetricV31" in cve["metrics"]:
                cvss = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "unknown")
                score = cvss.get("baseScore")
            elif "metrics" in cve and "cvssMetricV2" in cve["metrics"]:
                cvss = cve["metrics"]["cvssMetricV2"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "unknown")
                score = cvss.get("baseScore")
            # Infer severity from score if missing
            if severity == "unknown" and score is not None:
                if score >= 9.0:
                    severity = "critical"
                elif score >= 7.0:
                    severity = "high"
                elif score >= 4.0:
                    severity = "medium"
                elif score > 0:
                    severity = "low"
            vulns.append({
                "cve_id": cve["id"],
                "description": cve["descriptions"][0]["value"],
                "published": cve["published"],
                "last_modified": cve["lastModified"],
                "severity": severity,
                "cvss_score": score,
            })
        return vulns

    def search_cves_for_cpes(self, cpe_list):
        """
        Search for CVEs for a list of CPEs.
        
        Args:
            cpe_list (list): List of dictionaries containing CPE information
                           Each dict should have a 'cpe' key with the CPE string
                           and optionally a 'source' key indicating where it came from
        
        Returns:
            list: List of vulnerability dictionaries
        """
        all_vulns = []
        for cpe in cpe_list:
            vulns = self.search_cves(cpe["cpe"])
            for v in vulns:
                v["source"] = cpe.get("source", "unknown")
                all_vulns.append(v)
        return all_vulns