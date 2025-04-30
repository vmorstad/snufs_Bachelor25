# backend/cve_api.py
import requests
import json
from datetime import datetime, timedelta
import time

class CVEAPI:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = None  # Add your NVD API key here if you have one
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        if self.api_key:
            self.headers["apiKey"] = self.api_key
        self.last_request_time = 0
        self.min_request_interval = 6  # seconds between requests to respect rate limiting

    def search_cves(self, cpe_name):
        """
        Search for CVEs related to a specific CPE name
        """
        try:
            # Format the CPE name for the API
            cpe_name = cpe_name.replace(" ", "_")
            
            # Respect rate limiting
            current_time = time.time()
            time_since_last_request = current_time - self.last_request_time
            if time_since_last_request < self.min_request_interval:
                time.sleep(self.min_request_interval - time_since_last_request)
            
            # Make the API request
            params = {
                "cpeName": cpe_name,
                "resultsPerPage": 20  # Limit results to avoid rate limiting
            }
            
            print(f"Searching CVEs for CPE: {cpe_name}")
            response = requests.get(
                self.base_url,
                params=params,
                headers=self.headers,
                timeout=10  # Add timeout
            )
            
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                vulnerabilities = self._parse_cve_response(response.json())
                print(f"Found {len(vulnerabilities)} vulnerabilities for {cpe_name}")
                return vulnerabilities
            elif response.status_code == 403:
                print("Rate limit exceeded. Waiting before retrying...")
                time.sleep(30)  # Wait 30 seconds before retrying
                return self.search_cves(cpe_name)  # Retry once
            else:
                print(f"Error fetching CVEs: {response.status_code}")
                print(f"Response: {response.text}")
                return []
                
        except requests.exceptions.RequestException as e:
            print(f"Request error in CVE search: {str(e)}")
            return []
        except Exception as e:
            print(f"Unexpected error in CVE search: {str(e)}")
            return []

    def _parse_cve_response(self, response_data):
        """
        Parse the NVD API response into a standardized format
        """
        vulnerabilities = []
        
        if not response_data or "vulnerabilities" not in response_data:
            print("No vulnerabilities found in response")
            return vulnerabilities
            
        for item in response_data["vulnerabilities"]:
            try:
                cve = item["cve"]
                
                # Get CVSS score if available
                cvss_score = None
                severity = "unknown"
                
                if "metrics" in cve and "cvssMetricV31" in cve["metrics"]:
                    cvss_data = cve["metrics"]["cvssMetricV31"][0]
                    cvss_score = cvss_data["cvssData"]["baseScore"]
                    severity = self._get_severity(cvss_score)
                elif "metrics" in cve and "cvssMetricV2" in cve["metrics"]:
                    cvss_data = cve["metrics"]["cvssMetricV2"][0]
                    cvss_score = cvss_data["cvssData"]["baseScore"]
                    severity = self._get_severity(cvss_score)
                
                vulnerability = {
                    "cve_id": cve["id"],
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "description": cve["descriptions"][0]["value"],
                    "published": cve["published"],
                    "last_modified": cve["lastModified"]
                }
                
                vulnerabilities.append(vulnerability)
            except Exception as e:
                print(f"Error parsing CVE item: {str(e)}")
                continue
        
        return vulnerabilities

    def _get_severity(self, cvss_score):
        """
        Convert CVSS score to severity level
        """
        if cvss_score is None:
            return "unknown"
        elif cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"
