# backend/cve_api.py
import requests
import json
from datetime import datetime, timedelta
import time
import logging

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
        self.max_retries = 3
        self.retry_delay = 5  # seconds between retries

    def search_cves(self, cpe_name):
        """
        Search for CVEs related to a specific CPE name
        """
        if not self._validate_cpe(cpe_name):
            print(f"Invalid CPE format: {cpe_name}")
            return []

        for attempt in range(self.max_retries):
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
                    return self._parse_cve_response(response.json())
                elif response.status_code == 404:
                    print(f"No CVEs found for CPE: {cpe_name}")
                    return []
                elif response.status_code == 429:
                    print("Rate limited by NVD API. Waiting before retry...")
                    time.sleep(self.retry_delay)
                    continue
                else:
                    print(f"Error fetching CVEs: {response.status_code}")
                    print(f"Response: {response.text}")
                    if attempt < self.max_retries - 1:
                        time.sleep(self.retry_delay)
                        continue
                    return []
            except requests.exceptions.RequestException as e:
                print(f"Request error: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                return []
        
        return []

    def _validate_cpe(self, cpe_name):
        """
        Validate CPE format
        Format should be: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        """
        parts = cpe_name.split(':')
        if len(parts) != 13:
            return False
        if parts[0] != 'cpe' or parts[1] != '2.3':
            return False
        if parts[2] not in ['a', 'o', 'h']:  # application, operating system, hardware
            return False
        return True

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
