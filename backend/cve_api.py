# backend/cve_api.py
import requests
import json
from datetime import datetime, timedelta
import time
import logging
import os

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
        
        # Initialize cache
        self.cve_cache = {}
        self.load_cache()
        
        # Critical services to prioritize
        self.critical_services = {
            'ssh', 'rdp', 'smb', 'http', 'https', 'ftp', 'telnet',
            'microsoft-ds', 'msrpc', 'netbios-ssn', 'ldap', 'mysql',
            'postgresql', 'oracle', 'mssql', 'vnc', 'snmp'
        }

    def load_cache(self):
        """Load cache from disk if it exists"""
        try:
            if os.path.exists('cve_cache.json'):
                with open('cve_cache.json', 'r') as f:
                    self.cve_cache = json.load(f)
        except Exception as e:
            print(f"Error loading CVE cache: {e}")

    def save_cache(self):
        """Save cache to disk"""
        try:
            with open('cve_cache.json', 'w') as f:
                json.dump(self.cve_cache, f)
        except Exception as e:
            print(f"Error saving CVE cache: {e}")

    def search_cves(self, cpe_name, min_severity='high', max_results=5):
        """
        Search for CVEs related to a specific CPE name with filtering
        Args:
            cpe_name: CPE to search for
            min_severity: Minimum severity to include ('critical', 'high', 'medium', 'low')
            max_results: Maximum number of CVEs to return per CPE
        """
        if not self._validate_cpe(cpe_name):
            print(f"Invalid CPE format: {cpe_name}")
            return []

        # Check cache first
        cache_key = f"{cpe_name}:{min_severity}:{max_results}"
        if cache_key in self.cve_cache:
            return self.cve_cache[cache_key]

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
                    "resultsPerPage": 50  # Get more results to filter
                }
                
                print(f"Searching CVEs for CPE: {cpe_name}")
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=self.headers,
                    timeout=10
                )
                
                self.last_request_time = time.time()
                
                if response.status_code == 200:
                    cves = self._parse_cve_response(response.json(), min_severity, max_results)
                    # Cache the results
                    self.cve_cache[cache_key] = cves
                    self.save_cache()
                    return cves
                elif response.status_code == 404:
                    print(f"No CVEs found for CPE: {cpe_name}")
                    # Cache empty result
                    self.cve_cache[cache_key] = []
                    self.save_cache()
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

    def _parse_cve_response(self, response_data, min_severity='high', max_results=5):
        """
        Parse and filter the NVD API response
        """
        vulnerabilities = []
        
        if not response_data or "vulnerabilities" not in response_data:
            print("No vulnerabilities found in response")
            return vulnerabilities
            
        # Sort vulnerabilities by severity and date
        sorted_vulns = []
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
                
                # Skip if severity is below minimum
                if self._severity_to_number(severity) < self._severity_to_number(min_severity):
                    continue
                
                vulnerability = {
                    "cve_id": cve["id"],
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "description": cve["descriptions"][0]["value"],
                    "published": cve["published"],
                    "last_modified": cve["lastModified"]
                }
                
                sorted_vulns.append(vulnerability)
            except Exception as e:
                print(f"Error parsing CVE item: {str(e)}")
                continue
        
        # Sort by severity (critical first) and then by date (newest first)
        sorted_vulns.sort(key=lambda x: (
            -self._severity_to_number(x["severity"]),
            datetime.fromisoformat(x["published"].replace('Z', '+00:00'))
        ), reverse=True)
        
        # Take only the top results
        return sorted_vulns[:max_results]

    def _severity_to_number(self, severity):
        """Convert severity to a number for sorting"""
        severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'unknown': 0
        }
        return severity_map.get(severity.lower(), 0)

    def _get_severity(self, cvss_score):
        """Convert CVSS score to severity level"""
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
