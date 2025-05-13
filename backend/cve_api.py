# backend/cve_api.py
import requests
import json
from datetime import datetime, timedelta
import time
import logging
import os

class CVEAPI:
    """
    Handles communication with the NVD CVE API to search for vulnerabilities
    based on CPE names. Implements rate limiting and retries for reliability.
    """
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        if self.api_key:
            self.headers["apiKey"] = self.api_key
            print("Using NVD API key for authentication")
        else:
            print("Warning: No NVD API key found. Please set NVD_API_KEY environment variable.")
            print("You can get a free API key from: https://nvd.nist.gov/developers/request-an-api-key")
        self.last_request_time = 0
        self.min_request_interval = 6  # seconds between requests to respect rate limiting
        self.max_retries = 3
        self.retry_delay = 5  # seconds between retries
        
        # Critical services to prioritize
        self.critical_services = {
            'ssh', 'rdp', 'smb', 'http', 'https', 'ftp', 'telnet',
            'microsoft-ds', 'msrpc', 'netbios-ssn', 'ldap', 'mysql',
            'postgresql', 'oracle', 'mssql', 'vnc', 'snmp'
        }

    def search_cves(self, cpe_name, min_severity='high', max_results=5):
        """
        Search for CVEs for a given CPE name using the NVD API.
        Args:
            cpe_name (str): The CPE name to search for.
            min_severity (str): Minimum severity to include ('low', 'medium', 'high', 'critical').
            max_results (int): Maximum number of results to return.
        Returns:
            list: List of vulnerability dictionaries.
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
                    return self._parse_cve_response(response.json(), min_severity, max_results)
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
        Validate CPE format.
        Format should be: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        Args:
            cpe_name (str): The CPE name to validate.
        Returns:
            bool: True if valid, False otherwise.
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
        Parse and filter the NVD API response.
        Args:
            response_data (dict): The JSON response from the NVD API.
            min_severity (str): Minimum severity to include.
            max_results (int): Maximum number of results to return.
        Returns:
            list: List of vulnerability dictionaries.
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
        """
        Convert severity string to a number for sorting.
        Args:
            severity (str): Severity string ('critical', 'high', etc.)
        Returns:
            int: Numeric value for sorting.
        """
        severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'unknown': 0
        }
        return severity_map.get(severity.lower(), 0)

    def _get_severity(self, cvss_score):
        """
        Convert CVSS score to severity level.
        Args:
            cvss_score (float or None): CVSS base score.
        Returns:
            str: Severity string ('critical', 'high', etc.)
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
