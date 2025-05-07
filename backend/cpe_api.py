import re
from cve_api import CVEAPI
import subprocess
import requests
import time
import json
import os

class CPEAPI:
    """
    Handles CPE (Common Platform Enumeration) lookups and vulnerability analysis
    for devices and services using the NVD CPE and CVE APIs.
    """
    def __init__(self):
        self.cve_api = CVEAPI()
        self.cpe_base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        # Use the same API key as CVEAPI
        self.api_key = "22e61a54-0bb8-4551-8147-3ba44b9de37a"  # Your API key
        if self.api_key:
            self.headers["apiKey"] = self.api_key
        self.last_request_time = 0
        self.min_request_interval = 6  # seconds between requests to respect rate limiting

    def search_cpes(self, search_term):
        """
        Search for CPEs using NVD's CPE API.
        """
        try:
            # Respect rate limiting
            current_time = time.time()
            time_since_last_request = current_time - self.last_request_time
            if time_since_last_request < self.min_request_interval:
                time.sleep(self.min_request_interval - time_since_last_request)
            
            params = {
                "keywordSearch": search_term,
                "resultsPerPage": 20
            }
            
            print(f"Searching CPEs for: {search_term}")
            response = requests.get(
                self.cpe_base_url,
                params=params,
                headers=self.headers,
                timeout=10
            )
            
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                return self._parse_cpe_response(response.json())
            else:
                print(f"Error searching CPEs: {response.status_code}")
                print(f"Response: {response.text}")
                return []
        except Exception as e:
            print(f"Error in CPE search: {e}")
            return []

    def _parse_cpe_response(self, response_data):
        """
        Parse the CPE API response to extract valid CPEs
        """
        cpes = []
        if "products" in response_data:
            for product in response_data["products"]:
                if "cpe" in product:
                    cpe = product["cpe"]["cpeName"]
                    cpes.append(cpe)
        return cpes

    def extract_service_info(self, port_line):
        """
        Extract service name and version from Nmap port scan output.
        Example input: "80/tcp open  http    Apache httpd 2.4.41"
        """
        # Enhanced regex to capture more version patterns
        match = re.match(r'(\d+/tcp)\s+open\s+(\w+)(?:\s+([\w.\-]+))?(?:\s+([\d\.]+))?(?:\s+\(([^)]+)\))?', port_line)
        if match:
            service = match.group(2)
            # Try to get version from group 4, or group 3 if it looks like a version
            version = match.group(4) or (match.group(3) if match.group(3) and re.match(r'\d', match.group(3)) else None)
            # Get additional info from parentheses if present
            additional_info = match.group(5) if match.group(5) else None
            return service, version, additional_info
        return None, None, None

    def create_cpe_names(self, service, version, additional_info=None):
        """
        Create CPE names from service and version information
        """
        cpes = []
        service = service.lower()
        
        # Handle OS detection
        if service in ['windows', 'microsoft-ds', 'msrpc', 'netbios-ssn']:
            # Search for Windows CPEs
            search_term = f"microsoft windows {version if version else ''}"
            cpes.extend(self.search_cpes(search_term))
            if not cpes:  # If no specific version found, try without version
                cpes.extend(self.search_cpes("microsoft windows"))
            return cpes

        # Handle other services
        search_terms = []
        if version:
            search_terms.append(f"{service} {version}")
        search_terms.append(service)  # Always try without version too
        
        for term in search_terms:
            found_cpes = self.search_cpes(term)
            cpes.extend(found_cpes)
        
        # Remove duplicates
        return list(set(cpes))

    def _get_service_priority(self, port_info):
        """
        Get priority score for a service.
        Higher score means more important to check.
        """
        # Handle both string and dictionary port info
        if isinstance(port_info, dict):
            service = port_info.get('service', '').lower()
        else:
            service, _, _ = self.extract_service_info(port_info)
            service = service.lower() if service else ''
            
        if not service:
            return 0
            
        # Critical services get highest priority
        if service in self.cve_api.critical_services:
            return 100
            
        # Common services get medium priority
        common_services = {'dns', 'ntp', 'smtp', 'pop3', 'imap', 'nfs', 'samba'}
        if service in common_services:
            return 50
            
        # Everything else gets low priority
        return 10

    def analyze_device_vulnerabilities(self, device_info):
        """
        Analyze vulnerabilities for a device with optimized CVE lookup and time limit.
        Returns a list of vulnerability dictionaries grouped by CPE.
        """
        vulnerabilities = []
        start_time = time.time()
        time_limit = 60  # 1 minute per device
        
        def time_remaining():
            return time_limit - (time.time() - start_time)
        
        # Handle OS vulnerabilities first (always important)
        if device_info.get('os') and time_remaining() > 0:
            os_cpes = self.create_cpe_names(device_info['os'], None)
            for cpe in os_cpes:
                if time_remaining() <= 0:
                    print("Time limit reached while scanning OS vulnerabilities")
                    return vulnerabilities
                    
                cves = self.cve_api.search_cves(cpe, min_severity='low', max_results=10)
                if cves:
                    vulnerabilities.append({
                        'cpe': cpe,
                        'cpe_title': device_info['os'],
                        'cves': cves,
                        'type': 'os'
                    })

        # Handle service vulnerabilities, prioritizing critical services
        if device_info.get('ports') and time_remaining() > 0:
            # Sort ports by service importance
            sorted_ports = sorted(
                device_info['ports'],
                key=lambda x: self._get_service_priority(x),
                reverse=True
            )
            
            for port in sorted_ports:
                if time_remaining() <= 0:
                    print("Time limit reached while scanning service vulnerabilities")
                    return vulnerabilities
                    
                # Get service info from dictionary
                service = port.get('service', '').lower()
                version = port.get('version', '')
                
                if service:
                    # Skip if service is not critical and we already have enough vulnerabilities
                    if len(vulnerabilities) >= 20 and service not in self.cve_api.critical_services:
                        continue
                        
                    cpes = self.create_cpe_names(service, version)
                    for cpe in cpes:
                        if time_remaining() <= 0:
                            print("Time limit reached while scanning CPEs")
                            return vulnerabilities
                            
                        cves = self.cve_api.search_cves(cpe, min_severity='low', max_results=10)
                        if cves:
                            vulnerabilities.append({
                                'cpe': cpe,
                                'cpe_title': f"{service} {version}" if version else service,
                                'cves': cves,
                                'type': 'service'
                            })
                            
                            # Stop if we have too many vulnerabilities
                            if len(vulnerabilities) >= 30:
                                return vulnerabilities
        
        return vulnerabilities

# Create a global instance
cpe_api = CPEAPI()

# Export the function
def analyze_device_vulnerabilities(device_info):
    """
    Analyze vulnerabilities for a device using the global CPEAPI instance.
    Returns a list of vulnerability dictionaries grouped by CPE.
    """
    return cpe_api.analyze_device_vulnerabilities(device_info)

def scan_ports(ip):
    """
    Scan all ports on a device using Nmap with aggressive detection.
    Returns a ist of lines from Nmap output.
    """
    nmap_cmd = ["nmap", "-A", "-O", "-sV", "-p-", ip]
    result = subprocess.run(nmap_cmd, capture_output=True, text=True)
    return result.stdout.splitlines() 