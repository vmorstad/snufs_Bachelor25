import re
import requests
import time
import json
import os
from cve_api import CVEAPI
from port_scan import scan_device

# ============================================================================
# Configuration
# ============================================================================

class CPEAPI:
    """
    Handles CPE (Common Platform Enumeration) lookups and vulnerability analysis
    for devices and services using the NVD CPE and CVE APIs.
    """
    def __init__(self):
        # API Configuration
        self.cpe_base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        self.api_key = "22e61a54-0bb8-4551-8147-3ba44b9de37a"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        if self.api_key:
            self.headers["apiKey"] = self.api_key

        # Rate Limiting Configuration
        self.last_request_time = 0
        self.min_request_interval = 6  # seconds between requests

        # Initialize CVE API with our API key
        self.cve_api = CVEAPI(api_key=self.api_key)

# ============================================================================
# CPE String Handling
# ============================================================================

    def normalize_cpe(self, cpe_string):
        """
        Normalize CPE strings to the format expected by the CVE database.
        
        Args:
            cpe_string (str): The CPE string to normalize
            
        Returns:
            str or None: Normalized CPE string or None if invalid
        """
        if not cpe_string:
            return None
            
        # If it's already in CPE 2.3 format, return as is
        if cpe_string.startswith("cpe:2.3:"):
            return cpe_string
            
        # Convert old format to 2.3
        if cpe_string.startswith("cpe:/"):
            parts = cpe_string.split(":")
            if len(parts) < 3:
                return None
                
            vendor_product = parts[2].split("/")
            if len(vendor_product) != 2:
                return None
                
            vendor = vendor_product[0]
            product = vendor_product[1]
            
            return f"cpe:2.3:o:{vendor}:{product}:*:*:*:*:*:*:*:*"
        
        return None

# ============================================================================
# NVD API Communication
# ============================================================================

    def search_cpes(self, search_term):
        """
        Search for CPEs using NVD's CPE API.
        
        Args:
            search_term (str): The term to search for
            
        Returns:
            list: List of found CPE strings
        """
        try:
            # Respect rate limiting
            self._wait_for_rate_limit()
            
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

    def _wait_for_rate_limit(self):
        """Helper function to handle rate limiting"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last_request)

    def _parse_cpe_response(self, response_data):
        """
        Parse the CPE API response to extract valid CPEs
        
        Args:
            response_data (dict): JSON response from NVD API
            
        Returns:
            list: List of CPE strings
        """
        cpes = []
        if "products" in response_data:
            for product in response_data["products"]:
                if "cpe" in product:
                    cpe = product["cpe"]["cpeName"]
                    cpes.append(cpe)
        return cpes

# ============================================================================
# Service Information Processing
# ============================================================================

    def extract_service_info(self, port_line):
        """
        Extract service name and version from Nmap port scan output.
        
        Args:
            port_line (str): Line from Nmap output
            Example: "80/tcp open  http    Apache httpd 2.4.41"
            
        Returns:
            tuple: (service, version, additional_info) or (None, None, None)
        """
        match = re.match(r'(\d+/tcp)\s+open\s+(\w+)(?:\s+([\w.\-]+))?(?:\s+([\d\.]+))?(?:\s+\(([^)]+)\))?', port_line)
        if match:
            service = match.group(2)
            version = match.group(4) or (match.group(3) if match.group(3) and re.match(r'\d', match.group(3)) else None)
            additional_info = match.group(5) if match.group(5) else None
            return service, version, additional_info
        return None, None, None

    def create_cpe_names(self, service, version, additional_info=None):
        """
        Create CPE names from service and version information
        
        Args:
            service (str): Service name
            version (str): Service version
            additional_info (str, optional): Additional service information
            
        Returns:
            list: List of CPE strings
        """
        cpes = []
        service = service.lower()
        
        # Handle OS detection
        if service in ['windows', 'microsoft-ds', 'msrpc', 'netbios-ssn']:
            search_term = f"microsoft windows {version if version else ''}"
            cpes.extend(self.search_cpes(search_term))
            if not cpes:
                cpes.extend(self.search_cpes("microsoft windows"))
            return cpes

        # Handle other services
        search_terms = []
        if version:
            search_terms.append(f"{service} {version}")
        search_terms.append(service)
        
        for term in search_terms:
            found_cpes = self.search_cpes(term)
            cpes.extend(found_cpes)
        
        return list(set(cpes))

# ============================================================================
# Vulnerability Analysis
# ============================================================================

    def _get_service_priority(self, port_info):
        """
        Get priority score for a service.
        Higher score means more important to check.
        
        Args:
            port_info (dict or str): Port information
            
        Returns:
            int: Priority score (100 for critical, 50 for common, 10 for others)
        """
        if isinstance(port_info, dict):
            service = port_info.get('service', '').lower()
        else:
            service, _, _ = self.extract_service_info(port_info)
            service = service.lower() if service else ''
            
        if not service:
            return 0
            
        if service in self.cve_api.critical_services:
            return 100
            
        common_services = {'dns', 'ntp', 'smtp', 'pop3', 'imap', 'nfs', 'samba'}
        if service in common_services:
            return 50
            
        return 10

    def analyze_device_vulnerabilities(self, device_info):
        """
        Analyze vulnerabilities for a device with optimized CVE lookup and time limit.
        
        Args:
            device_info (dict): Device information including OS and ports
            
        Returns:
            list: List of vulnerability dictionaries grouped by CPE
        """
        vulnerabilities = []
        start_time = time.time()
        time_limit = 60  # 1 minute per device
        
        def time_remaining():
            return time_limit - (time.time() - start_time)
        
        # 1. Check OS vulnerabilities
        if device_info.get('os') and time_remaining() > 0:
            os_cpes = self.create_cpe_names(device_info['os'], None)
            for cpe in os_cpes:
                if time_remaining() <= 0:
                    return vulnerabilities
                    
                cves = self.cve_api.search_cves(cpe, min_severity='low', max_results=10)
                if cves:
                    vulnerabilities.append({
                        'cpe': cpe,
                        'cpe_title': device_info['os'],
                        'cves': cves,
                        'type': 'os'
                    })

        # 2. Check service vulnerabilities
        if device_info.get('ports') and time_remaining() > 0:
            sorted_ports = sorted(
                device_info['ports'],
                key=lambda x: self._get_service_priority(x),
                reverse=True
            )
            
            for port in sorted_ports:
                if time_remaining() <= 0:
                    return vulnerabilities
                    
                service = port.get('service', '').lower()
                version = port.get('version', '')
                
                if service:
                    if len(vulnerabilities) >= 20 and service not in self.cve_api.critical_services:
                        continue
                        
                    cpes = self.create_cpe_names(service, version)
                    for cpe in cpes:
                        if time_remaining() <= 0:
                            return vulnerabilities
                            
                        cves = self.cve_api.search_cves(cpe, min_severity='low', max_results=10)
                        if cves:
                            vulnerabilities.append({
                                'cpe': cpe,
                                'cpe_title': f"{service} {version}" if version else service,
                                'cves': cves,
                                'type': 'service'
                            })
                            
                            if len(vulnerabilities) >= 30:
                                return vulnerabilities
        
        return vulnerabilities

# ============================================================================
# Global Instance and Exports
# ============================================================================

# Create a global instance
cpe_api = CPEAPI()

def analyze_device_vulnerabilities(device_info):
    """
    Analyze vulnerabilities for a device using the global CPEAPI instance.
    
    Args:
        device_info (dict): Device information including OS and ports
        
    Returns:
        list: List of vulnerability dictionaries grouped by CPE
    """
    return cpe_api.analyze_device_vulnerabilities(device_info)

def scan_ports(ip):
    """
    Scan all ports on a device using the centralized scan_device function.
    
    Args:
        ip (str): IP address to scan
        
    Returns:
        list: List of port information dictionaries
    """
    try:
        result = scan_device(ip)
        return result["ports"]
    except Exception as e:
        print(f"Error scanning ports on {ip}: {e}")
        return [] 