import requests
import time
import os
import re

def extract_product_and_version(service, version_str):
    # Try to extract a version number from the version string
    # Example: "SimpleHTTPServer 0.6 (Python 3.13.2)" -> ("simplehttpserver", "0.6")
    if not version_str:
        return service, None
    # Try to find something that looks like a version number
    match = re.search(r'([a-zA-Z0-9_-]+)[\s:/-]?([0-9]+(?:\.[0-9]+)*)', version_str)
    if match:
        product = match.group(1).lower()
        version = match.group(2)
        return product, version
    return service, None

class CPEAPI:
    def __init__(self):
        self.cpe_base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        self.api_key = os.environ.get("NVD_API_KEY") or "22e61a54-0bb8-4551-8147-3ba44b9de37a"
        self.headers = {
            "User-Agent": "Mozilla/5.0",
            "apiKey": self.api_key
        }
        self.last_request_time = 0
        self.min_request_interval = 6

    def find_matching_cpes(self, name, version=None, timeout=10):
        """Find matching CPEs in NVD database for a detected OS or service, with timeout"""
        start = time.time()
        try:
            # First try exact CPE match if we have version
            if version:
                if 'windows' in name.lower():
                    cpe_string = f"cpe:2.3:o:microsoft:windows_{version.replace('.', '_')}"
                else:
                    cpe_string = f"cpe:2.3:a:{name}:{name}:{version}"
                params = {
                    "cpeMatchString": cpe_string,
                    "resultsPerPage": 20
                }
                print(f"[DEBUG] CPE search (exact) for name='{name}', version='{version}': {params}")
                response = requests.get(
                    self.cpe_base_url,
                    headers=self.headers,
                    params=params,
                    timeout=timeout
                )
                self.last_request_time = time.time()
                if response.status_code == 200:
                    data = response.json()
                    cpes = [product["cpe"]["cpeName"] for product in data.get("products", [])]
                    print(f"[DEBUG] CPEs found (exact): {cpes}")
                    if cpes:
                        return cpes
            # If no exact matches or no version, try keyword search
            params = {
                "keywordSearch": f"{name} {version}" if version else name,
                "resultsPerPage": 20
            }
            print(f"[DEBUG] CPE search (keyword) for name='{name}', version='{version}': {params}")
            response = requests.get(
                self.cpe_base_url,
                headers=self.headers,
                params=params,
                timeout=max(1, timeout - int(time.time() - start))
            )
            self.last_request_time = time.time()
            if response.status_code == 200:
                data = response.json()
                cpes = [product["cpe"]["cpeName"] for product in data.get("products", [])]
                print(f"[DEBUG] CPEs found (keyword): {cpes}")
                return cpes
            print(f"[DEBUG] No CPEs found (keyword) for name='{name}', version='{version}'")
            return []
        except Exception as e:
            print(f"Error finding CPEs: {e}")
            return []

    def get_device_cpes(self, device_info):
        """Get all matching CPEs for a device's OS and open ports, with timeout and filtering. No CVE lookup."""
        results = []
        # OS CPE
        if device_info.get("os_normalized"):
            print(f"[DEBUG] Searching CPE for OS: {device_info['os_normalized']}")
            os_cpes = self.find_matching_cpes(device_info["os_normalized"], timeout=10)
            os_norm = device_info["os_normalized"].lower()
            for cpe in os_cpes:
                cpe_l = cpe.lower()
                if (
                    ("windows" in os_norm and "microsoft:windows" in cpe_l) or
                    ("linux" in os_norm and ":linux:" in cpe_l) or
                    ("mac" in os_norm and "apple:mac_os" in cpe_l)
                ):
                    results.append({"cpe": cpe, "source": "os"})
        # Open ports/services
        SERVICE_TO_PRODUCT = {
            "netbios-ssn": "Microsoft Windows",
            "msrpc": "Microsoft Windows",
            "microsoft-ds?": "Microsoft Windows",
            "smb": "Samba",
            "ftp": "vsftpd",
            "ssh": "OpenSSH",
            "telnet": "telnetd",
            "smtp": "Postfix",
            "imap": "Dovecot",
            "pop3": "Dovecot",
            "http": "Apache httpd",
            # Add more mappings as needed
        }
        for port in device_info["ports"]:
            print(f"[DEBUG] Port dict: {port}")
            if port.get("state") != "open" or not port.get("service"):
                continue
            # Clean product and version
            product, clean_version = extract_product_and_version(port["service"], port.get("version"))
            # Map service name to likely product name if available
            mapped_product = SERVICE_TO_PRODUCT.get(product, product)
            if mapped_product != product:
                print(f"[DEBUG] Mapped service '{product}' to product '{mapped_product}' for CPE search")
            product = mapped_product
            print(f"[DEBUG] Cleaned product: {product}, version: {clean_version}")
            service_cpes = self.find_matching_cpes(
                product,
                clean_version,
                timeout=10
            )
            if not service_cpes and clean_version:
                print(f"[DEBUG] Retrying CPE search for service '{product}' without version")
                service_cpes = self.find_matching_cpes(
                    product,
                    None,
                    timeout=10
                )
            for cpe in service_cpes:
                results.append({
                    "cpe": cpe,
                    "source": cpe
                })
        return results

# Create global instance
cpe_api = CPEAPI()

def get_device_cpes(device_info):
    """Get all matching CPEs for a device, with timeout and filtering. No CVE lookup."""
    return cpe_api.get_device_cpes(device_info) 