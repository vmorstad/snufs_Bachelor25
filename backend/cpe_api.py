import requests
import time
import os

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
        for port in device_info["ports"]:
            if port["state"] != "open" or not port.get("service"):
                continue
            print(f"[DEBUG] Searching CPE for service: {port['service']} version: {port.get('version')}")
            service_cpes = self.find_matching_cpes(
                port["service"],
                port.get("version"),
                timeout=10
            )
            for cpe in service_cpes:
                results.append({
                    "cpe": cpe,
                    "source": f"port_{port['port']}"
                })
        return results

# Create global instance
cpe_api = CPEAPI()

def get_device_cpes(device_info):
    """Get all matching CPEs for a device, with timeout and filtering. No CVE lookup."""
    return cpe_api.get_device_cpes(device_info) 