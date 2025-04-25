import json
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from device_discovery import discover_network_devices, detect_os, get_device_name
from port_scan import scan_ports
from cpe_api import get_top_vulns
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import queue
import time

# Enhanced service to CPE mapping
SERVICE_TO_CPE = {
    "mysql": "cpe:2.3:a:mysql:mysql",
    "mariadb": "cpe:2.3:a:mariadb:mariadb",
    "http": "cpe:2.3:a:apache:http_server",
    "nginx": "cpe:2.3:a:nginx:nginx",
    "ssh": "cpe:2.3:a:openssh:openssh",
    "ftp": "cpe:2.3:a:vsftpd:vsftpd",
    "smb": "cpe:2.3:a:samba:samba",
    "rdp": "cpe:2.3:a:microsoft:remote_desktop_protocol",
    "postgresql": "cpe:2.3:a:postgresql:postgresql",
    "node.js": "cpe:2.3:a:nodejs:node.js",
    "redis": "cpe:2.3:a:redis:redis",
    "mongodb": "cpe:2.3:a:mongodb:mongodb",
}

# Store scan progress
scan_progress = {}
scan_results = {}

def scan_device(ip):
    """Scan a single device and return its information."""
    try:
        # Update progress
        scan_progress[ip] = {"status": "detecting_os", "progress": 20}
        
        # Get OS info
        os_info = detect_os(ip)
        name = get_device_name(ip)
        
        scan_progress[ip] = {"status": "scanning_ports", "progress": 40}
        
        # Get open ports and services
        ports = scan_ports(ip)
        
        scan_progress[ip] = {"status": "analyzing_vulnerabilities", "progress": 60}
        
        # Build CPE terms
        terms = []
        
        # Add OS CPE based on enhanced OS detection
        if os_info["name"] != "Unknown OS":
            os_name = os_info["name"].lower()
            if "windows" in os_name:
                base_cpe = "cpe:2.3:o:microsoft:windows"
                if os_info["version"]:
                    terms.append(f"{base_cpe}:{os_info['version']}")
                else:
                    terms.append(base_cpe)
            elif any(x in os_name for x in ["linux", "ubuntu", "debian", "centos", "fedora"]):
                for distro in ["ubuntu", "debian", "centos", "fedora"]:
                    if distro in os_name:
                        base_cpe = f"cpe:2.3:o:{distro}:{distro}"
                        if os_info["version"]:
                            terms.append(f"{base_cpe}:{os_info['version']}")
                        else:
                            terms.append(base_cpe)
                        break
                else:
                    terms.append("cpe:2.3:o:linux:linux_kernel")

        # Add service CPEs with improved mapping
        for svc in ports:
            service = svc.get("service", "").lower()
            version = svc.get("version", "")
            
            # Try exact service match first
            if service in SERVICE_TO_CPE:
                base_cpe = SERVICE_TO_CPE[service]
                version_match = re.search(r"\b\d+(?:\.\d+)+\b", version)
                if version_match:
                    terms.append(f"{base_cpe}:{version_match.group(0)}")
                else:
                    terms.append(base_cpe)
            
            # Try partial matches
            else:
                for key, cpe in SERVICE_TO_CPE.items():
                    if key in service or service in key:
                        version_match = re.search(r"\b\d+(?:\.\d+)+\b", version)
                        if version_match:
                            terms.append(f"{cpe}:{version_match.group(0)}")
                        else:
                            terms.append(cpe)
                        break
        
        scan_progress[ip] = {"status": "fetching_vulnerabilities", "progress": 80}
        
        # Query vulnerabilities with rate limiting
        all_vulns = []
        for term in terms:
            time.sleep(1)  # Rate limit NVD API
            try:
                vulns = get_top_vulns(term, max_results=5)
                all_vulns.extend(vulns)
            except Exception as e:
                print(f"[ERROR] Failed to get vulnerabilities for {term}: {e}")
        
        # Deduplicate and sort vulnerabilities
        seen = set()
        unique_vulns = []
        for v in sorted(all_vulns, key=lambda x: x.get("cvss") or 0, reverse=True):
            if v["id"] not in seen:
                seen.add(v["id"])
                unique_vulns.append(v)
        
        scan_progress[ip] = {"status": "completed", "progress": 100}
        
        return {
            "ip": ip,
            "name": name,
            "os": os_info,
            "ports": ports,
            "vulns": unique_vulns[:5]
        }
        
    except Exception as e:
        print(f"[ERROR] Scan failed for {ip}: {e}")
        scan_progress[ip] = {"status": "error", "progress": 0, "error": str(e)}
        return {
            "ip": ip,
            "name": "Error",
            "os": {"name": "Unknown", "version": "", "confidence": "none"},
            "ports": [],
            "vulns": [],
            "error": str(e)
        }

class ScanHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path)
        
        # Handle progress endpoint
        if p.path == "/scan/progress":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(scan_progress).encode())
            return
            
        # Handle results endpoint
        if p.path == "/scan/results":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(scan_results).encode())
            return
            
        # Handle scan initiation
        if p.path == "/scan":
            raw = parse_qs(p.query).get("auth_ips", [""])[0]
            ips = [ip.strip() for ip in raw.split(",") if ip.strip()]
            
            # Clear previous results
            scan_progress.clear()
            scan_results.clear()
            
            # Initialize progress for each IP
            for ip in ips:
                scan_progress[ip] = {"status": "queued", "progress": 0}
            
            # Start scanning in background thread
            def run_scans():
                with ThreadPoolExecutor(max_workers=3) as executor:
                    future_to_ip = {executor.submit(scan_device, ip): ip for ip in ips}
                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            scan_results[ip] = future.result()
                        except Exception as e:
                            print(f"[ERROR] Scan failed for {ip}: {e}")
                            scan_results[ip] = {
                                "ip": ip,
                                "error": str(e)
                            }
            
            threading.Thread(target=run_scans).start()
            
            # Return immediate response
            self.send_response(202)  # Accepted
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({
                "message": "Scan started",
                "ips": ips
            }).encode())
            return
            
        self.send_response(404)
        self.end_headers()

if __name__ == "__main__":
    print("Starting server on http://localhost:8000")
    print("Endpoints:")
    print("  - POST /scan?auth_ips=ip1,ip2,... - Start new scan")
    print("  - GET /scan/progress - Get scan progress")
    print("  - GET /scan/results - Get scan results")
    HTTPServer(("", 8000), ScanHandler).serve_forever()
