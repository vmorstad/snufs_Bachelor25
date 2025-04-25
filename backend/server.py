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
    # Web servers
    "http": "cpe:2.3:a:apache:http_server",
    "apache": "cpe:2.3:a:apache:http_server",
    "nginx": "cpe:2.3:a:nginx:nginx",
    "apache httpd": "cpe:2.3:a:apache:http_server",
    
    # Databases
    "mysql": "cpe:2.3:a:mysql:mysql",
    "mariadb": "cpe:2.3:a:mariadb:mariadb",
    "postgresql": "cpe:2.3:a:postgresql:postgresql",
    "mongodb": "cpe:2.3:a:mongodb:mongodb",
    "redis": "cpe:2.3:a:redis:redis",
    
    # Remote access
    "ssh": "cpe:2.3:a:openssh:openssh",
    "openssh": "cpe:2.3:a:openssh:openssh",
    "rdp": "cpe:2.3:a:microsoft:remote_desktop_services",
    "telnet": "cpe:2.3:a:telnet:telnet",
    
    # File sharing
    "smb": "cpe:2.3:a:samba:samba",
    "samba": "cpe:2.3:a:samba:samba",
    "ftp": "cpe:2.3:a:vsftpd:vsftpd",
    
    # Other services
    "node.js": "cpe:2.3:a:nodejs:node.js",
    "nodejs": "cpe:2.3:a:nodejs:node.js",
    "docker": "cpe:2.3:a:docker:docker",
    "kubernetes": "cpe:2.3:a:kubernetes:kubernetes",
}

# OS CPE mapping
OS_TO_CPE = {
    "windows": {
        "base": "cpe:2.3:o:microsoft:windows",
        "versions": {
            "10": "10",
            "11": "11",
            "server": "server",
            "2019": "server_2019",
            "2016": "server_2016",
        }
    },
    "linux": {
        "base": "cpe:2.3:o:linux:linux_kernel",
        "distros": {
            "ubuntu": "cpe:2.3:o:canonical:ubuntu_linux",
            "debian": "cpe:2.3:o:debian:debian_linux",
            "centos": "cpe:2.3:o:centos:centos",
            "fedora": "cpe:2.3:o:fedoraproject:fedora",
            "red hat": "cpe:2.3:o:redhat:enterprise_linux"
        }
    }
}

# Store scan progress
scan_progress = {}
scan_results = {}

def get_os_cpe(os_info):
    """Extract appropriate CPE for OS information."""
    os_name = os_info["name"].lower()
    version = os_info.get("version", "").lower()
    terms = []
    
    # Windows detection
    if "windows" in os_name:
        base = OS_TO_CPE["windows"]["base"]
        # Try to match version
        for key, ver in OS_TO_CPE["windows"]["versions"].items():
            if key in os_name or key in version:
                terms.append(f"{base}:{ver}")
                break
        else:
            terms.append(base)
            
    # Linux detection
    elif any(x in os_name for x in ["linux", "ubuntu", "debian", "centos", "fedora", "red hat"]):
        # Try specific distro first
        for distro, cpe in OS_TO_CPE["linux"]["distros"].items():
            if distro in os_name:
                if version:
                    terms.append(f"{cpe}:{version}")
                terms.append(cpe)
                break
        # Add generic Linux kernel CPE as fallback
        terms.append(OS_TO_CPE["linux"]["base"])
        
    return terms

def extract_version(service_info):
    """Enhanced version extraction from service information."""
    version = service_info.get("version", "").lower()
    if not version:
        return ""
        
    # Try different version patterns
    patterns = [
        r"(\d+\.\d+\.\d+)",  # matches x.y.z
        r"(\d+\.\d+)",       # matches x.y
        r"v?(\d+)"          # matches vX or just X
    ]
    
    for pattern in patterns:
        match = re.search(pattern, version)
        if match:
            return match.group(1)
    return ""

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
        
        # Add OS CPEs
        if os_info["name"] != "Unknown OS":
            terms.extend(get_os_cpe(os_info))
        
        # Add service CPEs
        for svc in ports:
            service = svc.get("service", "").lower()
            version = extract_version(svc)
            
            # Try exact service match first
            if service in SERVICE_TO_CPE:
                base_cpe = SERVICE_TO_CPE[service]
                if version:
                    terms.append(f"{base_cpe}:{version}")
                terms.append(base_cpe)
            
            # Try partial matches
            else:
                for key, cpe in SERVICE_TO_CPE.items():
                    if key in service or service in key:
                        if version:
                            terms.append(f"{cpe}:{version}")
                        terms.append(cpe)
                        break
        
        scan_progress[ip] = {"status": "fetching_vulnerabilities", "progress": 80}
        
        # Query vulnerabilities with improved rate limiting and retries
        all_vulns = []
        for term in terms:
            max_retries = 3
            retry_delay = 2  # seconds
            
            for attempt in range(max_retries):
                try:
                    time.sleep(retry_delay)  # Rate limit
                    vulns = get_top_vulns(term, max_results=5)
                    if vulns:  # Only add if we got results
                        # Ensure each vulnerability has required fields
                        for v in vulns:
                            if v.get('description') and v.get('cvss'):
                                all_vulns.append(v)
                    break  # Success, exit retry loop
                except Exception as e:
                    if attempt == max_retries - 1:  # Last attempt
                        print(f"[ERROR] Failed to get vulnerabilities for {term} after {max_retries} attempts: {e}")
                    else:
                        time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
        
        # Deduplicate and sort vulnerabilities
        seen = set()
        unique_vulns = []
        for v in sorted(all_vulns, key=lambda x: float(x.get('cvss') or 0), reverse=True):
            if v["id"] not in seen and v.get("description"):  # Only include vulns with descriptions
                seen.add(v["id"])
                # Ensure consistent format
                unique_vulns.append({
                    'id': v['id'],
                    'description': v['description'],
                    'cvss': v.get('cvss', 'N/A'),
                    'severity': v.get('severity', 'Unknown'),
                    'vector': v.get('vector', ''),
                    'published': v.get('published', 'Unknown'),
                    'lastModified': v.get('lastModified', 'Unknown'),
                    'references': v.get('references', [])
                })
        
        scan_progress[ip] = {"status": "completed", "progress": 100}
        
        result = {
            "ip": ip,
            "name": name,
            "os": os_info,
            "ports": ports,
            "vulns": unique_vulns[:5],
            "cpe_terms": terms  # Include CPE terms for debugging
        }
        
        # Log successful detection
        if unique_vulns:
            print(f"[INFO] Found {len(unique_vulns)} vulnerabilities for {ip} using {len(terms)} CPE terms")
            for v in unique_vulns[:3]:  # Log first 3 for debugging
                print(f"[INFO] {v['id']} - CVSS: {v['cvss']} - {v['severity']}")
        else:
            print(f"[WARNING] No vulnerabilities found for {ip} using CPE terms: {terms}")
            
        return result
        
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
