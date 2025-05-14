import json
import traceback
import sys
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from device_discovery import get_device_name, detect_os
from port_scan import scan_device
from cpe_api import get_device_cpes
from cve_api import CVEAPI
import mimetypes

# Force flush all prints
sys.stdout.reconfigure(line_buffering=True)

# Create global CVE API instance
cve_api = CVEAPI()

class MyHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for the vulnerability scanner API and static frontend files.
    Handles GET requests for both API endpoints and frontend assets.
    """
    def log_message(self, format, *args):
        """Override to force flush logging"""
        sys.stderr.write("%s - - [%s] %s\n" %
                        (self.address_string(),
                         self.log_date_time_string(),
                         format % args))
        sys.stderr.flush()

    def do_GET(self):
        print(f"[DEBUG] Received GET request: {self.path}", flush=True)
        """
        Handle GET requests. Serves the /scan API endpoint or static frontend files.
        """
        try:
            p = urlparse(self.path)
            # Serve API endpoint
            if p.path == "/scan":
                qs = parse_qs(p.query)
                auth = qs.get("auth_ips", [None])[0]
                if not auth:
                    print("[DEBUG] No authorized IPs provided", flush=True)
                    return self._reply(400, {"error": "No authorized IPs provided"})
                
                devices = []
                for ip in [x.strip() for x in auth.split(",") if x.strip()]:
                    print(f"[DEBUG] Processing device: {ip}", flush=True)
                    # First get device name and OS info
                    name = get_device_name(ip)
                    print(f"[DEBUG] Device name: {name}", flush=True)
                    
                    os_info_dict = detect_os(ip)
                    os_info = os_info_dict["os"]
                    os_normalized = os_info_dict["os_normalized"]
                    print(f"[DEBUG] OS info: {os_info}, Normalized: {os_normalized}", flush=True)
                    
                    # Then scan ports based on OS
                    scan_result = scan_device(ip, os_info)
                    print(f"[DEBUG] Scan result ports: {scan_result['ports']}", flush=True)
                    
                    device = {
                        "ip": ip,
                        "name": name,
                        "os": os_info,
                        "os_normalized": os_normalized,
                        "ports": scan_result["ports"]
                    }
                    try:
                        print(f"[DEBUG] Getting CPEs for {ip}", flush=True)
                        cpe_results = get_device_cpes(device)
                        device["cpes"] = []
                        device["vulnerabilities"] = []
                        for c in cpe_results:
                            vulns = cve_api.search_cves(c["cpe"])
                            if vulns:
                                device["cpes"].append({"cpe": c["cpe"], "source": c["source"]})
                                for v in vulns:
                                    v["source"] = c["source"]
                                    # Remove any cpe field from v if present
                                    if "cpe" in v:
                                        del v["cpe"]
                                    device["vulnerabilities"].append(v)
                        print(f"[DEBUG] Found {len(device['cpes'])} CPEs and {len(device['vulnerabilities'])} vulnerabilities for {ip}", flush=True)
                    except Exception as e:
                        print(f"[ERROR] Error analyzing device {ip}: {e}", flush=True)
                        print(traceback.format_exc(), flush=True)
                        device["cpes"] = []
                        device["vulnerabilities"] = []
                    devices.append(device)
                return self._reply(200, devices)
            # Serve static frontend files
            else:
                self.serve_frontend(p.path)
        except Exception as e:
            print(f"Error handling request: {e}")
            print(traceback.format_exc())
            return self._reply(500, {"error": "Internal server error"})

    def serve_frontend(self, path):
        """
        Serves static frontend files from the React build directory.
        Maps / to /index.html and prevents directory traversal.
        """
        build_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'frontend', 'build')
        # Map / to /index.html
        if path == '/' or path == '':
            path = '/index.html'
        file_path = os.path.normpath(os.path.join(build_dir, path.lstrip('/')))
        # Prevent directory traversal
        if not file_path.startswith(build_dir):
            self.send_error(403)
            return
        if not os.path.exists(file_path):
            # For client-side routing, serve index.html
            file_path = os.path.join(build_dir, 'index.html')
        # Guess content type
        content_type, _ = mimetypes.guess_type(file_path)
        if not content_type:
            content_type = 'application/octet-stream'
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            print(f"Error serving frontend file: {e}")
            print(traceback.format_exc())
            self.send_error(500)

    def _reply(self, code, data):
        """
        Send a JSON response with the given HTTP status code and data.
        Adds CORS headers for frontend-backend communication.
        """
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            response = json.dumps(data).encode()
            self.wfile.write(response)
        except ConnectionAbortedError:
            print("Client connection aborted while sending response")
        except Exception as e:
            print(f"Error sending response: {e}")
            print(traceback.format_exc())

if __name__ == "__main__":
    try:
        print("Starting server on port 8000...")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Python executable: {sys.executable}")
        print(f"Python version: {sys.version}")
        server = HTTPServer(('0.0.0.0', 8000), MyHandler)
        print("Server initialized successfully")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.server_close()
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)
