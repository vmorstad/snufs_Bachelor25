import json
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from device_discovery import detect_os, get_device_name
from port_scan import scan_ports
from cpe_api import analyze_device_vulnerabilities

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/scan":
            qs = parse_qs(p.query)
            auth = qs.get("auth_ips", [None])[0]
            if not auth:
                return self._reply(400, {"error": "No authorized IPs provided"})
            devices = []
            for ip in [x.strip() for x in auth.split(",") if x.strip()]:
                device = {
                  "ip": ip,
                  "name": get_device_name(ip),
                  "os":   detect_os(ip),
                  "ports": scan_ports(ip)
                }
                try:
                    device["vulnerabilities"] = analyze_device_vulnerabilities(device)
                except Exception as e:
                    print(f"Error analyzing vulnerabilities for {ip}: {e}")
                    print(traceback.format_exc())
                    device["vulnerabilities"] = []
                devices.append(device)
            return self._reply(200, devices)
        else:
            return self._reply(404, {"error": "Not found"})

    def _reply(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

if __name__ == "__main__":
    print("Starting server on port 8000...")
    HTTPServer(("", 8000), MyHandler).serve_forever()
