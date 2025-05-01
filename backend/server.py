import json
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from device_discovery import get_device_name
from port_scan import scan_device
from cpe_api import analyze_device_vulnerabilities

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            p = urlparse(self.path)
            if p.path == "/":
                return self._reply(200, {
                    "status": "ok",
                    "message": "Vulnerability Scanner API",
                    "endpoints": {
                        "/scan": "Scan devices for vulnerabilities",
                        "params": {
                            "auth_ips": "Comma-separated list of IP addresses to scan"
                        }
                    }
                })
            elif p.path == "/scan":
                qs = parse_qs(p.query)
                auth = qs.get("auth_ips", [None])[0]
                if not auth:
                    return self._reply(400, {"error": "No authorized IPs provided"})
                devices = []
                for ip in [x.strip() for x in auth.split(",") if x.strip()]:
                    # Get device info using the new scan_device function
                    scan_result = scan_device(ip)
                    device = {
                        "ip": ip,
                        "name": get_device_name(ip),
                        "os": scan_result["os"],
                        "ports": scan_result["ports"]
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
                return self._reply(404, {
                    "error": "Not found",
                    "path": p.path,
                    "message": "Available endpoints: /, /scan"
                })
        except Exception as e:
            print(f"Error handling request: {e}")
            print(traceback.format_exc())
            return self._reply(500, {"error": "Internal server error"})

    def _reply(self, code, data):
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
    print("Starting server on port 8000...")
    HTTPServer(("", 8000), MyHandler).serve_forever()
