import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from device_discovery import scan_network, detect_os

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/scan":
            # Scan the network for devices
            network_range = "192.168.0.0/24"  # Adjust if needed
            devices = scan_network(network_range)
            # Run OS detection for each discovered device
            for device in devices:
                device["os"] = detect_os(device["ip"])
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(devices).encode("utf-8"))
        elif parsed_path.path == "/device":
            # Expect a query parameter "ip"
            query = parse_qs(parsed_path.query)
            ip = query.get("ip", [None])[0]
            if not ip:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Missing ip parameter')
                return
            # Run OS detection for this device
            os_info = detect_os(ip)
            # For now, we return OS info and an empty vulnerabilities list
            device_info = {
                "ip": ip,
                "os": os_info,
                "vulnerabilities": {"results": []}  # Replace with CVE API data if available
            }
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(device_info).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=MyHandler, port=8000):
    server_address = ("", port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting server on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
