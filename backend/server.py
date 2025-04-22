import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from device_discovery import detect_os, get_device_name, scan_ports

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/scan":
            query = parse_qs(parsed_path.query)
            auth_ips = query.get("auth_ips", [None])[0]
            if not auth_ips or auth_ips.strip() == "":
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "No authorized IPs provided"}).encode("utf-8"))
                return
            
            ips = [ip.strip() for ip in auth_ips.split(",") if ip.strip()]
            devices = []
            for ip in ips:
                os_info = detect_os(ip)
                name = get_device_name(ip)
                ports = scan_ports(ip)
                devices.append({"ip": ip, "name": name, "os": os_info, "ports": ports})
            
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(devices).encode("utf-8"))
        
        elif parsed_path.path == "/device":
            query = parse_qs(parsed_path.query)
            ip = query.get("ip", [None])[0]
            if not ip:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing ip parameter")
                return
            os_info = detect_os(ip)
            name = get_device_name(ip)
            ports = scan_ports(ip)
            device_info = {
                "ip": ip,
                "name": name,
                "os": os_info,
                "ports": ports,
                "vulnerabilities": {"results": []}  # Placeholder
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
