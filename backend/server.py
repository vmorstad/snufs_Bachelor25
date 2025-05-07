import json
import traceback
import sys
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from device_discovery import get_device_name
from port_scan import scan_device
from cpe_api import analyze_device_vulnerabilities
import mimetypes

# Add logging to file
def setup_logging():
    """
    Redirect stdout and stderr to a log file for debugging and auditing.
    Creates a 'logs' directory if it does not exist.
    """
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'server.log')
    sys.stdout = open(log_file, 'a')
    sys.stderr = sys.stdout

class MyHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for the vulnerability scanner API and static frontend files.
    Handles GET requests for both API endpoints and frontend assets.
    """
    def do_GET(self):
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
                    return self._reply(400, {"error": "No authorized IPs provided"})
                devices = []
                for ip in [x.strip() for x in auth.split(",") if x.strip()]:
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
        setup_logging()
        print("Starting server on port 8000...")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Python executable: {sys.executable}")
        print(f"Python version: {sys.version}")

        server = HTTPServer(("", 8000), MyHandler)
        print("Server initialized successfully")
        server.serve_forever()
    except Exception as e:
        print(f"Failed to start server: {e}")
        print(traceback.format_exc())
        input("Press Enter to exit...")  # Keep window open if there's an error
