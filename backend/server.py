from flask import Flask, jsonify
from device_discovery import discover_devices
from port_scanner import scan_device_ports, grab_service_banner
from vulnerability_checker import check_vulnerabilities

app = Flask(__name__)

def perform_scan():
    # Define your network; ensure you have permission to scan.
    network = "192.168.1.0/24"
    devices = discover_devices(network)
    print(f"[DEBUG] Devices discovered: {devices}")
    results = []
    for device in devices:
        ip = device['ip']
        open_ports = scan_device_ports(ip, port_range=(1, 100))
        device_vulnerabilities = []
        for port in open_ports:
            banner = grab_service_banner(ip, port)
            if banner:
                vulns = check_vulnerabilities(banner)
                device_vulnerabilities.extend(vulns)
        results.append({
            'ip': ip,
            'open_ports': open_ports,
            'vulnerabilities': device_vulnerabilities
        })
    return results

@app.route("/api/scan", methods=["GET"])
def scan_api():
    scan_results = perform_scan()
    return jsonify(scan_results)

if __name__ == "__main__":
    # Run the Flask app on localhost port 5000
    app.run(debug=True)
