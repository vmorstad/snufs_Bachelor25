from scapy.all import ARP, Ether, srp, conf
import subprocess

# Set the default interface for Scapy
def scan_network(network_range):
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=5, verbose=True)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

# Run Nmap to detect OS
# This function requires Nmap to be installed and available in the system PATH
def detect_os(ip_address):
    try:
        # Run Nmap with OS detection (-O flag)
        result = subprocess.check_output(["nmap", "-O", ip_address], universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error running Nmap on {ip_address}: {e}"

if __name__ == "__main__":
    network_range = "192.168.0.0/24"
    print("Scanning network for devices...")
    devices = scan_network(network_range)
    
    if devices:
        print("\nDiscovered devices:")
        for device in devices:
            print(f"IP: {device['ip']} \t MAC: {device['mac']}")
        
        print("\nRunning OS detection on discovered devices:")
        for device in devices:
            ip = device['ip']
            print(f"\nOS detection for {ip}:")
            os_info = detect_os(ip)
            print(os_info)
    else:
        print("No devices discovered. Check your network settings, firewall, or interface.")
    
    print("Scan complete.")
