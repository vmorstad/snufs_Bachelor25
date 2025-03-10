from scapy.all import ARP, Ether, srp, IP, ICMP, sr1

# Define the network range to scan (first 10 IPs for quick test)
network_prefix = "192.168.1."
scan_range = range(1, 13)  # Only scan .1 to .12 (change if needed)

def arp_scan():
    print("\n[+] Running Fast ARP Scan...")
    target_ips = [network_prefix + str(ip) for ip in scan_range]
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)
    answered, _ = srp(packet, timeout=2, verbose=False)

    for sent, received in answered:
        print(f"Device Found - IP: {received.psrc}, MAC: {received.hwsrc}")

def icmp_scan():
    print("\n[+] Running Fast ICMP Scan...")
    for ip in scan_range:
        target_ip = network_prefix + str(ip)
        packet = IP(dst=target_ip)/ICMP()
        response = sr1(packet, timeout=1, verbose=False)

        if response:
            print(f"Device Found - IP: {target_ip}")

# Run scans (stops when done)
arp_scan()
icmp_scan()
print("\n[✔] Scan completed!")
