from scapy.all import *

# Craft a simple ICMP Echo Request (ping) packet
packet = IP(dst="192.168.1.10")/ICMP()

# Send the packet and wait for a response
response = sr1(packet, timeout=2)

if response:
    response.show()  # Display the response packet
else:
    print("No response received.")
