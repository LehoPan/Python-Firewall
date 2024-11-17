import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

PACKET_LIMIT = 20
HOST_IP = "192.168.2.2"
print(f"PACKETLIMIT: {PACKET_LIMIT}")

def packet_callback(packet):
    source_ip = packet[IP].src
    if source_ip != HOST_IP:
        packet_count[source_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval

            if packet_rate > PACKET_LIMIT and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)
    
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)