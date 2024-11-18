from scapy.all import *

def syn_scan(target_ip, port):
    # Send SYN packet
    syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
    response = sr1(syn_packet, timeout=1, verbose=0)

    if response is None:
        print(f"Port {port} is FILTERED (no response).")
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK received
            print(f"Port {port} is OPEN.")
        elif response.getlayer(TCP).flags == 0x14:  # RST-ACK received
            print(f"Port {port} is CLOSED.")

# Example usage
if __name__ == "__main__":
    target_ip = "192.168.2.2"
    for port in range(20, 1024):
        syn_scan(target_ip, port)
