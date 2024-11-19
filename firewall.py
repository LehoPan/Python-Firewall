import os
import sys
import time
import subprocess
from collections import defaultdict
from scapy.all import sniff, IP, TCP, ARP
import configparser

# config parser in order to grab settings form the configuration file
config = configparser.ConfigParser()
config.read('confs/host_options.conf')

# constants form the host options
SCAN_FREQUENCY = int(config.get('settings', 'SCAN_FREQUENCY'))  # period for checking ping rates
PACKET_LIMIT = int(config.get('settings', 'PACKET_LIMIT'))      # Ping rate limit before blocking
HOST_IP = config.get('settings', 'HOST_IP')                     # host's ip to whitelist itself
print(f"PACKETLIMIT: {PACKET_LIMIT}")

# Reads in an ip text file and returns a set
def read_ips(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)

# Reads in a text file of mac addresses and returns a set
def read_macs(filename):
    with open(filename, "r") as file:
        macs = [line.strip() for line in file]
    return set(macs)

# find all ips already blacklisted by scraping iptables
def existing_blacklisted_ips():
    try:
        # command to find all ip addresses block by iptables
        result = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True)

        if result.returncode != 0:
            print("Error iptables rules: ", result.stderr)
            return set()

        blacklisted = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("DROP"):  # Find DROP rules
                parts = line.split()
                if len(parts) >= 4:
                    blacklisted.add(parts[3])
        return blacklisted

    except Exception as e:
        print(f"Error getting the blacklisted IPs: {e}")
        return set()

# Checks for interestions between white and black list
def check_intersections(blacklist, whitelist):
    # Find conflicting IPs
    conflicting = blacklist & whitelist

    return conflicting

# Check for forkbomb signature
def is_fork_bomb(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].load
        return ":(){ :|:& };:" in str(payload)
    return False

# Log events
def add_log(message):
    logs = "logs"
    os.makedirs(logs, exist_ok=True) # only makes a new directory for logs if it doesn't exist

    # parses out all of the time component's values
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(logs, f"log_{timestamp}.txt")
    
    with open(log_file, "a") as file:
        file.write(f"{message}\n")

# Callback function for everytime we recieve a packet
def packet_callback(packet):
    source_ip = packet[IP].src
    source_mac = packet.hwsrc #add way to grab source mac of packet

    # doesn't do anything if the ip or mac is on the white list
    if (source_ip in whitelist_ips or source_ip == HOST_IP):
        if packet.haslayer(ARP) and source_mac in whitelist_macs:
            return
        return
    # checks if it is on blacklist and blocks
    elif source_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {source_ip} -j DROP")
        add_log(f"Blocking blacklisted IP: {source_ip}")
        return
    elif packet.haslayer(ARP) and source_mac not in whitelist_macs: #adds rule, drops packets based on mac address
        os.system(f"arptables -A INPUT --source-mac {source_mac} -j DROP")
        add_log(f"Blocking packets from: {source_mac}")
        return
    
    # does the check for the fork bomb signature
    if is_fork_bomb(packet):
        print(f"Fork bomb detected from IP: {source_ip}")
        os.system(f"iptables -A INPUT -s {source_ip} -j DROP")
        add_log(f"Blocking fork bomb IP: {source_ip}")
        return

    # logs how many times this ip has sent something in the interval
    packet_count[source_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    # runs once the time interval has elapsed, and starts blacklisting
    if time_interval >= SCAN_FREQUENCY:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval

            # triggers if the packet rate is exceeded and blacklists
            if packet_rate > PACKET_LIMIT and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                add_log(f"Blocking IP: {source_ip}, large packet rate: {packet_rate}")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time


if __name__ == "__main__":
    # makes sure the program has the necessary elevation
    if os.geteuid() != 0:
        print("Please run as root.")
        sys.exit(1)

    # FLUSHES OUT ALL EXISTING INPUT RULES
    # this is to make sure things in whitelist aren't already blocked
    if config.getboolean('settings', 'FLUSH_RULES'):
        os.system("iptables -F INPUT")
        add_log("BFlushing previous ruleset")

    # Import whitelist and blacklist IPs
    whitelist_ips = read_ips("confs/whitelist.txt")

    # Import whitelisted MAC addresses
    whitelist_macs = read_macs("confs/whitelistmac.txt")

    # Makes sure to add all existing blacklisted ips
    blacklist_ips = read_ips("confs/blacklist.txt").union(existing_blacklisted_ips())
    
    # Compares white and black to see if any are in both and alerts user
    intesections = check_intersections(whitelist_ips, blacklist_ips)
    if len(intesections) != 0:
        print(f"\nIp(s) found in both black/white lists were:\n{intesections}\nPlease resolve them.\n")
    
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    # checks if the option to block icmp echo requests (ping) is check and blocks it
    if config.getboolean('settings', 'BLOCK_ICMP_ECHO_REQUESTS'):
        print("Blocking ICMP echo requests")
        os.system(f"iptables -A INPUT -p icmp --icmp-type echo-request -j DROP")
        add_log("Blocking ICMP echo requests")


    print("Firewall Running!")
    sniff(filter="ip", prn=packet_callback)