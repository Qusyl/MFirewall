from scapy.all import IP, TCP, send

packet = (
    IP(src="201.13.1.18", dst="127.0.0.1") /
    TCP(sport=45000, dport=65000, flags="S")
)

send(packet, verbose=True)
