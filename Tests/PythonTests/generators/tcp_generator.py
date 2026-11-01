from scapy.all import IP, TCP, send


class TcpGenerator:

    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip

    def send_syn(self, dst_port: int, src_port: int = 40000):
        packet = (
            IP(src="127.0.0.1", dst=self.target_ip)
            / TCP(
                sport=src_port,
                dport=dst_port,
                flags="S"
            )
        )

        print(f"[SENDING] TCP SYN -> {self.target_ip}:{dst_port}")

        send(packet, verbose=True)

        print("[SENT] Packet sent")

    def scan_ports(self, ports: list[int]):
        for index, port in enumerate(ports):
            self.send_syn(
                dst_port=port,
                src_port=40000 + index
            )
