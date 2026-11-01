from scapy.all import IP, TCP, UDP, ICMP, Raw, send, conf
from scapy.supersocket import L3RawSocket
import time

conf.use_pcap = False
conf.L3socket = L3RawSocket


class PacketGenerator:

    def send_tcp(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flags="S"
    ):
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=src_port,
                dport=dst_port,
                flags=flags
            )
        )

        self._send(packet)

    def send_udp(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int
    ):
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=src_port, dport=dst_port)
            / Raw(load=b"MFirewall test")
        )

        self._send(packet)

    def send_tcp_scan(
        self,
        packet_count: int,
        start_port: int = 20000,
        src_ip: str = "127.0.0.2",
        dst_ip: str = "127.0.0.1",
        src_port: int = 45000,
        interval: float = 0.02
    ):
        packets = []

        for i in range(packet_count):
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(
                    sport=src_port,
                    dport=start_port + i,
                    flags="S",
                    seq=1000 + i
                )
            )

            packets.append(packet)

        print(f"\n[SCAN] Sending {packet_count} TCP SYN packets")

        for packet in packets:
            print(f"[SEND] {packet.summary()}")

        send(packets, inter=interval, verbose=False)

        print("[SCAN] Completed")

    def send_udp_scan(
        self,
        packet_count: int,
        start_port: int = 20000,
        src_ip: str = "127.0.0.2",
        dst_ip: str = "127.0.0.1",
        src_port: int = 45000,
        interval: float = 0.02
    ):
        packets = []

        for i in range(packet_count):
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(
                    sport=src_port,
                    dport=start_port + i
                )
                / Raw(load=f"MFirewall UDP scan {i}".encode())
            )

            packets.append(packet)

        print(f"\n[UDP SCAN] Sending {packet_count} packets")

        for packet in packets:
            print(f"[SEND] {packet.summary()}")

        send(
            packets,
            inter=interval,
            verbose=False
        )

        print("[UDP SCAN] Completed")

    def send_tcp_syn_burst(
        self,
        packet_count: int,
        src_ip: str = "127.0.0.2",
        dst_ip: str = "127.0.0.1",
        dst_port: int = 65000,
        start_src_port: int = 30000,
        interval: float = 0.02
    ):
        if packet_count < 1 or packet_count > 150:
            raise ValueError("Packet count must be between 1 and 150")

        if start_src_port + packet_count - 1 > 65535:
            raise ValueError("Source port range exceeds 65535")

        packets = []

        for i in range(packet_count):
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(
                    sport=start_src_port + i,
                    dport=dst_port,
                    flags="S",
                    seq=1000 + i
                )
            )

            packets.append(packet)

        print(
            f"\n[TCP SYN FLOOD] Sending {packet_count} packets "
            f"to {dst_ip}:{dst_port}"
        )

        send(packets, inter=interval, verbose=False)

        print("[TCP SYN FLOOD] Completed")

    def send_udp_burst(
        self,
        packet_count: int,
        src_ip: str = "127.0.0.2",
        dst_ip: str = "127.0.0.1",
        src_port: int = 45000,
        dst_port: int = 65000,
        interval: float = 0.005
    ):
        packets = []

        for i in range(packet_count):
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(
                    sport=src_port,
                    dport=dst_port
                )
                / Raw(load=f"MFirewall UDP flood {i}".encode())
            )

            packets.append(packet)

        print(f"\n[UDP FLOOD] Sending {packet_count} packets")

        send(packets, inter=interval, verbose=False)

        print("[UDP FLOOD] Completed")

    def send_rate_limit_burst(
        self,
        packet_count: int,
        src_ip: str = "127.0.0.2",
        dst_ip: str = "127.0.0.1",
        src_port: int = 45000,
        dst_port: int = 65000,
        interval: float = 0.001
    ):
        if packet_count < 1 or packet_count > 500:
            raise ValueError("Invalid packet count")

        packets = []

        for i in range(packet_count):
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(
                    sport=src_port,
                    dport=dst_port
                )
                / Raw(load=f"RateLimit test packet {i}".encode())
            )

            packets.append(packet)

        print(f"\n[RATE LIMIT] Sending {packet_count} packets")

        start = time.perf_counter()

        send(
            packets,
            inter=interval,
            verbose=False
        )

        elapsed = time.perf_counter() - start

        print(f"[RATE LIMIT] Completed in {elapsed:.3f} seconds")

    @staticmethod
    def _send(packet):
        print(f"[SEND] {packet.summary()}")

        send(packet, verbose=False)

        print("[SENT]")
