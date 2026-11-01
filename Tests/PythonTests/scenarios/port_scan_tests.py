from generators.packet_generator import PacketGenerator


class PortScanTests:

    def __init__(self):
        self.generator = PacketGenerator()

    def test_tcp_port_scan(self, packet_count: int):
        print("\n========== TCP PORT SCAN ==========")

        self.generator.send_tcp_scan(
            packet_count=packet_count,
            start_port=20000,
            interval=0.02
        )
    def test_udp_port_scan(self, packet_count: int):
        print("\n========== UDP PORT SCAN ==========")

        self.generator.send_udp_scan(
            packet_count=packet_count,
            start_port=30000,
            interval=0.02
        )
