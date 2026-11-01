from generators.packet_generator import PacketGenerator


class FloodTests:

    def __init__(self):
        self.generator = PacketGenerator()

    def test_tcp_syn_flood(self, packet_count: int):
        print("\n========== TCP SYN FLOOD TEST ==========")

        self.generator.send_tcp_syn_burst(
            packet_count=packet_count,
            dst_port=65000,
            start_src_port=30000,
            interval=0.02
        )
    def test_udp_flood(self, packet_count: int):
        print("\n========== UDP FLOOD TEST ==========")

        self.generator.send_udp_burst(
            packet_count=packet_count,
            dst_port=65000,
            interval=0.005
        )
