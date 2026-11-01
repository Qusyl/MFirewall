from generators.packet_generator import PacketGenerator


class RateLimitTests:

    def __init__(self):
        self.generator = PacketGenerator()

    def test_ip_rate_limit(self, packet_count: int):
        print("\n========== IP RATE LIMIT ==========")

        self.generator.send_rate_limit_burst(
            packet_count=packet_count,
            src_ip="127.0.0.2",
            dst_ip="127.0.0.1",
            src_port=45000,
            dst_port=65000,
            interval=0.001
        )
