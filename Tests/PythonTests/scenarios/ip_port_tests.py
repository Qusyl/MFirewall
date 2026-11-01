from generators.packet_generator import PacketGenerator


class IpPortTests:

    def __init__(self):
        self.generator = PacketGenerator()

   
    def test_source_port(
        self,
        blocked_port: int,
        dst_port: int = 65000
    ):
        print("\n=== SOURCE PORT TEST ===")

        # Совпадает с правилом
        self.generator.send_tcp(
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            src_port=blocked_port,
            dst_port=dst_port
        )

        # Не совпадает с правилом
        self.generator.send_tcp(
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            src_port=blocked_port + 1,
            dst_port=dst_port
        )

  
    def test_destination_port(
        self,
        blocked_port: int,
        src_port: int = 45000
    ):
        print("\n=== DESTINATION PORT TEST ===")

        self.generator.send_tcp(
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            src_port=src_port,
            dst_port=blocked_port
        )

        self.generator.send_tcp(
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            src_port=src_port,
            dst_port=blocked_port + 1
        )

 
    def test_source_ip(
        self,
        blocked_ip: str,
        allowed_ip: str = "127.0.0.3",
        dst_port: int = 65000
    ):
        print("\n=== SOURCE IP TEST ===")

        self.generator.send_tcp(
            src_ip=blocked_ip,
            dst_ip="127.0.0.1",
            src_port=45000,
            dst_port=dst_port
        )

        self.generator.send_tcp(
            src_ip=allowed_ip,
            dst_ip="127.0.0.1",
            src_port=45000,
            dst_port=dst_port
        )


    def test_destination_ip(
        self,
        blocked_ip: str,
        allowed_ip: str = "127.0.0.3"
    ):
        print("\n=== DESTINATION IP TEST ===")

        self.generator.send_tcp(
            src_ip="127.0.0.1",
            dst_ip=blocked_ip,
            src_port=45000,
            dst_port=65000
        )

        self.generator.send_tcp(
            src_ip="127.0.0.1",
            dst_ip=allowed_ip,
            src_port=45000,
            dst_port=65000
        )
