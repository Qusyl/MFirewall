from scenarios.ip_port_tests import IpPortTests
from scenarios.port_scan_tests import PortScanTests
from scenarios.flood_tests import FloodTests
from scenarios.rate_limit_tests import RateLimitTests

def main():
    tests = IpPortTests()
    ps_tests = PortScanTests()
    flood_tests = FloodTests()
    rate_limit_tests = RateLimitTests()

    print("=== MFirewall Tester ===")
    print("[1] Source Port")
    print("[2] Destination Port")
    print("[3] Source IP")
    print("[4] Destination IP")
    print("[5] TCP Port Scan")
    print("[6] UDP Port Scan")
    print("[7] TCP Syn Flood")
    print("[8] UDP Flood")
    print("[9] Rate Limit IP")

    choice = input("Select test: ")

    if choice == "1":
        tests.test_source_port(779)

    elif choice == "2":
        tests.test_destination_port(779)

    elif choice == "3":
        tests.test_source_ip("127.0.0.3")

    elif choice == "4":
        tests.test_destination_ip("127.0.0.17")
    elif choice == "5":
        count = int(input("Packet count: "))
        ps_tests.test_tcp_port_scan(count)
    elif choice == "6":
        count = int(input("Packet count: "))
        ps_tests.test_udp_port_scan(count)
    elif choice == "7":
        count = int(input("Packet count: "))
        flood_tests.test_tcp_syn_flood(count)
    elif choice == "8":
        count = int(input("Packet count: "))
        flood_tests.test_udp_flood(count)
    elif choice == "9":
        count = int(input("Packet count: "))
        rate_limit_tests.test_ip_rate_limit(count)


if __name__ == "__main__":
    main()
