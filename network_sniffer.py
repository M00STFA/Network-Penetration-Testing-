from scapy.all import *
from datetime import datetime


def analyze_packet(packet):
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"Timestamp: {timestamp}\n"

        # تحليل إطار الإيثرنت
        if packet.haslayer(Ether):
            ether = packet.getlayer(Ether)
            log_entry += f"Ethernet Frame:\n"
            log_entry += f"Destination MAC: {ether.dst}, Source MAC: {ether.src}, Protocol: {ether.type}\n"

        # تحليل طبقة الـ IP
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            log_entry += f"IP Packet:\n"
            log_entry += f"Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst}\n"
            log_entry += f"Protocol: {ip_layer.proto}\n"

            # تحليل طبقة الـ TCP إذا كانت موجودة
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                log_entry += f"TCP Segment:\n"
                log_entry += f"Source Port: {tcp_layer.sport} -> Destination Port: {tcp_layer.dport}\n"
                log_entry += f"Flags: {tcp_layer.flags}\n"

            # تحليل طبقة الـ UDP إذا كانت موجودة
            elif packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                log_entry += f"UDP Datagram:\n"
                log_entry += f"Source Port: {udp_layer.sport} -> Destination Port: {udp_layer.dport}\n"

        # دعم بروتوكولات ICMP و ARP
        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            log_entry += f"ICMP Packet:\n"
            log_entry += f"Type: {icmp_layer.type}, Code: {icmp_layer.code}\n"

        elif packet.haslayer(ARP):
            arp_layer = packet.getlayer(ARP)
            log_entry += f"ARP Packet:\n"
            log_entry += f"Operation: {arp_layer.op}, Source MAC: {arp_layer.hwsrc}, Source IP: {arp_layer.psrc}\n"
            log_entry += f"Destination MAC: {arp_layer.hwdst}, Destination IP: {arp_layer.pdst}\n"

        # طباعة البيانات
        print(log_entry)

        # تسجيل البيانات في ملف
        with open("packet_log.txt", "a") as log_file:
            log_file.write(log_entry + "\n" + "=" * 50 + "\n")

    except Exception as e:
        print(f"An error occurred: {e}")


def main(packet_count):
    # بدء عملية التقاط الحزم
    try:
        sniff(prn=analyze_packet, count=packet_count)
    except KeyboardInterrupt:
        print("Packet sniffing interrupted by user.")


if __name__ == "__main__":
    import sys

    packet_count = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    main(packet_count)

