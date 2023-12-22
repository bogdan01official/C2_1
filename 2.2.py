import scapy.all as scapy

MAX_LEN = 42
def process_dns_req(pkt):
    if scapy.DNSQR in pkt and pkt.dport == 53:
        print("Обнаружен DNS запрос: src_IP={}, dst_IP={}, src_PORT={},dsc_PORT = {}".format(pkt[scapy.IP].src, pkt[scapy.IP].dst,
        pkt[scapy.UDP].sport, pkt[scapy.UDP].dport))

        print("Запрос: " + pkt[scapy.DNSQR].qname.decode("utf-8"))
        if len(pkt[scapy.DNSQR].qname.decode("utf-8")) > MAX_LEN:
            print("Внимание! Подозрительно большой размер запроса!")


def process_dns_resp(pkt):
    if scapy.DNSRR in pkt and pkt.sport == 53:
        print("Обнаружен DNS ответ: src_IP={}, dst_IP={}, src_PORT={},dsc_PORT = {}".format(pkt[scapy.IP].src, pkt[scapy.IP].dst,
        pkt[scapy.UDP].sport, pkt[scapy.UDP].dport))

        print("Ответ: " + pkt[scapy.DNSRR].rrname.decode("utf-8"))
        print("Размер данных: " + str(pkt[scapy.DNSRR].rdlen))
        print("Данные ответа: " + str(pkt[scapy.DNSRR].rdata))
        if pkt[scapy.DNSRR].rdlen > MAX_LEN:
            print("Внимание! Подозрительно большой размер ответа!")

def process_dns(pkt):
    process_dns_req(pkt)
    process_dns_resp(pkt)

def main():
    scapy.sniff(filter="udp and port 53", prn=process_dns, store=0

if __name__ == "__main__":
    main()
