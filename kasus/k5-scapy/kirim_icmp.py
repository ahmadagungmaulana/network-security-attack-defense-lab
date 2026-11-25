import sys
from scapy.all import ICMP, IP, sr1

target = sys.argv[1]
paket = IP(dst=target) / ICMP()
print("Mengirim:", paket.summary())

balasan = sr1(paket, timeout=2, verbose=False)
if balasan is None:
    print("Tidak ada balasan.")
else:
    print("TTL balasan:", balasan[IP].ttl)
    print("Tipe ICMP balasan:", balasan[ICMP].type)