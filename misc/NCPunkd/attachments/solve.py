#!/usr/bin/env python3
from decrypt import decrypt
from scapy.all import *
from pathlib import Path
PKT_NUM = 6732 - 1 # the packet number where the flag is stored - 1 cos zerobased
IPX_HEADER_LEN = 30
NCP_HEADER_LEN = 10
TOTAL_HEADER_LEN = IPX_HEADER_LEN + NCP_HEADER_LEN
FLAG_REGEX = re.compile(r"[a-zA-Z]+\{[a-zA-Z0-9_]+\}")

def main(pcap_path):
    pcap = rdpcap(str(pcap_path)) 
    # find the packet with the flag
    flag_pkt = pcap[PKT_NUM][Raw]
    payload = flag_pkt.load[TOTAL_HEADER_LEN:].strip(b'\x00')  # Remove padding null bytes
    flag = decrypt(payload.decode('utf-8'))
    if FLAG_REGEX.match(flag):
        print(flag)

if __name__ == "__main__":
    pcap_dir = Path(sys.argv[1])
    pcap_path = pcap_dir / "capture.pcap"
    main(pcap_path)
