#!/usr/bin/env python3
## imporant ranges:
# 6729 - 6735 flag range
# 9560 - 9570 .pyc file range
from scapy.all import *
from pathlib import Path

IPX_HEADER_LEN = 30
NCP_HEADER_LEN = 10
TOTAL_HEADER_LEN = IPX_HEADER_LEN + NCP_HEADER_LEN

def main(pcap_path, file_path,  open_pkg_num, close_pkg_num):
    pcap = rdpcap(str(pcap_path))
    payload = b''

    for i in range(close_pkg_num - open_pkg_num + 1):
        idx = open_pkg_num + i
        if i in [0, 1]:
            continue  # Skip initial open packets
        if i % 2 == 1:  # Only responses
            print(f"Processing packet {idx + 1}...")
            pkt = pcap[idx]
            if Raw in pkt:
                raw_data = pkt[Raw].load
                if len(raw_data) > TOTAL_HEADER_LEN:
                    payload += raw_data[TOTAL_HEADER_LEN:]
                else:
                    print(f"Warning: packet {idx + 1} has too little data.")
            else:
                print(f"Warning: packet {idx + 1} has no Raw layer.")

    with open(file_path, "wb") as f:
        f.write(payload)

    print(f"Payload written to {file_path} file.")

if __name__ == "__main__":
    pcap_path = Path(sys.argv[1])
    file_path = Path(sys.argv[2])
    if not file_path.exists():
        print(f"Creating file: {file_path}")
        file_path.touch()
    open_pkg_num = int(sys.argv[3]) - 1  # get the packet number of the open file operation - 1 (zero-based instead of one-based)
    close_pkg_num = int(sys.argv[4]) - 1  # get the packet number of the close file operation -1 (zero-based instead of one-based)

    main(pcap_path, file_path, open_pkg_num, close_pkg_num)
