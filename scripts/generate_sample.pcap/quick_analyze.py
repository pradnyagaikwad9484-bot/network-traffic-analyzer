#!/usr/bin/env python3
"""Small standard-library PCAP summary. Wireshark is recommended for full dissection."""
import argparse, socket, struct
from collections import Counter
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?", default=str(Path(__file__).resolve().parents[1]/"captures"/"sample_traffic.pcap"))
    args=ap.parse_args()
    counts=Counter(); endpoints=Counter()
    with open(args.pcap,"rb") as f:
        hdr=f.read(24)
        if len(hdr)!=24: raise SystemExit("Not a classic PCAP file or file is truncated.")
        magic=hdr[:4]
        endian="<" if magic==b"\\xd4\\xc3\\xb2\\xa1" else ">"
        n=0
        while True:
            ph=f.read(16)
            if not ph: break
            if len(ph)!=16: break
            sec,usec,caplen,origlen=struct.unpack(endian+"IIII",ph)
            data=f.read(caplen)
            if len(data)!=caplen: break
            n+=1
            if len(data)<14: counts["truncated/non-Ethernet"]+=1; continue
            et=struct.unpack("!H",data[12:14])[0]
            if et!=0x0800 or len(data)<34: counts["non-IPv4"]+=1; continue
            ihl=(data[14]&15)*4
            proto=data[23]
            src=socket.inet_ntoa(data[26:30]); dst=socket.inet_ntoa(data[30:34])
            if proto==6 and len(data)>=14+ihl+4:
                sp,dp=struct.unpack("!HH",data[14+ihl:14+ihl+4]); name="TCP"
            elif proto==17 and len(data)>=14+ihl+4:
                sp,dp=struct.unpack("!HH",data[14+ihl:14+ihl+4]); name="UDP"
            else:
                counts["IPv4 other"]+=1; continue
            counts[name]+=1; endpoints[(src,sp,dst,dp,name)]+=1
    print(f"Packets read: {n}")
    print("Protocol counts:")
    for k,v in sorted(counts.items()): print(f"  {k}: {v}")
    print("Observed flows:")
    for (src,sp,dst,dp,name),v in sorted(endpoints.items()):
        print(f"  {name} {src}:{sp} -> {dst}:{dp} ({v} packet(s))")
if __name__=="__main__": main()
