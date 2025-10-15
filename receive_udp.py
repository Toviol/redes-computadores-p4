#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Script para receber e analisar pacotes UDP com DSCP
import os
import sys
from datetime import datetime

from scapy.all import UDP, IP, get_if_list, sniff


def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


packet_count = 0
dscp_stats = {}


def handle_pkt(pkt):
    global packet_count, dscp_stats
    
    if UDP in pkt and IP in pkt:
        packet_count += 1
        
        # Extract DSCP (upper 6 bits of TOS/diffserv)
        tos = pkt[IP].tos
        dscp = tos >> 2
        
        # Count DSCP values
        if dscp not in dscp_stats:
            dscp_stats[dscp] = 0
        dscp_stats[dscp] += 1
        
        # Determine priority
        if dscp == 34:  # AF41
            priority = "HIGH (AF41)"
        elif dscp == 0:  # BE
            priority = "LOW (BE)"
        else:
            priority = f"UNKNOWN ({dscp})"
        
        print(f"[{packet_count:4d}] {datetime.now().strftime('%H:%M:%S.%f')[:-3]} | "
              f"Src: {pkt[IP].src}:{pkt[UDP].sport} -> "
              f"Dst: {pkt[IP].dst}:{pkt[UDP].dport} | "
              f"DSCP: {dscp:2d} ({priority}) | "
              f"Size: {len(pkt):4d} bytes")
        
        sys.stdout.flush()


def print_stats():
    print("\n" + "=" * 80)
    print("DSCP Statistics:")
    print("=" * 80)
    for dscp in sorted(dscp_stats.keys()):
        if dscp == 34:
            label = "AF41 (High Priority)"
        elif dscp == 0:
            label = "BE (Low Priority)"
        else:
            label = f"Unknown ({dscp})"
        
        count = dscp_stats[dscp]
        percentage = (count / packet_count * 100) if packet_count > 0 else 0
        print(f"  DSCP {dscp:2d} ({label:20s}): {count:5d} packets ({percentage:5.1f}%)")
    
    print("=" * 80)
    print(f"Total packets received: {packet_count}")
    print("=" * 80)


def main():
    iface = get_if()
    print(f"Sniffing UDP packets on {iface}")
    print("Press Ctrl+C to stop and show statistics")
    print("=" * 80)
    sys.stdout.flush()
    
    try:
        sniff(iface=iface, prn=lambda x: handle_pkt(x), filter="udp")
    except KeyboardInterrupt:
        print_stats()


if __name__ == '__main__':
    main()
