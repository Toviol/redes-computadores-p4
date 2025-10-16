#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Script para enviar pacotes UDP com controle de taxa
import argparse
import socket
import sys
import time

from scapy.all import IP, UDP, Ether, get_if_hwaddr, get_if_list, sendp


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


def main():
    parser = argparse.ArgumentParser(description='Send UDP packets')
    parser.add_argument('--dst', required=True, help='Destination IP')
    parser.add_argument('--sport', type=int, default=5000, help='Source port')
    parser.add_argument('--dport', type=int, default=5001, help='Destination port')
    parser.add_argument('--count', type=int, default=100, help='Number of packets')
    parser.add_argument('--size', type=int, default=1000, help='Payload size in bytes')
    parser.add_argument('--rate', type=float, default=0, help='Rate in Mbps (0 = no limit)')
    
    args = parser.parse_args()
    
    addr = socket.gethostbyname(args.dst)
    iface = get_if()
    
    payload = 'X' * args.size
    
    print(f"Sending {args.count} UDP packets on {iface} to {addr}")
    print(f"  Source port: {args.sport}")
    print(f"  Destination port: {args.dport}")
    print(f"  Payload size: {args.size} bytes")
    print(f"  Target Rate: {args.rate if args.rate > 0 else 'unlimited'} Mbps")
    print("-" * 60)
    
    if args.rate > 0:
        total_size = 14 + 20 + 8 + args.size  
        bits_per_packet = total_size * 8
        target_bps = args.rate * 1_000_000  
        delay = bits_per_packet / target_bps  
    else:
        delay = 0
    
    start_time = time.time()
    
    for i in range(args.count):
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr) / UDP(sport=args.sport, dport=args.dport) / payload
        
        sendp(pkt, iface=iface, verbose=False)
        
        if delay > 0:
            time.sleep(delay)
        
        if (i + 1) % 10 == 0:
            print(f"Sent {i + 1} packets...")
    
    elapsed = time.time() - start_time
    actual_rate = (args.count * (14 + 20 + 8 + args.size) * 8) / elapsed / 1_000_000
    
    print("-" * 60)
    print(f"Done! Sent {args.count} packets")


if __name__ == '__main__':
    main()
