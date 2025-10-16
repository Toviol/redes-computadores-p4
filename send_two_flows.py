#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Script para enviar 2 fluxos UDP simultâneos com taxas diferentes
import argparse
import socket
import sys
import time
import threading

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


def send_flow(flow_id, dst, sport, dport, count, size, rate, iface):
    addr = socket.gethostbyname(dst)
    payload = 'X' * size
    
    if rate > 0:
        total_size = 14 + 20 + 8 + size  
        bits_per_packet = total_size * 8
        target_bps = rate * 1_000_000  
        delay = bits_per_packet / target_bps
    else:
        delay = 0
    
    print(f"[Flow {flow_id}] Starting...")
    print(f"[Flow {flow_id}]   Destination: {addr}")
    print(f"[Flow {flow_id}]   Ports: {sport} -> {dport}")
    print(f"[Flow {flow_id}]   Target Rate: {rate if rate > 0 else 'unlimited'} Mbps")
    print(f"[Flow {flow_id}]   Packets: {count}, Size: {size} bytes")
    
    start_time = time.time()
    
    for i in range(count):
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr) / UDP(sport=sport, dport=dport) / payload
        
        sendp(pkt, iface=iface, verbose=False)
        
        if delay > 0:
            time.sleep(delay)
        
        if (i + 1) % 20 == 0:
            print(f"[Flow {flow_id}] Sent {i + 1}/{count} packets...")
    
    elapsed = time.time() - start_time
    actual_rate = (count * (14 + 20 + 8 + size) * 8) / elapsed / 1_000_000
    
    print(f"[Flow {flow_id}] COMPLETED")


def main():
    parser = argparse.ArgumentParser(description='Send 2 concurrent UDP flows')
    
    parser.add_argument('--dst', required=True, help='Destination IP')
    parser.add_argument('--count', type=int, default=100, help='Number of packets per flow')
    
    parser.add_argument('--sport1', type=int, default=5000, help='Flow 1 source port')
    parser.add_argument('--dport1', type=int, default=5001, help='Flow 1 destination port')
    parser.add_argument('--size1', type=int, default=1000, help='Flow 1 payload size in bytes')
    parser.add_argument('--rate1', type=float, default=0.5, help='Flow 1 rate in Mbps')
    
    parser.add_argument('--sport2', type=int, default=6000, help='Flow 2 source port')
    parser.add_argument('--dport2', type=int, default=6001, help='Flow 2 destination port')
    parser.add_argument('--size2', type=int, default=1000, help='Flow 2 payload size in bytes')
    parser.add_argument('--rate2', type=float, default=1.0, help='Flow 2 rate in Mbps')
    
    args = parser.parse_args()
    
    iface = get_if()
    
    print("=" * 70)
    print("SENDING 2 UDP FLOWS")
    print("=" * 70)
    print(f"Interface: {iface}")
    print(f"Destination: {args.dst}")
    print("-" * 70)
    
    thread1 = threading.Thread(
        target=send_flow,
        args=(1, args.dst, args.sport1, args.dport1, args.count, args.size1, args.rate1, iface)
    )
    
    thread2 = threading.Thread(
        target=send_flow,
        args=(2, args.dst, args.sport2, args.dport2, args.count, args.size2, args.rate2, iface)
    )
    
    start_time = time.time()
    thread1.start()
    thread2.start()
    
    thread1.join()
    thread2.join()
    
    total_elapsed = time.time() - start_time
    
    print("=" * 70)
    print(f"Both flows completed")
    print("=" * 70)


if __name__ == '__main__':
    main()
