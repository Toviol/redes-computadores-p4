#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Script para enviar 1 fluxo UDP com taxa variável (mantendo mesma 5-tupla)
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


def send_variable_flow(dst, sport, dport, count1, size1, rate1, count2, size2, rate2, iface):
    addr = socket.gethostbyname(dst)
    
    print("=" * 70)
    print("SENDING VARIABLE RATE UDP FLOW")
    print("=" * 70)
    print(f"Interface: {iface}")
    print(f"Destination: {addr}")
    print(f"Source Port: {sport}")
    print(f"Destination Port: {dport}")
    print("-" * 70)
    
    print(f"\n[PHASE 1] Starting...")
    print(f"[PHASE 1]   Packets: {count1}")
    print(f"[PHASE 1]   Size: {size1} bytes")
    print(f"[PHASE 1]   Target Rate: {rate1} Mbps")
    
    payload1 = 'A' * size1
    total_size1 = 14 + 20 + 8 + size1  
    bits_per_packet1 = total_size1 * 8
    
    if rate1 > 0:
        target_bps1 = rate1 * 1_000_000
        delay1 = bits_per_packet1 / target_bps1
    else:
        delay1 = 0
    
    start_time = time.time()
    
    for i in range(count1):
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr) / UDP(sport=sport, dport=dport) / payload1
        
        sendp(pkt, iface=iface, verbose=False)
        
        if delay1 > 0:
            time.sleep(delay1)
        
        if (i + 1) % 20 == 0:
            print(f"[PHASE 1] Sent {i + 1}/{count1} packets...")
    
    phase1_elapsed = time.time() - start_time
    phase1_actual_rate = (count1 * total_size1 * 8) / phase1_elapsed / 1_000_000
    
    print(f"[PHASE 1] COMPLETED in {phase1_elapsed:.2f}s")
    
    print(f"\n[PHASE 2] Starting...")
    print(f"[PHASE 2]   Packets: {count2}")
    print(f"[PHASE 2]   Size: {size2} bytes")
    print(f"[PHASE 2]   Target Rate: {rate2} Mbps")
    
    payload2 = 'B' * size2
    total_size2 = 14 + 20 + 8 + size2
    bits_per_packet2 = total_size2 * 8
    
    if rate2 > 0:
        target_bps2 = rate2 * 1_000_000
        delay2 = bits_per_packet2 / target_bps2
    else:
        delay2 = 0
    
    phase2_start = time.time()
    
    for i in range(count2):
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr) / UDP(sport=sport, dport=dport) / payload2
        
        sendp(pkt, iface=iface, verbose=False)
        
        if delay2 > 0:
            time.sleep(delay2)
        
        if (i + 1) % 20 == 0:
            print(f"[PHASE 2] Sent {i + 1}/{count2} packets...")
    
    phase2_elapsed = time.time() - phase2_start
    phase2_actual_rate = (count2 * total_size2 * 8) / phase2_elapsed / 1_000_000
    
    print(f"[PHASE 2] COMPLETED")
    
    total_elapsed = time.time() - start_time
    total_packets = count1 + count2
    total_bytes = (count1 * total_size1) + (count2 * total_size2)
    total_bits = total_bytes * 8
    overall_rate = total_bits / total_elapsed / 1_000_000
    
    print("FLOW COMPLETED")

def main():
    parser = argparse.ArgumentParser(description='Send UDP flow with variable rate')
    
    parser.add_argument('--dst', required=True, help='Destination IP')
    parser.add_argument('--sport', type=int, default=5000, help='Source port (default: 5000)')
    parser.add_argument('--dport', type=int, default=5001, help='Destination port (default: 5001)')
    
    # Fase 1
    parser.add_argument('--count1', type=int, default=50, help='Phase 1: Number of packets (default: 50)')
    parser.add_argument('--size1', type=int, default=1000, help='Phase 1: Payload size in bytes (default: 1000)')
    parser.add_argument('--rate1', type=float, default=0.3, help='Phase 1: Rate in Mbps (default: 0.3)')
    
    # Fase 2
    parser.add_argument('--count2', type=int, default=50, help='Phase 2: Number of packets (default: 50)')
    parser.add_argument('--size2', type=int, default=1000, help='Phase 2: Payload size in bytes (default: 1000)')
    parser.add_argument('--rate2', type=float, default=0.8, help='Phase 2: Rate in Mbps (default: 0.8)')
    
    args = parser.parse_args()
    
    iface = get_if()
    
    send_variable_flow(
        args.dst,
        args.sport,
        args.dport,
        args.count1,
        args.size1,
        args.rate1,
        args.count2,
        args.size2,
        args.rate2,
        iface
    )


if __name__ == '__main__':
    main()
