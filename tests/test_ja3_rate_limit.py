#!/usr/bin/env python3
"""
Aethon IPS - JA3 Fingerprint Rate Limiting Test Suite
Tests rate-limiting of TLS ClientHello connections based on JA3 fingerprint.
Uses raw TCP injection (same method as test_tls_sni.py, test_dpi_scanner.py).
"""

import sys
import os
import socket
import struct
import time
import random

def checksum(data):
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def build_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
    offset_res = (5 << 4)
    window = 8192
    urg_ptr = 0

    tcp_hdr_dummy = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, offset_res, flags, window, 0, urg_ptr)
    pseudo = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, socket.IPPROTO_TCP, len(tcp_hdr_dummy) + len(payload))
    tcp_chk = checksum(pseudo + tcp_hdr_dummy + payload)
    tcp_hdr = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, offset_res, flags, window, tcp_chk, urg_ptr)

    tot_len = 20 + len(tcp_hdr) + len(payload)
    ip_hdr_dummy = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot_len, 54321, 0, 64, socket.IPPROTO_TCP, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_chk = checksum(ip_hdr_dummy)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot_len, 54321, 0, 64, socket.IPPROTO_TCP, ip_chk, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

    return ip_hdr + tcp_hdr + payload

def build_tls_client_hello(domain_str, ciphers=None):
    """
    Builds a TLS 1.2 ClientHello with a specific set of ciphers and extensions
    to create a deterministic JA3 fingerprint.
    """
    sni_bytes = domain_str.encode('ascii')
    sni_entry = struct.pack('!BH', 0x00, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('!HH', 0x0000, len(sni_list)) + sni_list

    # Supported groups (0x000a): x25519 (0x001d), secp256r1 (0x0017)
    groups = struct.pack('!HH', 0x001d, 0x0017)
    groups_ext = struct.pack('!HHH', 0x000a, len(groups) + 2, len(groups)) + groups

    # EC Point Formats (0x000b): uncompressed (0x00)
    ec_formats = struct.pack('!B', 0x00)
    ec_ext = struct.pack('!HHBB', 0x000b, len(ec_formats) + 1, len(ec_formats), 0x00)

    extensions_data = sni_ext + groups_ext + ec_ext
    extensions = struct.pack('!H', len(extensions_data)) + extensions_data

    client_version = struct.pack('!H', 0x0303)  # TLS 1.2
    random_bytes = os.urandom(32)
    session_id = b'\x00'

    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0x1303]

    ciphers_data = b"".join(struct.pack('!H', c) for c in ciphers)
    cipher_suites = struct.pack('!H', len(ciphers_data)) + ciphers_data
    compression = struct.pack('!BB', 1, 0x00)

    ch_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions
    ch_len = len(ch_body)

    hs_header = struct.pack('!B', 0x01) + struct.pack('!I', ch_len)[1:]
    hs_record = hs_header + ch_body

    record_header = struct.pack('!BHH', 0x16, 0x0301, len(hs_record))
    return record_header + hs_record

def send_client_hello(target_ip, src_ip, dst_port, src_port, payload):
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    init_seq = random.randint(1000, 50000)

    # 1. Send TCP SYN
    syn_pkt = build_packet(src_ip, target_ip, src_port, dst_port, init_seq, 0, 0x02, b"")
    sender.sendto(syn_pkt, (target_ip, 0))
    time.sleep(0.01)

    # 2. Send TCP PSH-ACK with TLS ClientHello payload
    data_pkt = build_packet(src_ip, target_ip, src_port, dst_port, init_seq + 1, 1, 0x18, payload)
    sender.sendto(data_pkt, (target_ip, 0))
    sender.close()

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.1"
    src_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.50.2"
    iface = sys.argv[3] if len(sys.argv) > 3 else "veth1"
    domain = sys.argv[4] if len(sys.argv) > 4 else "mydomain.com"

    # Drop kernel RSTs from disrupting raw TCP sessions inside namespace
    os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null")

    try:
        print("==========================================================")
        print("      AETHON JA3 FINGERPRINT RATE LIMITING TEST           ")
        print("==========================================================")
        print(f"Target       : {target_ip}:443")
        print(f"Source IP    : {src_ip}")
        print(f"Interface    : {iface}")
        print(f"SNI Domain   : {domain}")
        print(f"Rate Window  : 10 seconds")
        print(f"Rate Limit   : 10 connections / JA3")
        print("==========================================================")

        # JA3 Profile 1: Ciphers 0x1301, 0x1302, 0x1303 (e.g. Modern Chrome / Bot A)
        ciphers_profile_1 = [0x1301, 0x1302, 0x1303]
        ch_payload_1 = build_tls_client_hello(domain, ciphers_profile_1)

        # JA3 Profile 2: Ciphers 0xC02F, 0xC030 (e.g. Legacy Client / Bot B)
        ciphers_profile_2 = [0xC02F, 0xC030]
        ch_payload_2 = build_tls_client_hello(domain, ciphers_profile_2)

        base_port = 40000

        print("\n[PHASE 1] Sending 10 ClientHellos with JA3 Profile 1 (Within Quota)...")
        for i in range(1, 11):
            src_port = base_port + i
            send_client_hello(target_ip, src_ip, 443, src_port, ch_payload_1)
            print(f"  -> Packet {i}/10 sent (port {src_port}) - EXPECTED: ALLOWED")
            time.sleep(0.05)

        print("\n[PHASE 2] Sending 5 MORE ClientHellos with JA3 Profile 1 (Exceeding Limit)...")
        for i in range(11, 16):
            src_port = base_port + i
            send_client_hello(target_ip, src_ip, 443, src_port, ch_payload_1)
            print(f"  -> Packet {i} sent (port {src_port}) - EXPECTED: DROPPED ([IPS RATE-LIMIT])")
            time.sleep(0.05)

        print("\n[PHASE 3] Testing Fingerprint Isolation (JA3 Profile 2)...")
        print("  Sending ClientHello with DIFFERENT ciphers (distinct JA3 fingerprint)...")
        src_port_diff = base_port + 99
        send_client_hello(target_ip, src_ip, 443, src_port_diff, ch_payload_2)
        print(f"  -> Packet sent (port {src_port_diff}) - EXPECTED: ALLOWED (Has separate token quota)")

        print("\n----------------------------------------------------------")
        print("Check the Aethon afxdp_control console output:")
        print("  - First 10 connections: Processed normally")
        print("  - Next 5 connections: Dropped with '[IPS RATE-LIMIT]' alert")
        print("  - Distinct JA3 connection: Allowed through")
        print("----------------------------------------------------------")

        if "--wait-window" in sys.argv:
            print("\n[PHASE 4] Waiting 10 seconds for rate limit window to expire...")
            for remaining in range(10, 0, -1):
                sys.stdout.write(f"\r  Cooldown: {remaining}s remaining... ")
                sys.stdout.flush()
                time.sleep(1)
            print("\r  Cooldown complete!                             ")

            src_port_reset = base_port + 200
            send_client_hello(target_ip, src_ip, 443, src_port_reset, ch_payload_1)
            print(f"  -> Sent ClientHello (port {src_port_reset}) after window reset - EXPECTED: ALLOWED")

        print("\n[+] Test complete.")
    finally:
        os.system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null")

if __name__ == "__main__":
    main()
