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

def build_tls_client_hello(domain_str):
    sni_bytes = domain_str.encode('ascii')
    sni_entry = struct.pack('!BH', 0x00, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('!HH', 0x0000, len(sni_list)) + sni_list

    client_version = struct.pack('!H', 0x0303)
    random_bytes = os.urandom(32)
    session_id = b'\x00'
    cipher_suites = struct.pack('!HH', 2, 0x1301)
    compression = struct.pack('!BB', 1, 0x00)
    extensions = struct.pack('!H', len(sni_ext)) + sni_ext

    ch_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions
    ch_len = len(ch_body)

    hs_header = struct.pack('!B', 0x01) + struct.pack('!I', ch_len)[1:]
    hs_record = hs_header + ch_body

    record_header = struct.pack('!BHH', 0x16, 0x0301, len(hs_record))
    return record_header + hs_record

def test_sni_connection(target_ip, src_ip, iface, domain, should_block):
    src_port = random.randint(30000, 60000)
    dst_port = 443

    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sniffer.bind((iface, 0))
    sniffer.settimeout(2.0)

    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    init_seq = random.randint(1000, 50000)
    syn_pkt = build_packet(src_ip, target_ip, src_port, dst_port, init_seq, 0, 0x02, b"")
    sender.sendto(syn_pkt, (target_ip, 0))
    time.sleep(0.01)

    tls_payload = build_tls_client_hello(domain)
    data_pkt = build_packet(src_ip, target_ip, src_port, dst_port, init_seq + 1, 1, 0x18, tls_payload)
    sender.sendto(data_pkt, (target_ip, 0))
    sender.close()

    print(f"\n[*] Sent TLS ClientHello with SNI: '{domain}' to {target_ip}:{dst_port}")

    start_time = time.time()
    rst_captured = False

    while time.time() - start_time < 2.0:
        try:
            raw_frame, _ = sniffer.recvfrom(2048)
            if len(raw_frame) < 54:
                continue

            eth_type = struct.unpack("!H", raw_frame[12:14])[0]
            if eth_type != 0x0800:
                continue

            iph = raw_frame[14:34]
            if iph[9] != socket.IPPROTO_TCP:
                continue

            ip_saddr = socket.inet_ntoa(iph[12:16])
            ip_daddr = socket.inet_ntoa(iph[16:20])

            tcph = raw_frame[34:54]
            t_src_port, t_dst_port, seq, ack_seq, offset_res, flags = struct.unpack("!HHIIBB", tcph[:14])

            if t_src_port == dst_port and t_dst_port == src_port and (flags & 0x04) != 0:
                rst_captured = True
                print(f"[+] SUCCESS: TCP RST captured from Aethon IPS for blocked domain '{domain}'!")
                print(f"    From: {ip_saddr}:{t_src_port} -> To: {ip_daddr}:{t_dst_port}")
                print(f"    Flags: 0x{flags:02x} (RST bit set)")
                break
        except socket.timeout:
            break

    sniffer.close()

    if should_block and not rst_captured:
        print(f"[-] FAILED: Expected TCP RST for malicious domain '{domain}', but none received.")
        return False
    elif not should_block and rst_captured:
        print(f"[-] FAILED: Clean domain '{domain}' was unexpectedly blocked with TCP RST!")
        return False
    elif not should_block and not rst_captured:
        print(f"[+] SUCCESS: Clean domain '{domain}' passed through without RST (Fast-Patched).")
        return True

    return True

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.1"
    src_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.50.2"
    iface = sys.argv[3] if len(sys.argv) > 3 else "veth1"

    print("==========================================================")
    print("      AETHON TLS SNI DOMAIN BLOCKING TEST SUITE           ")
    print("==========================================================")
    print(f"Target   : {target_ip}")
    print(f"Source   : {src_ip}")
    print(f"Interface: {iface}")
    print("==========================================================")

    print("\n--- TEST 1: Unauthorized Domain 'c2-beacon.attacker.com' (Should Trigger TCP RST) ---")
    res1 = test_sni_connection(target_ip, src_ip, iface, "c2-beacon.attacker.com", should_block=True)

    time.sleep(0.5)

    print("\n--- TEST 2: Authorized Domain 'mydomain.com' (Should Pass Freely) ---")
    res2 = test_sni_connection(target_ip, src_ip, iface, "mydomain.com", should_block=False)

    time.sleep(0.5)

    print("\n--- TEST 3: Authorized Subdomain 'api.mydomain.com' (Should Pass Freely) ---")
    res3 = test_sni_connection(target_ip, src_ip, iface, "api.mydomain.com", should_block=False)

    if res1 and res2 and res3:
        print("\n==========================================================")
        print("    ALL STRICT ALLOWLIST & FAST-PATH TESTS PASSED!       ")
        print("==========================================================")
        sys.exit(0)
    else:
        print("\n[-] Some tests failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()

