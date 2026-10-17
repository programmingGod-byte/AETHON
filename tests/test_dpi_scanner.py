import sys
import socket
import struct
import time

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

def send_raw_tcp(src_ip, dst_ip, src_port, dst_port, payload, test_name):
    print(f"[*] Running: {test_name}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        syn_pkt = build_packet(src_ip, dst_ip, src_port, dst_port, 1000, 0, 0x02, b"")
        s.sendto(syn_pkt, (dst_ip, 0))
        time.sleep(0.01)

        data_pkt = build_packet(src_ip, dst_ip, src_port, dst_port, 1001, 1, 0x18, payload)
        s.sendto(data_pkt, (dst_ip, 0))

        s.close()
        print(f"[+] Injected raw TCP session + payload ({len(payload)} bytes) -> {dst_ip}:{dst_port}")
    except Exception as e:
        print(f"[-] Raw TCP injection failed: {e}")

def send_udp(target_ip, port, payload, test_name):
    print(f"[*] Running: {test_name}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, (target_ip, port))
        s.close()
        print(f"[+] Sent UDP packet ({len(payload)} bytes) -> {target_ip}:{port}")
    except Exception as e:
        print(f"[-] UDP send failed: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 test_dpi_scanner.py <target_ip> [src_ip] [tcp_port] [udp_port]")
        sys.exit(1)

    target_ip = sys.argv[1]
    src_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.50.2"
    tcp_port = int(sys.argv[3]) if len(sys.argv) > 3 else 3306
    udp_port = int(sys.argv[4]) if len(sys.argv) > 4 else 1434

    print(f"=== Testing DPI Scanner against {target_ip} (from {src_ip}) ===\n")

    clean_tcp = b"SELECT id, username, email FROM app_users WHERE active = 1;"
    send_raw_tcp(src_ip, target_ip, 50001, tcp_port, clean_tcp, "Test 1: Clean TCP SQL Query")
    time.sleep(0.5)

    attack_tcp = b"SELECT user,password from mysql.user;"
    send_raw_tcp(src_ip, target_ip, 50002, tcp_port, attack_tcp, "Test 2: Malicious TCP Payload (SID: 2014910 MySQL Dump)")
    time.sleep(0.5)

    cmdshell_tcp = b"prefix x\x00p\x00_\x00c\x00m\x00d\x00s\x00h\x00e\x00l\x00l\x00 suffix"
    send_raw_tcp(src_ip, target_ip, 50003, 139, cmdshell_tcp, "Test 3: Malicious TCP Payload (SID: 2100681 xp_cmdshell)")
    time.sleep(0.5)

    clean_udp = b"PING normal UDP health check packet"
    send_udp(target_ip, udp_port, clean_udp, "Test 4: Clean UDP Datagram")
    time.sleep(0.5)

    slammer_udp = b"\x04" + b"0123456789" + b"\x81\xf1\x03\x01\x04\x9b\x81\xf1\x01" + b"sock" + b"send"
    send_udp(target_ip, udp_port, slammer_udp, "Test 5: Malicious UDP Payload (SID: 2102003 Slammer Worm)")

    print("\n=== Test Injections Complete ===")
    print("Check your Aethon engine terminal output for [IPS BLOCK] and [ALERT] logs.")

if __name__ == "__main__":
    main()
