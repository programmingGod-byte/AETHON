import sys
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

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.1"
    src_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.50.2"
    iface = sys.argv[3] if len(sys.argv) > 3 else "veth1"
    src_port = int(sys.argv[4]) if len(sys.argv) > 4 else random.randint(30000, 60000)
    dst_port = 3306

    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sniffer.bind((iface, 0))
    sniffer.settimeout(3.0)

    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    init_seq = random.randint(1000, 50000)
    syn_pkt = build_packet(src_ip, target_ip, src_port, dst_port, init_seq, 0, 0x02, b"")
    sender.sendto(syn_pkt, (target_ip, 0))
    time.sleep(0.01)

    malicious_payload = b"SELECT user,password from mysql.user;"
    data_pkt = build_packet(src_ip, target_ip, src_port, dst_port, init_seq + 1, 1, 0x18, malicious_payload)
    sender.sendto(data_pkt, (target_ip, 0))
    sender.close()

    print(f"[*] Injected exploit TCP payload ({len(malicious_payload)} bytes) to {target_ip}:{dst_port}")
    print(f"[*] Sniffing on interface '{iface}' for TCP RST response from Aethon IPS...")

    start_time = time.time()
    rst_captured = False

    while time.time() - start_time < 3.0:
        try:
            raw_frame, _ = sniffer.recvfrom(2048)
            if len(raw_frame) < 54:
                continue

            eth_dst = ":".join(f"{b:02x}" for b in raw_frame[0:6])
            eth_src = ":".join(f"{b:02x}" for b in raw_frame[6:12])
            eth_type = struct.unpack("!H", raw_frame[12:14])[0]
            if eth_type != 0x0800:
                continue

            iph = raw_frame[14:34]
            ip_proto = iph[9]
            if ip_proto != socket.IPPROTO_TCP:
                continue

            ip_saddr = socket.inet_ntoa(iph[12:16])
            ip_daddr = socket.inet_ntoa(iph[16:20])

            tcph = raw_frame[34:54]
            t_src_port, t_dst_port, seq, ack_seq, offset_res, flags = struct.unpack("!HHIIBB", tcph[:14])

            if t_src_port == dst_port and t_dst_port == src_port and (flags & 0x04) != 0:
                rst_captured = True
                print("\n" + "=" * 60)
                print("[+] SUCCESS: TCP RST PACKET CAPTURED FROM AETHON IPS!")
                print("=" * 60)
                print(f"Ethernet Layer : {eth_src} -> {eth_dst}")
                print(f"IP Layer       : {ip_saddr} -> {ip_daddr}")
                print(f"TCP Ports      : {t_src_port} -> {t_dst_port}")
                print(f"TCP Flags      : 0x{flags:02x} (RST={1 if flags & 0x04 else 0}, ACK={1 if flags & 0x10 else 0})")
                print(f"Sequence No    : {seq}")
                print(f"Ack Number     : {ack_seq}")
                print(f"Frame Length   : {len(raw_frame)} bytes")
                print("-" * 60)
                print("Hex Dump of Captured RST Packet:")
                hex_dump = " ".join(f"{b:02x}" for b in raw_frame)
                print(hex_dump)
                print("=" * 60)

                with open("captured_rst.bin", "wb") as f:
                    f.write(raw_frame)

                with open("captured_rst.txt", "w") as f:
                    f.write(f"Ethernet: {eth_src} -> {eth_dst}\n")
                    f.write(f"IP: {ip_saddr} -> {ip_daddr}\n")
                    f.write(f"TCP: {t_src_port} -> {t_dst_port}\n")
                    f.write(f"Flags: 0x{flags:02x}\n")
                    f.write(f"Seq: {seq}\n")
                    f.write(f"Ack: {ack_seq}\n")
                    f.write(f"Hex: {hex_dump}\n")

                print("[+] Saved binary packet to: captured_rst.bin")
                print("[+] Saved formatted details to: captured_rst.txt\n")
                break
        except socket.timeout:
            break

    sniffer.close()

    if not rst_captured:
        print("[-] TIMEOUT: No TCP RST packet received within 2.5 seconds.")
        sys.exit(1)

if __name__ == "__main__":
    main()

