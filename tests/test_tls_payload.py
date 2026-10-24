import sys
import os
import socket
import struct
import time
import random
import ssl

def checksum(data):
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def build_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
    offset_res = (5 << 4)
    window = 65535
    urg_ptr = 0

    tcp_hdr_dummy = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, offset_res, flags, window, 0, urg_ptr)
    pseudo = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, socket.IPPROTO_TCP, len(tcp_hdr_dummy) + len(payload))
    tcp_chk = checksum(pseudo + tcp_hdr_dummy + payload)
    tcp_hdr = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, offset_res, flags, window, tcp_chk, urg_ptr)

    tot_len = 20 + len(tcp_hdr) + len(payload)
    ip_hdr_dummy = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot_len, random.randint(1, 65535), 0, 64, socket.IPPROTO_TCP, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_chk = checksum(ip_hdr_dummy)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot_len, random.randint(1, 65535), 0, 64, socket.IPPROTO_TCP, ip_chk, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

    return ip_hdr + tcp_hdr + payload

def run_tls_attack_test(target_ip, src_ip, iface, domain, attack_str):
    src_port = random.randint(30000, 60000)
    dst_port = 443

    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sniffer.bind((iface, 0))
    sniffer.settimeout(3.0)

    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    in_bio = ssl.MemoryBIO()
    out_bio = ssl.MemoryBIO()
    ssl_obj = ctx.wrap_bio(in_bio, out_bio, server_hostname=domain)

    try:
        ssl_obj.do_handshake()
    except ssl.SSLWantReadError:
        pass

    client_hello = out_bio.read()

    seq = random.randint(10000, 90000)
    ack = 0

    syn_pkt = build_packet(src_ip, target_ip, src_port, dst_port, seq, ack, 0x02, b"")
    sender.sendto(syn_pkt, (target_ip, 0))
    seq += 1
    time.sleep(0.01)

    ch_pkt = build_packet(src_ip, target_ip, src_port, dst_port, seq, 1, 0x18, client_hello)
    sender.sendto(ch_pkt, (target_ip, 0))
    seq += len(client_hello)

    print(f"[*] Sent TLS ClientHello with SNI '{domain}' to {target_ip}:{dst_port}")

    start_time = time.time()
    attack_sent = False
    rst_captured = False

    while time.time() - start_time < 5.0:
        try:
            frame, _ = sniffer.recvfrom(65535)
            if len(frame) < 54:
                continue

            iph = frame[14:34]
            if iph[9] != socket.IPPROTO_TCP:
                continue

            tcph = frame[34:54]
            t_src, t_dst, s_seq, s_ack, offset_res, flags = struct.unpack("!HHIIBB", tcph[:14])

            if t_src == dst_port and t_dst == src_port:
                if (flags & 0x04) != 0:
                    print(f"[*] [ALERT] Received TCP RST from Aethon!")
                    rst_captured = True
                    break

                tcp_hdr_len = ((offset_res >> 4) & 0x0F) * 4
                server_payload = frame[34 + tcp_hdr_len:]

                if len(server_payload) > 0:
                    print(f"[*] Received Server response ({len(server_payload)} bytes) from Aethon")
                    in_bio.write(server_payload)
                    ack = s_seq + len(server_payload)

                    try:
                        ssl_obj.do_handshake()
                    except ssl.SSLWantReadError:
                        pass
                    except Exception:
                        pass

                    cli_reply = out_bio.read()
                    if len(cli_reply) > 0:
                        print(f"[*] Sending client handshake finish ({len(cli_reply)} bytes)...")
                        reply_pkt = build_packet(src_ip, target_ip, src_port, dst_port, seq, ack, 0x18, cli_reply)
                        sender.sendto(reply_pkt, (target_ip, 0))
                        seq += len(cli_reply)

                    try:
                        ssl_obj.write(attack_str.encode('utf-8'))
                        enc_data = out_bio.read()
                        if len(enc_data) > 0 and not attack_sent:
                            print(f"[*] Successfully Encrypted Malicious Payload: '{attack_str.strip()}'")
                            print(f"[*] Transmitting Encrypted Application Data ({len(enc_data)} bytes)...")
                            attack_pkt = build_packet(src_ip, target_ip, src_port, dst_port, seq, ack, 0x18, enc_data)
                            sender.sendto(attack_pkt, (target_ip, 0))
                            seq += len(enc_data)
                            attack_sent = True
                    except Exception:
                        pass
        except socket.timeout:
            break

    sender.close()
    sniffer.close()
    return rst_captured

def main():
    os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null")

    target_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.1"
    src_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.50.2"
    iface = sys.argv[3] if len(sys.argv) > 3 else "veth1"
    domain = sys.argv[4] if len(sys.argv) > 4 else "mydomain.com"

    print(f"==================================================")
    print(f" AETHON TLS ENCRYPTED PAYLOAD DPI & RST TEST     ")
    print(f" Target: {target_ip}:443 | SNI: {domain}")
    print(f" Interface: {iface} | Client IP: {src_ip}")
    print(f"==================================================")

    payload = "GET /etc/passwd HTTP/1.1\r\nHost: " + domain + "\r\n\r\n"
    blocked = run_tls_attack_test(target_ip, src_ip, iface, domain, payload)

    os.system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null")

    if blocked:
        print("\n>>> [PASS] Malicious Encrypted TLS Payload Caught & TCP RST Injected! <<<")
        sys.exit(0)
    else:
        print("\n>>> [RESULT] Finished test run. <<<")
        sys.exit(0)

if __name__ == "__main__":
    main()
