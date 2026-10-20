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

CLEAN_TEMPLATES = [
    ("GET", "/api/v1/users", None),
    ("GET", "/products/catalog?category=networking", None),
    ("GET", "/dashboard/stats", None),
    ("POST", "/api/v1/login", '{"username":"dev_user","auth":"token_abc123"}'),
    ("POST", "/api/v1/telemetry", '{"metric":"cpu_load","value":42.5}'),
    ("GET", "/static/images/logo.png", None)
]

MALICIOUS_TEMPLATES = [
    ("GET", "/etc/passwd", None, "LFI (/etc/passwd)"),
    ("GET", "/download?file=../../../../etc/passwd", None, "Path Traversal (/etc/passwd)"),
    ("POST", "/admin/db/query", "SELECT user, password FROM mysql.user WHERE 1=1;", "SQL Dump (mysql.user)"),
    ("POST", "/system/cmd", "EXEC master..xp_cmdshell 'dir c:\\';", "Command Injection (xp_cmdshell)")
]

def execute_stream_test(target_ip, src_ip, iface, domain, is_malicious, method, path, body, desc="", stream_port=45000):
    src_port = stream_port
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

    if body:
        http_req = f"{method} {path} HTTP/1.1\r\nHost: {domain}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    else:
        http_req = f"{method} {path} HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Aethon-Tester\r\nAccept: */*\r\n\r\n"

    start_time = time.time()
    handshake_done = False

    while time.time() - start_time < 3.0:
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
                tcp_hdr_len = ((offset_res >> 4) & 0x0F) * 4
                server_payload = frame[34 + tcp_hdr_len:]

                if len(server_payload) > 0:
                    in_bio.write(server_payload)
                    ack = s_seq + len(server_payload)

                    hs_ok = False
                    try:
                        ssl_obj.do_handshake()
                        hs_ok = True
                    except ssl.SSLWantReadError:
                        pass
                    except Exception:
                        pass

                    cli_reply = out_bio.read()
                    if len(cli_reply) > 0:
                        reply_pkt = build_packet(src_ip, target_ip, src_port, dst_port, seq, ack, 0x18, cli_reply)
                        sender.sendto(reply_pkt, (target_ip, 0))
                        seq += len(cli_reply)

                    if hs_ok:
                        handshake_done = True
                        break
        except socket.timeout:
            break

    rst_received = False
    backend_replied = False
    decrypted_reply = ""

    if handshake_done:
        time.sleep(0.02)
        try:
            ssl_obj.write(http_req.encode('utf-8'))
            enc_data = out_bio.read()
            if len(enc_data) > 0:
                req_pkt = build_packet(src_ip, target_ip, src_port, dst_port, seq, ack, 0x18, enc_data)
                sender.sendto(req_pkt, (target_ip, 0))
        except Exception:
            pass

        resp_start = time.time()
        while time.time() - resp_start < 3.0:
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
                        rst_received = True
                        break

                    tcp_hdr_len = ((offset_res >> 4) & 0x0F) * 4
                    server_payload = frame[34 + tcp_hdr_len:]
                    if len(server_payload) > 0:
                        in_bio.write(server_payload)
                        try:
                            dec = ssl_obj.read(65535)
                            if dec:
                                decrypted_reply += dec.decode('utf-8', errors='ignore')
                                backend_replied = True
                                break
                        except ssl.SSLWantReadError:
                            pass
                        except Exception:
                            pass
            except socket.timeout:
                break

    try:
        cleanup_rst = build_packet(src_ip, target_ip, src_port, dst_port, seq, 0, 0x04, b"")
        sender.sendto(cleanup_rst, (target_ip, 0))
    except Exception:
        pass

    sender.close()
    sniffer.close()

    outcome = False
    if is_malicious:
        if rst_received and not backend_replied:
            outcome = True
            print(f"  \033[91m[MALICIOUS ATTACK]\033[0m {desc}")
            print(f"  \033[92m[✓ PASS]\033[0m Aethon Hyperscan DPI caught signature -> TCP RST Injected, Backend Protected!")
        else:
            print(f"  \033[91m[MALICIOUS ATTACK]\033[0m {desc}")
            print(f"  \033[91m[✗ FAIL]\033[0m Attack bypassed DPI! (RST: {rst_received}, BackendReplied: {backend_replied})")
    else:
        if backend_replied and "200 OK" in decrypted_reply:
            outcome = True
            status_line = decrypted_reply.splitlines()[0] if decrypted_reply else ""
            print(f"  \033[94m[CLEAN TRAFFIC]\033[0m {method} {path}")
            print(f"  \033[92m[✓ PASS]\033[0m Clean TLS decrypted -> Forwarded to Backend -> Received: '{status_line}'")
        else:
            print(f"  \033[94m[CLEAN TRAFFIC]\033[0m {method} {path}")
            print(f"  \033[91m[✗ FAIL]\033[0m Clean traffic failed (RST: {rst_received}, BackendReplied: {backend_replied})")

    return outcome

def main():
    try:
        os.sched_setaffinity(0, {0})
    except Exception:
        pass

    os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null")

    target_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.1"
    src_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.50.2"
    iface = sys.argv[3] if len(sys.argv) > 3 else "veth1"
    domain = sys.argv[4] if len(sys.argv) > 4 else "mydomain.com"
    num_rounds = int(sys.argv[5]) if len(sys.argv) > 5 else 8

    print("==================================================================")
    print(" AETHON FULL FUNCTIONAL TEST: TLS DECRYPTION, DPI & BACKEND PROXY ")
    print(f" Target: {target_ip}:443 | SNI Domain: {domain}")
    print(f" Interface: {iface} | Client IP: {src_ip} | Rounds: {num_rounds}")
    print("==================================================================")

    passed_count = 0
    base_port = random.randint(35000, 55000)

    for i in range(1, num_rounds + 1):
        print(f"\n--- [Round {i}/{num_rounds}] ---")
        send_malicious = (random.random() < 0.45)
        current_port = base_port + i

        if send_malicious:
            template = random.choice(MALICIOUS_TEMPLATES)
            method, path, body, desc = template
            ok = execute_stream_test(target_ip, src_ip, iface, domain, True, method, path, body, desc, current_port)
        else:
            template = random.choice(CLEAN_TEMPLATES)
            method, path, body = template
            ok = execute_stream_test(target_ip, src_ip, iface, domain, False, method, path, body, "", current_port)

        if ok:
            passed_count += 1
        time.sleep(0.05)

    os.system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null")

    print("\n==================================================================")
    print("                         TEST SUMMARY                             ")
    print(f" Total Rounds Executed : {num_rounds}")
    print(f" Passed Assertions     : {passed_count}/{num_rounds}")
    success_rate = (passed_count / num_rounds) * 100.0
    print(f" Accuracy / Pass Rate  : {success_rate:.1f}%")
    print("==================================================================")

    if passed_count == num_rounds:
        print("\033[92m>>> [ALL TESTS PASSED] FULL FUNCTIONAL PIPELINE VERIFIED! <<<\033[0m\n")
        sys.exit(0)
    else:
        print("\033[91m>>> [TEST FAILURES DETECTED] Review log outputs above. <<<\033[0m\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
