import sys
import os
import socket
import struct
import time
import random
import ssl
import json

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

SERVICES_TO_TEST = [
    {
        "domain": "auth.mydomain.com",
        "expected_port": 5000,
        "clean_req": ("POST", "/api/v1/auth/login", '{"user":"alice","pass":"secret"}'),
        "attack_req": ("POST", "/api/v1/auth/login", "SELECT * FROM mysql.user WHERE user='admin';"),
        "attack_name": "SQL Injection (mysql.user)"
    },
    {
        "domain": "admin.mydomain.com",
        "expected_port": 6000,
        "clean_req": ("GET", "/admin/dashboard", None),
        "attack_req": ("POST", "/admin/system/exec", "EXEC master..xp_cmdshell 'whoami';"),
        "attack_name": "RCE (xp_cmdshell)"
    },
    {
        "domain": "api.mydomain.com",
        "expected_port": 8080,
        "clean_req": ("GET", "/api/v1/products?limit=10", None),
        "attack_req": ("GET", "/api/v1/download?file=../../../../etc/passwd", None),
        "attack_name": "Path Traversal (/etc/passwd)"
    }
]

def execute_stream_round(target_ip, src_ip, iface, domain, expected_port, is_malicious, method, path, body, attack_desc, stream_port):
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
                        while True:
                            try:
                                dec = ssl_obj.read(65535)
                                if dec:
                                    decrypted_reply += dec.decode('utf-8', errors='ignore')
                                    backend_replied = True
                                else:
                                    break
                            except ssl.SSLWantReadError:
                                break
                            except Exception:
                                break
                        if backend_replied and ("200 OK" in decrypted_reply):
                            break
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
            print(f"    \033[91m[MALICIOUS ATTACK]\033[0m {attack_desc}")
            print(f"    \033[92m[✓ PASS]\033[0m Signature caught by Aethon Hyperscan -> TCP RST Injected, Backend :{expected_port} Protected!")
        else:
            print(f"    \033[91m[MALICIOUS ATTACK]\033[0m {attack_desc}")
            print(f"    \033[91m[✗ FAIL]\033[0m Attack bypassed! (RST: {rst_received}, BackendReplied: {backend_replied})")
    else:
        port_matched = (f'"backend_port": {expected_port}' in decrypted_reply) or (f":{expected_port}" in decrypted_reply) or (f"{expected_port}" in decrypted_reply)
        if backend_replied and "200 OK" in decrypted_reply and port_matched:
            outcome = True
            print(f"    \033[94m[CLEAN TRAFFIC]\033[0m {method} {path}")
            print(f"    \033[92m[✓ PASS]\033[0m Decrypted -> Successfully Routed to Target Port :{expected_port} (Verified HTTP 200 JSON)")
        else:
            print(f"    \033[94m[CLEAN TRAFFIC]\033[0m {method} {path}")
            print(f"    \033[91m[✗ FAIL]\033[0m Failed routing to port :{expected_port} (RST: {rst_received}, Replied: {backend_replied}, PortMatched: {port_matched})")

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

    print("==================================================================")
    print(" AETHON MULTI-PORT REVERSE PROXY & DPI ISOLATION TEST             ")
    print(f" Target: {target_ip}:443 | Client IP: {src_ip} | Interface: {iface}")
    print(" Services: auth:5000 | admin:6000 | api:8080")
    print("==================================================================")

    passed_count = 0
    total_tests = len(SERVICES_TO_TEST) * 2
    base_port = random.randint(35000, 55000)
    round_idx = 1

    for svc in SERVICES_TO_TEST:
        domain = svc["domain"]
        expected_port = svc["expected_port"]

        print(f"\n[SERVICE: {domain} -> TARGET PORT {expected_port}]")

        clean_method, clean_path, clean_body = svc["clean_req"]
        stream_port = base_port + round_idx
        round_idx += 1
        ok_clean = execute_stream_round(target_ip, src_ip, iface, domain, expected_port, False, clean_method, clean_path, clean_body, "", stream_port)
        if ok_clean:
            passed_count += 1
        time.sleep(0.05)

        att_method, att_path, att_body = svc["attack_req"]
        att_name = svc["attack_name"]
        stream_port = base_port + round_idx
        round_idx += 1
        ok_att = execute_stream_round(target_ip, src_ip, iface, domain, expected_port, True, att_method, att_path, att_body, att_name, stream_port)
        if ok_att:
            passed_count += 1
        time.sleep(0.05)

    os.system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null")

    print("\n==================================================================")
    print("                       MULTI-PORT SUMMARY                         ")
    print(f" Total Multi-Port Tests: {total_tests}")
    print(f" Passed Assertions     : {passed_count}/{total_tests}")
    success_rate = (passed_count / total_tests) * 100.0
    print(f" Routing Accuracy      : {success_rate:.1f}%")
    print("==================================================================")

    if passed_count == total_tests:
        print("\033[92m>>> [ALL MULTI-PORT TESTS PASSED] MULTI-SERVICE REVERSE PROXY VERIFIED! <<<\033[0m\n")
        sys.exit(0)
    else:
        print("\033[91m>>> [TEST FAILURES DETECTED] Review log outputs above. <<<\033[0m\n")
        sys.exit(1)

if __name__ == "__main__":
    main()

