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

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.1"
    src_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.50.2"
    num_connections = int(sys.argv[3]) if len(sys.argv) > 3 else 35000
    dst_port = 80
    start_port = 10000

    print(f"Pre-building {num_connections} TCP SYN & Data packets...")
    syn_packets = []
    data_packets = []
    payload = b"GET /index.html HTTP/1.1\r\nHost: 192.168.50.1\r\nUser-Agent: BenchClient\r\n\r\n"

    for i in range(num_connections):
        client_ip = socket.inet_ntoa(struct.pack('!I', (10 << 24) | (1 + i)))
        port = start_port + (i % 50000)
        syn_pkt = build_packet(client_ip, target_ip, port, dst_port, 1000, 0, 0x02, b"")
        data_pkt = build_packet(client_ip, target_ip, port, dst_port, 1001, 1, 0x18, payload)
        syn_packets.append(syn_pkt)
        data_packets.append(data_pkt)

    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    target_addr = (target_ip, 0)

    print(f"Opening {num_connections} TCP connections (SYN phase)...")
    for pkt in syn_packets:
        sender.sendto(pkt, target_addr)

    time.sleep(0.1)

    print(f"Streaming data continuously across all {num_connections} connections (Ctrl+C to stop)...")
    total_sent = 0
    start_time = time.time()
    last_print = start_time

    try:
        while True:
            for pkt in data_packets:
                sender.sendto(pkt, target_addr)
                total_sent += 1

            now = time.time()
            if now - last_print >= 1.0:
                elapsed = now - start_time
                pps = int(total_sent / elapsed)
                print(f"\r[Client] Transmitting across {num_connections} active streams | Speed: {pps} pps | Total: {total_sent} pkts", end="", flush=True)
                last_print = now
    except KeyboardInterrupt:
        print(f"\n[Client] Finished. Total data packets: {total_sent}")
    finally:
        sender.close()

if __name__ == "__main__":
    main()

