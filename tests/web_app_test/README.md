# Web app end-to-end test

A real web stack behind Aethon, so you can test with real clients (curl, wrk, a browser) instead of hand-crafted packets.

```
client_ns 192.168.50.2 ──veth1══veth0── 192.168.50.1
                                          │ XDP: managed TCP ports → AF_XDP
                                          ▼
                                       Aethon ──▶ nginx 127.0.0.1:8080 ──▶ static web app + /files/*.bin
                                                                     └──▶ /api/* → Node.js 127.0.0.1:3000
```

nginx and Node listen on **127.0.0.1 only**, so from `client_ns` the only way in is through Aethon.

## Requirements
- Node.js ≥ 18 (no npm packages needed)
- `sudo apt install -y nginx wrk ethtool`
- Aethon built: `cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j`
- `rules/services.conf` maps `192.168.50.1:80` (plain) and `192.168.50.1:443` (TLS) to backend port `8080` (this is the default config)

## Run
```bash
cd tests/web_app_test
./start.sh                                   # as your normal user (asks for sudo for the network setup)

# in another terminal, from the repo root:
sudo ./build/src/afxdp_control veth0

# back in tests/web_app_test:
./test.sh                                    # functional + integrity + security
./test.sh --netem                            # same with 50 ms delay and 2% loss
./test.sh --netem "delay 150ms loss 1%" --full
./test.sh --load                             # wrk through Aethon vs. nginx directly

./stop.sh                                    # stop nginx + node
./stop.sh --net                              # also remove veth0/client_ns and detach XDP
```

## What the tests check
| Test | Proves |
|---|---|
| Static page, API health, notes POST/GET | Basic proxying of HTTP to nginx and Node |
| 5 requests on one connection | Keep-alive works |
| `sha256sum` of 1 MB / 5 MB (/ 50 MB with `--full`) downloads | Large responses arrive byte-exact (send buffer, cwnd, retransmission, FIN) |
| Node-streamed 5 MB | Chunked/streamed backend responses through nginx |
| 20 MB upload with the sha256 computed by the backend | Client → backend flow control and backpressure |
| Slow backend (1.5 s) | Pending connections survive a slow backend |
| `/etc/passwd` in the URL | Hyperscan DPI blocks it (plain and inside TLS) |
| Direct access to :8080 | The backend can't be reached around Aethon |
| TLS health, downloads, upload | TLS termination with large records in both directions |
| Blocked SNI | The first domain in `rules/blocked_domains.txt` gets reset |

Run it once normally and once with `--netem`: integrity under loss is the real test of the TCP implementation.

## Use a browser
```bash
sudo ip netns exec client_ns sudo -u "$USER" firefox http://192.168.50.1/   # or chromium
```
or test from the host without Aethon at http://127.0.0.1:8080.

## Logs
`/tmp/aethon_web_app_test/logs/` contains `access.log`, `error.log` and `node.log`. Every client appears as `127.0.0.1` in nginx's log because Aethon proxies over loopback.
