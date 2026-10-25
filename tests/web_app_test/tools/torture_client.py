#!/usr/bin/env python3
"""Socket-level torture helpers for Aethon. Run inside client_ns (torture.sh does this).

Every subcommand prints one line starting with OK / BAD / INFO and exits 0 (OK/INFO) or 1 (BAD).
Only the Python standard library is used.
"""
import argparse
import hashlib
import os
import random
import socket
import ssl
import struct
import sys
import threading
import time

SERVER = os.environ.get("TORTURE_SERVER", "192.168.50.1")
HTTP_PORT = int(os.environ.get("TORTURE_HTTP_PORT", "80"))
TLS_PORT = int(os.environ.get("TORTURE_TLS_PORT", "443"))
TLS_HOST = "test.local"


def done(ok, msg):
    print(("OK " if ok else "BAD ") + msg)
    sys.exit(0 if ok else 1)


def connect(tls=False, timeout=10.0, rcvbuf=None, sni=TLS_HOST):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.settimeout(timeout)
    s.connect((SERVER, TLS_PORT if tls else HTTP_PORT))
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=sni)
    return s


def recv_all(s, limit=1 << 30):
    chunks, n = [], 0
    try:
        while n < limit:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
            n += len(b)
    except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
        pass
    return b"".join(chunks)


def read_response(s):
    """Read one HTTP/1.1 response with Content-Length. Returns (status, body)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        b = s.recv(65536)
        if not b:
            raise ConnectionError("closed before headers")
        buf += b
    head, body = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    length = 0
    for line in lines[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            length = int(v.strip())
    while len(body) < length:
        b = s.recv(min(65536, length - len(body)))
        if not b:
            raise ConnectionError("closed mid-body")
        body += b
    return status, body


def req(path, method="GET", body=b"", close=False, extra=""):
    h = f"{method} {path} HTTP/1.1\r\nHost: {TLS_HOST}\r\n"
    if body or method == "POST":
        h += f"Content-Length: {len(body)}\r\nContent-Type: application/octet-stream\r\n"
    if close:
        h += "Connection: close\r\n"
    return (h + extra + "\r\n").encode() + body


def health_once(tls=False, timeout=5.0):
    t0 = time.monotonic()
    s = connect(tls, timeout)
    s.sendall(req("/api/health", close=True))
    status, body = read_response(s)
    s.close()
    return status == 200 and b'"ok":true' in body, time.monotonic() - t0


# ---------------------------------------------------------------- evasion
def cmd_split_evasion(a):
    """'/etc/passwd' split across TCP segments (or TLS records) with pauses between them."""
    pieces = [b"GET /api/health?f=/et", b"c/pas", b"swd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"]
    if a.bytewise:
        whole = b"".join(pieces)
        pieces = [whole[i:i + 1] for i in range(len(whole))]
    try:
        s = connect(a.tls)
        for p in pieces:
            s.send(p)                      # TCP_NODELAY (and one TLS record per send)
            time.sleep(0.005 if a.bytewise else 0.2)
        data = recv_all(s)
    except (ConnectionError, OSError, ssl.SSLError) as e:
        done(True, f"blocked ({type(e).__name__})")
    done(b'"ok":true' not in data, "blocked" if b'"ok":true' not in data else "EVADED: request reached the backend")


# ---------------------------------------------------------------- protocol edges
def cmd_half_close(a):
    # Static page: nginx aborts *proxied* requests on client EOF, so /api/ would test nginx, not Aethon
    s = connect(False)
    s.sendall(req("/", close=True))
    s.shutdown(socket.SHUT_WR)             # client FIN right after the request
    data = recv_all(s)
    done(b"Aethon Notes" in data, f"response after client FIN ({len(data)} bytes)")


def cmd_pipeline(a):
    s = connect(a.tls)
    batch = b"".join(req("/api/health", close=(i == a.count - 1)) for i in range(a.count))
    s.sendall(batch)                       # all requests in one write
    data = recv_all(s)
    n = data.count(b"HTTP/1.1 200")
    done(n == a.count, f"{n}/{a.count} pipelined responses")


def cmd_idle_keepalive(a):
    s = connect(a.tls, timeout=a.idle + 15)
    s.sendall(req("/api/health"))
    st1, _ = read_response(s)
    time.sleep(a.idle)
    try:
        s.sendall(req("/api/health", close=True))
        st2, body = read_response(s)
        done(st1 == 200 and st2 == 200, f"second request after {a.idle}s idle answered")
    except (ConnectionError, OSError, ssl.SSLError) as e:
        done(False, f"connection lost after {a.idle}s idle ({type(e).__name__}); "
                    f"browsers keep idle keep-alive connections, so sessions must not expire this early")


def cmd_slow_reader(a):
    """Tiny receive buffer + slow reads: forces zero windows and window updates."""
    s = connect(a.tls, timeout=30, rcvbuf=4096)
    s.sendall(req(a.path, close=True))
    buf = b""
    while b"\r\n\r\n" not in buf:
        b = s.recv(4096)
        if not b:
            done(False, "connection closed before response headers")
        buf += b
    _, body = buf.split(b"\r\n\r\n", 1)
    h = hashlib.sha256(body)
    n = len(body)
    t0 = time.monotonic()
    while True:
        try:
            b = s.recv(4096)
        except (socket.timeout, OSError, ssl.SSLError) as e:
            done(False, f"stalled after {n} bytes ({type(e).__name__})")
        if not b:
            break
        h.update(b)
        n += len(b)
        time.sleep(a.delay)
    ok = h.hexdigest() == a.sha
    done(ok, f"{n} bytes in {time.monotonic() - t0:.1f}s, sha256 {'matches' if ok else 'MISMATCH'}")


# ---------------------------------------------------------------- concurrency
def run_threads(n, fn):
    results = [None] * n

    def wrap(i):
        try:
            results[i] = fn(i)
        except Exception as e:  # noqa: BLE001 - report any failure
            results[i] = (False, f"{type(e).__name__}: {e}")

    ts = [threading.Thread(target=wrap, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return results


def cmd_parallel_download(a):
    def one(_):
        s = connect(a.tls, timeout=120)
        s.sendall(req(a.path, close=True))
        st, body = read_response(s)
        s.close()
        return st == 200 and hashlib.sha256(body).hexdigest() == a.sha, f"{len(body)} bytes"

    t0 = time.monotonic()
    res = run_threads(a.count, one)
    good = sum(1 for r in res if r[0])
    first_bad = next((r[1] for r in res if not r[0]), "")
    done(good == a.count, f"{good}/{a.count} parallel downloads intact in {time.monotonic() - t0:.1f}s {first_bad}")


def cmd_parallel_upload(a):
    def one(i):
        data = os.urandom(a.size)
        s = connect(a.tls, timeout=120)
        s.sendall(req("/api/upload", "POST", data, close=True))
        st, body = read_response(s)
        s.close()
        return st == 200 and hashlib.sha256(data).hexdigest().encode() in body, f"status {st}"

    t0 = time.monotonic()
    res = run_threads(a.count, one)
    good = sum(1 for r in res if r[0])
    first_bad = next((r[1] for r in res if not r[0]), "")
    done(good == a.count, f"{good}/{a.count} parallel uploads intact in {time.monotonic() - t0:.1f}s {first_bad}")


def cmd_many_short(a):
    t0, good, err = time.monotonic(), 0, ""
    for _ in range(a.count):
        try:
            ok, _ = health_once(a.tls)
            good += ok
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {e}"
    dt = time.monotonic() - t0
    done(good == a.count, f"{good}/{a.count} short connections ({a.count / dt:.0f}/s) {err}")


# ---------------------------------------------------------------- abuse
def cmd_abort(a):
    """Abort transfers mid-way with RST (SO_LINGER 0), then check the service still works."""
    for _ in range(a.count):
        try:
            s = connect(a.tls, timeout=10)
            if a.mode == "download":
                s.sendall(req("/files/50mb.bin"))
                got = 0
                while got < 200_000:
                    got += len(s.recv(65536))
            else:
                # Announce 20 MB, send 1 MB, then vanish
                s.sendall(f"POST /api/upload HTTP/1.1\r\nHost: {TLS_HOST}\r\n"
                          f"Content-Length: {20 << 20}\r\n\r\n".encode())
                s.sendall(os.urandom(1 << 20))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))  # close() sends RST
            s.close()
        except (OSError, ssl.SSLError):
            pass
    ok, dt = health_once(a.tls)
    done(ok, f"service healthy after {a.count} aborted {a.mode}s (health {dt * 1000:.0f} ms)")


def cmd_garbage(a):
    """Random bytes to port 80 and a corrupt TLS handshake to 443; Aethon must survive."""
    for port, payload in ((HTTP_PORT, os.urandom(64 << 10)),
                          (TLS_PORT, b"\x16\x03\x01\x40\x00\x01" + os.urandom(2000)),   # bogus ClientHello
                          (TLS_PORT, os.urandom(4096))):                                # not TLS at all
        try:
            s = socket.create_connection((SERVER, port), timeout=5)
            s.sendall(payload)
            recv_all(s)
            s.close()
        except OSError:
            pass
    ok, dt = health_once(False)
    ok_tls, _ = health_once(True)
    done(ok and ok_tls, f"HTTP and HTTPS still healthy after garbage (health {dt * 1000:.0f} ms)")


def cmd_slowloris(a):
    """Hold many connections with slowly trickling headers while real users keep working."""
    stop = time.monotonic() + a.seconds
    socks = []
    for _ in range(a.conns):
        try:
            s = socket.create_connection((SERVER, HTTP_PORT), timeout=5)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")
            socks.append(s)
        except OSError:
            break
    worst, failures, checks = 0.0, 0, 0
    while time.monotonic() < stop:
        for s in socks:
            try:
                s.sendall(b"X-a: %d\r\n" % random.randint(1, 9999))
            except OSError:
                pass
        try:
            ok, dt = health_once(False, timeout=5)
            worst = max(worst, dt)
            failures += not ok
        except Exception:  # noqa: BLE001
            failures += 1
        checks += 1
        time.sleep(1)
    for s in socks:
        s.close()
    done(failures == 0 and worst < 2.0,
         f"{len(socks)} slowloris conns held; {checks - failures}/{checks} health checks ok, worst {worst * 1000:.0f} ms")


def cmd_handshake_flood(a):
    """Many TLS handshakes at once, half abandoned right after the ClientHello."""
    def one(i):
        if i % 2:
            # Send a real ClientHello, then abort without finishing the handshake
            s = socket.create_connection((SERVER, TLS_PORT), timeout=10)
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            obj = ctx.wrap_bio(incoming, outgoing, server_hostname=TLS_HOST)
            try:
                obj.do_handshake()
            except ssl.SSLWantReadError:
                pass
            s.sendall(outgoing.read())
            time.sleep(0.05)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close()
            return True, ""
        ok, _ = health_once(True, timeout=15)
        return ok, "health failed during flood"

    t0 = time.monotonic()
    res = run_threads(a.count, one)
    good = sum(1 for r in res if r[0])
    ok, dt = health_once(True)
    done(good == a.count and ok,
         f"{good}/{a.count} handshake-flood tasks ok in {time.monotonic() - t0:.1f}s; TLS health after: {dt * 1000:.0f} ms")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, **kw):
        sp = sub.add_parser(name)
        sp.add_argument("--tls", action="store_true")
        for k, (typ, default) in kw.items():
            if typ is bool:
                sp.add_argument(f"--{k}", action="store_true")
            else:
                sp.add_argument(f"--{k}", type=typ, default=default)
        sp.set_defaults(fn=fn)

    add("split-evasion", cmd_split_evasion, bytewise=(bool, False))
    add("half-close", cmd_half_close)
    add("pipeline", cmd_pipeline, count=(int, 10))
    add("idle-keepalive", cmd_idle_keepalive, idle=(int, 40))
    add("slow-reader", cmd_slow_reader, path=(str, "/files/5mb.bin"), sha=(str, ""), delay=(float, 0.002))
    add("parallel-download", cmd_parallel_download, count=(int, 16), path=(str, "/files/5mb.bin"), sha=(str, ""))
    add("parallel-upload", cmd_parallel_upload, count=(int, 8), size=(int, 5 << 20))
    add("many-short", cmd_many_short, count=(int, 1000))
    add("abort", cmd_abort, mode=(str, "download"), count=(int, 20))
    add("garbage", cmd_garbage)
    add("slowloris", cmd_slowloris, conns=(int, 200), seconds=(int, 15))
    add("handshake-flood", cmd_handshake_flood, count=(int, 200))

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
