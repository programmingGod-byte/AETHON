import sys
import os
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class MultiPortHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        server_port = self.server.server_address[1]
        service_name = "Auth Service" if server_port == 5000 else ("Admin Service" if server_port == 6000 else "API Service")
        color = "\033[93m" if server_port == 5000 else ("\033[95m" if server_port == 6000 else "\033[96m")
        print(f"{color}[BACKEND :{server_port}]\033[0m Forwarded by Aethon -> {service_name} | GET {self.path}")

        resp_body = json.dumps({
            "status": "success",
            "service": service_name,
            "backend_port": server_port,
            "path": self.path,
            "method": "GET"
        }).encode('utf-8')

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Backend-Port", str(server_port))
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def do_POST(self):
        server_port = self.server.server_address[1]
        service_name = "Auth Service" if server_port == 5000 else ("Admin Service" if server_port == 6000 else "API Service")
        color = "\033[93m" if server_port == 5000 else ("\033[95m" if server_port == 6000 else "\033[96m")
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode('utf-8', errors='ignore')
        print(f"{color}[BACKEND :{server_port}]\033[0m Forwarded by Aethon -> {service_name} | POST {self.path}")
        if body:
            print(f"  Body: {body[:80]}")

        resp_body = json.dumps({
            "status": "success",
            "service": service_name,
            "backend_port": server_port,
            "path": self.path,
            "method": "POST"
        }).encode('utf-8')

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Backend-Port", str(server_port))
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, format, *args):
        return

def run_single_server(port):
    HTTPServer.allow_reuse_address = True
    server = HTTPServer(("0.0.0.0", port), MultiPortHandler)
    server.serve_forever()

if __name__ == "__main__":
    ports = [5000, 6000, 8080]
    print(f"\033[94m[MULTI-BACKEND]\033[0m Starting backend services on ports {ports}...")
    threads = []
    for p in ports:
        t = threading.Thread(target=run_single_server, args=(p,), daemon=True)
        t.start()
        threads.append(t)
    print("\033[92m[MULTI-BACKEND]\033[0m All 3 backend services listening and ready!\n")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        sys.exit(0)

