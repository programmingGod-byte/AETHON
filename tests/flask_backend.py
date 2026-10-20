import sys
import os
import json

try:
    from flask import Flask, jsonify, request
    app = Flask(__name__)

    @app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
    def catch_all(path):
        method = request.method
        full_path = f"/{path}"
        body = request.get_data(as_text=True)
        print(f"\033[92m[FLASK BACKEND]\033[0m Clean Request Forwarded by Aethon -> {method} {full_path}")
        if body:
            print(f"  Body: {body[:100]}")
        return jsonify({
            "status": "success",
            "server": "Flask-10Gbps-Backend",
            "path": full_path,
            "method": method,
            "msg": "Clean packet received and processed successfully"
        }), 200

    def run_server(port):
        print(f"\033[94m[FLASK BACKEND]\033[0m Listening on 0.0.0.0:{port} for Aethon reverse-proxy traffic...")
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class AethonBackendHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            print(f"\033[92m[BACKEND]\033[0m Clean Request Forwarded by Aethon -> GET {self.path}")
            resp = json.dumps({
                "status": "success",
                "server": "Python-Backend",
                "path": self.path,
                "method": "GET",
                "msg": "Clean packet received and processed successfully"
            }).encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            print(f"\033[92m[BACKEND]\033[0m Clean Request Forwarded by Aethon -> POST {self.path}")
            if body:
                print(f"  Body: {body[:100]}")
            resp = json.dumps({
                "status": "success",
                "server": "Python-Backend",
                "path": self.path,
                "method": "POST",
                "msg": "Clean packet received and processed successfully"
            }).encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def log_message(self, format, *args):
            return

    def run_server(port):
        print(f"\033[94m[BACKEND]\033[0m Listening on 0.0.0.0:{port} for Aethon reverse-proxy traffic...")
        HTTPServer.allow_reuse_address = True
        server = HTTPServer(("0.0.0.0", port), AethonBackendHandler)
        server.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
