"""Local operator UI. Same-origin writes; no tool execution or remote binding."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .core import Store


def make_handler(database):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def do_POST(self):
            host = f"127.0.0.1:{self.server.server_port}"
            if (self.headers.get("Host") != host or self.headers.get("Origin") != f"http://{host}"
                or self.headers.get("X-OTSec-Request") != "local-ui"
                or self.headers.get("Content-Type") != "application/json"):
                self.send_error(403)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 6 * 1024 * 1024:
                    self.send_error(413)
                    return
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError("Expected an object")
                store = Store(database)
                try:
                    if self.path == "/api/environments":
                        result = store.add_environment(data["name"], data["mode"], data["cidr"])
                    elif self.path == "/api/import":
                        content = data["content"].encode("utf-8")
                        if data["tool"] == "zeek":
                            result = store.import_zeek(data["environment"], content)
                        else:
                            result = store.import_report(data["environment"], data["tool"], data["application"], content)
                    elif self.path == "/api/plans":
                        result = store.plan(data["environment"], data["tool"], data["action"], data["target"])
                    else:
                        self.send_error(404)
                        return
                finally:
                    store.close()
                self.respond(200, {"result": result})
            except ValueError as error:
                self.respond(400, {"error": str(error)})
            except (TypeError, KeyError, AttributeError, RecursionError, UnicodeError):
                self.respond(400, {"error": "Invalid request. Check the fields, environment scope and report format."})

        def respond(self, status, data):
            payload = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                self.send_error(403)
                return
            if self.path.startswith('/fonts/') and self.path[7:] in (
                'plex-sans-400.ttf', 'plex-sans-500.ttf', 'plex-sans-600.ttf',
                'plex-mono-400.ttf', 'baskerville-700.ttf', 'inter-400.ttf',
                'inter-500.ttf', 'inter-600.ttf', 'inter-700.ttf'):
                payload = (Path(__file__).parent / 'web' / self.path[1:]).read_bytes()
                mime = 'font/ttf'
            elif self.path == '/wct-logo.png':
                payload = (Path(__file__).parent / 'web' / 'wct-logo.png').read_bytes()
                mime = 'image/png'
            elif self.path == "/api/status":
                store = Store(database)
                try:
                    payload = json.dumps(store.snapshot()).encode()
                finally:
                    store.close()
                mime = "application/json"
            elif self.path in ("/", "/app.js", "/style.css"):
                name = {"/": "index.html", "/app.js": "app.js", "/style.css": "style.css"}[self.path]
                payload = (Path(__file__).parent / "web" / name).read_bytes()
                mime = {"/": "text/html", "/app.js": "text/javascript", "/style.css": "text/css"}[self.path]
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            pass  # Do not copy caller-controlled requests into logs.

    return Handler


def serve(database, port):
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    store = Store(database)
    store.close()
    with HTTPServer(("127.0.0.1", port), make_handler(database)) as server:
        server.timeout = 10
        print(f"OTSec dashboard: http://127.0.0.1:{port} (local operator workspace)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
