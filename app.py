import json
import os
import platform
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = os.getenv("GATESOCKS_BIND", "127.0.0.1")
PORT = int(os.getenv("GATESOCKS_PORT", "19080"))
VERSION = os.getenv("GATESOCKS_VERSION", "0.1.0-dev")


def command_version(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        out = (p.stdout or p.stderr).strip().splitlines()
        return out[0] if out else "unknown"
    except Exception:
        return "unavailable"


class Handler(BaseHTTPRequestHandler):
    server_version = "GateSocks"

    def _send(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {
                "status": "ok",
                "service": "GateSocks",
                "version": VERSION
            })

        if self.path in ("/", "/api/info"):
            return self._send(200, {
                "service": "GateSocks",
                "version": VERSION,
                "stage": "development",
                "python": platform.python_version(),
                "openvpn": command_version(["openvpn", "--version"]),
                "tun_present": os.path.exists("/dev/net/tun"),
                "bind": BIND,
                "port": PORT
            })

        return self._send(404, {"error": "not_found"})

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    print(f"GateSocks {VERSION} listening on http://{BIND}:{PORT}", flush=True)
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
