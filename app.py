import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"

BIND = os.getenv("GATESOCKS_BIND", "127.0.0.1")
PORT = int(os.getenv("GATESOCKS_PORT", "19080"))
VERSION = os.getenv("GATESOCKS_VERSION", "0.2.0-dev")
SOCKS_START = int(os.getenv("GATESOCKS_SOCKS_START", "18001"))
SOCKS_END = int(os.getenv("GATESOCKS_SOCKS_END", "18099"))
TEST_START = int(os.getenv("GATESOCKS_TEST_START", "18100"))
TEST_END = int(os.getenv("GATESOCKS_TEST_END", "18149"))

app = FastAPI(title="GateSocks", version=VERSION)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def run(cmd: list[str], timeout: int = 4) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or proc.stderr or "").strip()
    except Exception:
        return ""


def openvpn_version() -> str:
    text = run(["openvpn", "--version"])
    return text.splitlines()[0] if text else "unavailable"


def tun_interfaces() -> list[dict]:
    text = run(["ip", "-o", "link", "show"])
    result = []
    for line in text.splitlines():
        match = re.match(r"\d+: ([^:@]+)", line)
        if not match:
            continue
        name = match.group(1)
        if name.startswith(("tun", "tap")):
            result.append({
                "name": name,
                "state": "UP" if "state UP" in line or "<" in line and "UP" in line.split(">", 1)[0] else "UNKNOWN",
                "raw": line,
            })
    return result


@app.get("/health")
def health():
    return {"status": "ok", "service": "GateSocks", "version": VERSION}


@app.get("/api/status")
def status():
    tunnels = tun_interfaces()
    return {
        "service": "GateSocks",
        "version": VERSION,
        "stage": "development",
        "time": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "openvpn": openvpn_version(),
        "tun_present": os.path.exists("/dev/net/tun"),
        "tunnel_count": len(tunnels),
        "socks_online": 0,
        "candidate_nodes": 0,
        "alerts": 0,
        "bind": BIND,
        "port": PORT,
    }


@app.get("/api/nodes")
def nodes():
    return {
        "items": [],
        "message": "节点抓取与真实测速引擎将在下一阶段接入。"
    }


@app.get("/api/socks")
def socks():
    return {
        "items": [],
        "port_pool": {"start": SOCKS_START, "end": SOCKS_END},
        "message": "尚未生成 SOCKS5 实例。"
    }


@app.get("/api/openvpn")
def openvpn():
    return {
        "version": openvpn_version(),
        "tun_present": os.path.exists("/dev/net/tun"),
        "tunnels": tun_interfaces(),
    }


@app.get("/api/tests")
def tests():
    return {"items": [], "message": "暂无测试记录。"}


@app.get("/api/logs")
def logs():
    return {
        "items": [
            {
                "time": datetime.now(timezone.utc).isoformat(),
                "level": "INFO",
                "message": f"GateSocks {VERSION} Web panel is running."
            }
        ]
    }


@app.get("/api/settings")
def settings():
    return {
        "web": {"bind": BIND, "port": PORT},
        "socks_port_pool": {"start": SOCKS_START, "end": SOCKS_END},
        "test_port_pool": {"start": TEST_START, "end": TEST_END},
        "backend": {
            "openvpn": True,
            "tun_device": "/dev/net/tun",
            "network_mode": "host"
        }
    }


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")
