import base64
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"

BIND = os.getenv("GATESOCKS_BIND", "0.0.0.0")
PORT = int(os.getenv("GATESOCKS_PORT", "19080"))
VERSION = os.getenv("GATESOCKS_VERSION", "0.3.0-dev")
SOCKS_START = int(os.getenv("GATESOCKS_SOCKS_START", "18001"))
SOCKS_END = int(os.getenv("GATESOCKS_SOCKS_END", "18099"))
TEST_START = int(os.getenv("GATESOCKS_TEST_START", "18100"))
TEST_END = int(os.getenv("GATESOCKS_TEST_END", "18149"))

ADMIN_USER = os.getenv("GATESOCKS_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("GATESOCKS_ADMIN_PASS", "")
SESSION_SECRET = os.getenv("GATESOCKS_SESSION_SECRET", "")
SESSION_TTL = int(os.getenv("GATESOCKS_SESSION_TTL", "43200"))
COOKIE_SECURE = os.getenv("GATESOCKS_COOKIE_SECURE", "false").lower() in {"1", "true", "yes", "on"}
COOKIE_NAME = "gatesocks_session"

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
                "state": "UP" if "state UP" in line or ("<" in line and "UP" in line.split(">", 1)[0]) else "UNKNOWN",
                "raw": line,
            })
    return result


def auth_configured() -> bool:
    return bool(ADMIN_PASS and SESSION_SECRET)


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def make_session(username: str) -> str:
    payload = json.dumps(
        {"u": username, "exp": int(time.time()) + SESSION_TTL},
        separators=(",", ":"),
    ).encode()
    body = b64e(payload)
    sig = hmac.new(SESSION_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return body + "." + b64e(sig)


def session_user(request: Request) -> str | None:
    if not auth_configured():
        return None
    token = request.cookies.get(COOKIE_NAME, "")
    try:
        body, signature = token.split(".", 1)
        expected = hmac.new(SESSION_SECRET.encode(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64d(signature)):
            return None
        payload = json.loads(b64d(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        username = str(payload.get("u", ""))
        return username if hmac.compare_digest(username, ADMIN_USER) else None
    except Exception:
        return None


@app.middleware("http")
async def require_auth(request: Request, call_next):
    path = request.url.path
    public = path == "/health" or path == "/login" or path == "/api/login" or path == "/api/me" or path.startswith("/static/")
    if not public and not session_user(request):
        if path.startswith("/api/"):
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        return FileResponse(STATIC_DIR / "login.html", status_code=401)
    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok", "service": "GateSocks", "version": VERSION}


@app.get("/login")
def login_page(request: Request):
    if session_user(request):
        return FileResponse(STATIC_DIR / "index.html")
    return FileResponse(STATIC_DIR / "login.html")


@app.post("/api/login")
async def login(request: Request):
    if not auth_configured():
        return JSONResponse(
            {"detail": "authentication is not configured; set GATESOCKS_ADMIN_PASS and GATESOCKS_SESSION_SECRET"},
            status_code=503,
        )
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid request"}, status_code=400)
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    valid_user = hmac.compare_digest(username, ADMIN_USER)
    valid_pass = hmac.compare_digest(password, ADMIN_PASS)
    if not (valid_user and valid_pass):
        return JSONResponse({"detail": "用户名或密码错误"}, status_code=401)
    response = JSONResponse({"ok": True, "username": ADMIN_USER})
    response.set_cookie(
        COOKIE_NAME,
        make_session(ADMIN_USER),
        max_age=SESSION_TTL,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/api/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@app.get("/api/me")
def me(request: Request):
    username = session_user(request)
    return {"authenticated": bool(username), "username": username, "configured": auth_configured()}


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
    return {"items": [], "message": "节点抓取与真实测速引擎将在下一阶段接入。"}


@app.get("/api/socks")
def socks():
    return {"items": [], "port_pool": {"start": SOCKS_START, "end": SOCKS_END}, "message": "尚未生成 SOCKS5 实例。"}


@app.get("/api/openvpn")
def openvpn():
    return {"version": openvpn_version(), "tun_present": os.path.exists("/dev/net/tun"), "tunnels": tun_interfaces()}


@app.get("/api/tests")
def tests():
    return {"items": [], "message": "暂无测试记录。"}


@app.get("/api/logs")
def logs():
    return {"items": [{"time": datetime.now(timezone.utc).isoformat(), "level": "INFO", "message": f"GateSocks {VERSION} Web panel is running."}]}


@app.get("/api/settings")
def settings():
    return {
        "web": {"bind": BIND, "port": PORT},
        "socks_port_pool": {"start": SOCKS_START, "end": SOCKS_END},
        "test_port_pool": {"start": TEST_START, "end": TEST_END},
        "backend": {
            "openvpn": True,
            "tun_device": "/dev/net/tun",
            "network_mode": "docker-bridge",
            "caddy_network": os.getenv("GATESOCKS_CADDY_NETWORK", "sublink-worker_default"),
        },
        "auth": {"username": ADMIN_USER, "session_ttl": SESSION_TTL, "cookie_secure": COOKIE_SECURE},
    }


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")
