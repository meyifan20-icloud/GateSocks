import base64
import csv
import hashlib
import hmac
import io
import json
import os
import platform
import re
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
CONFIG_DIR = APP_DIR / "config"
DATA_DIR = APP_DIR / "data"
AUTH_FILE = CONFIG_DIR / "auth.json"
NODE_CACHE_FILE = DATA_DIR / "vpngate_nodes.json"

BIND = os.getenv("GATESOCKS_BIND", "0.0.0.0")
PORT = int(os.getenv("GATESOCKS_PORT", "19080"))
VERSION = os.getenv("GATESOCKS_VERSION", "0.4.0-dev")
SOCKS_START = int(os.getenv("GATESOCKS_SOCKS_START", "18001"))
SOCKS_END = int(os.getenv("GATESOCKS_SOCKS_END", "18099"))
TEST_START = int(os.getenv("GATESOCKS_TEST_START", "18100"))
TEST_END = int(os.getenv("GATESOCKS_TEST_END", "18149"))

ADMIN_USER_ENV = os.getenv("GATESOCKS_ADMIN_USER", "admin")
ADMIN_PASS_ENV = os.getenv("GATESOCKS_ADMIN_PASS", "")
SESSION_SECRET = os.getenv("GATESOCKS_SESSION_SECRET", "")
SESSION_TTL = int(os.getenv("GATESOCKS_SESSION_TTL", "43200"))
COOKIE_SECURE = os.getenv("GATESOCKS_COOKIE_SECURE", "false").lower() in {"1", "true", "yes", "on"}
COOKIE_NAME = "gatesocks_session"

VPNGATE_URL = os.getenv("GATESOCKS_VPNGATE_URL", "https://www.vpngate.net/api/iphone/")
VPNGATE_TIMEOUT = int(os.getenv("GATESOCKS_VPNGATE_TIMEOUT", "15"))
VPNGATE_MAX_NODES = int(os.getenv("GATESOCKS_VPNGATE_MAX_NODES", "500"))
PBKDF2_ROUNDS = 200_000

CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

AUTH_LOCK = threading.Lock()
NODE_LOCK = threading.Lock()

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


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def atomic_write_json(path: Path, payload: dict, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    if private:
        os.chmod(tmp, 0o600)
    tmp.replace(path)


def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return b64e(salt), b64e(digest)


def load_auth_state() -> dict:
    try:
        if AUTH_FILE.exists():
            data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
            if data.get("username") and data.get("salt") and data.get("password_hash"):
                return {
                    "source": "panel",
                    "username": str(data["username"]),
                    "salt": str(data["salt"]),
                    "password_hash": str(data["password_hash"]),
                    "auth_version": int(data.get("auth_version", 1)),
                }
    except Exception:
        pass
    return {
        "source": "environment",
        "username": ADMIN_USER_ENV,
        "password_plain": ADMIN_PASS_ENV,
        "auth_version": 1,
    }


def verify_password(password: str, state: dict | None = None) -> bool:
    state = state or load_auth_state()
    if state.get("source") == "panel":
        try:
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                b64d(state["salt"]),
                PBKDF2_ROUNDS,
            )
            return hmac.compare_digest(digest, b64d(state["password_hash"]))
        except Exception:
            return False
    return hmac.compare_digest(password, str(state.get("password_plain", "")))


def auth_configured() -> bool:
    state = load_auth_state()
    has_password = bool(state.get("password_hash")) if state.get("source") == "panel" else bool(state.get("password_plain"))
    return bool(has_password and SESSION_SECRET)


def make_session(username: str, auth_version: int) -> str:
    payload = json.dumps(
        {"u": username, "v": auth_version, "exp": int(time.time()) + SESSION_TTL},
        separators=(",", ":"),
    ).encode()
    body = b64e(payload)
    sig = hmac.new(SESSION_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return body + "." + b64e(sig)


def set_session_cookie(response: JSONResponse, username: str, auth_version: int) -> None:
    response.set_cookie(
        COOKIE_NAME,
        make_session(username, auth_version),
        max_age=SESSION_TTL,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def session_user(request: Request) -> str | None:
    if not auth_configured():
        return None
    token = request.cookies.get(COOKIE_NAME, "")
    state = load_auth_state()
    try:
        body, signature = token.split(".", 1)
        expected = hmac.new(SESSION_SECRET.encode(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64d(signature)):
            return None
        payload = json.loads(b64d(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        username = str(payload.get("u", ""))
        auth_version = int(payload.get("v", 0))
        if not hmac.compare_digest(username, str(state["username"])):
            return None
        if auth_version != int(state.get("auth_version", 1)):
            return None
        return username
    except Exception:
        return None


def safe_int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def read_node_cache() -> dict:
    try:
        if NODE_CACHE_FILE.exists():
            data = json.loads(NODE_CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(data.get("items"), list):
                return data
    except Exception:
        pass
    return {"source": "VPN Gate", "source_url": VPNGATE_URL, "updated_at": None, "items": []}


def public_node(node: dict) -> dict:
    return {k: v for k, v in node.items() if k != "openvpn_config_b64"}


def refresh_vpngate_nodes() -> dict:
    with NODE_LOCK:
        request = urllib.request.Request(
            VPNGATE_URL,
            headers={"User-Agent": f"GateSocks/{VERSION}"},
        )
        with urllib.request.urlopen(request, timeout=VPNGATE_TIMEOUT) as response:
            raw = response.read().decode("utf-8-sig", errors="replace")

        lines = [line for line in raw.splitlines() if line.strip() and not line.startswith("*")]
        if not lines or not lines[0].startswith("#HostName"):
            raise RuntimeError("VPN Gate API returned an unexpected format")

        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        items = []
        for row in reader:
            ip = str(row.get("IP", "")).strip()
            hostname = str(row.get("#HostName", "")).strip()
            country_short = str(row.get("CountryShort", "")).strip().upper()
            config_b64 = str(row.get("OpenVPN_ConfigData_Base64", "")).strip()
            if not ip or not country_short or not config_b64:
                continue

            speed_bps = safe_int(row.get("Speed"))
            ping_ms = safe_int(row.get("Ping"), -1)
            node_id = hashlib.sha256(f"{hostname}|{ip}|{config_b64[:48]}".encode()).hexdigest()[:16]
            items.append({
                "id": node_id,
                "source": "VPN Gate",
                "hostname": hostname,
                "ip": ip,
                "country_long": str(row.get("CountryLong", "")).strip(),
                "country_short": country_short,
                "score": safe_int(row.get("Score")),
                "source_ping_ms": ping_ms if ping_ms >= 0 else None,
                "source_speed_mbps": round(speed_bps / 1_000_000, 1) if speed_bps > 0 else None,
                "sessions": safe_int(row.get("NumVpnSessions")),
                "uptime_ms": safe_int(row.get("Uptime")),
                "operator": str(row.get("Operator", "")).strip(),
                "log_type": str(row.get("LogType", "")).strip(),
                "status": "candidate",
                "openvpn_config_b64": config_b64,
            })

        items.sort(key=lambda item: (item["score"], item.get("source_speed_mbps") or 0), reverse=True)
        items = items[:VPNGATE_MAX_NODES]
        payload = {
            "source": "VPN Gate",
            "source_url": VPNGATE_URL,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "items": items,
        }
        atomic_write_json(NODE_CACHE_FILE, payload)
        return payload


def nodes_response(payload: dict, message: str | None = None) -> dict:
    items = [public_node(item) for item in payload.get("items", [])]
    return {
        "source": payload.get("source", "VPN Gate"),
        "source_url": payload.get("source_url", VPNGATE_URL),
        "updated_at": payload.get("updated_at"),
        "count": len(items),
        "items": items,
        "message": message,
    }


@app.middleware("http")
async def require_auth(request: Request, call_next):
    path = request.url.path
    public = path == "/health" or path == "/favicon.ico" or path == "/login" or path == "/api/login" or path == "/api/me" or path.startswith("/static/")
    if not public and not session_user(request):
        if path.startswith("/api/"):
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        return FileResponse(STATIC_DIR / "login.html", status_code=401)
    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok", "service": "GateSocks", "version": VERSION}


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")


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

    state = load_auth_state()
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    valid_user = hmac.compare_digest(username, str(state["username"]))
    valid_pass = verify_password(password, state)
    if not (valid_user and valid_pass):
        return JSONResponse({"detail": "用户名或密码错误"}, status_code=401)

    response = JSONResponse({"ok": True, "username": state["username"]})
    set_session_cookie(response, state["username"], int(state.get("auth_version", 1)))
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


@app.post("/api/settings/auth")
async def update_auth(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid request"}, status_code=400)

    with AUTH_LOCK:
        state = load_auth_state()
        current_password = str(data.get("current_password", ""))
        if not verify_password(current_password, state):
            return JSONResponse({"detail": "当前密码错误"}, status_code=403)

        new_username = str(data.get("username", "")).strip() or str(state["username"])
        new_password = str(data.get("new_password", ""))
        confirm_password = str(data.get("confirm_password", ""))

        if len(new_username) < 3 or len(new_username) > 64:
            return JSONResponse({"detail": "用户名长度必须为 3–64 个字符"}, status_code=400)
        if new_password != confirm_password:
            return JSONResponse({"detail": "两次输入的新密码不一致"}, status_code=400)
        if new_password and len(new_password) < 8:
            return JSONResponse({"detail": "新密码至少需要 8 个字符"}, status_code=400)

        if new_password:
            salt, password_hash = hash_password(new_password)
        elif state.get("source") == "panel":
            salt = str(state["salt"])
            password_hash = str(state["password_hash"])
        else:
            salt, password_hash = hash_password(current_password)

        next_version = int(state.get("auth_version", 1)) + 1
        auth_payload = {
            "username": new_username,
            "salt": salt,
            "password_hash": password_hash,
            "auth_version": next_version,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        atomic_write_json(AUTH_FILE, auth_payload, private=True)

    response = JSONResponse({
        "ok": True,
        "username": new_username,
        "message": "管理员账号已更新并持久化到 config/auth.json",
    })
    set_session_cookie(response, new_username, next_version)
    return response


@app.get("/api/status")
def status():
    tunnels = tun_interfaces()
    node_cache = read_node_cache()
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
        "candidate_nodes": len(node_cache.get("items", [])),
        "alerts": 0,
        "bind": BIND,
        "port": PORT,
    }


@app.get("/api/nodes")
def nodes():
    payload = read_node_cache()
    message = None
    if not payload.get("items"):
        try:
            payload = refresh_vpngate_nodes()
            message = "已自动从 VPN Gate 拉取候选节点。"
        except Exception as exc:
            message = f"VPN Gate 拉取失败：{exc}"
    return nodes_response(payload, message)


@app.post("/api/nodes/refresh")
def refresh_nodes():
    try:
        payload = refresh_vpngate_nodes()
        return nodes_response(payload, "VPN Gate 候选节点已刷新。")
    except (urllib.error.URLError, TimeoutError, RuntimeError, OSError) as exc:
        return JSONResponse({"detail": f"VPN Gate 拉取失败：{exc}"}, status_code=502)
    except Exception as exc:
        return JSONResponse({"detail": f"节点池刷新失败：{exc}"}, status_code=500)


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
    cache = read_node_cache()
    return {"items": [
        {"time": datetime.now(timezone.utc).isoformat(), "level": "INFO", "message": f"GateSocks {VERSION} Web panel is running."},
        {"time": cache.get("updated_at") or datetime.now(timezone.utc).isoformat(), "level": "INFO", "message": f"VPN Gate candidate cache: {len(cache.get('items', []))} nodes."},
    ]}


@app.get("/api/settings")
def settings():
    auth_state = load_auth_state()
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
        "nodes": {
            "source": "VPN Gate",
            "source_url": VPNGATE_URL,
            "cache_file": str(NODE_CACHE_FILE),
        },
        "auth": {
            "username": auth_state["username"],
            "source": auth_state["source"],
            "session_ttl": SESSION_TTL,
            "cookie_secure": COOKIE_SECURE,
            "panel_changes_persist": True,
        },
    }


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")
