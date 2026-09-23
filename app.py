import base64
import csv
import hashlib
import hmac
import io
import json
import os
import platform
import re
import shutil
import secrets
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path

import qrcode
import qrcode.image.svg
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
CONFIG_DIR = APP_DIR / "config"
DATA_DIR = APP_DIR / "data"
AUTH_FILE = CONFIG_DIR / "auth.json"
NODE_CACHE_FILE = DATA_DIR / "vpngate_nodes.json"
TEST_RESULTS_FILE = DATA_DIR / "test_results.json"
SELECTED_NODE_FILE = DATA_DIR / "selected_node.json"
SOCKS_INSTANCES_FILE = DATA_DIR / "socks_instances.json"
SOCKS_DATA_DIR = DATA_DIR / "socks"
SOCKS_SERVER_SCRIPT = APP_DIR / "socks_server.py"

BIND = os.getenv("GATESOCKS_BIND", "0.0.0.0")
PORT = int(os.getenv("GATESOCKS_PORT", "19080"))
VERSION = os.getenv("GATESOCKS_VERSION", "0.4.6-dev")
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
TEST_BATCH_LIMIT = int(os.getenv("GATESOCKS_TEST_BATCH_LIMIT", "5"))
TEST_MAX_BATCH = int(os.getenv("GATESOCKS_TEST_MAX_BATCH", "200"))
TEST_CONNECT_TIMEOUT = int(os.getenv("GATESOCKS_TEST_CONNECT_TIMEOUT", "30"))
TEST_DOWNLOAD_BYTES = int(os.getenv("GATESOCKS_TEST_DOWNLOAD_BYTES", "5000000"))
TEST_UPLOAD_BYTES = int(os.getenv("GATESOCKS_TEST_UPLOAD_BYTES", "1048576"))
SOCKS_CONNECT_TIMEOUT = int(os.getenv("GATESOCKS_SOCKS_CONNECT_TIMEOUT", "35"))
SOCKS_MARK_BASE = int(os.getenv("GATESOCKS_SOCKS_MARK_BASE", "12000"))
SOCKS_TABLE_BASE = int(os.getenv("GATESOCKS_SOCKS_TABLE_BASE", "20000"))
SOCKS_RULE_PRIORITY_BASE = int(os.getenv("GATESOCKS_SOCKS_RULE_PRIORITY_BASE", "21000"))
PUBLIC_HOST_ENV = os.getenv("GATESOCKS_PUBLIC_HOST", "").strip()
PROBE_UID = 65534
PROBE_TABLE = 100
PROBE_RULE_PRIORITY = 10000
PBKDF2_ROUNDS = 200_000

CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
SOCKS_DATA_DIR.mkdir(parents=True, exist_ok=True)

AUTH_LOCK = threading.Lock()
NODE_LOCK = threading.Lock()
TEST_LOCK = threading.Lock()
TEST_JOB = {"running": False, "total": 0, "completed": 0, "current_id": None, "started_at": None, "finished_at": None, "last_error": None}
IP_META_CACHE: dict[str, dict] = {}
SOCKS_LOCK = threading.RLock()
SOCKS_RUNTIME: dict[str, dict] = {}
PUBLIC_HOST_CACHE = {"value": None, "checked_at": 0.0}

DATA_SOURCES = {
    "candidate": {
        "name": "VPN Gate",
        "url": "https://www.vpngate.net/api/iphone/",
        "purpose": "候选节点、源 Ping、源线路 Speed/Throughput",
    },
    "exit_ip": {
        "name": "ipify / icanhazip",
        "urls": ["https://api.ipify.org", "https://icanhazip.com"],
        "purpose": "OpenVPN 隧道建立后确认真实公网出口 IPv4",
    },
    "throughput": {
        "name": "Cloudflare Speed Test",
        "url": "https://speed.cloudflare.com/",
        "download_endpoint": "https://speed.cloudflare.com/__down",
        "upload_endpoint": "https://speed.cloudflare.com/__up",
        "purpose": "本 VPS 经临时 VPN 隧道的下载/上传吞吐抽样",
    },
    "ip_intel": {
        "name": "ip-api.com",
        "url": "https://ip-api.com/docs/api:json",
        "fields": ["isp", "org", "as", "asname", "mobile", "proxy", "hosting"],
        "purpose": "ISP/ASN 与住宅/代理/机房倾向辅助判断",
        "rules": [
            "hosting=true 或 proxy=true：非住宅/代理倾向；公开库已标记",
            "mobile=true 且 hosting/proxy=false：移动网络倾向；需复核",
            "hosting/proxy/mobile 均为 false：仅表示未发现机房/代理/移动标记，不能证明是住宅 IP",
        ],
    },
}

app = FastAPI(title="GateSocks", version=VERSION)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def build_qr_svg(text: str) -> bytes:
    value = str(text)
    if not value or len(value) > 4096:
        raise ValueError("QR text must be between 1 and 4096 characters")
    image = qrcode.make(
        value,
        image_factory=qrcode.image.svg.SvgPathImage,
        box_size=8,
        border=4,
    )
    stream = io.BytesIO()
    image.save(stream)
    return stream.getvalue()

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


def read_selected_node() -> dict:
    try:
        if SELECTED_NODE_FILE.exists():
            data = json.loads(SELECTED_NODE_FILE.read_text(encoding="utf-8"))
            if data.get("node_id"):
                return data
    except Exception:
        pass
    return {}


def classify_ip_meta(meta: dict) -> tuple[str, str, dict]:
    evidence = {
        "hosting": bool(meta.get("hosting")) if meta else None,
        "proxy": bool(meta.get("proxy")) if meta else None,
        "mobile": bool(meta.get("mobile")) if meta else None,
    }
    if not meta:
        return "未知", "未知", evidence
    if evidence["hosting"] or evidence["proxy"]:
        return "非住宅/代理倾向", "公开库已标记", evidence
    if evidence["mobile"]:
        return "移动网络倾向", "需复核", evidence
    return "未发现机房标记（需复核）", "未知", evidence


def read_test_results() -> list[dict]:
    try:
        if TEST_RESULTS_FILE.exists():
            data = json.loads(TEST_RESULTS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def save_test_result(result: dict) -> None:
    with TEST_LOCK:
        items = read_test_results()
        items = [item for item in items if item.get("node_id") != result.get("node_id")]
        items.insert(0, result)
        atomic_write_json(TEST_RESULTS_FILE, items[:200])


def nodes_response(payload: dict, message: str | None = None) -> dict:
    latest = {item.get("node_id"): item for item in read_test_results() if item.get("node_id")}
    selected_id = read_selected_node().get("node_id")
    items = []
    for raw in payload.get("items", []):
        item = public_node(raw)
        test = latest.get(item.get("id"))
        item["selected"] = item.get("id") == selected_id
        if test:
            item.update({
                "status": test.get("status", item.get("status")),
                "exit_ip": test.get("exit_ip"),
                "isp": test.get("isp"),
                "asn": test.get("asn"),
                "residential_hint": test.get("residential_hint"),
                "risk": test.get("risk"),
                "latency_ms": test.get("latency_ms"),
                "download_mbps": test.get("download_mbps"),
                "upload_mbps": test.get("upload_mbps"),
                "stability_percent": test.get("stability_percent"),
                "tested_at": test.get("tested_at"),
                "test_error": test.get("error"),
            })
        items.append(item)
    return {
        "source": payload.get("source", "VPN Gate"),
        "source_url": payload.get("source_url", VPNGATE_URL),
        "updated_at": payload.get("updated_at"),
        "count": len(items),
        "items": items,
        "message": message,
    }


def resolve_ipv4(host: str) -> str:
    infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise RuntimeError(f"无法解析 {host}")
    return infos[0][4][0]


def run_probe_curl(args: list[str], timeout: int = 25, input_bytes: bytes | None = None) -> str:
    cmd = [
        "setpriv",
        "--reuid", str(PROBE_UID),
        "--regid", str(PROBE_UID),
        "--clear-groups",
        "--inh-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "curl",
    ] + args
    proc = subprocess.run(cmd, input=input_bytes, capture_output=True, timeout=timeout)
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        detail = (stderr or stdout or "curl failed").strip()
        raise RuntimeError(detail[-240:])
    return stdout.strip()


def curl_https_text(host: str, url: str, timeout: int = 12) -> str:
    ip = resolve_ipv4(host)
    return run_probe_curl([
        "-4", "-sS", "--fail",
        "--connect-timeout", "5",
        "--max-time", str(timeout),
        "--resolve", f"{host}:443:{ip}",
        url,
    ], timeout=timeout + 5)


def curl_https_metric(
    host: str,
    url: str,
    metric: str,
    timeout: int = 15,
    extra: list[str] | None = None,
    input_bytes: bytes | None = None,
) -> float:
    ip = resolve_ipv4(host)
    args = [
        "-4", "-sS", "--fail",
        "--connect-timeout", "5",
        "--max-time", str(timeout),
        "--resolve", f"{host}:443:{ip}",
    ]
    if extra:
        args.extend(extra)
    args.extend(["-o", "/dev/null", "-w", f"%{{{metric}}}", url])
    return float(run_probe_curl(args, timeout=timeout + 5, input_bytes=input_bytes))


def ip_metadata(exit_ip: str) -> dict:
    if exit_ip in IP_META_CACHE:
        return IP_META_CACHE[exit_ip]
    url = (
        f"http://ip-api.com/json/{exit_ip}"
        "?fields=status,message,country,countryCode,isp,org,as,asname,mobile,proxy,hosting,query"
    )
    req = urllib.request.Request(url, headers={"User-Agent": f"GateSocks/{VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=7) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
            if data.get("status") == "success":
                IP_META_CACHE[exit_ip] = data
                return data
    except Exception:
        pass
    return {}


def sanitized_ovpn(config_b64: str) -> str:
    try:
        text = base64.b64decode(config_b64).decode("utf-8", errors="replace")
    except Exception as exc:
        raise RuntimeError(f"OpenVPN 配置解码失败：{exc}") from exc

    blocked = {
        "up", "down", "route-up", "ipchange", "learn-address",
        "client-connect", "client-disconnect", "plugin", "script-security",
        "management", "management-client-user", "management-client-group",
        "redirect-gateway", "route", "route-ipv6", "dhcp-option",
        "pull-filter", "dev", "dev-type", "config", "cd", "chroot",
        "daemon", "log", "log-append", "status", "writepid", "user", "group",
        "askpass", "auth-user-pass", "http-proxy", "http-proxy-user-pass",
        "socks-proxy", "tls-crypt-v2-verify",
    }
    output = []
    in_inline = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("<") and not line.startswith("</"):
            in_inline = True
            output.append(raw)
            continue
        if in_inline:
            output.append(raw)
            if line.startswith("</"):
                in_inline = False
            continue
        if not line or line.startswith("#") or line.startswith(";"):
            output.append(raw)
            continue
        key = line.split(None, 1)[0].lower()
        if key in blocked:
            continue
        output.append(raw)
    return "\n".join(output) + "\n"


def build_openvpn_command(config_path: Path, tun_name: str) -> list[str]:
    return [
        "openvpn",
        "--config", str(config_path),
        "--dev", tun_name,
        "--dev-type", "tun",
        "--disable-dco",
        "--route-nopull",
        "--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM",
        "--cipher", "AES-128-CBC",
        "--connect-retry-max", "1",
        "--reneg-sec", "0",
        "--auth-nocache",
        "--verb", "3",
    ]


def cleanup_probe_route() -> None:
    subprocess.run(
        ["ip", "rule", "del", "priority", str(PROBE_RULE_PRIORITY), "uidrange", f"{PROBE_UID}-{PROBE_UID}", "lookup", str(PROBE_TABLE)],
        capture_output=True,
    )
    subprocess.run(["ip", "route", "flush", "table", str(PROBE_TABLE)], capture_output=True)


def install_probe_route(tun_name: str) -> None:
    cleanup_probe_route()
    subprocess.run(
        ["ip", "route", "replace", "default", "dev", tun_name, "table", str(PROBE_TABLE)],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        ["ip", "rule", "add", "priority", str(PROBE_RULE_PRIORITY), "uidrange", f"{PROBE_UID}-{PROBE_UID}", "lookup", str(PROBE_TABLE)],
        check=True, capture_output=True, text=True,
    )


def test_one_node(node: dict) -> dict:
    node_id = str(node.get("id", "unknown"))
    tun_name = "tun-gstest0"
    tested_at = datetime.now(timezone.utc).isoformat()
    work_dir = Path(tempfile.mkdtemp(prefix="gatesocks-test-"))
    config_path = work_dir / "node.ovpn"
    log_path = work_dir / "openvpn.log"
    proc = None
    log_handle = None
    result = {
        "node_id": node_id,
        "country_short": node.get("country_short"),
        "source_ip": node.get("ip"),
        "tested_at": tested_at,
        "status": "unavailable",
        "exit_ip": None,
        "isp": None,
        "asn": None,
        "residential_hint": "未知",
        "risk": "未知",
        "latency_ms": None,
        "download_mbps": None,
        "upload_mbps": None,
        "stability_percent": 0,
        "error": None,
        "evidence": {
            "candidate_source": "VPN Gate",
            "exit_ip_source": None,
            "speed_source": "Cloudflare speed.cloudflare.com",
            "ip_intel_source": "ip-api.com",
            "ip_intel_fields": {"hosting": None, "proxy": None, "mobile": None},
        },
    }

    try:
        config_path.write_text(sanitized_ovpn(str(node.get("openvpn_config_b64", ""))), encoding="utf-8")
        log_handle = log_path.open("w", encoding="utf-8")
        cmd = build_openvpn_command(config_path, tun_name)
        proc = subprocess.Popen(cmd, stdout=log_handle, stderr=subprocess.STDOUT, text=True)

        deadline = time.time() + TEST_CONNECT_TIMEOUT
        connected = False
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            try:
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                log_text = ""
            if "Initialization Sequence Completed" in log_text and Path(f"/sys/class/net/{tun_name}").exists():
                connected = True
                break
            time.sleep(0.5)

        if log_handle:
            log_handle.flush()
        if not connected:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-700:]
            raise RuntimeError("OpenVPN 未建立隧道：" + tail.replace("\n", " ")[-500:])

        install_probe_route(tun_name)

        exit_ip = ""
        exit_host = ""
        exit_url = ""
        for host, url in [
            ("api.ipify.org", "https://api.ipify.org"),
            ("icanhazip.com", "https://icanhazip.com"),
        ]:
            try:
                candidate = curl_https_text(host, url, timeout=10).strip()
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", candidate):
                    exit_ip, exit_host, exit_url = candidate, host, url
                    break
            except Exception:
                continue
        if not exit_ip:
            raise RuntimeError("隧道已建立，但无法通过隧道读取公网出口 IP")

        result["exit_ip"] = exit_ip
        result["evidence"]["exit_ip_source"] = exit_host

        try:
            latency_samples = [
                curl_https_metric(exit_host, exit_url, "time_connect", timeout=10)
                for _ in range(3)
            ]
            result["latency_ms"] = round(statistics.median(latency_samples) * 1000, 1)
        except Exception:
            pass

        success_checks = 1
        for _ in range(2):
            try:
                check_ip = curl_https_text(exit_host, exit_url, timeout=8).strip()
                if check_ip == exit_ip:
                    success_checks += 1
            except Exception:
                pass
        result["stability_percent"] = round(success_checks / 3 * 100)

        try:
            speed_bps = curl_https_metric(
                "speed.cloudflare.com",
                f"https://speed.cloudflare.com/__down?bytes={TEST_DOWNLOAD_BYTES}",
                "speed_download",
                timeout=15,
            )
            result["download_mbps"] = round(speed_bps * 8 / 1_000_000, 2)
        except Exception:
            pass

        try:
            speed_bps = curl_https_metric(
                "speed.cloudflare.com",
                "https://speed.cloudflare.com/__up",
                "speed_upload",
                timeout=15,
                extra=["-X", "POST", "--data-binary", "@-"],
                input_bytes=b"0" * TEST_UPLOAD_BYTES,
            )
            result["upload_mbps"] = round(speed_bps * 8 / 1_000_000, 2)
        except Exception:
            pass

        meta = ip_metadata(exit_ip)
        if meta:
            result["isp"] = meta.get("isp") or meta.get("org")
            result["asn"] = meta.get("as") or meta.get("asname")
        residential_hint, risk, intel_fields = classify_ip_meta(meta)
        result["residential_hint"] = residential_hint
        result["risk"] = risk
        result["evidence"]["ip_intel_fields"] = intel_fields

        result["status"] = "available" if result["stability_percent"] >= 67 else "unavailable"
        return result
    except Exception as exc:
        result["error"] = str(exc)[-700:]
        return result
    finally:
        cleanup_probe_route()
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
        if log_handle:
            log_handle.close()
        subprocess.run(["ip", "link", "del", tun_name], capture_output=True)
        try:
            for child in work_dir.iterdir():
                child.unlink(missing_ok=True)
            work_dir.rmdir()
        except Exception:
            pass


def run_test_batch(nodes_to_test: list[dict]) -> None:
    try:
        for index, node in enumerate(nodes_to_test, start=1):
            with TEST_LOCK:
                TEST_JOB["current_id"] = node.get("id")
                TEST_JOB["completed"] = index - 1
            result = test_one_node(node)
            save_test_result(result)
            with TEST_LOCK:
                TEST_JOB["completed"] = index
                if result.get("error"):
                    TEST_JOB["last_error"] = result["error"]
    finally:
        cleanup_probe_route()
        with TEST_LOCK:
            TEST_JOB["running"] = False
            TEST_JOB["current_id"] = None
            TEST_JOB["finished_at"] = datetime.now(timezone.utc).isoformat()



def read_socks_instances() -> list[dict]:
    try:
        if SOCKS_INSTANCES_FILE.exists():
            data = json.loads(SOCKS_INSTANCES_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def save_socks_instances(items: list[dict]) -> None:
    atomic_write_json(SOCKS_INSTANCES_FILE, items, private=True)


def find_cached_node(node_id: str) -> dict | None:
    return next((item for item in read_node_cache().get("items", []) if str(item.get("id")) == str(node_id)), None)


def latest_node_test(node_id: str) -> dict | None:
    return next((item for item in read_test_results() if str(item.get("node_id")) == str(node_id)), None)


def instance_network_values(port: int) -> dict:
    slot = int(port) - SOCKS_START + 1
    if slot < 1 or int(port) > SOCKS_END:
        raise ValueError("SOCKS5 port is outside the configured pool")
    return {
        "tun_name": f"gst{int(port)}",
        "mark": SOCKS_MARK_BASE + slot,
        "route_table": SOCKS_TABLE_BASE + slot,
        "rule_priority": SOCKS_RULE_PRIORITY_BASE + slot,
    }


def build_socks_uri(host: str, port: int, username: str, password: str) -> str:
    target = str(host).strip()
    if ":" in target and not target.startswith("["):
        target = f"[{target}]"
    return f"socks5://{quote(str(username), safe='')}:{quote(str(password), safe='')}@{target}:{int(port)}"


def is_tcp_port_free(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", int(port)))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def allocate_socks_port(items: list[dict] | None = None) -> int:
    items = items if items is not None else read_socks_instances()
    reserved = {int(item.get("port", 0)) for item in items if item.get("port")}
    for port in range(SOCKS_START, SOCKS_END + 1):
        if port not in reserved and is_tcp_port_free(port):
            return port
    raise RuntimeError("SOCKS5 正式端口池已满或端口均被占用")


def detect_public_host() -> str:
    if PUBLIC_HOST_ENV:
        return PUBLIC_HOST_ENV
    now = time.time()
    if PUBLIC_HOST_CACHE.get("value") and now - float(PUBLIC_HOST_CACHE.get("checked_at", 0)) < 3600:
        return str(PUBLIC_HOST_CACHE["value"])
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": f"GateSocks/{VERSION}"})
        with urllib.request.urlopen(req, timeout=6) as response:
            value = response.read().decode("utf-8", errors="replace").strip()
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
            PUBLIC_HOST_CACHE["value"] = value
            PUBLIC_HOST_CACHE["checked_at"] = now
            return value
    except Exception:
        pass
    return ""


def persist_socks_instance(instance: dict) -> None:
    items = read_socks_instances()
    replaced = False
    for index, item in enumerate(items):
        if item.get("id") == instance.get("id"):
            items[index] = instance
            replaced = True
            break
    if not replaced:
        items.append(instance)
    save_socks_instances(items)


def cleanup_instance_policy(instance: dict) -> None:
    priority = str(instance.get("rule_priority", ""))
    table = str(instance.get("route_table", ""))
    if priority:
        for _ in range(2):
            proc = subprocess.run(["ip", "rule", "del", "priority", priority], capture_output=True)
            if proc.returncode != 0:
                break
    if table:
        subprocess.run(["ip", "route", "flush", "table", table], capture_output=True)


def install_instance_policy(instance: dict) -> None:
    cleanup_instance_policy(instance)
    subprocess.run(
        ["ip", "route", "replace", "default", "dev", str(instance["tun_name"]), "table", str(instance["route_table"])],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        ["ip", "rule", "add", "priority", str(instance["rule_priority"]), "fwmark", str(instance["mark"]), "lookup", str(instance["route_table"])],
        check=True, capture_output=True, text=True,
    )


def terminate_process(proc: subprocess.Popen | None, timeout: int = 4) -> None:
    if not proc or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=2)
        except Exception:
            pass


def cleanup_instance_runtime(instance: dict) -> None:
    runtime = SOCKS_RUNTIME.pop(str(instance.get("id")), None)
    if runtime:
        terminate_process(runtime.get("socks"))
        terminate_process(runtime.get("openvpn"))
        for key in ("socks_log_handle", "openvpn_log_handle"):
            handle = runtime.get(key)
            try:
                if handle:
                    handle.close()
            except Exception:
                pass
    cleanup_instance_policy(instance)
    tun_name = str(instance.get("tun_name", ""))
    if tun_name:
        subprocess.run(["ip", "link", "del", tun_name], capture_output=True)


def wait_openvpn_ready(proc: subprocess.Popen, log_path: Path, tun_name: str) -> None:
    deadline = time.time() + SOCKS_CONNECT_TIMEOUT
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            log_text = ""
        if "Initialization Sequence Completed" in log_text and Path(f"/sys/class/net/{tun_name}").exists():
            return
        time.sleep(0.5)
    try:
        tail = log_path.read_text(encoding="utf-8", errors="replace")[-900:]
    except Exception:
        tail = ""
    raise RuntimeError("OpenVPN 未建立长期隧道：" + tail.replace("\n", " ")[-650:])


def wait_socks_listener(proc: subprocess.Popen, port: int) -> None:
    deadline = time.time() + 5
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("SOCKS5 进程启动后立即退出")
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=0.4):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("SOCKS5 监听端口未就绪")


def proxy_curl(instance: dict, args: list[str], timeout: int = 18, input_bytes: bytes | None = None) -> str:
    cmd = [
        "curl", "-4", "-sS", "--fail",
        "--connect-timeout", "6",
        "--max-time", str(timeout),
        "--socks5-hostname", f"127.0.0.1:{int(instance['port'])}",
        "--proxy-user", f"{instance['username']}:{instance['password']}",
    ] + args
    proc = subprocess.run(cmd, input=input_bytes, capture_output=True, timeout=timeout + 5)
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError((stderr or stdout or "SOCKS5 curl failed").strip()[-300:])
    return stdout.strip()


def probe_socks_instance(instance: dict, full: bool = False) -> dict:
    exit_ip = proxy_curl(instance, ["https://api.ipify.org"], timeout=14).strip()
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", exit_ip):
        raise RuntimeError("SOCKS5 已监听，但无法确认公网出口 IP")
    result = {
        "tested_at": datetime.now(timezone.utc).isoformat(),
        "exit_ip": exit_ip,
        "latency_ms": None,
        "download_mbps": None,
        "upload_mbps": None,
    }
    if full:
        try:
            seconds = float(proxy_curl(instance, ["-o", "/dev/null", "-w", "%{time_appconnect}", "https://api.ipify.org"], timeout=14))
            result["latency_ms"] = round(seconds * 1000, 1)
        except Exception:
            pass
        try:
            speed = float(proxy_curl(instance, ["-o", "/dev/null", "-w", "%{speed_download}", "https://speed.cloudflare.com/__down?bytes=1000000"], timeout=18))
            result["download_mbps"] = round(speed * 8 / 1_000_000, 2)
        except Exception:
            pass
        try:
            speed = float(proxy_curl(
                instance,
                ["-X", "POST", "--data-binary", "@-", "-o", "/dev/null", "-w", "%{speed_upload}", "https://speed.cloudflare.com/__up"],
                timeout=18,
                input_bytes=b"0" * 262144,
            ))
            result["upload_mbps"] = round(speed * 8 / 1_000_000, 2)
        except Exception:
            pass
    return result


def runtime_active(instance_id: str) -> bool:
    runtime = SOCKS_RUNTIME.get(str(instance_id))
    if not runtime:
        return False
    vpn = runtime.get("openvpn")
    socks_proc = runtime.get("socks")
    return bool(vpn and socks_proc and vpn.poll() is None and socks_proc.poll() is None)


def public_socks_instance(instance: dict) -> dict:
    item = {k: v for k, v in instance.items() if k not in {"config_path"}}
    host = detect_public_host()
    item["runtime_active"] = runtime_active(str(instance.get("id")))
    if item.get("status") == "online" and not item["runtime_active"]:
        item["status"] = "starting" if item.get("enabled") else "stopped"
    item["local_host"] = "127.0.0.1"
    item["host"] = host
    item["address"] = host
    item["local_uri"] = build_socks_uri("127.0.0.1", item["port"], item["username"], item["password"])
    item["url"] = build_socks_uri(host, item["port"], item["username"], item["password"]) if host else ""
    return item


def start_socks_instance(instance_id: str) -> dict:
    with SOCKS_LOCK:
        items = read_socks_instances()
        instance = next((item for item in items if item.get("id") == instance_id), None)
        if not instance:
            raise KeyError("SOCKS5 实例不存在")
        cleanup_instance_runtime(instance)
        instance["status"] = "starting"
        instance["enabled"] = True
        instance["last_error"] = None
        persist_socks_instance(instance)
        work_dir = SOCKS_DATA_DIR / instance_id
        config_path = work_dir / "node.ovpn"
        openvpn_log = work_dir / "openvpn.log"
        socks_log = work_dir / "socks.log"
        if not config_path.exists():
            instance["status"] = "error"
            instance["enabled"] = False
            instance["last_error"] = "持久化 OpenVPN 配置不存在"
            persist_socks_instance(instance)
            return public_socks_instance(instance)
        try:
            openvpn_handle = openvpn_log.open("a", encoding="utf-8")
            openvpn_handle.write(f"\n=== GateSocks start {datetime.now(timezone.utc).isoformat()} ===\n")
            openvpn_handle.flush()
            vpn_proc = subprocess.Popen(build_openvpn_command(config_path, str(instance["tun_name"])), stdout=openvpn_handle, stderr=subprocess.STDOUT, text=True)
            SOCKS_RUNTIME[instance_id] = {"openvpn": vpn_proc, "socks": None, "openvpn_log_handle": openvpn_handle, "socks_log_handle": None}
            wait_openvpn_ready(vpn_proc, openvpn_log, str(instance["tun_name"]))
            install_instance_policy(instance)
            socks_handle = socks_log.open("a", encoding="utf-8")
            socks_handle.write(f"\n=== GateSocks start {datetime.now(timezone.utc).isoformat()} ===\n")
            socks_handle.flush()
            socks_proc = subprocess.Popen(
                ["python", str(SOCKS_SERVER_SCRIPT), "--bind", "0.0.0.0", "--port", str(instance["port"]), "--username", str(instance["username"]), "--password", str(instance["password"]), "--mark", str(instance["mark"])],
                stdout=socks_handle, stderr=subprocess.STDOUT, text=True,
            )
            SOCKS_RUNTIME[instance_id]["socks"] = socks_proc
            SOCKS_RUNTIME[instance_id]["socks_log_handle"] = socks_handle
            wait_socks_listener(socks_proc, int(instance["port"]))
            probe = probe_socks_instance(instance, full=False)
            instance["exit_ip"] = probe["exit_ip"]
            meta = ip_metadata(probe["exit_ip"])
            if meta:
                instance["isp"] = meta.get("isp") or meta.get("org")
                instance["asn"] = meta.get("as") or meta.get("asname")
            instance["status"] = "online"
            instance["enabled"] = True
            instance["started_at"] = datetime.now(timezone.utc).isoformat()
            instance["last_probe"] = probe
            instance["last_error"] = None
        except Exception as exc:
            cleanup_instance_runtime(instance)
            instance["status"] = "error"
            instance["enabled"] = False
            instance["last_error"] = str(exc)[-900:]
        persist_socks_instance(instance)
        return public_socks_instance(instance)


def stop_socks_instance(instance_id: str) -> dict:
    with SOCKS_LOCK:
        items = read_socks_instances()
        instance = next((item for item in items if item.get("id") == instance_id), None)
        if not instance:
            raise KeyError("SOCKS5 实例不存在")
        cleanup_instance_runtime(instance)
        instance["status"] = "stopped"
        instance["enabled"] = False
        instance["stopped_at"] = datetime.now(timezone.utc).isoformat()
        persist_socks_instance(instance)
        return public_socks_instance(instance)


def retest_socks_instance(instance_id: str) -> dict:
    with SOCKS_LOCK:
        items = read_socks_instances()
        instance = next((item for item in items if item.get("id") == instance_id), None)
        if not instance:
            raise KeyError("SOCKS5 实例不存在")
        if not runtime_active(instance_id):
            raise RuntimeError("实例当前未运行，请先启动 SOCKS5")
        probe = probe_socks_instance(instance, full=True)
        instance["exit_ip"] = probe["exit_ip"]
        instance["last_probe"] = probe
        meta = ip_metadata(probe["exit_ip"])
        if meta:
            instance["isp"] = meta.get("isp") or meta.get("org")
            instance["asn"] = meta.get("as") or meta.get("asname")
        persist_socks_instance(instance)
        return public_socks_instance(instance)


def delete_socks_instance(instance_id: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{12}", str(instance_id)):
        raise KeyError("SOCKS5 实例不存在")
    with SOCKS_LOCK:
        items = read_socks_instances()
        instance = next((item for item in items if item.get("id") == instance_id), None)
        if not instance:
            raise KeyError("SOCKS5 实例不存在")
        cleanup_instance_runtime(instance)
        save_socks_instances([item for item in items if item.get("id") != instance_id])
        shutil.rmtree(SOCKS_DATA_DIR / instance_id, ignore_errors=True)


def restore_enabled_socks_instances() -> None:
    for item in read_socks_instances():
        if item.get("enabled"):
            try:
                start_socks_instance(str(item["id"]))
            except Exception:
                pass


def stop_all_socks_runtime() -> None:
    with SOCKS_LOCK:
        for instance in read_socks_instances():
            try:
                cleanup_instance_runtime(instance)
            except Exception:
                pass


@app.on_event("startup")
def restore_socks_on_startup():
    threading.Thread(target=restore_enabled_socks_instances, daemon=True).start()


@app.on_event("shutdown")
def cleanup_socks_on_shutdown():
    stop_all_socks_runtime()


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


@app.get("/api/data-sources")
def data_sources():
    return DATA_SOURCES


@app.get("/api/nodes/selected")
def selected_node():
    selected = read_selected_node()
    if not selected.get("node_id"):
        return {"selected": None}
    payload = nodes_response(read_node_cache())
    node = next((item for item in payload["items"] if item.get("id") == selected["node_id"]), None)
    if node:
        return {"selected": node, "selected_at": selected.get("selected_at")}
    return {"selected": selected, "stale": True}


@app.post("/api/nodes/select")
async def select_node(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid request"}, status_code=400)

    node_id = str(data.get("node_id", "")).strip()
    cache = read_node_cache()
    node = next((item for item in cache.get("items", []) if str(item.get("id")) == node_id), None)
    if not node:
        return JSONResponse({"detail": "节点不存在或已从当前候选池消失"}, status_code=404)

    selected = {
        "node_id": node_id,
        "ip": node.get("ip"),
        "hostname": node.get("hostname"),
        "country_short": node.get("country_short"),
        "selected_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_json(SELECTED_NODE_FILE, selected)
    return {
        "ok": True,
        "message": "节点已选择；测试结果仅供参考，不限制手动选择。",
        "selected": selected,
    }


@app.delete("/api/nodes/selected")
def clear_selected_node():
    try:
        SELECTED_NODE_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    return {"ok": True}


@app.post("/api/tests/start")
async def start_tests(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}

    with TEST_LOCK:
        if TEST_JOB["running"]:
            return JSONResponse({"detail": "已有实测任务正在运行"}, status_code=409)

    cache = read_node_cache()
    by_id = {str(item.get("id")): item for item in cache.get("items", [])}
    requested = []
    seen = set()
    for value in data.get("ids", []):
        node_id = str(value)
        if node_id in by_id and node_id not in seen:
            requested.append(node_id)
            seen.add(node_id)

    if not requested:
        return JSONResponse({"detail": "请先在节点池勾选要实测的 IP"}, status_code=400)

    selected_ids = requested[:max(1, TEST_MAX_BATCH)]
    selected = [by_id[node_id] for node_id in selected_ids]

    if not selected:
        return JSONResponse({"detail": "没有可测试的候选节点"}, status_code=400)

    with TEST_LOCK:
        TEST_JOB.update({
            "running": True,
            "total": len(selected),
            "completed": 0,
            "current_id": None,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "last_error": None,
        })

    thread = threading.Thread(target=run_test_batch, args=(selected,), daemon=True)
    thread.start()
    return {"ok": True, "total": len(selected), "message": f"实测任务已启动：{len(selected)} 个手动选择节点"}


@app.get("/api/tests/status")
def test_status():
    with TEST_LOCK:
        return dict(TEST_JOB)


@app.post("/api/qr")
async def qr_code(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid request"}, status_code=400)

    text = str(data.get("text", ""))
    label = str(data.get("label", "")).strip()
    try:
        svg = build_qr_svg(text)
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "X-QR-Label": label[:120],
        },
    )

@app.get("/api/socks")
def socks():
    with SOCKS_LOCK:
        items = [public_socks_instance(item) for item in read_socks_instances()]
    return {
        "items": items,
        "count": len(items),
        "port_pool": {"start": SOCKS_START, "end": SOCKS_END},
        "qr_supported": True,
        "public_host": detect_public_host(),
        "message": None if items else "尚未生成 SOCKS5 实例。",
    }


@app.post("/api/socks")
async def create_socks(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    node_id = str(data.get("node_id") or read_selected_node().get("node_id") or "").strip()
    if not node_id:
        return JSONResponse({"detail": "请先在节点池点击一个 IP，设置为待生成节点"}, status_code=400)
    node = find_cached_node(node_id)
    if not node:
        return JSONResponse({"detail": "待生成节点已不在当前候选池，请重新选择 IP"}, status_code=404)
    with SOCKS_LOCK:
        items = read_socks_instances()
        duplicate = next((item for item in items if str(item.get("node_id")) == node_id), None)
        if duplicate:
            return JSONResponse({"detail": f"该节点已经生成 SOCKS5 实例：{duplicate.get('name') or duplicate.get('id')}"}, status_code=409)
        try:
            port = allocate_socks_port(items)
        except RuntimeError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=409)
        instance_id = secrets.token_hex(6)
        network = instance_network_values(port)
        work_dir = SOCKS_DATA_DIR / instance_id
        work_dir.mkdir(parents=True, exist_ok=False)
        config_path = work_dir / "node.ovpn"
        try:
            config_path.write_text(sanitized_ovpn(str(node.get("openvpn_config_b64", ""))), encoding="utf-8")
            os.chmod(config_path, 0o600)
        except Exception as exc:
            shutil.rmtree(work_dir, ignore_errors=True)
            return JSONResponse({"detail": f"OpenVPN 配置准备失败：{exc}"}, status_code=500)
        previous_test = latest_node_test(node_id) or {}
        instance = {
            "id": instance_id,
            "name": f"{node.get('country_short') or 'NODE'}-{port}",
            "node_id": node_id,
            "country_short": node.get("country_short"),
            "source_ip": node.get("ip"),
            "source_hostname": node.get("hostname"),
            "port": port,
            "username": "gs_" + secrets.token_hex(4),
            "password": secrets.token_urlsafe(18),
            "status": "created",
            "enabled": True,
            "exit_ip": previous_test.get("exit_ip"),
            "isp": previous_test.get("isp"),
            "asn": previous_test.get("asn"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "started_at": None,
            "stopped_at": None,
            "last_error": None,
            "last_probe": None,
            "config_path": str(config_path),
            **network,
        }
        items.append(instance)
        save_socks_instances(items)
    item = start_socks_instance(instance_id)
    return JSONResponse({"ok": item.get("status") == "online", "instance": item}, status_code=201)


@app.post("/api/socks/{instance_id}/start")
def start_socks(instance_id: str):
    try:
        return {"ok": True, "instance": start_socks_instance(instance_id)}
    except KeyError as exc:
        return JSONResponse({"detail": str(exc).strip("'")}, status_code=404)


@app.post("/api/socks/{instance_id}/stop")
def stop_socks(instance_id: str):
    try:
        return {"ok": True, "instance": stop_socks_instance(instance_id)}
    except KeyError as exc:
        return JSONResponse({"detail": str(exc).strip("'")}, status_code=404)


@app.post("/api/socks/{instance_id}/reconnect")
def reconnect_socks(instance_id: str):
    try:
        stop_socks_instance(instance_id)
        return {"ok": True, "instance": start_socks_instance(instance_id)}
    except KeyError as exc:
        return JSONResponse({"detail": str(exc).strip("'")}, status_code=404)


@app.post("/api/socks/{instance_id}/test")
def test_socks(instance_id: str):
    try:
        return {"ok": True, "instance": retest_socks_instance(instance_id)}
    except KeyError as exc:
        return JSONResponse({"detail": str(exc).strip("'")}, status_code=404)
    except RuntimeError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=409)


@app.delete("/api/socks/{instance_id}")
def delete_socks(instance_id: str):
    try:
        delete_socks_instance(instance_id)
        return {"ok": True, "message": "SOCKS5 实例已删除，端口、隧道、策略路由和实例配置已释放；节点池与历史测试记录保留。"}
    except KeyError as exc:
        return JSONResponse({"detail": str(exc).strip("'")}, status_code=404)



@app.get("/api/openvpn")
def openvpn():
    return {"version": openvpn_version(), "tun_present": os.path.exists("/dev/net/tun"), "tunnels": tun_interfaces()}


@app.get("/api/tests")
def tests():
    items = read_test_results()
    return {"items": items, "count": len(items), "message": None if items else "暂无测试记录。"}


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
            "socks_routing": "socket-fwmark-policy-routing",
            "public_host": detect_public_host(),
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
