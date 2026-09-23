import base64
import unittest
from unittest.mock import patch
from pathlib import Path

import app
import socks_server


class EngineTests(unittest.TestCase):
    def test_vpngate_profile_sanitizer(self):
        raw = """client
dev tun
proto tcp
remote 203.0.113.10 443
route 0.0.0.0 0.0.0.0
redirect-gateway def1
config /etc/passwd
up /tmp/hook.sh
<ca>
CERTDATA
</ca>
"""
        clean = app.sanitized_ovpn(base64.b64encode(raw.encode()).decode())
        self.assertIn("client", clean)
        self.assertIn("remote 203.0.113.10 443", clean)
        self.assertIn("<ca>", clean)
        self.assertNotIn("redirect-gateway", clean)
        self.assertNotIn("config /etc/passwd", clean)
        self.assertNotIn("up /tmp/hook.sh", clean)
        self.assertNotIn("dev tun", clean)

    def test_openvpn_command_has_explicit_tun_and_vpngate_cipher(self):
        cmd = app.build_openvpn_command(Path("/tmp/test.ovpn"), "tun-gstest0")
        joined = " ".join(cmd)
        self.assertIn("--dev tun-gstest0", joined)
        self.assertIn("--dev-type tun", joined)
        self.assertIn("--disable-dco", joined)
        self.assertIn("--route-nopull", joined)
        self.assertIn("--pull-filter ignore route-ipv6", joined)
        self.assertIn("--connect-timeout 10", joined)
        self.assertNotIn("--auth-user-pass", joined)
        self.assertIn("--data-ciphers-fallback AES-128-CBC", joined)
        self.assertIn("CHACHA20-POLY1305", joined)
        self.assertNotIn("--hand-window", joined)

    def test_ip_intel_classification(self):
        hint, risk, evidence = app.classify_ip_meta({"hosting": True, "proxy": False, "mobile": False})
        self.assertEqual(hint, "非住宅/代理倾向")
        self.assertEqual(risk, "公开库已标记")
        self.assertTrue(evidence["hosting"])

        hint, risk, evidence = app.classify_ip_meta({"hosting": False, "proxy": False, "mobile": False})
        self.assertEqual(hint, "未发现机房标记（需复核）")
        self.assertEqual(risk, "未知")

    def test_qr_svg_generation(self):
        svg = app.build_qr_svg("socks5://user:pass@example.com:18001")
        self.assertIn(b"<svg", svg)
        with self.assertRaises(ValueError):
            app.build_qr_svg("")

    def test_qr_response_supports_chinese_ui_labels_without_header_encoding(self):
        response = app.build_qr_response("socks5://user:pass@example.com:18001")
        self.assertEqual(response.media_type, "image/svg+xml")
        self.assertIn(b"<svg", response.body)
        self.assertNotIn("x-qr-label", {key.lower() for key in response.headers.keys()})
        self.assertEqual(response.headers.get("cache-control"), "no-store, max-age=0")

    def test_qr_frontend_surfaces_errors_instead_of_swallowing_them(self):
        source = Path("static/app.js").read_text(encoding="utf-8")
        self.assertIn("function showQrError", source)
        self.assertNotIn("showQr(value,label).catch(()=>{})", source)
        self.assertIn("body:JSON.stringify({text})", source)

    def test_socks_instance_network_values(self):
        values = app.instance_network_values(app.SOCKS_START)
        self.assertEqual(values["tun_name"], f"gst{app.SOCKS_START}")
        self.assertEqual(values["route_table"], app.SOCKS_TABLE_BASE + 1)

    def test_socks_uri_encodes_credentials(self):
        uri = app.build_socks_uri("203.0.113.10", 18001, "u ser", "p@ss")
        self.assertEqual(uri, "socks5://u%20ser:p%40ss@203.0.113.10:18001")

    def test_socks_uri_brackets_ipv6(self):
        uri = app.build_socks_uri("2001:db8::1", 18001, "u", "p")
        self.assertEqual(uri, "socks5://u:p@[2001:db8::1]:18001")

    def test_vpngate_auth_file_is_controlled(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = app.write_vpngate_auth_file(Path(tmp))
            self.assertEqual(auth_path.read_text(encoding="utf-8"), f"{app.VPNGATE_USERNAME}\n{app.VPNGATE_PASSWORD}\n")
            self.assertEqual(auth_path.stat().st_mode & 0o777, 0o600)

    def test_profile_auth_path_is_not_trusted(self):
        raw = """client
auth-user-pass /etc/shadow
remote 203.0.113.10 443
"""
        clean = app.sanitized_ovpn(base64.b64encode(raw.encode()).decode())
        self.assertNotIn("auth-user-pass", clean)
        self.assertIn("remote 203.0.113.10 443", clean)

    def test_openvpn_command_adds_auth_only_when_requested(self):
        cmd = app.build_openvpn_command(
            Path("/tmp/test.ovpn"),
            "tun-gstest0",
            Path("/tmp/vpngate.auth"),
        )
        self.assertIn("--auth-user-pass /tmp/vpngate.auth", " ".join(cmd))

    def test_vpngate_profile_auth_detection(self):
        no_auth = "client\nremote 203.0.113.10 443\n"
        with_auth = "client\nauth-user-pass\nremote 203.0.113.10 443\n"
        self.assertFalse(app.vpngate_profile_requests_auth(base64.b64encode(no_auth.encode()).decode()))
        self.assertTrue(app.vpngate_profile_requests_auth(base64.b64encode(with_auth.encode()).decode()))

    def test_socks_server_binds_outbound_socket_to_tun(self):
        class FakeSocket:
            def __init__(self):
                self.calls = []
            def setsockopt(self, *args):
                self.calls.append(args)

        sock = FakeSocket()
        socks_server.bind_socket_to_interface(sock, "gst18001")
        self.assertTrue(sock.calls)
        level, option, value = sock.calls[0]
        self.assertEqual(level, socks_server.socket.SOL_SOCKET)
        self.assertEqual(option, socks_server.SO_BINDTODEVICE)
        self.assertEqual(value, b"gst18001\x00")

    def test_openvpn_reference_mode_always_accepts_controlled_auth(self):
        cmd = app.build_openvpn_command(
            Path("/tmp/test.ovpn"),
            "gst18001",
            Path("/tmp/vpngate.auth"),
        )
        joined = " ".join(cmd)
        self.assertIn("--auth-user-pass /tmp/vpngate.auth", joined)
        self.assertIn("--pull-filter ignore route-ipv6", joined)
        self.assertIn("--pull-filter ignore ifconfig-ipv6", joined)
        self.assertIn("--route-nopull", joined)

    def test_socks_credentials_can_come_from_environment(self):
        self.assertIn("GATESOCKS_PROXY_USERNAME", Path("socks_server.py").read_text(encoding="utf-8"))
        self.assertIn("GATESOCKS_PROXY_PASSWORD", Path("socks_server.py").read_text(encoding="utf-8"))


    def test_version_comes_from_version_file_not_environment(self):
        expected = Path("VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(app.VERSION, expected)
        self.assertNotIn("GATESOCKS_VERSION", Path("docker-compose.yml").read_text(encoding="utf-8"))

    def test_tun_interfaces_include_gatesocks_gst_devices(self):
        sample = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN mode DEFAULT
3: gst18001: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN mode DEFAULT
4: tun-gstest0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN mode DEFAULT
5: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT
"""
        with patch.object(app, "run", return_value=sample):
            tunnels = app.tun_interfaces()
            names = [item["name"] for item in tunnels]
        self.assertEqual(names, ["gst18001", "tun-gstest0"])
        groups = app.tunnel_groups(tunnels)
        self.assertEqual([item["name"] for item in groups["instance"]], ["gst18001"])
        self.assertEqual([item["name"] for item in groups["test"]], ["tun-gstest0"])
        self.assertEqual(groups["other"], [])

    def test_effective_instance_status_uses_runtime_as_truth(self):
        instance = {"id": "abc", "enabled": True, "status": "online", "last_error": None}
        with patch.object(app, "runtime_active", return_value=False):
            self.assertEqual(app.effective_instance_status(instance), "starting")
        instance["last_error"] = "boom"
        with patch.object(app, "runtime_active", return_value=False):
            self.assertEqual(app.effective_instance_status(instance), "error")
        with patch.object(app, "runtime_active", return_value=True):
            self.assertEqual(app.effective_instance_status(instance), "online")

    def test_port_plan_ui_is_not_hardcoded(self):
        html = Path("static/index.html").read_text(encoding="utf-8")
        js = Path("static/app.js").read_text(encoding="utf-8")
        self.assertIn('id="dashboardSocksPool"', html)
        self.assertIn('id="settingsSocksPool"', html)
        self.assertIn("s.socks_port_pool.start", js)



if __name__ == "__main__":
    unittest.main()
