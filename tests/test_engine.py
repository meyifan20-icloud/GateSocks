import base64
import unittest
from pathlib import Path

import app


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
        self.assertIn("--connect-timeout 15", joined)
        self.assertNotIn("--auth-user-pass", joined)
        self.assertIn("AES-128-CBC", joined)
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

    def test_socks_instance_network_values(self):
        values = app.instance_network_values(app.SOCKS_START)
        self.assertEqual(values["tun_name"], f"gst{app.SOCKS_START}")
        self.assertEqual(values["mark"], app.SOCKS_MARK_BASE + 1)
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


if __name__ == "__main__":
    unittest.main()
