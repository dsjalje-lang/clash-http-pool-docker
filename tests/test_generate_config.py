import base64
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import generate_config


class ShadowrocketSubscriptionTests(unittest.TestCase):
    def test_uses_the_reference_shadowrocket_request_headers_by_default(self):
        old_user_agent = os.environ.pop("SUBSCRIPTION_USER_AGENT", None)
        old_headers = os.environ.pop("SUBSCRIPTION_HEADERS", None)
        try:
            headers = generate_config.subscription_headers()
        finally:
            if old_user_agent is not None:
                os.environ["SUBSCRIPTION_USER_AGENT"] = old_user_agent
            if old_headers is not None:
                os.environ["SUBSCRIPTION_HEADERS"] = old_headers

        self.assertEqual(
            headers["User-Agent"], generate_config.DEFAULT_SHADOWROCKET_USER_AGENT
        )
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(headers["Connection"], "close")

    def test_allows_custom_subscription_headers(self):
        old_user_agent = os.environ.get("SUBSCRIPTION_USER_AGENT")
        old_headers = os.environ.get("SUBSCRIPTION_HEADERS")
        try:
            os.environ["SUBSCRIPTION_USER_AGENT"] = "TestClient/1.0"
            os.environ["SUBSCRIPTION_HEADERS"] = '{"X-Subscription-Token":"token"}'
            headers = generate_config.subscription_headers()
        finally:
            if old_user_agent is None:
                os.environ.pop("SUBSCRIPTION_USER_AGENT", None)
            else:
                os.environ["SUBSCRIPTION_USER_AGENT"] = old_user_agent
            if old_headers is None:
                os.environ.pop("SUBSCRIPTION_HEADERS", None)
            else:
                os.environ["SUBSCRIPTION_HEADERS"] = old_headers

        self.assertEqual(headers["User-Agent"], "TestClient/1.0")
        self.assertEqual(headers["X-Subscription-Token"], "token")

    def test_rejects_non_json_custom_headers(self):
        old_headers = os.environ.get("SUBSCRIPTION_HEADERS")
        try:
            os.environ["SUBSCRIPTION_HEADERS"] = "not-json"
            with self.assertRaisesRegex(generate_config.ConfigError, "JSON object"):
                generate_config.subscription_headers()
        finally:
            if old_headers is None:
                os.environ.pop("SUBSCRIPTION_HEADERS", None)
            else:
                os.environ["SUBSCRIPTION_HEADERS"] = old_headers

    def test_parses_base64_legacy_ss_link(self):
        legacy = base64.b64encode(
            b"aes-256-gcm:password@example.com:8388"
        ).decode("ascii")
        response = base64.b64encode(
            f"ss://{legacy}#Legacy%20Node".encode("utf-8")
        )

        config = generate_config.parse_subscription(response)

        self.assertEqual(
            config["proxies"],
            [
                {
                    "name": "Legacy Node",
                    "type": "ss",
                    "server": "example.com",
                    "port": 8388,
                    "cipher": "aes-256-gcm",
                    "password": "password",
                    "udp": True,
                }
            ],
        )

    def test_parses_sip002_ss_link_and_uniquifies_names(self):
        credentials = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:secret").decode(
            "ascii"
        ).rstrip("=")
        links = "\n".join(
            [
                f"ss://{credentials}@one.example:443#Duplicate",
                f"ss://{credentials}@two.example:8443#Duplicate",
            ]
        )

        config = generate_config.parse_subscription(links.encode("utf-8"))

        self.assertEqual([proxy["name"] for proxy in config["proxies"]], ["Duplicate", "Duplicate [2]"])
        self.assertEqual(config["proxies"][0]["server"], "one.example")
        self.assertEqual(config["proxies"][1]["port"], 8443)

    def test_parses_anytls_uri(self):
        config = generate_config.parse_subscription(
            b"STATUS=expire%3A123\nREMARKS=Example\n"
            b"anytls://password@example.com:443?sni=cdn.example&insecure=1&udp=0#AnyTLS%20Node"
        )

        self.assertEqual(
            config["proxies"],
            [
                {
                    "name": "AnyTLS Node",
                    "type": "anytls",
                    "server": "example.com",
                    "port": 443,
                    "password": "password",
                    "udp": False,
                    "skip-cert-verify": True,
                    "sni": "cdn.example",
                }
            ],
        )

    def test_rejects_unsupported_uri_schemes(self):
        with self.assertRaisesRegex(generate_config.ConfigError, "vless"):
            generate_config.parse_subscription(b"vless://not-supported")


if __name__ == "__main__":
    unittest.main()
