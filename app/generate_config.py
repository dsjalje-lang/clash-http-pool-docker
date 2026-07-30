#!/usr/bin/env python3
"""Build a Mihomo configuration with one authenticated HTTP listener per proxy."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import yaml


DEFAULT_SHADOWROCKET_USER_AGENT = (
    "Shadowrocket/3131 CFNetwork/3860.500.112 Darwin/25.4.0 iPhone16,2"
)


class ConfigError(Exception):
    pass


def environment_value(name: str, *, required: bool = False) -> str:
    file_name = os.environ.get(f"{name}_FILE", "").strip()
    if file_name:
        try:
            value = Path(file_name).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as error:
            raise ConfigError(f"Unable to read {name}_FILE: {error}") from error
    else:
        value = os.environ.get(name, "")

    if required and not value:
        raise ConfigError(f"{name} or {name}_FILE is required")
    return value


def positive_integer(name: str, default: int) -> int:
    value = os.environ.get(name, str(default))
    try:
        number = int(value)
    except ValueError as error:
        raise ConfigError(f"{name} must be an integer") from error
    if number < 1:
        raise ConfigError(f"{name} must be positive")
    return number


def subscription_headers() -> dict[str, str]:
    headers = {
        "User-Agent": environment_value("SUBSCRIPTION_USER_AGENT")
        or DEFAULT_SHADOWROCKET_USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    raw_headers = environment_value("SUBSCRIPTION_HEADERS")
    if not raw_headers:
        return headers

    try:
        extra_headers = json.loads(raw_headers)
    except json.JSONDecodeError as error:
        raise ConfigError("SUBSCRIPTION_HEADERS must be a JSON object") from error
    if not isinstance(extra_headers, dict):
        raise ConfigError("SUBSCRIPTION_HEADERS must be a JSON object")

    for key, value in extra_headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ConfigError("SUBSCRIPTION_HEADERS keys and values must be strings")
        if not key or "\r" in key or "\n" in key or "\r" in value or "\n" in value:
            raise ConfigError("SUBSCRIPTION_HEADERS contains an invalid header")
        headers[key] = value
    return headers


def decode_base64(value: str, description: str) -> str:
    compact = re.sub(r"\s+", "", value)
    if not compact:
        raise ConfigError(f"{description} is empty")
    normalized = compact.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError) as error:
        raise ConfigError(f"{description} is not valid UTF-8 Base64") from error


def split_host_port(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator:
        raise ConfigError("Shadowsocks URI is missing a port")
    host = host.strip("[]")
    if not host:
        raise ConfigError("Shadowsocks URI is missing a server")
    try:
        port = int(port_text)
    except ValueError as error:
        raise ConfigError("Shadowsocks URI has an invalid port") from error
    if not 1 <= port <= 65535:
        raise ConfigError("Shadowsocks URI port is outside 1-65535")
    return host, port


def parse_ss_plugin(query: str) -> dict[str, Any]:
    plugin_values = parse_qs(query, keep_blank_values=True).get("plugin", [])
    if not plugin_values:
        return {}

    fields = unquote(plugin_values[-1]).split(";")
    plugin = fields[0].strip()
    if not plugin:
        raise ConfigError("Shadowsocks URI plugin is empty")

    options: dict[str, Any] = {}
    for field in fields[1:]:
        if not field:
            continue
        key, separator, value = field.partition("=")
        options[key] = value if separator else True

    if plugin in {"obfs-local", "simple-obfs"}:
        plugin = "obfs"
    if "obfs" in options:
        options["mode"] = options.pop("obfs")
    if "obfs-host" in options:
        options["host"] = options.pop("obfs-host")
    return {"plugin": plugin, "plugin-opts": options}


def parse_ss_uri(uri: str, index: int) -> dict[str, Any]:
    parts = urlsplit(uri)
    authority = parts.netloc
    if not authority:
        raise ConfigError("Shadowsocks URI is missing its authority")

    if "@" in authority:
        encoded_credentials, server_port = authority.rsplit("@", 1)
        credentials = decode_base64(unquote(encoded_credentials), "Shadowsocks credentials")
    else:
        legacy = decode_base64(unquote(authority), "legacy Shadowsocks URI")
        credentials, separator, server_port = legacy.rpartition("@")
        if not separator:
            raise ConfigError("Legacy Shadowsocks URI is missing its server")

    cipher, separator, password = credentials.partition(":")
    if not separator or not cipher or not password:
        raise ConfigError("Shadowsocks URI must contain cipher and password")

    server, port = split_host_port(server_port)
    name = unquote(parts.fragment).strip() or f"ss-{index}"
    proxy: dict[str, Any] = {
        "name": name,
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": cipher,
        "password": password,
        "udp": True,
    }
    proxy.update(parse_ss_plugin(parts.query))
    return proxy


def query_value(query: dict[str, list[str]], *keys: str) -> str | None:
    for key in keys:
        values = query.get(key)
        if values and values[-1]:
            return values[-1]
    return None


def query_boolean(query: dict[str, list[str]], default: bool, *keys: str) -> bool:
    value = query_value(query, *keys)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_anytls_uri(uri: str, index: int) -> dict[str, Any]:
    parts = urlsplit(uri)
    if "@" not in parts.netloc:
        raise ConfigError("AnyTLS URI must include a password and server")

    password, server_port = parts.netloc.rsplit("@", 1)
    password = unquote(password)
    if not password:
        raise ConfigError("AnyTLS URI password is empty")

    server, port = split_host_port(server_port)
    query = parse_qs(parts.query, keep_blank_values=True)
    name = unquote(parts.fragment).strip() or f"anytls-{index}"
    proxy: dict[str, Any] = {
        "name": name,
        "type": "anytls",
        "server": server,
        "port": port,
        "password": password,
        "udp": query_boolean(query, True, "udp"),
        "skip-cert-verify": query_boolean(
            query, False, "insecure", "allowInsecure", "skip-cert-verify"
        ),
    }
    sni = query_value(query, "sni", "peer")
    if sni:
        proxy["sni"] = sni
    return proxy


def unique_proxy_names(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for proxy in proxies:
        name = proxy["name"]
        count = counts.get(name, 0) + 1
        counts[name] = count
        if count > 1:
            proxy["name"] = f"{name} [{count}]"
    return proxies


def parse_uri_subscription(text: str) -> dict[str, Any]:
    compact = text.strip()
    if re.fullmatch(r"[A-Za-z0-9+/=_\r\n-]+", compact):
        compact = decode_base64(compact, "Subscription response")

    links = [
        line.strip()
        for line in compact.splitlines()
        if line.strip()
        and not line.startswith("#")
        and not re.match(r"^(?:STATUS|REMARKS)=", line.strip(), re.IGNORECASE)
    ]
    if not links:
        raise ConfigError("Subscription has no proxy links")

    unsupported: set[str] = set()
    proxies: list[dict[str, Any]] = []
    for index, link in enumerate(links, start=1):
        scheme = urlsplit(link).scheme.lower()
        if scheme == "ss":
            proxies.append(parse_ss_uri(link, index))
        elif scheme == "anytls":
            proxies.append(parse_anytls_uri(link, index))
        else:
            unsupported.add(scheme or "unrecognized")

    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise ConfigError(f"Unsupported URI subscription scheme(s): {names}")
    return {"proxies": unique_proxy_names(proxies)}


def parse_subscription(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ConfigError("Subscription must be UTF-8 text") from error

    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ConfigError("Subscription is neither valid Clash YAML nor a URI list") from error

    if isinstance(document, dict):
        return document
    return parse_uri_subscription(text)


def fetch_subscription(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=subscription_headers())
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ConfigError(f"Unable to fetch subscription: {error}") from error

    return parse_subscription(payload)


def load_previous_ports(path: Path) -> dict[str, int]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError):
        return {}

    records = document.get("proxies", []) if isinstance(document, dict) else []
    if not isinstance(records, list):
        return {}

    ports: dict[str, int] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        name, port = record.get("name"), record.get("port")
        if isinstance(name, str) and isinstance(port, int):
            ports[name] = port
    return ports


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False, newline=""
    ) as temporary:
        temporary.write(content)
        temporary_path = Path(temporary.name)
    temporary_path.replace(path)


def atomic_write_json(path: Path, document: dict[str, Any]) -> None:
    content = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    atomic_write_text(path, content)


def atomic_write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False, newline=""
    ) as temporary:
        writer = csv.DictWriter(temporary, fieldnames=["port", "name", "endpoint"])
        writer.writeheader()
        writer.writerows(records)
        temporary_path = Path(temporary.name)
    temporary_path.replace(path)


def proxy_names(config: dict[str, Any], node_filter: str) -> list[str]:
    proxies = config.get("proxies")
    if not isinstance(proxies, list):
        raise ConfigError("Subscription does not contain a proxies list")

    try:
        pattern = re.compile(node_filter) if node_filter else None
    except re.error as error:
        raise ConfigError(f"NODE_FILTER is not a valid regular expression: {error}") from error

    names: list[str] = []
    seen: set[str] = set()
    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        name = proxy.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ConfigError("Every proxy must have a non-empty string name")
        if name in seen:
            raise ConfigError(f"Duplicate proxy name: {name!r}")
        seen.add(name)
        if pattern is None or pattern.search(name):
            names.append(name)

    if not names:
        raise ConfigError("No proxies matched the subscription and NODE_FILTER")
    return names


def assign_ports(
    names: list[str], previous: dict[str, int], port_start: int, maximum: int
) -> list[tuple[str, int]]:
    port_end = port_start + maximum - 1
    if port_end > 65535:
        raise ConfigError("PORT_START + MAX_PROXIES exceeds port 65535")
    if len(names) > maximum:
        raise ConfigError(
            f"Subscription has {len(names)} matched proxies but MAX_PROXIES is {maximum}"
        )

    available = set(range(port_start, port_end + 1))
    assigned: dict[str, int] = {}
    for name in names:
        old_port = previous.get(name)
        if old_port in available:
            assigned[name] = old_port
            available.remove(old_port)

    for name in names:
        if name not in assigned:
            port = min(available)
            assigned[name] = port
            available.remove(port)

    return [(name, assigned[name]) for name in names]


def build_config(
    config: dict[str, Any], assignments: list[tuple[str, int]], username: str, password: str
) -> dict[str, Any]:
    sanitized = dict(config)
    for key in (
        "port",
        "socks-port",
        "mixed-port",
        "redir-port",
        "tproxy-port",
        "tun",
        "listeners",
        "inbounds",
        "tunnels",
        "external-controller",
        "external-controller-tls",
        "secret",
        "external-ui",
        "external-ui-name",
        "external-ui-url",
        "external-doh-server",
        "authentication",
        "skip-auth-prefixes",
    ):
        sanitized.pop(key, None)

    dns = sanitized.get("dns")
    if isinstance(dns, dict):
        sanitized["dns"] = dict(dns)
        sanitized["dns"].pop("listen", None)

    listen_address = os.environ.get("LISTEN_ADDRESS", "0.0.0.0")
    sanitized["allow-lan"] = False
    sanitized["listeners"] = [
        {
            "name": f"http-{port}",
            "type": "http",
            "listen": listen_address,
            "port": port,
            "proxy": name,
            "users": [{"username": username, "password": password}],
        }
        for name, port in assignments
    ]
    return sanitized


def run(arguments: argparse.Namespace) -> int:
    subscription_url = environment_value("SUBSCRIPTION_URL", required=True)
    username = environment_value("HTTP_USERNAME", required=True)
    password = environment_value("HTTP_PASSWORD", required=True)
    port_start = positive_integer("PORT_START", 18000)
    maximum = positive_integer("MAX_PROXIES", 128)

    source = fetch_subscription(subscription_url)
    names = proxy_names(source, os.environ.get("NODE_FILTER", ""))
    previous = load_previous_ports(arguments.mapping_output)
    assignments = assign_ports(names, previous, port_start, maximum)
    rendered = build_config(source, assignments, username, password)

    endpoint_records = [
        {"port": port, "name": name, "endpoint": f"http://HOST:{port}"}
        for name, port in assignments
    ]
    mapping = {
        "generated_at": datetime.now(UTC).isoformat(),
        "proxy_count": len(endpoint_records),
        "port_start": port_start,
        "port_end": port_start + maximum - 1,
        "proxies": endpoint_records,
    }

    yaml_text = yaml.safe_dump(rendered, allow_unicode=True, sort_keys=False)
    atomic_write_text(arguments.output, yaml_text)
    atomic_write_json(arguments.mapping_output, mapping)
    atomic_write_csv(arguments.mapping_output.with_suffix(".csv"), endpoint_records)
    print(f"Rendered {len(endpoint_records)} HTTP proxy listeners.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mapping-output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        return run(arguments)
    except ConfigError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
