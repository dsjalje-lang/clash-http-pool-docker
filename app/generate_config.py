#!/usr/bin/env python3
"""Build a Mihomo configuration with one authenticated HTTP listener per proxy."""

from __future__ import annotations

import argparse
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

import yaml


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


def fetch_subscription(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "clash-http-pool/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ConfigError(f"Unable to fetch subscription: {error}") from error

    try:
        document = yaml.safe_load(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise ConfigError("Subscription must be a UTF-8 Clash YAML document") from error

    if not isinstance(document, dict):
        raise ConfigError("Subscription root must be a YAML mapping")
    return document


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
