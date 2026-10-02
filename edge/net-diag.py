#!/usr/bin/env python3
"""Diagnose the edge device's path to the telemetry backend."""

import argparse
import os
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


def report(layer: str, passed: bool, detail: str) -> None:
    """Print a colored diagnostic result."""

    label = "[OK]" if passed else "[FAIL]"
    if sys.stdout.isatty():
        color = "\033[32m" if passed else "\033[31m"
        label = f"{color}{label}\033[0m"
    print(f"{label} {layer}: {detail}")


def run_command(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run a network utility without invoking a shell."""

    return subprocess.run(arguments, capture_output=True, text=True, timeout=5, check=False)


def check_link() -> tuple[bool, str]:
    """Check eth0 carrier state and its IPv4 address."""

    try:
        state = Path("/sys/class/net/eth0/operstate").read_text(encoding="ascii").strip()
        address = run_command("ip", "-4", "-o", "addr", "show", "dev", "eth0", "scope", "global")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if state != "up":
        return False, f"eth0 state is {state}"
    if address.returncode != 0 or not address.stdout.strip():
        return False, "eth0 has no global IPv4 address"
    fields = address.stdout.split()
    try:
        ip_address = fields[fields.index("inet") + 1]
    except (ValueError, IndexError):
        return False, "eth0 address output could not be parsed"
    return True, f"eth0 is up with {ip_address}"


def check_gateway() -> tuple[bool, str]:
    """Ping the default IPv4 gateway on eth0."""

    try:
        route = run_command("ip", "-4", "route", "show", "default", "dev", "eth0")
        if route.returncode != 0 or not route.stdout.strip():
            return False, "no default IPv4 gateway on eth0"
        fields = route.stdout.split()
        gateway = fields[fields.index("via") + 1]
        ping = run_command("ping", "-n", "-c", "1", "-W", "2", gateway)
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError) as exc:
        return False, f"gateway unavailable: {exc}"
    if ping.returncode != 0:
        return False, f"gateway {gateway} did not respond"
    return True, f"gateway {gateway} responded"


def check_tcp(backend_ip: str) -> tuple[bool, str]:
    """Attempt a TCP connection to the backend on port 443."""

    try:
        with socket.create_connection((backend_ip, 443), timeout=3):
            pass
    except OSError as exc:
        return False, f"{backend_ip}:443: {exc}"
    return True, f"connected to {backend_ip}:443"


def check_dns(hostname: str) -> tuple[bool, str]:
    """Resolve the backend hostname."""

    try:
        addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"{hostname}: {exc}"
    resolved = sorted({entry[4][0] for entry in addresses})
    return True, f"{hostname} resolves to {', '.join(resolved)}"


def main() -> int:
    """Run each diagnostic and return failure when any layer fails."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-ip", default=os.environ.get("EDGE_BACKEND_IP"))
    parser.add_argument("--backend-host", default=None)
    arguments = parser.parse_args()

    configured_url = os.environ.get("EDGE_BACKEND_URL", "")
    backend_host = arguments.backend_host or urlsplit(configured_url).hostname
    if not arguments.backend_ip or not backend_host:
        parser.error("provide --backend-ip and --backend-host, or configure EDGE_BACKEND_IP and EDGE_BACKEND_URL")

    checks = (
        ("Layer 1/2", check_link()),
        ("Layer 3", check_gateway()),
        ("Layer 4", check_tcp(arguments.backend_ip)),
        ("Layer 7", check_dns(backend_host)),
    )
    for layer, (passed, detail) in checks:
        report(layer, passed, detail)
    return 0 if all(result[0] for _, result in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
