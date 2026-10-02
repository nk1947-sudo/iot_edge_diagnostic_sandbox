#!/usr/bin/env python3
"""Diagnose edge connectivity and capture failed network probes."""

import argparse
import concurrent.futures
import ipaddress
import os
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

CAPTURE_PATH = Path("/tmp/support_diagnostic.pcap")
NTP_HOST = "time.control.verkada.com"
NTS_HOST = "time.cloudflare.com"
NTP_EPOCH_OFFSET = 2_208_988_800


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


def resolve_ipv4(hostname: str, port: int, socket_type: int) -> str:
    """Resolve one IPv4 address for a network probe."""

    addresses = socket.getaddrinfo(hostname, port, socket.AF_INET, socket_type)
    if not addresses:
        raise OSError(f"no IPv4 address for {hostname}")
    return addresses[0][4][0]


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


def check_tcp(hostname: str, port: int) -> tuple[bool, str]:
    """Attempt an IPv4 TCP connection to a service."""

    try:
        address = resolve_ipv4(hostname, port, socket.SOCK_STREAM)
        with socket.create_connection((address, port), timeout=3):
            pass
    except OSError as exc:
        return False, f"{hostname}:{port}: {exc}"
    return True, f"connected to {hostname} ({address}):{port}"


def check_ntp() -> tuple[bool, str]:
    """Exchange an NTP packet with the Verkada time service."""

    request = bytearray(48)
    request[0] = 0x23
    now = time.time() + NTP_EPOCH_OFFSET
    struct.pack_into("!II", request, 40, int(now), int(now % 1 * 2**32))
    try:
        address = resolve_ipv4(NTP_HOST, 123, socket.SOCK_DGRAM)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.connect((address, 123))
            client.send(request)
            response = client.recv(512)
    except OSError as exc:
        return False, f"{NTP_HOST}:123/UDP: {exc}"
    if len(response) < 48 or response[0] & 7 != 4:
        return False, f"{NTP_HOST}:123/UDP returned an invalid NTP response"
    if response[1] == 0 or response[24:32] != request[40:48]:
        return False, f"{NTP_HOST}:123/UDP returned an unusable NTP response"
    return True, f"NTP response from {NTP_HOST} ({address}):123/UDP"


def check_dns(hostname: str) -> tuple[bool, str]:
    """Resolve the backend hostname."""

    try:
        addresses = socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"{hostname}: {exc}"
    resolved = sorted({entry[4][0] for entry in addresses})
    if not resolved:
        return False, f"{hostname} has no IPv4 address"
    return True, f"{hostname} resolves to {', '.join(resolved)}"


def check_tls(hostname: str, backend_ip: str, expected_issuer: str) -> tuple[bool, str]:
    """Verify the backend certificate and compare its issuer."""

    try:
        context = ssl.create_default_context()
        with (
            socket.create_connection((backend_ip, 443), timeout=5) as connection,
            context.wrap_socket(connection, server_hostname=hostname) as secure,
        ):
            certificate = secure.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return False, f"certificate verification failed; possible TLS inspection: {exc}"
    except (OSError, ssl.SSLError) as exc:
        return False, f"TLS handshake with {hostname} ({backend_ip}) failed: {exc}"
    issuer = ",".join(
        f"{attribute}={value}"
        for name in certificate.get("issuer", ())
        for attribute, value in name
    )
    if issuer.casefold() != expected_issuer.strip().casefold():
        return False, f"SSL/TLS Inspection Detected: expected issuer {expected_issuer!r}; observed {issuer!r}"
    return True, f"verified certificate from {hostname}; issuer {issuer}"


def prepare_capture_file() -> None:
    """Reserve the capture path without following an existing symlink."""

    capture_uid = os.geteuid()
    capture_gid = None
    if capture_uid == 0:
        try:
            import pwd

            account = pwd.getpwnam("tcpdump")
        except (ImportError, KeyError):
            pass
        else:
            capture_uid = account.pw_uid
            capture_gid = account.pw_gid
    try:
        existing = CAPTURE_PATH.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(existing.st_mode) or existing.st_uid not in (os.geteuid(), capture_uid):
            raise OSError(f"unsafe existing capture path: {CAPTURE_PATH}")
        CAPTURE_PATH.unlink()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(CAPTURE_PATH, flags, 0o600)
    try:
        if capture_gid is not None:
            os.fchown(descriptor, capture_uid, capture_gid)
    finally:
        os.close(descriptor)


def capture_failed_checks(probes: list) -> tuple[bool, str]:
    """Capture traffic while repeating failed Layer 4 and 7 probes."""

    try:
        prepare_capture_file()
        process = subprocess.Popen(
            ["tcpdump", "-i", "eth0", "-w", str(CAPTURE_PATH), "-G", "15", "-W", "1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        return False, f"cannot start tcpdump: {exc}"

    deadline = time.monotonic() + 18
    try:
        time.sleep(0.5)
        if process.poll() is None:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(probes)) as executor:
                for probe in probes:
                    executor.submit(probe)
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGINT)
            process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()

    error = process.stderr.read().strip()
    if process.returncode not in (0, -signal.SIGINT):
        return False, f"tcpdump exited with status {process.returncode}: {error}"
    try:
        size = CAPTURE_PATH.stat().st_size
    except OSError as exc:
        return False, f"capture file unavailable: {exc}"
    if size <= 24:
        return False, f"{CAPTURE_PATH} contains no packets"
    return True, f"saved {size} bytes to {CAPTURE_PATH}"


def main() -> int:
    """Run diagnostics and capture traffic for failed service checks."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-ip", default=os.environ.get("EDGE_BACKEND_IP"))
    parser.add_argument("--backend-host")
    parser.add_argument(
        "--expected-issuer",
        default=os.environ.get("EDGE_EXPECTED_TLS_ISSUER"),
        help="Expected full certificate issuer DN",
    )
    arguments = parser.parse_args()

    hostname = arguments.backend_host or urlsplit(os.environ.get("EDGE_BACKEND_URL", "")).hostname
    if not arguments.backend_ip or not hostname or not arguments.expected_issuer:
        parser.error("backend IP, hostname, and expected TLS issuer are required")
    try:
        backend_ip = str(ipaddress.IPv4Address(arguments.backend_ip))
    except ipaddress.AddressValueError as exc:
        parser.error(str(exc))

    checks = (
        ("Layer 1/2", check_link, False),
        ("Layer 3 gateway", check_gateway, False),
        ("Layer 4 HTTPS", lambda: check_tcp(backend_ip, 443), True),
        ("Layer 4 NTP", check_ntp, True),
        ("Layer 4 NTS", lambda: check_tcp(NTS_HOST, 4460), True),
        ("Layer 7 DNS", lambda: check_dns(hostname), True),
        ("Layer 7 TLS", lambda: check_tls(hostname, backend_ip, arguments.expected_issuer), True),
    )
    failed_probes = []
    failures = 0
    for layer, probe, capture_on_failure in checks:
        passed, detail = probe()
        report(layer, passed, detail)
        if not passed:
            failures += 1
            if capture_on_failure:
                failed_probes.append(probe)

    if failed_probes:
        captured, detail = capture_failed_checks(failed_probes)
        report("PCAP", captured, detail)
        if not captured:
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
