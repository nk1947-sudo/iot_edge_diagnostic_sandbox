#!/usr/bin/env python3
"""Send BeagleBone telemetry and show connectivity on user LEDs."""

import logging
import os
import re
import socket
import time
from datetime import datetime, timezone

import requests

LOG = logging.getLogger(__name__)
LED_ROOT = "/sys/class/leds"
THERMAL_PATH = "/sys/class/thermal/thermal_zone0/temp"
MAC_PATTERN = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
INTERVAL_SECONDS = 10


def read_mac_address() -> str:
    """Read the first usable Ethernet or wireless MAC address."""

    for interface in ("eth0", "wlan0"):
        try:
            with open(f"/sys/class/net/{interface}/address", encoding="ascii") as source:
                address = source.read().strip().lower()
        except OSError:
            continue
        if MAC_PATTERN.fullmatch(address) and address != "00:00:00:00:00:00":
            return address
    raise RuntimeError("No usable MAC address found on eth0 or wlan0")


def read_cpu_temperature() -> float:
    """Read CPU temperature in Celsius, falling back to simulated data."""

    try:
        with open(THERMAL_PATH, encoding="ascii") as source:
            return int(source.read().strip()) / 1000.0
    except (OSError, ValueError):
        return 42.0


def set_led(index: int, enabled: bool) -> None:
    """Set a BeagleBone user LED without stopping telemetry on LED errors."""

    root = f"{LED_ROOT}/beaglebone:green:usr{index}"
    try:
        trigger = f"{root}/trigger"
        if os.path.exists(trigger):
            with open(trigger, "w", encoding="ascii") as target:
                target.write("none")
        with open(f"{root}/brightness", "w", encoding="ascii") as target:
            target.write("1" if enabled else "0")
    except OSError as exc:
        LOG.warning("Cannot set usr%d LED: %s", index, exc)


def show_online() -> None:
    """Show a successful backend connection."""

    set_led(1, False)
    set_led(2, True)
    set_led(3, True)


def show_offline() -> None:
    """Show an offline state and flash the fault LED."""

    set_led(2, False)
    set_led(3, False)
    set_led(1, True)
    time.sleep(0.25)
    set_led(1, False)
    time.sleep(0.25)
    set_led(1, True)
    time.sleep(0.25)
    set_led(1, False)


def run() -> None:
    """Send telemetry every ten seconds."""

    backend_url = os.environ.get("EDGE_BACKEND_URL", "").strip()
    if not backend_url.startswith("https://"):
        raise ValueError("EDGE_BACKEND_URL must be an HTTPS URL")

    LOG.info("Starting edge telemetry on %s", socket.gethostname())
    set_led(0, True)
    with requests.Session() as session:
        while True:
            started = time.monotonic()
            try:
                payload = {
                    "mac_address": read_mac_address(),
                    "cpu_temp": read_cpu_temperature(),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                response = session.post(backend_url, json=payload, timeout=(3, 5))
                if response.status_code != 200:
                    LOG.warning("Backend returned HTTP %d", response.status_code)
                    show_offline()
                else:
                    show_online()
            except (requests.RequestException, RuntimeError) as exc:
                LOG.warning("Telemetry delivery failed: %s", exc)
                show_offline()
            time.sleep(max(0, INTERVAL_SECONDS - (time.monotonic() - started)))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run()
