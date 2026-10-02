#!/usr/bin/env bash
set -euo pipefail

CHAIN=EDGE_DIAG_FAULTS
STATE_DIR=/var/lib/iot-edge-diagnostic-sandbox
DNS_BACKUP="$STATE_DIR/resolv.conf.backup"

if (( EUID != 0 )); then
    printf 'Run this script with sudo.\n' >&2
    exit 1
fi

ensure_chain() {
    if ! iptables -w -S "$CHAIN" >/dev/null 2>&1; then
        iptables -w -N "$CHAIN"
    fi
    if ! iptables -w -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; then
        iptables -w -I OUTPUT 1 -j "$CHAIN"
    fi
}

add_drop() {
    local protocol=$1 port=$2
    ensure_chain
    if ! iptables -w -C "$CHAIN" -p "$protocol" --dport "$port" -j DROP >/dev/null 2>&1; then
        iptables -w -A "$CHAIN" -p "$protocol" --dport "$port" -j DROP
    fi
}

break_dns() {
    install -d -m 0700 "$STATE_DIR"
    if [[ ! -e "$DNS_BACKUP" && ! -L "$DNS_BACKUP" ]]; then
        cp -a -- /etc/resolv.conf "$DNS_BACKUP"
    fi
    rm -f -- /etc/resolv.conf
    printf 'nameserver 192.0.2.0\n' > /etc/resolv.conf
}

clear_faults() {
    if iptables -w -S "$CHAIN" >/dev/null 2>&1; then
        iptables -w -F "$CHAIN"
        while iptables -w -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; do
            iptables -w -D OUTPUT -j "$CHAIN"
        done
        iptables -w -X "$CHAIN"
    fi
    if [[ -e "$DNS_BACKUP" || -L "$DNS_BACKUP" ]]; then
        rm -f -- /etc/resolv.conf
        mv -- "$DNS_BACKUP" /etc/resolv.conf
    fi
}

printf '%s\n' \
    '1) Drop outbound HTTPS (TCP 443)' \
    '2) Drop outbound NTP (UDP 123)' \
    '3) Break DNS' \
    '4) Clear injected faults'
read -r -p 'Select an option: ' choice

case "$choice" in
    1) add_drop tcp 443 ;;
    2) add_drop udp 123 ;;
    3) break_dns ;;
    4) clear_faults ;;
    *) printf 'Invalid option.\n' >&2; exit 2 ;;
esac
