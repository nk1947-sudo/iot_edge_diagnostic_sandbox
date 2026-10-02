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
    local protocol=$1 port=$2 destination=${3:-}
    local -a rule=(-p "$protocol" --dport "$port")
    if [[ -n $destination ]]; then
        rule+=(-d "$destination")
    fi
    rule+=(-j DROP)
    ensure_chain
    if ! iptables -w -C "$CHAIN" "${rule[@]}" >/dev/null 2>&1; then
        iptables -w -A "$CHAIN" "${rule[@]}"
    fi
}

valid_ipv4() {
    local address=$1 octet
    local -a octets
    [[ $address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$address"
    for octet in "${octets[@]}"; do
        (( 10#$octet <= 255 )) || return 1
    done
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

block_backend_ip() {
    local address
    read -r -p 'Backend IPv4 address to block: ' address
    if ! valid_ipv4 "$address"; then
        printf 'Invalid IPv4 address.\n' >&2
        return 2
    fi
    clear_faults
    add_drop tcp 443 "$address"
}

printf '%s\n' \
    '1) Drop outbound HTTPS (TCP 443)' \
    '2) Drop time sync (UDP 123 and TCP 4460)' \
    '3) Break DNS' \
    '4) Block a backend HTTPS IP; keep DNS available' \
    '5) Clear injected faults'
read -r -p 'Select an option: ' choice

case "$choice" in
    1) clear_faults; add_drop tcp 443 ;;
    2) clear_faults; add_drop udp 123; add_drop tcp 4460 ;;
    3) clear_faults; break_dns ;;
    4) block_backend_ip ;;
    5) clear_faults ;;
    *) printf 'Invalid option.\n' >&2; exit 2 ;;
esac
