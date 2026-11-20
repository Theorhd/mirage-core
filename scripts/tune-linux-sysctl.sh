#!/usr/bin/env bash
# Idempotent Linux VPS kernel network tuning for mirage-core (low latency,
# TCP BBR + fq pacing, zero video stuttering on HLS/DASH adaptive streaming).
#
# Usage:
#   sudo ./scripts/tune-linux-sysctl.sh

set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
    printf 'Erreur: ce script est réservé à un hôte Linux.\n' >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    printf 'Erreur: lance ce script avec sudo / root.\n' >&2
    exit 1
fi

SYSCTL_FILE="/etc/sysctl.d/99-mirage-core.conf"

# Load tcp_bbr module if not built-in.
modprobe tcp_bbr >/dev/null 2>&1 || true

cat > "$SYSCTL_FILE" <<'EOF'
# mirage-core low-latency & smooth video streaming sysctl profile

# Fair Queueing packet pacing + TCP BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Keep cwnd warm between HLS/DASH video segments (prevents re-buffering after brief pauses)
net.ipv4.tcp_slow_start_after_idle = 0

# Automatic PMTU blackhole detection (fixes stalls on 4G/5G/PPPoE links)
net.ipv4.tcp_mtu_probing = 1

# Limit unsent bytes in socket write queue to minimize local bufferbloat & tail latency
net.ipv4.tcp_notsent_lowat = 16384

# High-BDP TCP & UDP socket buffers (up to 16 MiB for high-bitrate 4K/8K & bursts)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# Accept queue & backlog sizing for bursts of parallel media connections
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 8192
net.ipv4.tcp_max_syn_backlog = 4096
EOF

sysctl -p "$SYSCTL_FILE" >/dev/null

printf '[+] Profil sysctl appliqué : %s\n' "$SYSCTL_FILE"
printf '    tcp_congestion_control = %s\n' "$(sysctl -n net.ipv4.tcp_congestion_control)"
printf '    default_qdisc          = %s\n' "$(sysctl -n net.core.default_qdisc)"
printf '    tcp_slow_start_after_idle = %s\n' "$(sysctl -n net.ipv4.tcp_slow_start_after_idle)"
