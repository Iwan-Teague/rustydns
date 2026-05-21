#!/usr/bin/env bash
# rustydns install script
# Creates the rustydns system user, directories, and capabilities.
# Must be run as root.

set -euo pipefail

BINARY_PATH="${1:-target/release/rustydnsd}"
INSTALL_PREFIX="${2:-/usr/local}"
CONFIG_DIR="/etc/rustydns"
STATE_DIR="/var/lib/rustydns"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: this script must be run as root." >&2
    exit 1
fi

echo "==> Creating rustydns system user..."
if ! id -u rustydns &>/dev/null; then
    useradd \
        --system \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "rustydns DNS daemon" \
        rustydns
    echo "    Created user: rustydns"
else
    echo "    User rustydns already exists, skipping."
fi

echo "==> Creating directories..."
install -d -m 750 -o rustydns -g rustydns "$STATE_DIR"
install -d -m 755 "$CONFIG_DIR"

echo "==> Installing binary..."
install -m 755 "$BINARY_PATH" "$INSTALL_PREFIX/bin/rustydnsd"

echo "==> Granting CAP_NET_BIND_SERVICE (allows binding port 53 without root)..."
if command -v setcap &>/dev/null; then
    setcap 'cap_net_bind_service=+ep' "$INSTALL_PREFIX/bin/rustydnsd"
    echo "    Capability set via setcap."
else
    echo "    WARNING: setcap not found. Install libcap2-bin:" >&2
    echo "      apt install libcap2-bin  # Debian/Ubuntu" >&2
    echo "    Alternatively, run the daemon on port >1024 and redirect with:" >&2
    echo "      iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353" >&2
fi

echo "==> Installing systemd unit..."
install -m 644 install/rustydns.service /etc/systemd/system/rustydns.service
systemctl daemon-reload

echo ""
echo "==> Installation complete."
echo ""
echo "Next steps:"
echo "  1. Copy the example config:  cp rustydns.example.toml $CONFIG_DIR/rustydns.toml"
echo "  2. Edit the config:          \$EDITOR $CONFIG_DIR/rustydns.toml"
echo "  3. Enable and start:         systemctl enable --now rustydns"
echo "  4. Check logs:               journalctl -u rustydns -f"
echo ""
echo "Verify the capability is set correctly:"
echo "  getcap $INSTALL_PREFIX/bin/rustydnsd"
echo "  (should show: cap_net_bind_service=ep)"
