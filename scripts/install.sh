#!/usr/bin/env bash
# rustydns install script
# ─────────────────────────────────────────────────────────────────────────────
# Creates the rustydns system user, installs the binary with correct
# permissions, writes an example config, and registers the systemd unit.
# Must be run as root.
#
# Usage:
#   sudo bash scripts/install.sh [BINARY_PATH] [INSTALL_PREFIX]
#
# Defaults:
#   BINARY_PATH    = target/release/rustydnsd
#   INSTALL_PREFIX = /usr/local
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BINARY_PATH="${1:-target/release/rustydnsd}"
INSTALL_PREFIX="${2:-/usr/local}"
CONFIG_DIR="/etc/rustydns"
STATE_DIR="/var/lib/rustydns"
EXAMPLE_CONFIG="rustydns.example.toml"
INSTALLED_CONFIG="$CONFIG_DIR/rustydns.toml"
SYSTEMD_UNIT="install/rustydns.service"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "    [WARN] $*" >&2; }
die()   { echo "Error: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "this script must be run as root."

# ─────────────────────────────────────────────────────────────────────────────
# 1. System user
# ─────────────────────────────────────────────────────────────────────────────

info "Creating rustydns system user..."
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

# ─────────────────────────────────────────────────────────────────────────────
# 2. Directories
# ─────────────────────────────────────────────────────────────────────────────

info "Creating directories..."

# State directory: owned by rustydns, no world access.
install -d -m 750 -o rustydns -g rustydns "$STATE_DIR"

# Config directory: 750 — readable only by root and rustydns group.
# World-readable config dirs can allow enumeration of config file names.
install -d -m 750 -o root -g rustydns "$CONFIG_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# 3. Binary
# ─────────────────────────────────────────────────────────────────────────────

info "Installing binary..."

[[ -f "$BINARY_PATH" ]] || die "binary not found at $BINARY_PATH — run 'cargo build --release' first."

# Mode 750: executable by root and rustydns group only.
# Not world-executable — reduces the attack surface by preventing arbitrary
# users from probing the binary's behaviour.
install -m 750 -o root -g rustydns "$BINARY_PATH" "$INSTALL_PREFIX/bin/rustydnsd"

echo "    Installed: $INSTALL_PREFIX/bin/rustydnsd (mode 750, root:rustydns)"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Filesystem capability (CAP_NET_BIND_SERVICE)
# ─────────────────────────────────────────────────────────────────────────────

info "Granting CAP_NET_BIND_SERVICE (bind port 53 without root)..."
if command -v setcap &>/dev/null; then
    setcap 'cap_net_bind_service=+ep' "$INSTALL_PREFIX/bin/rustydnsd"
    echo "    Capability set via setcap."
    echo "    Verify: getcap $INSTALL_PREFIX/bin/rustydnsd"
    echo "      (expected: cap_net_bind_service=ep)"
else
    warn "setcap not found — install libcap2-bin:"
    warn "  apt install libcap2-bin   # Debian/Ubuntu"
    warn "  dnf install libcap        # Fedora/RHEL"
    warn "Alternatively, run the daemon on port >1024 and redirect with:"
    warn "  iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353"
    warn "  iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5353"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 5. Configuration file
# ─────────────────────────────────────────────────────────────────────────────

info "Installing configuration..."
if [[ -f "$INSTALLED_CONFIG" ]]; then
    echo "    Config already exists at $INSTALLED_CONFIG — not overwriting."
    echo "    To reset to defaults: cp $EXAMPLE_CONFIG $INSTALLED_CONFIG"
else
    if [[ -f "$EXAMPLE_CONFIG" ]]; then
        # Mode 640: readable by root and rustydns group; not world-readable.
        # The daemon enforces this at startup and will refuse to start if the
        # config is world-readable.
        install -m 640 -o root -g rustydns "$EXAMPLE_CONFIG" "$INSTALLED_CONFIG"
        echo "    Installed: $INSTALLED_CONFIG (mode 640, root:rustydns)"
        echo ""
        echo "    ⚠  Edit the config before starting the daemon:"
        echo "       \$EDITOR $INSTALLED_CONFIG"
    else
        warn "Example config not found at $EXAMPLE_CONFIG — skipping."
        warn "Manually copy and configure before starting the daemon."
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6. Systemd unit
# ─────────────────────────────────────────────────────────────────────────────

info "Installing systemd unit..."
if [[ -f "$SYSTEMD_UNIT" ]]; then
    install -m 644 -o root -g root "$SYSTEMD_UNIT" /etc/systemd/system/rustydns.service
    systemctl daemon-reload
    echo "    Installed: /etc/systemd/system/rustydns.service"
else
    warn "Systemd unit not found at $SYSTEMD_UNIT — skipping."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 7. Summary
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Installation complete."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo " Next steps:"
echo "   1. Edit the config:    \$EDITOR $INSTALLED_CONFIG"
echo "   2. Enable and start:   systemctl enable --now rustydns"
echo "   3. Check status:       systemctl status rustydns"
echo "   4. Follow logs:        journalctl -u rustydns -f"
echo ""
echo " Security verification:"
echo "   Binary permissions:    ls -l $INSTALL_PREFIX/bin/rustydnsd"
echo "   Capability:            getcap $INSTALL_PREFIX/bin/rustydnsd"
echo "   Config permissions:    ls -l $INSTALLED_CONFIG"
echo "   Config dir:            ls -ld $CONFIG_DIR"
echo "   Running as:            systemctl show -p User rustydns"
echo ""
echo " Expected permission summary:"
echo "   $INSTALL_PREFIX/bin/rustydnsd  -rwxr-x--- root:rustydns  (750)"
echo "   $CONFIG_DIR                    drwxr-x--- root:rustydns  (750)"
echo "   $INSTALLED_CONFIG              -rw-r----- root:rustydns  (640)"
echo "   $STATE_DIR                     drwxr-x--- rustydns:rustydns (750)"
echo ""
