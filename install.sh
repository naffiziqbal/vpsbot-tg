#!/usr/bin/env bash
# Install the Telegram VPS bot. Re-runnable. Does not start it - run `sudo vpsbot-set-secret` after.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

id vpsbot >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vpsbot
echo "✓ user vpsbot (no login, no home, no docker group)"

# code is root-owned so the bot user can't modify what it (or root) runs
install -o root -g root -m 755 "$SRC/vpsbot-query" /usr/local/sbin/vpsbot-query
install -o root -g root -m 755 "$SRC/vpsbot-set-secret" /usr/local/sbin/vpsbot-set-secret
install -d -o root -g root -m 755 /opt/vpsbot
install -o root -g root -m 644 "$SRC/bot.py" /opt/vpsbot/bot.py
install -d -o root -g vpsbot -m 750 /etc/vpsbot
install -d -o root -g root -m 700 /var/lib/vpsbot-query
echo "✓ files installed"

tmp=$(mktemp)
cat > "$tmp" <<'EOF'
# vpsbot may run ONLY the read-only query helper (it validates every argument itself)
Defaults:vpsbot !log_allowed, !pam_session, !lecture
vpsbot ALL=(root) NOPASSWD: /usr/local/sbin/vpsbot-query
EOF
visudo -cf "$tmp" >/dev/null
install -o root -g root -m 440 "$tmp" /etc/sudoers.d/vpsbot; rm -f "$tmp"
echo "✓ sudoers rule"

install -o root -g root -m 644 "$SRC/vpsbot.service" /etc/systemd/system/vpsbot.service
systemctl daemon-reload
systemctl enable vpsbot >/dev/null 2>&1
echo "✓ vpsbot.service (enabled, not started yet)"

# smoke test as the bot user, through sudo, exactly as the bot will call it
sudo -u vpsbot sudo -n /usr/local/sbin/vpsbot-query apps | head -3
sudo -u vpsbot sudo -n /usr/local/sbin/vpsbot-query baseline   # must be refused
/usr/local/sbin/vpsbot-query baseline
echo
echo "Next: in your own SSH session run  sudo vpsbot-set-secret"
