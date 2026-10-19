#!/usr/bin/env bash
# vpsbot-tg — install, update or remove the read-only Telegram VPS monitor.
#
#   curl -fsSL https://raw.githubusercontent.com/naffiziqbal/vpsbot-tg/main/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/naffiziqbal/vpsbot-tg/main/install.sh | sudo bash -s -- --uninstall
#
# Re-running updates the code and keeps your token and /etc/vpsbot/config.
set -euo pipefail
REPO="${VPSBOT_REPO:-naffiziqbal/vpsbot-tg}"
REF="${VPSBOT_REF:-main}"
FILES=(bot.py vpsbot-query vpsbot-setup vpsbot.service config.example)

say() { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (… | sudo bash)"
[ -d /run/systemd/system ] || die "systemd is required"

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now vpsbot >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/vpsbot.service /etc/sudoers.d/vpsbot \
        /usr/local/sbin/vpsbot-query /usr/local/sbin/vpsbot-setup /usr/local/sbin/vpsbot-set-secret
  rm -rf /opt/vpsbot /var/lib/vpsbot-query /etc/vpsbot
  systemctl daemon-reload
  id vpsbot >/dev/null 2>&1 && userdel vpsbot
  say "vpsbot removed (revoke the token in @BotFather if you won't reuse it)"
  exit 0
fi

# --- requirements ---
if ! [ -x /usr/bin/python3 ]; then
  if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3 >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q python3
  elif command -v yum >/dev/null; then yum install -y -q python3
  else die "/usr/bin/python3 is required"; fi
fi
/usr/bin/python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die "python3 >= 3.8 is required"
command -v sudo >/dev/null || die "sudo is required"
command -v setpriv >/dev/null || die "setpriv (util-linux) is required"

# --- get the files: local checkout or download ---
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "$(dirname "${BASH_SOURCE[0]}")/bot.py" ]; then
  SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  say "installing from $SRC"
else
  command -v curl >/dev/null || die "curl is required"
  SRC="$(mktemp -d)"; trap 'rm -rf "$SRC"' EXIT
  for f in "${FILES[@]}"; do
    curl -fsSL "https://raw.githubusercontent.com/$REPO/$REF/$f" -o "$SRC/$f" || die "download failed: $f"
  done
  say "downloaded $REPO@$REF"
fi
/usr/bin/python3 -I -c 'import ast, sys; [ast.parse(open(p).read()) for p in sys.argv[1:]]' \
  "$SRC/bot.py" "$SRC/vpsbot-query" "$SRC/vpsbot-setup" || die "source files are corrupt"

# --- user + files (code is root-owned so the bot user can't modify what it or root runs) ---
id vpsbot >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent \
  --shell "$(command -v nologin || echo /bin/false)" vpsbot
install -o root -g root -m 755 "$SRC/vpsbot-query" /usr/local/sbin/vpsbot-query
install -o root -g root -m 755 "$SRC/vpsbot-setup" /usr/local/sbin/vpsbot-setup
rm -f /usr/local/sbin/vpsbot-set-secret
install -d -o root -g root -m 755 /opt/vpsbot
install -o root -g root -m 644 "$SRC/bot.py" /opt/vpsbot/bot.py
install -o root -g root -m 644 "$SRC/config.example" /opt/vpsbot/config.example
install -d -o root -g vpsbot -m 750 /etc/vpsbot
install -d -o root -g root -m 700 /var/lib/vpsbot-query
if [ ! -f /etc/vpsbot/config ]; then
  install -o root -g vpsbot -m 640 "$SRC/config.example" /etc/vpsbot/config
fi
say "user vpsbot + files installed"

# --- sudo: the bot may run ONLY the read-only helper ---
tmp="$(mktemp)"
{ echo "# vpsbot may run ONLY the read-only query helper (it validates every argument itself)"
  echo "Defaults:vpsbot !log_allowed, !pam_session, !lecture"
  echo "vpsbot ALL=(root) NOPASSWD: /usr/local/sbin/vpsbot-query"; } > "$tmp"
if ! visudo -cf "$tmp" >/dev/null 2>&1; then          # sudo < 1.9.10 has no log_allowed
  sed -i 's/!log_allowed, //' "$tmp"
  visudo -cf "$tmp" >/dev/null || die "sudoers rule failed validation"
fi
install -o root -g root -m 440 "$tmp" /etc/sudoers.d/vpsbot; rm -f "$tmp"
say "sudoers rule"

install -o root -g root -m 644 "$SRC/vpsbot.service" /etc/systemd/system/vpsbot.service
systemctl daemon-reload
systemctl enable vpsbot >/dev/null 2>&1
say "systemd service"

# the helper refuses to rebaseline when called by the bot - check that, then record known-good state
sudo -u vpsbot sudo -n /usr/local/sbin/vpsbot-query baseline | grep -q Refused || die "privilege check failed"
say "$(/usr/local/sbin/vpsbot-query baseline)"

# --- token: keep existing, else run setup interactively ---
if [ -f /etc/vpsbot/env ]; then
  systemctl restart vpsbot
  sleep 3
  systemctl is-active --quiet vpsbot && say "updated and restarted — your token and config were kept" \
    || { journalctl -u vpsbot -n 15 --no-pager; die "vpsbot failed to start"; }
elif { : </dev/tty; } 2>/dev/null; then
  echo
  /usr/local/sbin/vpsbot-setup </dev/tty
else
  echo; echo "Installed. Now run:  sudo vpsbot-setup"
fi
echo
echo "Settings: /etc/vpsbot/config   ·   after intended system changes: sudo vpsbot-query baseline"
