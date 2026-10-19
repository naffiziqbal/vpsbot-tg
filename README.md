# vpsbot-tg

A **read-only Telegram bot that watches your VPS**. Ask it for status (`/health`, `/logs`, `/sites`…)
and it pushes alerts when something breaks — or when something looks like an intrusion.

One command to install, one token to paste. No dependencies beyond Python 3.8+.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/naffiziqbal/vpsbot-tg/main/install.sh | sudo bash
```

The installer sets everything up, then walks you through:

1. **Create a bot** — in Telegram message [@BotFather](https://t.me/BotFather), send `/newbot`, copy the token.
2. **Paste the token** — the prompt is hidden; the token never appears on screen or in shell history.
3. **Message your bot once** — the installer detects your chat ID and asks you to confirm it.
   Only that account can use the bot.

That's it — the bot says hello in Telegram. Send `/health`.

> Prefer to read before you run? `git clone https://github.com/naffiziqbal/vpsbot-tg && sudo ./vpsbot-tg/install.sh`
> does the same from a local checkout.

**Update:** run the same `curl … | sudo bash` again — your token and settings are kept.
**Uninstall:** `curl -fsSL https://raw.githubusercontent.com/naffiziqbal/vpsbot-tg/main/install.sh | sudo bash -s -- --uninstall`
**Change token / chat:** `sudo vpsbot-setup`

Requirements: Linux with systemd, `sudo`, Python ≥ 3.8 (installed automatically via apt/dnf if missing).
Built for Debian/Ubuntu (Python 3.8+ compatible); tested on Ubuntu 24.04.

## Commands

| Command | Shows |
|---|---|
| `/health` | CPU / RAM / disk bars, services, apps, containers, file integrity, threat indicators |
| `/apps` | PM2 apps per user: status, uptime, memory, CPU, restarts |
| `/docker` | Containers with status, memory, CPU |
| `/sites` | HTTPS status + certificate days for every nginx `server_name` |
| `/certs` | Let's Encrypt certificates grouped by expiry |
| `/logs <name> [lines]` | PM2 app logs, `nginx`, `access`, `ssh`, `system`, `docker:<name>`, `backup` — secrets redacted |
| `/errors` | Recent stderr of every app, nginx errors, system journal errors |
| `/top` `/disk` `/net` | Processes, disk/Docker/log usage, ports and external connections |
| `/security` | SSH logins & failures, fail2ban bans, sudo usage, integrity, threat indicators |
| `/backup` | Latest backup (if configured) |
| `/alerts` | Alerts currently active |

Sections for things you don't run (Docker, PM2, nginx, fail2ban…) simply don't appear.

## Alerts

Checked every minute (sites every 5). Each alert fires **once**, then a ✅ when it clears.

- **Down:** systemd services, PM2 apps (plus every restart), Docker containers, HTTPS sites (2 failed checks)
- **Resources:** CPU ≥ 90 % for 5 min, RAM ≥ 90 %, disk ≥ 85 % — configurable
- **Certificates** expiring within 14 days · **backups** older than 26 h (if configured) · **reboots**
- **Every SSH login**, with user, source IP and key fingerprint
- **Intrusion indicators:** changes to cron, systemd units, sshd/PAM config, sudoers, shell profiles,
  `authorized_keys`, `passwd`/`shadow`, `/usr/local/{bin,sbin}`; new listening ports; anything in
  `/etc/ld.so.preload`; executable or hidden files in `/tmp`, `/var/tmp`, `/dev/shm`; traffic to IPs you've blocked
- A daily `/health` report at 09:00

The integrity check compares against a baseline taken at install. After you change those files on
purpose (new cron job, new service, new SSH key…) accept the new state:

```bash
sudo vpsbot-query baseline
```

The bot itself can never reset the baseline — an attacker who hijacked your Telegram couldn't silence it.

## Settings

Everything is auto-detected: PM2 users (only those with a running PM2 daemon — the bot never starts one),
enabled services (nginx, Docker, SSH, cron, fail2ban, databases, `certbot.timer`, `pm2-*`), Docker,
nginx sites and Let's Encrypt certs. Optional extras go in `/etc/vpsbot/config`
(see [`config.example`](config.example)), then `sudo systemctl restart vpsbot`:

```ini
CPU_ALERT=90  MEM_ALERT=90  DISK_ALERT=85  CERT_DAYS=14  DAILY_HOUR=9
EXTRA_UNITS="myapp worker"                 # more systemd units to watch
PM2_USERS="deploy"                         # limit PM2 users
BLOCKED_NETS="203.0.113.7 198.51.100.0/24" # alert on outbound packets to these (iptables OUTPUT DROP)
BACKUP_NAME="Postgres backup"
BACKUP_LOG=/var/log/backup.log
BACKUP_GLOB=/var/backups/db/*.dump         # alert if newest is older than BACKUP_MAX_AGE_H (26)
SITES_BEHIND_PROXY=1                       # also check sites whose DNS points at a CDN
```

## Security model

```
Telegram ⇄ bot.py  (user "vpsbot": no login shell, no home, not in docker group, can't read app files)
              │  sudo -n /usr/local/sbin/vpsbot-query <command>     ← its only sudo right
              ▼
        vpsbot-query  (root, read-only: fixed commands, args limited to [A-Za-z0-9_.:-],
                       log names must match a known source, secrets redacted from output)
```

- **Read-only.** There is no command that restarts, stops or executes anything.
- **Only your chat.** Messages from anyone else are ignored, and you're told someone tried.
- **No open ports.** Long-polling, outbound HTTPS only; no webhook.
- **Code is root-owned** (`/opt/vpsbot`, `/usr/local/sbin`), so the bot user can't modify what it runs.
- **Token** lives only in `/etc/vpsbot/env` (`root:vpsbot 640`). Never commit or paste it anywhere;
  if it leaks, `/revoke` it in @BotFather and run `sudo vpsbot-setup`.
- **Resilient.** Telegram is reached over IPv4; a watchdog restarts the bot if polling stalls for 5 minutes.
- Log output is redacted for common secrets (passwords, tokens, API keys, JWTs, DB URLs), but treat
  `/logs` like any chat message — Telegram bot chats are not end-to-end encrypted.

## Operating

```bash
systemctl status vpsbot        # running?
journalctl -u vpsbot -f        # bot log
sudo vpsbot-query health       # any report in the terminal (strip the '#html' line)
sudo vpsbot-query baseline     # accept intended system changes
sudo vpsbot-setup              # new token or chat
```

| Path | What |
|---|---|
| `/opt/vpsbot/bot.py` | Telegram side (runs as `vpsbot`) |
| `/usr/local/sbin/vpsbot-query` | root helper |
| `/usr/local/sbin/vpsbot-setup` | token / chat setup |
| `/etc/vpsbot/env` · `/etc/vpsbot/config` | secrets · settings |
| `/var/lib/vpsbot-query/` | integrity baseline + SSH journal cursor |
| `/etc/sudoers.d/vpsbot` · `/etc/systemd/system/vpsbot.service` | sudo rule · service |

