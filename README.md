# vpsbot-tg

Read-only Telegram bot for monitoring a single VPS: on-demand status commands plus pushed alerts.
Python 3 standard library only — no dependencies.

## Commands

| Command | Shows |
|---|---|
| `/health` | CPU / RAM / disk bars, services, apps, containers, integrity, malware indicators |
| `/apps` | PM2 apps per user: status, uptime, memory, CPU, restarts |
| `/docker` | Containers with status, memory, CPU |
| `/sites` | HTTPS status + cert days for every nginx `server_name` |
| `/certs` | Let's Encrypt expiry, grouped by urgency |
| `/logs <name> [lines]` | PM2 app logs, `nginx`, `access`, `backup`, `ssh`, `system`, `docker:<name>` (secrets redacted) |
| `/errors` | Recent stderr of all apps + nginx error log |
| `/top` `/disk` `/net` | Processes, disk/Docker/log usage, ports and connections |
| `/security` | SSH logins/failures, fail2ban, sudo, watched-file integrity, C2 / preload / tmp checks |
| `/backup` | Last ThoughtExpense DB backup |
| `/alerts` | Currently active alerts |

## Alerts (pushed automatically)

Checked every 60 s (sites every 5 min); each fires once and sends a ✅ when it clears:
service / PM2 app / container down, app restarts, site down (2 failed checks), CPU ≥ 90 % for 5 min,
RAM ≥ 90 %, disk ≥ 85 %, cert < 14 days, every SSH login, reboot, packets to known C2 IPs,
non-empty `/etc/ld.so.preload`, executables in tmp dirs, changes to cron / systemd / sshd / sudoers /
profile / authorized_keys / passwd / `/usr/local/{s,}bin`, new listening ports. Daily `/health` at 09:00.

## Design

```
Telegram ⇄ bot.py (user vpsbot: no login, no docker, no app files)
                │  sudo -n /usr/local/sbin/vpsbot-query <cmd>   ← its only sudo right
                ▼
          vpsbot-query (root, read-only, whitelisted commands/args, redacts secrets)
```

- The network-facing process is unprivileged; the root helper takes only fixed commands and
  `[A-Za-z0-9_.:-]` arguments, and `logs` names must match a known source.
- Only the configured chat ID is answered; other senders are ignored and reported to you.
- No commands change server state. The integrity baseline can only be reset by an admin on the box.
- Long-polling (outbound only) — no open port, no webhook. Telegram is reached over IPv4 and a
  watchdog restarts the bot if polling stalls for 5 minutes.

## Install

```bash
sudo ./install.sh            # user, files, sudoers rule, systemd unit, initial baseline
sudo vpsbot-set-secret       # token from @BotFather (hidden prompt) + chat ID; starts the service
```

Then open the bot in Telegram, press **Start**, and send `/health`.

Never commit or paste the token — it lives only in `/etc/vpsbot/env` (root:vpsbot 640).

## Operating

```bash
systemctl status vpsbot          # running?
journalctl -u vpsbot -f          # bot log
sudo vpsbot-query health         # same report in the terminal
sudo vpsbot-query baseline       # accept intended changes to watched files/ports
```

Server-specific settings are at the top of `vpsbot-query` (`PM2_USERS`, `UNITS`, `ATTACKER_NETS`,
backup paths) and `bot.py` (thresholds, intervals). After editing, re-run `sudo ./install.sh`
(it re-baselines, since the helper itself is a watched file) and `sudo systemctl restart vpsbot`.
