#!/usr/bin/python3 -I
"""Telegram bot for this VPS: read-only status commands + push alerts.

Runs as the unprivileged `vpsbot` user (systemd: vpsbot.service). All data comes
from `sudo /usr/local/sbin/vpsbot-query`, which only accepts whitelisted commands.
Only messages from VPSBOT_CHAT_ID are answered; everyone else is ignored and reported.
"""
import hashlib
import html
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime

TOKEN = os.environ["VPSBOT_TOKEN"]
CHAT_ID = int(os.environ["VPSBOT_CHAT_ID"])
DAILY_HOUR = int(os.environ.get("DAILY_HOUR") or os.environ.get("VPSBOT_DAILY_HOUR") or 9)
CPU_ALERT = float(os.environ.get("CPU_ALERT") or 90)
MEM_ALERT = float(os.environ.get("MEM_ALERT") or 90)
DISK_ALERT = float(os.environ.get("DISK_ALERT") or 85)
BACKUP_MAX_AGE_H = float(os.environ.get("BACKUP_MAX_AGE_H") or 26)
HAS_BACKUP = bool(os.environ.get("BACKUP_LOG") or os.environ.get("BACKUP_GLOB"))
HELPER = "/usr/local/sbin/vpsbot-query"
API = f"https://api.telegram.org/bot{TOKEN}/"
CHECK_EVERY = 60
SITES_EVERY = 300
POLL_STALE = 300          # no successful getUpdates for this long -> exit, systemd restarts us
last_poll_ok = time.time()

# IPv6 to Telegram once left a connect stuck in SYN-SENT and the bot went deaf; IPv4 is reliable here.
_getaddrinfo = socket.getaddrinfo
socket.getaddrinfo = lambda *a, **k: [r for r in _getaddrinfo(*a, **k) if r[0] == socket.AF_INET] or _getaddrinfo(*a, **k)

COMMANDS = [
    ("health", "Overall health: CPU, RAM, disk, services, apps, threat checks"),
    ("apps", "PM2 apps: status, uptime, restarts, memory"),
    ("docker", "Docker containers and their usage"),
    ("sites", "HTTPS status of every site + cert days"),
    ("certs", "SSL certificate expiry"),
    ("logs", "/logs <name> [lines] - app/nginx/docker logs (no name = list)"),
    ("errors", "Recent errors from all apps + nginx"),
    ("top", "Top processes by CPU and memory"),
    ("disk", "Disk, Docker and log usage"),
    ("net", "Listening ports and external connections"),
    ("security", "SSH logins, sudo, integrity, threat indicators"),
    ("backup", "Latest backup status"),
    ("alerts", "Currently active alerts"),
    ("help", "This list"),
]
if not HAS_BACKUP:
    COMMANDS = [c for c in COMMANDS if c[0] != "backup"]


def log(*a):
    print(datetime.now().strftime("%F %T"), *a, file=sys.stderr, flush=True)


def tg(method, data=None, timeout=70):
    req = urllib.request.Request(API + method, data=json.dumps(data or {}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r).get("result")
    except urllib.error.HTTPError as e:
        log(f"telegram {method} HTTP {e.code}: {e.read()[:200]!r}")
    except Exception as e:
        log(f"telegram {method} failed: {e}")
    return None


def send_document(name, text, caption=""):
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in (("chat_id", str(CHAT_ID)), ("caption", caption[:1000])):
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{name}"\r\n'
                 f'Content-Type: text/plain\r\n\r\n'.encode() + text.encode() + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    req = urllib.request.Request(API + "sendDocument", data=b"".join(parts),
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        urllib.request.urlopen(req, timeout=60).read()
    except Exception as e:
        log(f"sendDocument failed: {e}")


def send(text, pre=True, filename="output.txt"):
    text = text.strip() or "(empty)"
    is_html = text.startswith("#html\n")   # helper already produced escaped Telegram HTML
    if is_html:
        text = text[len("#html\n"):]
    if len(text) > 3 * 3800 and not is_html:
        send_document(filename, text, caption=text.splitlines()[0][:200])
        return
    chunk, chunks = "", []
    for line in text.splitlines():
        if len(chunk) + len(line) + 1 > 3800:
            chunks.append(chunk)
            chunk = ""
        chunk += line[:3800] + "\n"
    chunks.append(chunk)
    for c in chunks:
        body = c if is_html else f"<pre>{html.escape(c)}</pre>" if pre else html.escape(c)
        tg("sendMessage", {"chat_id": CHAT_ID, "text": body, "parse_mode": "HTML",
                           "disable_web_page_preview": True})


def query(*args, timeout=120):
    try:
        r = subprocess.run(["sudo", "-n", HELPER, *args], capture_output=True, text=True, timeout=timeout)
        return (r.stdout or r.stderr).strip()
    except subprocess.TimeoutExpired:
        return f"timed out after {timeout}s"


# ---------- alerts ----------

class Monitor:
    def __init__(self):
        self.active = {}          # key -> message
        self.prev = None
        self.cpu_high = 0
        self.site_fail = {}
        self.last_sites = 0
        self.last_daily = None
        self.lock = threading.Lock()

    def raise_(self, key, msg):
        with self.lock:
            if key in self.active:
                return
            self.active[key] = msg
        send(msg, pre=False)

    def clear(self, key, msg):
        with self.lock:
            if key not in self.active:
                return
            del self.active[key]
        send(msg, pre=False)

    def state(self, key, bad, bad_msg, ok_msg):
        (self.raise_ if bad else self.clear)(key, bad_msg if bad else ok_msg)

    def check(self):
        try:
            d = json.loads(query("check"))
        except ValueError:
            log("check returned non-JSON")
            return
        p = self.prev

        self.cpu_high = self.cpu_high + 1 if d["cpu"] >= CPU_ALERT else 0
        self.state("cpu", self.cpu_high >= 5, f"🔥 CPU at {d['cpu']}% for 5+ min (load {d['load1']:.1f}). /top",
                   f"✅ CPU back to normal ({d['cpu']}%)")
        self.state("mem", d["mem"] >= MEM_ALERT, f"🔥 RAM at {d['mem']}%. /top", f"✅ RAM back to {d['mem']}%")
        self.state("disk", d["disk"] >= DISK_ALERT, f"💾 Disk at {d['disk']}%. /disk", f"✅ Disk at {d['disk']}%")
        if HAS_BACKUP and d.get("backup_age_h") is not None:
            self.state("backup", d["backup_age_h"] > BACKUP_MAX_AGE_H,
                       f"💾 No new backup for {d['backup_age_h']:.0f}h. /backup", "✅ Fresh backup found")

        for u, s in d["units"].items():
            self.state(f"unit:{u}", s != "active", f"🔴 Service {u} is {s}", f"✅ Service {u} is active again")
        for name, a in d["apps"].items():
            self.state(f"app:{name}", a["status"] != "online", f"🔴 App {name} is {a['status']}",
                       f"✅ App {name} is online again")
            if p and name in p["apps"] and a["restarts"] > p["apps"][name]["restarts"]:
                send(f"🔁 App {name} restarted (↺{a['restarts']}). /logs {name.split('/')[-1]}", pre=False)
        for name, s in d["docker"].items():
            self.state(f"docker:{name}", s != "running", f"🔴 Container {name} is {s}",
                       f"✅ Container {name} is running again")

        if d["integrity"]:
            key = "integrity:" + hashlib.sha1("\n".join(d["integrity"]).encode()).hexdigest()
            for k in [k for k in self.active if k.startswith("integrity:") and k != key]:
                self.active.pop(k, None)
            self.raise_(key, "🚨 Watched system files changed (cron/systemd/ssh/sudoers/profile…):\n"
                        + "\n".join(d["integrity"][:25])
                        + "\n\nIf this was you: sudo vpsbot-query baseline")
        else:
            for k in [k for k in self.active if k.startswith("integrity:")]:
                self.clear(k, "✅ Watched files match the baseline again")
        self.state("ports", bool(d["new_ports"]), "🚨 New listening port(s):\n" + "\n".join(d["new_ports"]),
                   "✅ No unknown listening ports")
        self.state("preload", bool(d["preload"]), f"🚨 /etc/ld.so.preload is NOT empty: {d['preload']}",
                   "✅ /etc/ld.so.preload is empty again")
        self.state("tmpexec", bool(d["tmp_exec"]), "🚨 Executable/hidden files in tmp dirs:\n" + "\n".join(d["tmp_exec"][:15]),
                   "✅ tmp dirs clean again")
        if p and d["blocked_out"] > p["blocked_out"]:
            send(f"🚨 Something on the server tried to reach a blocked IP from BLOCKED_NETS "
                 f"({d['blocked_out'] - p['blocked_out']} packets dropped). Check /top and /net now.", pre=False)
        for login in d["ssh_logins"]:
            send(f"🔑 SSH login: {login}", pre=False)
        for c in d["certs_low"]:
            self.raise_(f"cert:{c.split()[0]}", f"🔐 Certificate expiring soon: {c}. /certs")
        if p and d["uptime"] < p["uptime"]:
            send(f"♻️ Server rebooted ({int(d['uptime'] // 60)} min ago). /health", pre=False)
        self.prev = d

        if time.time() - self.last_sites >= SITES_EVERY:
            self.last_sites = time.time()
            self.check_sites()

        now = datetime.now()
        if now.hour == DAILY_HOUR and self.last_daily != now.date():
            self.last_daily = now.date()
            health = query("health")
            send(health.replace("#html\n", "#html\n☀️ <b>Daily report</b>\n\n", 1) if health.startswith("#html\n") else health)

    def check_sites(self):
        try:
            sites = json.loads(query("check-sites"))
        except ValueError:
            return
        for host, s in sites.items():
            ok = isinstance(s["status"], int) and s["status"] < 500
            self.site_fail[host] = 0 if ok else self.site_fail.get(host, 0) + 1
            self.state(f"site:{host}", self.site_fail[host] >= 2, f"🌐 {host} is DOWN ({s['status']})",
                       f"✅ {host} is back up ({s['status']})")

    def run(self):
        while True:
            try:
                self.check()
            except Exception as e:
                log(f"monitor error: {e!r}")
            if time.time() - last_poll_ok > POLL_STALE:
                log(f"no successful getUpdates for {POLL_STALE}s - exiting so systemd restarts the bot")
                os._exit(1)
            time.sleep(CHECK_EVERY)


# ---------- commands ----------

def handle(text, monitor):
    parts = text.split()
    cmd = parts[0][1:].split("@")[0].lower()
    args = parts[1:3]
    if cmd in ("start", "help"):
        send("#html\n🤖 <b>VPS bot</b>  ·  read-only\n\n"
             + "\n".join(f"/{c}  —  {html.escape(d)}" for c, d in COMMANDS)
             + "\n\n<b>🔔 Pushed automatically</b>\nservices · apps · containers · sites · CPU/RAM/disk · "
             "file integrity · SSH logins · certs · threat indicators\n\n<i>Daily report at "
             f"{DAILY_HOUR:02d}:00</i>")
        return
    if cmd == "alerts":
        with monitor.lock:
            items = list(monitor.active.values())
        send("No active alerts ✅" if not items else "Active alerts:\n\n" + "\n\n".join(items), pre=False)
        return
    if cmd not in {c for c, _ in COMMANDS}:
        send("Unknown command. /help", pre=False)
        return
    tg("sendChatAction", {"chat_id": CHAT_ID, "action": "typing"}, timeout=10)
    if cmd == "logs":
        send(query("logs", *args), filename=f"{args[0] if args else 'logs'}.txt")
    else:
        send(query(cmd), filename=f"{cmd}.txt")


def main():
    global last_poll_ok
    me = tg("getMe")
    if not me:
        sys.exit("cannot reach Telegram / bad token")
    log(f"started as @{me['username']}")
    tg("setMyCommands", {"commands": [{"command": c, "description": d[:256]} for c, d in COMMANDS]})

    monitor = Monitor()
    threading.Thread(target=monitor.run, daemon=True).start()
    up = float(open("/proc/uptime").read().split()[0])
    send(f"🟢 VPS bot online." + (f" ⚠️ Server booted {int(up // 60)} min ago." if up < 900 else "") + " /help", pre=False)

    # skip messages that arrived while the bot was down
    pending = tg("getUpdates", {"offset": -1, "timeout": 0}) or []
    offset = pending[-1]["update_id"] + 1 if pending else None
    reported = set()
    while True:
        updates = tg("getUpdates", {"offset": offset, "timeout": 50, "allowed_updates": ["message"]})
        if updates is None:
            time.sleep(5)
            continue
        last_poll_ok = time.time()
        for u in updates:
            offset = u["update_id"] + 1
            msg = u.get("message") or {}
            text = msg.get("text", "")
            chat, sender = msg.get("chat", {}), msg.get("from", {})
            if chat.get("id") != CHAT_ID or (chat.get("type") == "private" and sender.get("id") != CHAT_ID):
                who = f"{sender.get('first_name', '')} @{sender.get('username', '?')} id={sender.get('id')}"
                log(f"ignored message from {who}")
                if sender.get("id") not in reported:
                    reported.add(sender.get("id"))
                    send(f"⚠️ Someone else messaged your VPS bot and was ignored: {who}", pre=False)
                continue
            if text.startswith("/"):
                try:
                    handle(text, monitor)
                except Exception as e:
                    log(f"command error: {e!r}")
                    send(f"Error: {e}", pre=False)


if __name__ == "__main__":
    main()
