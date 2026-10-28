#!/usr/bin/python3 -I
"""Telegram bot for this VPS: read-only status commands + push alerts.

Runs as the unprivileged `vpsbot` user (systemd: vpsbot.service). All data comes
from `sudo /usr/local/sbin/vpsbot-query`, which only accepts whitelisted commands.
Only messages from VPSBOT_CHAT_ID are answered; everyone else is ignored and reported.
Metrics history (for /graph, forecasts, leak detection, /week) lives in a small SQLite
file in the service's StateDirectory.
"""
import hashlib
import html
import json
import math
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import zlib
from datetime import datetime, timedelta

TOKEN = os.environ["VPSBOT_TOKEN"]
CHAT_ID = int(os.environ["VPSBOT_CHAT_ID"])


def env(name, default):
    return float(os.environ.get(name) or default)


DAILY_HOUR = int(os.environ.get("DAILY_HOUR") or os.environ.get("VPSBOT_DAILY_HOUR") or 9)
WEEKLY_DAY = int(env("WEEKLY_DAY", 0))              # 0 = Monday
CPU_ALERT = env("CPU_ALERT", 90)
MEM_ALERT = env("MEM_ALERT", 90)
DISK_ALERT = env("DISK_ALERT", 85)
DISK_FULL_DAYS = env("DISK_FULL_DAYS", 7)
BACKUP_MAX_AGE_H = env("BACKUP_MAX_AGE_H", 26)
SITE_SLOW_MS = env("SITE_SLOW_MS", 2000)
DOMAIN_DAYS = env("DOMAIN_DAYS", 30)
LEAK_MB = env("LEAK_MB", 150)
CRASH_LOOP = env("CRASH_LOOP", 3)                   # restarts within an hour
TRAFFIC_5XX_MIN = env("TRAFFIC_5XX_MIN", 20)        # per 5 min
TRAFFIC_5XX_PCT = env("TRAFFIC_5XX_PCT", 10)
TRAFFIC_SPIKE_X = env("TRAFFIC_SPIKE_X", 10)
TRAFFIC_MIN_RPM = env("TRAFFIC_MIN_RPM", 100)
IP_FLOOD_RPM = env("IP_FLOOD_RPM", 200)
NET_TX_MB = env("NET_TX_MB", 50)                    # MB per minute, sustained 5 min
NET_SPIKE_X = env("NET_SPIKE_X", 10)
HEARTBEAT_URL = os.environ.get("HEARTBEAT_URL", "").strip()
HAS_BACKUP = bool(os.environ.get("BACKUP_LOG") or os.environ.get("BACKUP_GLOB"))
HELPER = "/usr/local/sbin/vpsbot-query"
DB_FILE = os.path.join(os.environ.get("STATE_DIRECTORY") or "/var/lib/vpsbot", "history.db")
API = f"https://api.telegram.org/bot{TOKEN}/"
CHECK_EVERY = 60
SITES_EVERY = 300
DOMAINS_EVERY = 6 * 3600
POLL_STALE = 300          # no successful getUpdates for this long -> exit, systemd restarts us
MB = 1024 ** 2
last_poll_ok = time.time()

# IPv6 to Telegram once left a connect stuck in SYN-SENT and the bot went deaf; IPv4 is reliable here.
_getaddrinfo = socket.getaddrinfo
socket.getaddrinfo = lambda *a, **k: [r for r in _getaddrinfo(*a, **k) if r[0] == socket.AF_INET] or _getaddrinfo(*a, **k)

COMMANDS = [
    ("health", "Overall health: CPU, RAM, disk, services, apps, threat checks"),
    ("apps", "PM2 apps: status, uptime, restarts, memory"),
    ("docker", "Docker containers and their usage"),
    ("sites", "HTTPS status, response time + cert days of every site"),
    ("traffic", "/traffic [minutes] - nginx requests, top IPs, 404s, 5xx, scanners"),
    ("graph", "/graph <metric> [1h|6h|24h|7d] - charts from history"),
    ("db", "Databases: connections, size, slow queries"),
    ("domains", "Domain registration expiry"),
    ("certs", "SSL certificate expiry"),
    ("logs", "/logs <name> [lines] - app/nginx/docker logs (no name = list)"),
    ("errors", "Recent errors from all apps + nginx"),
    ("top", "Top processes by CPU and memory"),
    ("disk", "Disk, Docker and log usage"),
    ("net", "Listening ports and external connections"),
    ("security", "SSH logins, sudo, integrity, threat indicators"),
    ("backup", "Latest backup status"),
    ("week", "Weekly summary: uptime, restarts, peaks, growth"),
    ("alerts", "Currently active alerts"),
    ("help", "This list"),
]
if not HAS_BACKUP:
    COMMANDS = [c for c in COMMANDS if c[0] != "backup"]
REFRESHABLE = {"health", "apps", "docker", "sites", "traffic", "db", "domains", "certs", "errors", "top", "disk",
               "net", "security", "backup", "alerts", "week"}


def log(*a):
    print(datetime.now().strftime("%F %T"), *a, file=sys.stderr, flush=True)


def tg(method, data=None, timeout=70):
    req = urllib.request.Request(API + method, data=json.dumps(data or {}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r).get("result")
    except urllib.error.HTTPError as e:
        body = e.read()[:200]
        if b"message is not modified" not in body:
            log(f"telegram {method} HTTP {e.code}: {body!r}")
    except Exception as e:
        log(f"telegram {method} failed: {e}")
    return None


def tg_upload(method, fields, field, name, content, ctype):
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{name}"\r\n'
                 f'Content-Type: {ctype}\r\n\r\n'.encode() + content + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    req = urllib.request.Request(API + method, data=b"".join(parts),
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r).get("result")
    except urllib.error.HTTPError as e:
        log(f"{method} HTTP {e.code}: {e.read()[:200]!r}")
    except Exception as e:
        log(f"{method} failed: {e}")
    return None


def keyboard(buttons):
    """[(label, callback_data)] -> inline keyboard, 3 per row; data over Telegram's 64-byte limit is dropped."""
    btns = [{"text": t, "callback_data": d} for t, d in buttons if len(d.encode()) <= 64]
    return {"inline_keyboard": [btns[i:i + 3] for i in range(0, len(btns), 3)]} if btns else None


def send_document(name, text, caption=""):
    tg_upload("sendDocument", {"chat_id": str(CHAT_ID), "caption": caption[:1000]}, "document", name,
              text.encode(), "text/plain")


def send(text, pre=True, filename="output.txt", buttons=None, refresh=None):
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
    buttons = list(buttons or [])
    if refresh and len(chunks) == 1:
        buttons.append(("🔄 Refresh", f"r:{refresh}"))
    for i, c in enumerate(chunks):
        body = render(c, is_html, pre, stamp=bool(refresh and len(chunks) == 1))
        data = {"chat_id": CHAT_ID, "text": body, "parse_mode": "HTML", "disable_web_page_preview": True}
        if i == len(chunks) - 1 and keyboard(buttons):
            data["reply_markup"] = keyboard(buttons)
        tg("sendMessage", data)


def render(text, is_html, pre, stamp=False):
    body = text if is_html else f"<pre>{html.escape(text)}</pre>" if pre else html.escape(text)
    return body + (f"\n<i>⟳ {datetime.now():%H:%M:%S}</i>" if stamp else "")


def send_photo(png, caption, buttons=None):
    fields = {"chat_id": str(CHAT_ID), "caption": caption[:1000], "parse_mode": "HTML"}
    if keyboard(buttons or []):
        fields["reply_markup"] = json.dumps(keyboard(buttons))
    tg_upload("sendPhoto", fields, "photo", "graph.png", png, "image/png")


def query(*args, timeout=120):
    try:
        r = subprocess.run(["sudo", "-n", HELPER, *args], capture_output=True, text=True, timeout=timeout)
        return (r.stdout or r.stderr).strip()
    except subprocess.TimeoutExpired:
        return f"timed out after {timeout}s"


def query_json(*args):
    try:
        return json.loads(query(*args))
    except ValueError:
        log(f"{args[0]} returned non-JSON")
        return None


def heartbeat():
    """Dead-man's switch: an external service (healthchecks.io etc.) alerts you when these pings stop."""
    if not HEARTBEAT_URL:
        return
    def ping():
        try:
            urllib.request.urlopen(urllib.request.Request(HEARTBEAT_URL, headers={"User-Agent": "vpsbot"}),
                                   timeout=15).read()
        except Exception as e:
            log(f"heartbeat failed: {e}")
    threading.Thread(target=ping, daemon=True).start()


# ---------- history ----------

class History:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS sys(ts INTEGER, cpu REAL, mem REAL, disk REAL, disk_used INTEGER,
                disk_total INTEGER, load REAL, rx_rate REAL, tx_rate REAL, req INTEGER, err5 INTEGER);
            CREATE TABLE IF NOT EXISTS app(ts INTEGER, name TEXT, mem INTEGER, restarts INTEGER, online INTEGER);
            CREATE TABLE IF NOT EXISTS site(ts INTEGER, host TEXT, ms INTEGER, ok INTEGER);
            CREATE TABLE IF NOT EXISTS dbs(ts INTEGER, name TEXT, size INTEGER, conns INTEGER);
            CREATE TABLE IF NOT EXISTS alert(ts INTEGER, key TEXT, msg TEXT);
            CREATE INDEX IF NOT EXISTS sys_ts ON sys(ts);
            CREATE INDEX IF NOT EXISTS app_name_ts ON app(name, ts);
            CREATE INDEX IF NOT EXISTS site_host_ts ON site(host, ts);
            CREATE INDEX IF NOT EXISTS dbs_name_ts ON dbs(name, ts);
            CREATE INDEX IF NOT EXISTS alert_ts ON alert(ts);
        """)

    def add(self, table, rows):
        if not rows:
            return
        with self.lock:
            self.db.executemany(f"INSERT INTO {table} VALUES ({','.join('?' * len(rows[0]))})", rows)
            self.db.commit()

    def q(self, sql, *args):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def prune(self):
        now = time.time()
        with self.lock:
            for table, days in (("sys", 8), ("app", 8), ("site", 35), ("dbs", 35), ("alert", 35)):
                self.db.execute(f"DELETE FROM {table} WHERE ts < ?", (now - days * 86400,))
            self.db.commit()


def median(v):
    v = sorted(v)
    return v[len(v) // 2] if v else 0


def linfit(pts):
    """Least squares over [(x, y)] -> slope, intercept, r²."""
    n = len(pts)
    mx, my = sum(p[0] for p in pts) / n, sum(p[1] for p in pts) / n
    sxx = sum((p[0] - mx) ** 2 for p in pts)
    syy = sum((p[1] - my) ** 2 for p in pts)
    if not sxx:
        return 0, my, 0
    sxy = sum((p[0] - mx) * (p[1] - my) for p in pts)
    slope = sxy / sxx
    return slope, my - slope * mx, (sxy * sxy / (sxx * syy) if syy else 0)


def fmt_bytes(n):
    for unit, size in (("G", 1024 ** 3), ("M", MB), ("K", 1024)):
        if abs(n) >= size:
            return f"{n / size:.1f}{unit}" if abs(n) < 10 * size else f"{n / size:.0f}{unit}"
    return f"{n:.0f}"


def fmt_dur(sec):
    d, h = int(sec // 86400), int(sec % 86400 // 3600)
    return f"{d}d {h}h" if d else f"{h}h {int(sec % 3600 // 60)}m" if h else f"{int(sec // 60)}m"


# ---------- PNG charts (no dependencies) ----------

FONT = {  # 3x5 glyphs, rows top to bottom
    "0": "111101101101111", "1": "010110010010111", "2": "111001111100111", "3": "111001111001111",
    "4": "101101111001001", "5": "111100111001111", "6": "111100111101111", "7": "111001001001001",
    "8": "111101111101111", "9": "111101111001111", ".": "000000000000010", ":": "000010000010000",
    "%": "101001010100101", "-": "000000111000000", "/": "001001010100100", " ": "000000000000000",
    "K": "101101110101101", "M": "101111111101101", "G": "111100101101111", "B": "110101110101110",
    "s": "000011010001110", "m": "000000111111101", "h": "100100111101101", "d": "001001111101111",
}
BG, GRID, AXIS = (255, 255, 255), (231, 234, 239), (107, 114, 128)
SERIES = [((37, 99, 235), (219, 231, 253)), ((234, 88, 12), None)]


class Canvas:
    def __init__(self, w, h):
        self.w, self.h = w, h
        self.px = bytearray(bytes(BG) * (w * h))

    def dot(self, x, y, c):
        if 0 <= x < self.w and 0 <= y < self.h:
            i = (y * self.w + x) * 3
            self.px[i:i + 3] = bytes(c)

    def rect(self, x0, y0, x1, y1, c):
        for y in range(max(0, y0), min(self.h, y1)):
            i = (y * self.w + max(0, x0)) * 3
            n = min(self.w, x1) - max(0, x0)
            if n > 0:
                self.px[i:i + 3 * n] = bytes(c) * n

    def line(self, x0, y0, x1, y1, c):
        dx, dy = abs(x1 - x0), -abs(y1 - y0)
        sx, sy = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1)
        err = dx + dy
        while True:
            self.rect(x0 - 1, y0 - 1, x0 + 1, y0 + 2, c)
            if x0 == x1 and y0 == y1:
                return
            e2 = 2 * err
            if e2 >= dy:
                err, x0 = err + dy, x0 + sx
            if e2 <= dx:
                err, y0 = err + dx, y0 + sy

    def text(self, x, y, s, c, scale=2):
        for ch in s:
            g = FONT.get(ch, FONT[" "])
            for i, bit in enumerate(g):
                if bit == "1":
                    self.rect(x + i % 3 * scale, y + i // 3 * scale, x + i % 3 * scale + scale,
                              y + i // 3 * scale + scale, c)
            x += 4 * scale

    def png(self):
        raw = b"".join(b"\x00" + bytes(self.px[y * self.w * 3:(y + 1) * self.w * 3]) for y in range(self.h))
        chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", self.w, self.h, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def nice_top(v):
    """Smallest 4 × (1|2|2.5|5 × 10^k) above v, so the y-axis ticks are round numbers."""
    if v <= 0:
        return 1
    step = v / 4
    mag = 10 ** math.floor(math.log10(step))
    return 4 * mag * next(f for f in (1, 2, 2.5, 5, 10) if f * mag >= step)


def chart(series, t0, t1, fmt, ymax=None):
    """series: [[(ts, value)], ...] -> PNG bytes."""
    W, H, L, R, T, B = 900, 380, 78, 20, 18, 42
    pw, ph = W - L - R, H - T - B
    c = Canvas(W, H)
    vals = [v for s in series for _, v in s]
    top = ymax or nice_top(max(vals) if vals else 0)
    for i in range(5):
        y = T + ph - round(ph * i / 4)
        c.rect(L, y, L + pw, y + 1, GRID)
        label = fmt(top * i / 4)
        c.text(L - 10 - len(label) * 8, y - 5, label, AXIS)
    span = t1 - t0
    for i in range(5):
        x = L + round(pw * i / 4)
        t = datetime.fromtimestamp(t0 + span * i / 4)
        label = t.strftime("%H:%M") if span <= 36 * 3600 else t.strftime("%m-%d")
        c.rect(x, T + ph, x + 1, T + ph + 5, AXIS)
        c.text(min(max(x - len(label) * 4, 0), W - len(label) * 8), T + ph + 14, label, AXIS)
    c.rect(L, T + ph, L + pw, T + ph + 1, AXIS)
    for (color, fill), pts in zip(SERIES, series):
        cols = {}                                   # pixel column -> values (bucket average)
        for ts, v in pts:
            cols.setdefault(min(pw - 1, int((ts - t0) / span * pw)), []).append(v)
        gap = max(3, pw * 3 * 60 / span)            # > 3 missed samples: don't join the line
        ys = {x: T + ph - round(ph * min(sum(v) / len(v), top) / top) for x, v in cols.items()}
        prev = None
        for x in sorted(ys):
            if fill:
                c.rect(L + x, ys[x], L + x + 1, T + ph, fill)
                if prev is not None and x - prev[0] <= gap:
                    for xx in range(prev[0] + 1, x):    # fill between sparse samples
                        yy = round(prev[1] + (ys[x] - prev[1]) * (xx - prev[0]) / (x - prev[0]))
                        c.rect(L + xx, yy, L + xx + 1, T + ph, fill)
            prev = (x, ys[x])
        prev = None
        for x in sorted(ys):
            if prev is not None and x - prev[0] <= gap:
                c.line(L + prev[0], prev[1], L + x, ys[x], color)
            else:
                c.rect(L + x - 1, ys[x] - 1, L + x + 2, ys[x] + 2, color)
            prev = (x, ys[x])
    return c.png()


RANGE_RX = re.compile(r"(\d{1,3})([hd])")


def graph(hist, metric, rng="24h"):
    """-> (png, caption) or (None, error text)."""
    m = RANGE_RX.fullmatch(rng or "24h")
    if not m:
        return None, "Range must look like 1h, 6h, 24h or 7d."
    secs = int(m.group(1)) * (3600 if m.group(2) == "h" else 86400)
    secs = max(3600, min(secs, 35 * 86400 if metric.startswith(("site:", "db:")) else 8 * 86400))
    t1 = time.time()
    t0 = t1 - secs
    pct = lambda v: f"{v:.0f}%"
    simple = {"cpu": ("CPU", "cpu", pct, 100), "mem": ("RAM", "mem", pct, 100), "disk": ("Disk", "disk", pct, 100),
              "load": ("Load", "load", lambda v: f"{v:.1f}", None)}
    legend = ""
    if metric in simple:
        title, col, fmt, ymax = simple[metric]
        series = [hist.q(f"SELECT ts, {col} FROM sys WHERE ts >= ? AND {col} IS NOT NULL ORDER BY ts", t0)]
    elif metric == "net":
        title, fmt, ymax = "Network", lambda v: fmt_bytes(v) + "/s", None
        series = [hist.q(f"SELECT ts, {c} FROM sys WHERE ts >= ? AND {c} IS NOT NULL ORDER BY ts", t0)
                  for c in ("rx_rate", "tx_rate")]
        legend = "🔵 in  🟠 out"
    elif metric == "req":
        title, fmt, ymax = "Requests/min", lambda v: f"{v:.0f}", None
        series = [hist.q(f"SELECT ts, {c} / 5.0 FROM sys WHERE ts >= ? AND {c} IS NOT NULL ORDER BY ts", t0)
                  for c in ("req", "err5")]
        legend = "🔵 all  🟠 5xx"
    elif metric.startswith("app:"):
        name = metric[4:]
        title, fmt, ymax = f"{name} memory", fmt_bytes, None
        series = [hist.q("SELECT ts, mem FROM app WHERE (name = ? OR name LIKE ?) AND ts >= ? ORDER BY ts",
                         name, f"%/{name}", t0)]
    elif metric.startswith("site:"):
        title, fmt, ymax = f"{metric[5:]} response", lambda v: f"{v:.0f}ms", None
        series = [hist.q("SELECT ts, ms FROM site WHERE host = ? AND ts >= ? AND ms IS NOT NULL ORDER BY ts",
                         metric[5:], t0)]
    elif metric.startswith("db:"):
        title, fmt, ymax = f"{metric[3:]} size", fmt_bytes, None
        series = [hist.q("SELECT ts, size FROM dbs WHERE name = ? AND ts >= ? ORDER BY ts", metric[3:], t0)]
    else:
        return None, f"Unknown metric '{metric}'. /graph shows the list."
    main = series[0]
    if len(main) < 2:
        return None, f"Not enough history for {metric} yet (collected every minute; sites/DBs every 5)."
    v = [x[1] for x in main]
    caption = (f"📈 <b>{html.escape(title)}</b> · last {rng}\n"
               f"now {fmt(v[-1])} · avg {fmt(sum(v) / len(v))} · max {fmt(max(v))}" + (f"\n{legend}" if legend else ""))
    return chart(series, t0, t1, fmt, ymax), caption


# ---------- alerts ----------

WEB_UNITS = ("unit:nginx", "unit:apache2", "unit:httpd", "unit:caddy")


def btn(label, cmd):
    return (label, f"c:{cmd}")


def alert_buttons(key):
    kind, _, rest = key.partition(":")
    short = rest.split("/")[-1]
    return {
        "app": [btn("📜 Logs", f"logs {short}"), btn("📦 Apps", "apps")],
        "crash": [btn("📜 Logs", f"logs {short}"), btn("📈 Memory", f"graph app:{short} 6h")],
        "leak": [btn("📈 Memory", f"graph app:{short} 24h"), btn("📦 Apps", "apps")],
        "site": [btn("🌐 Sites", "sites"), btn("🚦 Traffic", "traffic"), btn("📜 nginx", "logs nginx")],
        "slow": [btn("📈 Response", f"graph site:{rest} 24h"), btn("🌐 Sites", "sites")],
        "content": [btn("🌐 Sites", "sites"), btn("📜 nginx", "logs nginx")],
        "unit": [btn("🩺 Health", "health"), btn("📜 System log", "logs system")],
        "docker": [btn("📜 Logs", f"logs docker:{rest}"), btn("🐳 Docker", "docker")],
        "cpu": [btn("📊 Top", "top"), btn("📈 CPU", "graph cpu 6h")],
        "mem": [btn("📊 Top", "top"), btn("📈 RAM", "graph mem 6h")],
        "disk": [btn("💾 Disk", "disk"), btn("📈 Disk", "graph disk 7d")],
        "diskfull": [btn("💾 Disk", "disk"), btn("📈 Disk", "graph disk 7d")],
        "traffic": [btn("🚦 Traffic", "traffic 15"), btn("📈 Requests", "graph req 6h"), btn("📜 nginx", "logs nginx")],
        "net": [btn("🌐 Net", "net"), btn("📊 Top", "top"), btn("📈 Network", "graph net 6h")],
        "out": [btn("🌐 Net", "net"), btn("📊 Top", "top"), btn("🛡 Security", "security")],
        "proc": [btn("📊 Top", "top"), btn("🛡 Security", "security")],
        "db": [btn("🗄 DB", "db")],
        "domain": [btn("🌍 Domains", "domains")],
        "cert": [btn("🔐 Certs", "certs")],
        "backup": [btn("💾 Backup", "backup")],
    }.get("traffic" if kind == "flood" else kind, [btn("🛡 Security", "security")] if kind in ("integrity", "ports", "preload", "tmpexec") else [])


class Monitor:
    def __init__(self, hist):
        self.hist = hist
        self.active = {}          # key -> {"msg", "under": parent key when grouped (silent) or None}
        self.outbox = []          # (text, buttons) sent as one message per check cycle
        self.prev = None
        self.prev_ts = None
        self.cpu_high = 0
        self.site_fail = {}
        self.site_bad_content = {}
        self.db_fail = {}
        self.db_slow = {}
        self.db_rejected = {}
        self.site_count = 0
        self.last_sites = 0
        self.last_domains = 0
        self.last_analysis = 0
        self.last_daily = None
        self.last_weekly = None
        self.lock = threading.Lock()

    # --- grouping: a child alert stays silent while its root cause is already alerted ---
    def parent_of(self, key):
        kind, _, rest = key.partition(":")
        if kind in ("site", "slow", "content"):
            cands = list(WEB_UNITS) + ([f"site:{rest}"] if kind != "site" else [])
        elif kind == "docker" or kind == "db":
            cands = ["unit:docker"]
        elif kind in ("app", "leak", "crash"):
            user = rest.split("/")[0]
            cands = [f"unit:pm2-{user}", f"app:{user}/?"]
        else:
            return None
        for c in cands:
            if c != key and c in self.active and not self.active[c]["under"]:
                return c
        return None

    def children_hint(self, key):
        if key in WEB_UNITS and self.site_count:
            return f"\n→ {self.site_count} site(s) affected"
        if key == "unit:docker" and self.prev and self.prev.get("docker"):
            return f"\n→ {len(self.prev['docker'])} container(s) affected"
        if key.startswith("unit:pm2-") and self.prev:
            n = sum(a.startswith(key[9:] + "/") for a in self.prev["apps"])
            return f"\n→ {n} app(s) affected" if n else ""
        return ""

    def notify(self, msg, buttons=None, key="event"):
        self.outbox.append((msg, buttons or []))
        self.hist.add("alert", [(int(time.time()), key, msg[:300])])

    def raise_(self, key, msg):
        with self.lock:
            if key in self.active:
                return
            parent = self.parent_of(key)
            self.active[key] = {"msg": msg, "under": parent}
        self.hist.add("alert", [(int(time.time()), key, msg[:300])])
        if not parent:
            self.outbox.append((msg + self.children_hint(key), alert_buttons(key)))

    def clear(self, key, msg):
        with self.lock:
            if key not in self.active:
                return
            ent = self.active.pop(key)
            # children are dropped; if they are still broken they re-alert on their own next cycle
            kids = [k for k, v in self.active.items() if v["under"] == key]
            for k in kids:
                del self.active[k]
        if not ent["under"]:
            self.outbox.append((msg + (f" ({len(kids)} grouped alert(s) re-checked)" if kids else ""), []))

    def state(self, key, bad, bad_msg, ok_msg):
        if bad:
            self.raise_(key, bad_msg)
        else:
            self.clear(key, ok_msg)

    def sync(self, prefix, items, bad_fmt, ok_fmt):
        """One alert per item (keyed by a hash), cleared when the item disappears."""
        keys = {f"{prefix}:{hashlib.sha1(i.encode()).hexdigest()[:12]}": i for i in items}
        for k, i in keys.items():
            self.raise_(k, bad_fmt(i))
        for k in [k for k in list(self.active) if k.startswith(prefix + ":") and k not in keys]:
            self.clear(k, ok_fmt(self.active[k]["msg"]))

    def flush(self):
        out, self.outbox = self.outbox, []
        if not out:
            return
        if len(out) == 1:
            send(out[0][0], pre=False, buttons=out[0][1])
            return
        buttons = list(dict.fromkeys(b for _, bs in out for b in bs))[:6]
        head = f"⚠️ {len(out)} events\n\n" if len(out) >= 3 else ""
        send(head + "\n\n".join(m for m, _ in out), pre=False, buttons=buttons)

    # --- the checks ---
    def check(self):
        d = query_json("check")
        if d is None:
            return False
        p, now = self.prev, time.time()
        dt_s = now - self.prev_ts if self.prev_ts else None

        rx_rate = tx_rate = None
        if p and dt_s and d["rx"] >= p["rx"] and d["tx"] >= p["tx"]:
            rx_rate, tx_rate = (d["rx"] - p["rx"]) / dt_s, (d["tx"] - p["tx"]) / dt_s
        tr = d.get("traffic") or {}
        self.hist.add("sys", [(int(now), d["cpu"], d["mem"], d["disk"], d["disk_used"], d["disk_total"], d["load1"],
                               rx_rate, tx_rate, tr.get("req"), tr.get("err5"))])
        self.hist.add("app", [(int(now), n, a.get("mem", 0), a.get("restarts", 0), int(a["status"] == "online"))
                              for n, a in d["apps"].items()])

        self.cpu_high = self.cpu_high + 1 if d["cpu"] >= CPU_ALERT else 0
        self.state("cpu", self.cpu_high >= 5, f"🔥 CPU at {d['cpu']}% for 5+ min (load {d['load1']:.1f}).",
                   f"✅ CPU back to normal ({d['cpu']}%)")
        self.state("mem", d["mem"] >= MEM_ALERT, f"🔥 RAM at {d['mem']}%.", f"✅ RAM back to {d['mem']}%")
        self.state("disk", d["disk"] >= DISK_ALERT, f"💾 Disk at {d['disk']}%.", f"✅ Disk at {d['disk']}%")
        if HAS_BACKUP and d.get("backup_age_h") is not None:
            self.state("backup", d["backup_age_h"] > BACKUP_MAX_AGE_H,
                       f"💾 No new backup for {d['backup_age_h']:.0f}h.", "✅ Fresh backup found")

        # units first so grouped children (sites/containers/apps) see their parent
        for u, s in d["units"].items():
            self.state(f"unit:{u}", s != "active", f"🔴 Service {u} is {s}", f"✅ Service {u} is active again")
        for name, a in d["apps"].items():
            self.state(f"app:{name}", a["status"] != "online", f"🔴 App {name} is {a['status']}",
                       f"✅ App {name} is online again")
        self.check_restarts(d, p)
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
        self.sync("out", d.get("out_odd", []), lambda i: f"🚨 Outbound connection on an unusual port: {i}",
                  lambda m: "✅ Gone: " + m.split(": ", 1)[-1])
        self.sync("proc", d.get("odd_procs", []),
                  lambda i: f"🚨 Process running from a deleted or tmp binary: {i}\n"
                            "(a deleted binary can also just mean a service wasn't restarted after an upgrade)",
                  lambda m: "✅ Process gone: " + m.split(": ", 1)[-1].split("\n")[0])
        self.check_traffic(tr)
        self.check_net(tx_rate)

        if p and d["blocked_out"] > p["blocked_out"]:
            self.notify(f"🚨 Something on the server tried to reach a blocked IP from BLOCKED_NETS "
                        f"({d['blocked_out'] - p['blocked_out']} packets dropped).", alert_buttons("out:x"), "blocked")
        for login in d["ssh_logins"]:
            self.notify(f"🔑 SSH login: {login}", [btn("🛡 Security", "security")], "ssh")
        for c in d["certs_low"]:
            self.raise_(f"cert:{c.split()[0]}", f"🔐 Certificate expiring soon: {c}.")
        if p and d["uptime"] < p["uptime"]:
            self.notify(f"♻️ Server rebooted ({int(d['uptime'] // 60)} min ago).", [btn("🩺 Health", "health")], "reboot")
        self.prev, self.prev_ts = d, now

        if now - self.last_sites >= SITES_EVERY:
            self.last_sites = now
            self.check_sites()
            self.check_dbs()
        if now - self.last_analysis >= 600:
            self.last_analysis = now
            self.check_disk_forecast()
            self.check_leaks(d)
        if now - self.last_domains >= DOMAINS_EVERY:
            self.last_domains = now
            self.check_domains()
        self.flush()

        today = datetime.now()
        if today.hour == DAILY_HOUR and self.last_daily != today.date():
            self.last_daily = today.date()
            self.hist.prune()
            health = query("health")
            send(health.replace("#html\n", "#html\n☀️ <b>Daily report</b>\n\n", 1) if health.startswith("#html\n") else health,
                 refresh="health")
            if today.weekday() == WEEKLY_DAY and self.last_weekly != today.date():
                self.last_weekly = today.date()
                send(week_report(self.hist), refresh="week")
        return True

    def check_restarts(self, d, p):
        hour_ago = time.time() - 3600
        for name, a in d["apps"].items():
            first = self.hist.q("SELECT restarts FROM app WHERE name = ? AND ts >= ? ORDER BY ts LIMIT 1", name, hour_ago)
            n = a["restarts"] - first[0][0] if first and a["restarts"] >= first[0][0] else 0
            self.state(f"crash:{name}", n >= CRASH_LOOP, f"🔁 Crash loop: {name} restarted {n}× in the last hour.",
                       f"✅ {name} stopped restarting")
            if (p and name in p["apps"] and a["restarts"] > p["apps"][name]["restarts"]
                    and f"crash:{name}" not in self.active):
                self.notify(f"🔁 App {name} restarted (↺{a['restarts']}).", alert_buttons(f"app:{name}"), f"restart:{name}")

    def check_traffic(self, tr):
        if not tr:
            return
        req, err5 = tr["req"], tr["err5"]
        self.state("traffic:5xx", err5 >= TRAFFIC_5XX_MIN and err5 >= req * TRAFFIC_5XX_PCT / 100,
                   f"🚨 5xx spike: {err5} server errors in 5 min ({100 * err5 / max(req, 1):.0f}% of requests).",
                   "✅ 5xx errors back to normal")
        rows = self.hist.q("SELECT req FROM sys WHERE ts >= ? AND req IS NOT NULL", time.time() - 86400)
        normal = median([r[0] for r in rows]) / 5 if len(rows) >= 60 else None
        rpm = req / 5
        self.state("traffic:spike", normal is not None and rpm >= TRAFFIC_MIN_RPM and rpm >= TRAFFIC_SPIKE_X * max(normal, 1),
                   f"📈 Traffic spike: {rpm:.0f} req/min (normal ~{normal or 0:.0f}). "
                   f"Top IP {tr.get('top_ip')} ({tr.get('top_ip_n')} in 5 min).",
                   f"✅ Traffic back to normal ({rpm:.0f} req/min)")
        flood = [tr["top_ip"]] if tr.get("top_ip") and tr["top_ip_n"] / 5 >= IP_FLOOD_RPM else []
        self.sync("flood", flood, lambda ip: f"🚨 Single IP hammering the server: {ip} → {tr['top_ip_n'] / 5:.0f} req/min.",
                  lambda m: "✅ Flood stopped: " + m.split(": ", 1)[-1].split(" →")[0])

    def check_net(self, tx_rate):
        if tx_rate is None:
            return
        rows = self.hist.q("SELECT tx_rate FROM sys WHERE ts >= ? AND tx_rate IS NOT NULL ORDER BY ts", time.time() - 86400)
        if len(rows) < 120:
            return
        recent = [r[0] for r in rows[-5:]]
        per_min = sum(recent) / len(recent) * 60
        normal = median([r[0] for r in rows]) * 60
        self.state("net:tx", min(recent) * 60 >= NET_TX_MB * MB and per_min >= NET_SPIKE_X * max(normal, 1),
                   f"📤 Unusual outbound traffic: {fmt_bytes(per_min)}B/min for 5+ min (normal ~{fmt_bytes(normal)}B/min). "
                   "Backup upload, or data leaving the server?",
                   f"✅ Outbound traffic back to normal ({fmt_bytes(per_min)}B/min)")

    def check_sites(self):
        sites = query_json("check-sites")
        if sites is None:
            return
        self.site_count = len(sites)
        now = int(time.time())
        self.hist.add("site", [(now, h, s.get("ms"), int(isinstance(s["status"], int) and s["status"] < 500))
                               for h, s in sites.items()])
        for host, s in sites.items():
            ok = isinstance(s["status"], int) and s["status"] < 500
            self.site_fail[host] = 0 if ok else self.site_fail.get(host, 0) + 1
            self.state(f"site:{host}", self.site_fail[host] >= 2, f"🌐 {host} is DOWN ({s['status']})",
                       f"✅ {host} is back up ({s['status']})")
            last = [r[0] for r in self.hist.q("SELECT ms FROM site WHERE host = ? AND ok = 1 ORDER BY ts DESC LIMIT 3", host)]
            slow = ok and len(last) == 3 and min(x or 0 for x in last) >= SITE_SLOW_MS
            self.state(f"slow:{host}", slow, f"🐢 {host} is slow: {sum(last) / 3000:.1f}s average over the last 3 checks.",
                       f"✅ {host} responds normally again ({s.get('ms')}ms)")
            if s.get("content_ok") is not None:
                self.site_bad_content[host] = 0 if s["content_ok"] else self.site_bad_content.get(host, 0) + 1
                self.state(f"content:{host}", self.site_bad_content[host] >= 2,
                           f"⚠️ {host}: expected text (SITE_EXPECT) is missing from the page — broken deploy or defacement?",
                           f"✅ {host} content check passes again")

    def check_dbs(self):
        res = query_json("check-db")
        if res is None:
            return
        self.hist.add("dbs", [(int(time.time()), n, r.get("size"), r.get("conns")) for n, r in res.items() if r.get("ok")])
        for name, r in res.items():
            self.db_fail[name] = 0 if r["ok"] else self.db_fail.get(name, 0) + 1
            self.state(f"db:{name}", self.db_fail[name] >= 2, f"🔴 Database {name} is unreachable: {r.get('err', '?')}",
                       f"✅ Database {name} answers again")
            if not r["ok"]:
                continue
            full = r.get("max") and r.get("conns", 0) >= 0.8 * r["max"]
            self.state(f"db:{name}:conns", bool(full), f"🗄 {name}: {r.get('conns')}/{r.get('max')} connections in use.",
                       f"✅ {name} connections back to {r.get('conns')}/{r.get('max')}")
            self.db_slow[name] = self.db_slow.get(name, 0) + 1 if r.get("slow") else 0
            self.state(f"db:{name}:slow", self.db_slow[name] >= 2,
                       f"🐢 {name}: {r.get('slow')} queries running longer than 30s.", f"✅ {name}: no long-running queries")
            if r.get("maxmem"):
                self.state(f"db:{name}:mem", r["size"] >= 0.9 * r["maxmem"],
                           f"🗄 {name} memory at {fmt_bytes(r['size'])}B of {fmt_bytes(r['maxmem'])}B maxmemory.",
                           f"✅ {name} memory back under 90%")
            if name in self.db_rejected and r.get("rejected", 0) > self.db_rejected[name]:
                self.notify(f"🗄 {name} rejected {r['rejected'] - self.db_rejected[name]} connection(s) (maxclients reached?).",
                            alert_buttons("db:x"), f"db:{name}:rejected")
            self.db_rejected[name] = r.get("rejected", 0)

    def check_domains(self):
        res = query_json("check-domains")
        for dom, r in (res or {}).items():
            days = r.get("days")
            self.state(f"domain:{dom}", days is not None and days < DOMAIN_DAYS,
                       f"🌍 Domain {dom} " + ("EXPIRED on " + r.get("expires", "?") if (days or 0) < 0
                                              else f"expires in {days} days ({r.get('expires')})") + " — renew it.",
                       f"✅ Domain {dom} renewed (expires {r.get('expires')})")

    def check_disk_forecast(self):
        rows = self.hist.q("SELECT ts, disk_used, disk_total FROM sys WHERE ts >= ? AND disk_used IS NOT NULL ORDER BY ts",
                           time.time() - 72 * 3600)
        if len(rows) < 60 or rows[-1][0] - rows[0][0] < 12 * 3600:
            return
        slope = linfit([(r[0], r[1]) for r in rows])[0]           # bytes per second
        free = rows[-1][2] - rows[-1][1]
        days = free / slope / 86400 if slope > 0 else None
        grows = slope * (rows[-1][0] - rows[0][0]) > 0.005 * rows[-1][2]
        if days is not None and days < DISK_FULL_DAYS and grows:
            self.raise_("diskfull", f"💾 Disk will be full in ~{days:.1f} days at the current growth "
                                    f"(+{fmt_bytes(slope * 86400)}B/day, {fmt_bytes(free)}B free).")
        elif days is None or days > DISK_FULL_DAYS * 1.5:
            self.clear("diskfull", "✅ Disk growth slowed down — no longer on track to fill up")

    def check_leaks(self, d):
        since = time.time() - 6 * 3600
        for name, a in d["apps"].items():
            if a["status"] != "online":
                continue
            rows = self.hist.q("SELECT ts, mem, restarts FROM app WHERE name = ? AND ts >= ? ORDER BY ts", name, since)
            rows = [r for r in rows if r[2] == a["restarts"]]          # only since the last restart
            if len(rows) < 60 or rows[-1][0] - rows[0][0] < 3 * 3600:
                self.clear(f"leak:{name}", f"✅ {name} memory stable again (restarted)")
                continue
            slope, icpt, r2 = linfit([(r[0], r[1]) for r in rows])
            start, end = icpt + slope * rows[0][0], icpt + slope * rows[-1][0]
            hours = (rows[-1][0] - rows[0][0]) / 3600
            growth = end - start
            if growth >= LEAK_MB * MB and growth >= 0.5 * max(start, 1) and r2 >= 0.8:
                self.raise_(f"leak:{name}", f"📈 Possible memory leak in {name}: {fmt_bytes(start)}B → {fmt_bytes(end)}B "
                                            f"over {hours:.0f}h (+{fmt_bytes(growth / hours)}B/h, steady climb).")
            elif growth < LEAK_MB * MB / 2:
                self.clear(f"leak:{name}", f"✅ {name} memory stable again")

    def run(self):
        while True:
            ok = False
            try:
                ok = self.check()
            except Exception as e:
                log(f"monitor error: {e!r}")
                self.outbox = []
            if ok and time.time() - last_poll_ok <= POLL_STALE:
                heartbeat()
            if time.time() - last_poll_ok > POLL_STALE:
                log(f"no successful getUpdates for {POLL_STALE}s - exiting so systemd restarts the bot")
                os._exit(1)
            time.sleep(CHECK_EVERY)


# ---------- weekly summary ----------

def week_report(hist):
    t0 = time.time() - 7 * 86400
    e = html.escape
    lines = [f"📅 <b>Weekly summary</b>  ·  {datetime.fromtimestamp(t0):%b %d} – {datetime.now():%b %d}"]
    s = hist.q("SELECT MAX(cpu), AVG(cpu), MAX(mem), AVG(mem), SUM(req), SUM(err5), COUNT(*) FROM sys WHERE ts >= ?", t0)[0]
    if s[6]:
        disk = hist.q("SELECT disk_used FROM sys WHERE ts >= ? AND disk_used IS NOT NULL ORDER BY ts", t0)
        net = hist.q("SELECT SUM(rx_rate) * 60, SUM(tx_rate) * 60 FROM sys WHERE ts >= ?", t0)[0]
        lines += ["", "<b>Resources</b>",
                  f"CPU avg {s[1]:.0f}% · peak {s[0]:.0f}%", f"RAM avg {s[3]:.0f}% · peak {s[2]:.0f}%"]
        if disk:
            lines.append(f"Disk {'+' if disk[-1][0] >= disk[0][0] else ''}{fmt_bytes(disk[-1][0] - disk[0][0])}B this week")
        if net[0] is not None:
            lines.append(f"Network ↓ {fmt_bytes(net[0])}B · ↑ {fmt_bytes(net[1])}B")
        if s[4] is not None:      # each row covers 5 min, sampled every minute
            lines.append(f"Requests ~{s[4] / 5:,.0f} · 5xx ~{(s[5] or 0) / 5:,.0f}")
        lines.append(f"<i>{100 * s[6] / (7 * 1440):.0f}% of the week monitored</i>")
    sites = hist.q("SELECT host, AVG(ok), AVG(ms), COUNT(*) FROM site WHERE ts >= ? GROUP BY host ORDER BY AVG(ok), host", t0)
    if sites:
        lines += ["", "<b>Site uptime</b>  <i>(avg response)</i>"]
        for host, ok, ms, _ in sites:
            lines.append(f"{'🟢' if ok >= 0.999 else '🟡' if ok >= 0.99 else '🔴'} <code>{100 * ok:6.2f}%</code> "
                         f"{e(host)} <i>{ms or 0:.0f}ms</i>")
    apps = hist.q("SELECT name, MIN(restarts), MAX(restarts), MAX(mem) FROM app WHERE ts >= ? GROUP BY name", t0)
    if apps:
        lines += ["", "<b>Apps</b>  <i>(restarts · peak memory)</i>"]
        for name, lo, hi, mem in sorted(apps, key=lambda a: -(a[2] - a[1])):
            lines.append(f"{'⚠️' if hi - lo else '▫️'} {e(name)} · ↺{hi - lo} · {fmt_bytes(mem or 0)}B")
    dbs = hist.q("SELECT name, MIN(ts), MAX(ts) FROM dbs WHERE ts >= ? AND size IS NOT NULL GROUP BY name", t0)
    if dbs:
        lines += ["", "<b>Database growth</b>"]
        for name, a, b in dbs:
            first = hist.q("SELECT size FROM dbs WHERE name = ? AND ts = ?", name, a)[0][0] or 0
            last = hist.q("SELECT size FROM dbs WHERE name = ? AND ts = ?", name, b)[0][0] or 0
            lines.append(f"{e(name)} {fmt_bytes(last)}B ({'+' if last >= first else ''}{fmt_bytes(last - first)}B)")
    alerts = hist.q("SELECT key FROM alert WHERE ts >= ?", t0)
    if alerts:
        kinds = {}
        for (k,) in alerts:
            kinds[k.split(":")[0]] = kinds.get(k.split(":")[0], 0) + 1
        lines += ["", f"<b>Alerts</b>  ·  {len(alerts)}",
                  " · ".join(f"{k} {n}" for k, n in sorted(kinds.items(), key=lambda x: -x[1]))]
    return "#html\n" + "\n".join(lines)


# ---------- commands ----------

def graph_menu(hist):
    t0 = time.time() - 86400
    opts = [("CPU", "cpu"), ("RAM", "mem"), ("Disk", "disk"), ("Load", "load"), ("Network", "net"), ("Requests", "req")]
    opts += [(f"📦 {n.split('/')[-1]}", f"app:{n.split('/')[-1]}")
             for (n,) in hist.q("SELECT DISTINCT name FROM app WHERE ts >= ? ORDER BY name", t0) if not n.endswith("/?")]
    opts += [(f"🌐 {h}", f"site:{h}") for (h,) in hist.q("SELECT DISTINCT host FROM site WHERE ts >= ? ORDER BY host", t0)]
    opts += [(f"🗄 {n}", f"db:{n}") for (n,) in hist.q("SELECT DISTINCT name FROM dbs WHERE ts >= ? ORDER BY name", t0)]
    text = ("#html\n📈 <b>Graphs</b>\nPick a metric, or type <code>/graph cpu 7d</code>.\n"
            "Metrics: " + ", ".join(f"<code>{html.escape(m)}</code>" for _, m in opts)
            + "\nRanges: 1h–8d (sites/DBs up to 35d)")
    return text, [btn(label[:30], f"graph {m}") for label, m in opts]


def range_buttons(metric):
    return [(r, f"r:graph {metric} {r}") for r in ("1h", "6h", "24h", "7d")]


def run(cmdline, monitor):
    """-> dict(text=..., buttons=[...], refresh=cmdline|None) or dict(photo=..., caption=..., buttons=[...])."""
    parts = cmdline.split()
    cmd, args = parts[0].lower(), parts[1:3]
    if cmd in ("start", "help"):
        return {"text": "#html\n🤖 <b>VPS bot</b>  ·  read-only\n\n"
                + "\n".join(f"/{c}  —  {html.escape(d)}" for c, d in COMMANDS)
                + "\n\n<b>🔔 Pushed automatically</b>\nservices · apps (crash loops, memory leaks) · containers · "
                "sites (down, slow, content) · 5xx/traffic floods · databases · CPU/RAM/disk (+ disk-full forecast) · "
                "file integrity · SSH logins · outbound anomalies · certs · domain expiry · threat indicators\n\n"
                f"<i>Daily report at {DAILY_HOUR:02d}:00 · weekly summary on "
                f"{['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][WEEKLY_DAY % 7]}s · heartbeat "
                f"{'on' if HEARTBEAT_URL else 'off (set HEARTBEAT_URL)'}</i>"}
    if cmd not in {c for c, _ in COMMANDS}:
        return {"text": "Unknown command. /help", "pre": False}
    if cmd == "alerts":
        with monitor.lock:
            loud = [v["msg"] for v in monitor.active.values() if not v["under"]]
            quiet = [k for k, v in monitor.active.items() if v["under"]]
        text = "No active alerts ✅" if not loud else "Active alerts:\n\n" + "\n\n".join(loud)
        if quiet:
            text += f"\n\n(+{len(quiet)} grouped under the alerts above: {', '.join(quiet[:10])})"
        return {"text": text, "pre": False, "refresh": "alerts"}
    if cmd == "week":
        return {"text": week_report(monitor.hist), "refresh": "week"}
    if cmd == "graph":
        if not args:
            text, buttons = graph_menu(monitor.hist)
            return {"text": text, "buttons": buttons}
        rng = args[1] if len(args) > 1 else "24h"
        png, caption = graph(monitor.hist, args[0], rng)
        if png is None:
            return {"text": caption, "pre": False}
        return {"photo": png, "caption": caption, "buttons": range_buttons(args[0])}
    extra = {"health": [btn("📦 Apps", "apps"), btn("🌐 Sites", "sites"), btn("📈 CPU", "graph cpu")],
             "sites": [btn("🚦 Traffic", "traffic"), btn("🌍 Domains", "domains")],
             "apps": [btn("❗ Errors", "errors")], "top": [btn("📈 CPU", "graph cpu 6h"), btn("📈 RAM", "graph mem 6h")],
             "disk": [btn("📈 Disk 7d", "graph disk 7d")], "net": [btn("📈 Network", "graph net 6h")],
             "traffic": [btn("📈 Requests", "graph req 24h"), btn("15 min", "traffic 15"), btn("24 h", "traffic 1440")],
             "db": [btn("🗄 Graph " + n[:20], f"graph db:{n}") for (n,) in
                    monitor.hist.q("SELECT DISTINCT name FROM dbs WHERE ts >= ?", time.time() - 3600)][:6]}
    out = query(cmd, *args) if cmd in ("logs", "traffic") else query(cmd)
    name = f"{args[0] if args else cmd}.txt"
    return {"text": out, "filename": name, "buttons": extra.get(cmd, []),
            "refresh": " ".join([cmd] + args) if cmd in REFRESHABLE else None}


def deliver(res):
    if "photo" in res:
        send_photo(res["photo"], res["caption"], res.get("buttons"))
    else:
        send(res["text"], pre=res.get("pre", True), filename=res.get("filename", "output.txt"),
             buttons=res.get("buttons"), refresh=res.get("refresh"))


def handle(text, monitor):
    parts = text[1:].split()
    parts[0] = parts[0].split("@")[0]
    if parts[0].lower() not in ("start", "help", "alerts", "week", "graph"):
        tg("sendChatAction", {"chat_id": CHAT_ID, "action": "typing"}, timeout=10)
    deliver(run(" ".join(parts), monitor))


def handle_callback(cq, monitor):
    data = cq.get("data", "")
    msg = cq.get("message") or {}
    tg("answerCallbackQuery", {"callback_query_id": cq["id"]}, timeout=10)
    kind, _, cmdline = data.partition(":")
    if not cmdline:
        return
    res = run(cmdline, monitor)
    if kind != "r" or not msg.get("message_id"):
        deliver(res)
        return
    target = {"chat_id": CHAT_ID, "message_id": msg["message_id"]}
    if "photo" in res:
        fields = {**{k: str(v) for k, v in target.items()},
                  "media": json.dumps({"type": "photo", "media": "attach://graph", "caption": res["caption"],
                                       "parse_mode": "HTML"}),
                  "reply_markup": json.dumps(keyboard(res["buttons"]))}
        if not tg_upload("editMessageMedia", fields, "graph", "graph.png", res["photo"], "image/png"):
            deliver(res)
        return
    text = res["text"].strip() or "(empty)"
    is_html = text.startswith("#html\n")
    text = text[6:] if is_html else text
    if len(text) > 3800:
        deliver(res)
        return
    buttons = list(res.get("buttons") or []) + [("🔄 Refresh", f"r:{res['refresh']}")] * bool(res.get("refresh"))
    tg("editMessageText", {**target, "text": render(text, is_html, res.get("pre", True), stamp=True),
                           "parse_mode": "HTML", "disable_web_page_preview": True,
                           "reply_markup": keyboard(buttons)})


def authorized(chat, sender):
    return chat.get("id") == CHAT_ID and not (chat.get("type") == "private" and sender.get("id") != CHAT_ID)


def main():
    global last_poll_ok
    me = tg("getMe")
    if not me:
        sys.exit("cannot reach Telegram / bad token")
    log(f"started as @{me['username']}")
    tg("setMyCommands", {"commands": [{"command": c, "description": d[:256]} for c, d in COMMANDS]})

    monitor = Monitor(History(DB_FILE))
    threading.Thread(target=monitor.run, daemon=True).start()
    up = float(open("/proc/uptime").read().split()[0])
    send(f"🟢 VPS bot online." + (f" ⚠️ Server booted {int(up // 60)} min ago." if up < 900 else "") + " /help", pre=False)

    # skip messages that arrived while the bot was down
    pending = tg("getUpdates", {"offset": -1, "timeout": 0}) or []
    offset = pending[-1]["update_id"] + 1 if pending else None
    reported = set()
    while True:
        updates = tg("getUpdates", {"offset": offset, "timeout": 50, "allowed_updates": ["message", "callback_query"]})
        if updates is None:
            time.sleep(5)
            continue
        last_poll_ok = time.time()
        for u in updates:
            offset = u["update_id"] + 1
            cq = u.get("callback_query")
            msg = u.get("message") or (cq or {}).get("message") or {}
            chat, sender = msg.get("chat", {}), (cq or msg).get("from", {})
            if not authorized(chat, sender):
                who = f"{sender.get('first_name', '')} @{sender.get('username', '?')} id={sender.get('id')}"
                log(f"ignored update from {who}")
                if sender.get("id") not in reported:
                    reported.add(sender.get("id"))
                    send(f"⚠️ Someone else messaged your VPS bot and was ignored: {who}", pre=False)
                continue
            try:
                if cq:
                    handle_callback(cq, monitor)
                elif msg.get("text", "").startswith("/"):
                    handle(msg["text"], monitor)
            except Exception as e:
                log(f"command error: {e!r}")
                send(f"Error: {e}", pre=False)


if __name__ == "__main__":
    main()
