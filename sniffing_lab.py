#!/usr/bin/env python3
"""
Protocol Sniffing Challenge Lab
5 levels of increasing difficulty. Use Wireshark to find the flags!

Usage:
    python3 sniffing_lab.py --setup      # first-time setup (installs deps)
    sudo python3 sniffing_lab.py         # run the lab
"""

import subprocess
import threading
import socket
import os
import sys
import time
import hashlib
import random
import base64
import logging
import tempfile
import platform
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs


# ── SETUP ────────────────────────────────────────────────────────────────

REQUIRED_PACKAGES = ["rich", "pyftpdlib", "tftpy", "Pillow"]
SETUP_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup.log")


def run_setup():
    log_lines = []

    def log(msg):
        print(msg)
        log_lines.append(msg)

    log("=" * 60)
    log("PROTOCOL SNIFFING LAB - SETUP")
    log(f"Date:     {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"Platform: {platform.platform()}")
    log(f"Python:   {sys.version}")
    log(f"Exe:      {sys.executable}")
    log("=" * 60)
    log("")

    # Determine pip command
    pip_cmd = [sys.executable, "-m", "pip"]
    log(f"[*] Using pip: {' '.join(pip_cmd)}")
    log("")

    # Upgrade pip first
    log("[*] Upgrading pip...")
    result = subprocess.run(
        pip_cmd + ["install", "--upgrade", "pip"],
        capture_output=True, text=True,
    )
    log(f"    stdout: {result.stdout.strip()}")
    if result.returncode != 0:
        log(f"    stderr: {result.stderr.strip()}")
        log("    [!] pip upgrade failed (non-critical, continuing)")
    else:
        log("    [OK]")
    log("")

    all_ok = True
    for pkg in REQUIRED_PACKAGES:
        log(f"[*] Installing {pkg}...")
        result = subprocess.run(
            pip_cmd + ["install", pkg],
            capture_output=True, text=True,
        )
        log(f"    stdout: {result.stdout.strip()}")
        if result.returncode != 0:
            log(f"    stderr: {result.stderr.strip()}")
            log(f"    [FAIL] Could not install {pkg}")
            all_ok = False
        else:
            log(f"    [OK]")
        log("")

    # Verify imports
    log("[*] Verifying imports...")
    verify_map = {
        "rich":      "from rich.console import Console",
        "pyftpdlib": "from pyftpdlib.handlers import FTPHandler",
        "tftpy":     "import tftpy",
        "Pillow":    "from PIL import Image",
    }
    for pkg, stmt in verify_map.items():
        result = subprocess.run(
            [sys.executable, "-c", stmt],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            log(f"    {pkg:<12} [OK]")
        else:
            log(f"    {pkg:<12} [FAIL] {result.stderr.strip()}")
            all_ok = False
    log("")

    # Check port availability
    log("[*] Checking port availability...")
    for name, port in [("HTTP", 80), ("FTP", 21), ("Telnet", 23), ("TFTP", 69)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.bind(("0.0.0.0", port))
            s.close()
            log(f"    Port {port:<5} ({name:<7}) [OK]")
        except OSError as e:
            log(f"    Port {port:<5} ({name:<7}) [IN USE] {e}")
            log(f"    -> Fix: kill the process using port {port}, or run with sudo")
    log("")

    # Check privileges
    log("[*] Checking privileges...")
    if sys.platform == "win32":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            log("    Running as Administrator [OK]")
        else:
            log("    [WARN] Not running as Administrator.")
            log("    -> Fix: right-click terminal > Run as Administrator")
    else:
        if os.geteuid() == 0:
            log("    Running as root [OK]")
        else:
            log("    [WARN] Not running as root. Ports < 1024 require root.")
            log("    -> Fix: run with sudo:  sudo python3 sniffing_lab.py")
    log("")

    # Windows-specific checks
    if sys.platform == "win32":
        log("[*] Checking Windows requirements...")

        # Check Npcap (required for Wireshark loopback capture)
        npcap_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                  "System32", "Npcap")
        if os.path.isdir(npcap_path):
            log("    Npcap                [OK]")
        else:
            log("    Npcap                [NOT FOUND]")
            log("    -> Wireshark cannot capture loopback traffic without Npcap.")
            log("    -> Install from: https://npcap.com/#download")
            log("    -> IMPORTANT: check 'Support loopback traffic' during install.")
            all_ok = False

        # Check telnet client
        telnet_check = subprocess.run(
            ["where", "telnet"], capture_output=True, text=True,
        )
        if telnet_check.returncode == 0:
            log("    Telnet client        [OK]")
        else:
            log("    Telnet client        [NOT FOUND]")
            log("    -> Needed for Level 4. Enable it:")
            log("    -> Run as Admin: dism /online /Enable-Feature /FeatureName:TelnetClient")
            log("    -> Or: Control Panel > Programs > Turn Windows features on/off > Telnet Client")

        log("")

    # Write log file
    log("=" * 60)
    if all_ok:
        log("SETUP COMPLETE. All dependencies installed successfully.")
        log(f"Run the lab:  sudo {sys.executable} {os.path.abspath(__file__)}")
    else:
        log("SETUP FINISHED WITH ERRORS. Check messages above.")
    log("=" * 60)

    with open(SETUP_LOG, "w") as f:
        f.write("\n".join(log_lines) + "\n")
    print(f"\nFull log saved to: {SETUP_LOG}")

    sys.exit(0 if all_ok else 1)


if "--setup" in sys.argv:
    run_setup()


# ── Rich imports (after setup gate so --setup works without rich) ────────

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

# Suppress noisy library logging
logging.getLogger("tftpy").setLevel(logging.CRITICAL)
logging.getLogger("pyftpdlib").setLevel(logging.CRITICAL)

# ── PORTS ────────────────────────────────────────────────────────────────

HTTP_PORT   = 80
FTP_PORT    = 21
TELNET_PORT = 23
TFTP_PORT   = 69

# ── FLAGS & CREDENTIALS ─────────────────────────────────────────────────
# Answers are verified by hash. Reading the source won't teach Wireshark ;)

FLAG_1 = "TrustN0one!"        # Level 1: HTTP POST password
FLAG_2 = "H3ader_Hunt3r"      # Level 2: HTTP Basic Auth password
FLAG_3 = "N33dle!"            # Level 3: FTP real password among noise
FLAG_4 = "Scr0ll_C4tch3r"    # Level 4: hidden in telnet banner
FLAG_5 = "TFTP_L00T"         # Level 5: hidden across TFTP blocks

HTTP_USER      = "alice"
API_USER       = "sysadmin"
FTP_REAL_USER  = "jsmith"
TELNET_USER    = "admin"
TELNET_PASS    = "SniffLab"

FTP_DECOY_CREDS = [
    ("scanner",    "admin123"),
    ("backup_svc", "backup2024!"),
    ("monitor",    "check123"),
    ("deploy_bot", "d3pl0y!ng"),
    ("testuser",   "Password1"),
    ("nagios",     "n4g10s!"),
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FTP_DIR    = os.path.join(SCRIPT_DIR, "ftp-files")
TFTP_DIR   = os.path.join(SCRIPT_DIR, "tftp-files")

ANSWER_HASHES = {
    i: hashlib.sha256(f.encode()).hexdigest()
    for i, f in enumerate([FLAG_1, FLAG_2, FLAG_3, FLAG_4, FLAG_5], 1)
}

# ── HTTP SERVER (Levels 1 & 2) ──────────────────────────────────────────

LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head>
<title>Company Portal</title>
<style>
  body {{ font-family: sans-serif; display: flex; justify-content: center;
         align-items: center; height: 100vh; margin: 0; background: #f0f2f5; }}
  .login {{ background: white; padding: 40px; border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }}
  h1 {{ font-size: 20px; margin-bottom: 20px; }}
  input {{ width: 100%; padding: 10px; margin: 6px 0 16px 0;
           border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
  button {{ width: 100%; padding: 10px; background: #1a73e8; color: white;
            border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
</style>
</head>
<body>
<div class="login">
  <h1>Company Portal Login</h1>
  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" value="">
    <label>Password</label>
    <input type="password" name="password" value="">
    <button type="submit">Sign In</button>
  </form>
  {message}
</div>
</body>
</html>"""


class HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/data":
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth[6:]).decode()
                    user, pwd = decoded.split(":", 1)
                    if user == API_USER and pwd == FLAG_2:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"status":"ok","employees":42,"revenue":"classified"}')
                        return
                except Exception:
                    pass
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Company API"')
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"401 Unauthorized")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(LOGIN_PAGE.format(message="").encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = parse_qs(body)
        user = params.get("username", [""])[0]
        pwd = params.get("password", [""])[0]

        if user == HTTP_USER and pwd == FLAG_1:
            self.send_response(200, "OK")
            msg = '<p style="color:green;margin-top:16px;">Login successful!</p>'
        else:
            self.send_response(403, "Forbidden")
            msg = '<p style="color:red;margin-top:16px;">Invalid credentials.</p>'
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(LOGIN_PAGE.format(message=msg).encode())

    def log_message(self, *args):
        pass


def start_http():
    server = HTTPServer(("0.0.0.0", HTTP_PORT), HTTPHandler)
    server.serve_forever()


# ── FTP SERVER (Level 3) ────────────────────────────────────────────────

def start_ftp():
    try:
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import FTPServer
        from pyftpdlib.authorizers import DummyAuthorizer
    except ImportError:
        return

    authorizer = DummyAuthorizer()
    os.makedirs(FTP_DIR, exist_ok=True)

    with open(os.path.join(FTP_DIR, "passwords.txt"), "w") as f:
        f.write("Database: db.company.com\nUser: dbadmin\nPass: Sup3rS3cret!\n")
    with open(os.path.join(FTP_DIR, "employees.csv"), "w") as f:
        f.write("name,email,ssn\nJohn Doe,jdoe@company.com,123-45-6789\n")

    authorizer.add_user(FTP_REAL_USER, FLAG_3, FTP_DIR, perm="elradfmw")

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.passive_ports = range(60000, 60010)
    handler.banner = "Welcome to Company FTP Server"
    handler.log_prefix = ""

    # Silence all pyftpdlib output
    from pyftpdlib import log as _ftplog
    _ftplog.log = lambda msg, *a, **kw: None
    _ftplog.logline = lambda msg, *a, **kw: None
    _ftplog.logerror = lambda msg, *a, **kw: None
    _ftplog.logger.handlers = [logging.NullHandler()]
    _ftplog.logger.propagate = False

    server = FTPServer(("0.0.0.0", FTP_PORT), handler)
    server.serve_forever()


# ── TELNET SERVER (Level 4) ─────────────────────────────────────────────

def _telnet_read_line(conn):
    """Read one line from a telnet client, filtering out IAC sequences."""
    buf = b""
    while True:
        data = conn.recv(1)
        if not data:
            return None
        b = data[0]
        if b == 0xff:
            conn.recv(2)
            continue
        if b in (0x0a, 0x0d):
            if buf:
                conn.setblocking(False)
                try:
                    conn.recv(1)
                except BlockingIOError:
                    pass
                conn.setblocking(True)
                return buf.decode(errors="replace")
            continue
        buf += data


_DIAG_MODULES = [
    "kernel", "sshd", "systemd", "NetworkManager", "auth.pam",
    "cron.daily", "ufw", "dbus-daemon", "snapd", "rsyslogd",
    "multipathd", "polkitd", "containerd", "dockerd", "kubelet",
]
_DIAG_ACTIONS = [
    "service started successfully",
    "health check passed (200 OK)",
    "memory pool: {m}MB allocated",
    "CPU core {c}: load {l:.1f}%",
    "disk I/O: {io} iops",
    "pid {p} running normally",
    "listening on 0.0.0.0:{port}",
    "log rotation complete",
    "cache invalidated and rebuilt",
    "watchdog: all processes responsive",
    "connection pool: {a}/{t} active",
    "TLS certificate valid, 243 days remaining",
    "queue depth: {q} messages pending",
    "firewall rules reloaded (42 rules active)",
    "uptime: {d} days {h}h {mi}m",
]


def _random_diag_line():
    mod = random.choice(_DIAG_MODULES)
    act = random.choice(_DIAG_ACTIONS).format(
        m=random.randint(128, 8192), c=random.randint(0, 7),
        l=random.uniform(0.1, 95.0), io=random.randint(50, 9000),
        p=random.randint(1000, 65535), port=random.randint(1024, 65535),
        a=random.randint(1, 200), t=random.randint(200, 500),
        q=random.randint(0, 50), d=random.randint(1, 365),
        h=random.randint(0, 23), mi=random.randint(0, 59),
    )
    ts = "{}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}".format(
        2024, random.randint(1, 12), random.randint(1, 28),
        random.randint(0, 23), random.randint(0, 59), random.randint(0, 59),
    )
    return f"{ts} {mod}: {act}"


def handle_telnet_client(conn, addr):
    try:
        conn.sendall(b"\r\n=== Company Server ===\r\n")
        conn.sendall(b"Login: ")
        username = _telnet_read_line(conn)
        if username is None:
            return

        conn.sendall(b"\xff\xfb\x01")  # WILL ECHO
        conn.sendall(b"Password: ")
        password = _telnet_read_line(conn)
        conn.sendall(b"\r\n")
        conn.sendall(b"\xff\xfc\x01")  # WONT ECHO
        if password is None:
            return

        if username == TELNET_USER and password == TELNET_PASS:
            conn.sendall(b"\r\nLogin successful!\r\n")
            conn.sendall(b"Running system diagnostics...\r\n\r\n")
            time.sleep(0.3)

            # Level 4: flag is buried in a massive dump, then screen clears
            total_lines = 800
            flag_line = random.randint(200, 400)
            buf = []
            for i in range(total_lines):
                if i == flag_line:
                    buf.append(f"[DIAG] auth.token.verify: {FLAG_4}\r\n")
                else:
                    buf.append(f"[DIAG] {_random_diag_line()}\r\n")
                # send in chunks for speed
                if len(buf) >= 40:
                    conn.sendall("".join(buf).encode())
                    buf.clear()
            if buf:
                conn.sendall("".join(buf).encode())
            conn.sendall(b"\033[2J\033[H")  # ANSI clear screen
            conn.sendall(b"Diagnostics complete. All systems nominal.\r\n\r\n")
            conn.sendall(b"server$ ")

            while True:
                cmd_str = _telnet_read_line(conn)
                if cmd_str is None:
                    return
                conn.sendall(b"\r\n")
                if cmd_str.lower() in ("exit", "quit", "logout"):
                    conn.sendall(b"Goodbye!\r\n")
                    return
                elif cmd_str == "whoami":
                    conn.sendall(f"{TELNET_USER}\r\n".encode())
                elif cmd_str == "help":
                    conn.sendall(b"Commands: whoami, help, exit\r\n")
                else:
                    conn.sendall(f"-bash: {cmd_str}: command not found\r\n".encode())
                conn.sendall(b"server$ ")
        else:
            conn.sendall(b"\r\nLogin failed.\r\n")
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        conn.close()


def start_telnet():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", TELNET_PORT))
    server.listen(5)
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_telnet_client, args=(conn, addr), daemon=True)
        t.start()


# ── TFTP SERVER (Level 5) ───────────────────────────────────────────────

def _create_tftp_files():
    """Create TFTP challenge image with the flag drawn on it."""
    os.makedirs(TFTP_DIR, exist_ok=True)

    filepath = os.path.join(TFTP_DIR, "confidential.png")
    try:
        from PIL import Image, ImageDraw, ImageFont

        img = Image.new("RGB", (480, 240), color=(20, 20, 30))
        draw = ImageDraw.Draw(img)

        # Try to find a usable font, fall back to default
        font_large = None
        font_small = None
        font_paths = [
            "/System/Library/Fonts/Helvetica.ttc",           # macOS
            "/Library/Fonts/Arial.ttf",                      # macOS
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Linux
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                         "Fonts", "arial.ttf"),              # Windows
        ]
        for fp in font_paths:
            try:
                font_large = ImageFont.truetype(fp, 48)
                font_small = ImageFont.truetype(fp, 20)
                break
            except (IOError, OSError):
                continue
        if font_large is None:
            font_large = ImageFont.load_default()
            font_small = font_large

        draw.text((40, 30), "CONFIDENTIAL", fill=(180, 0, 0), font=font_small)
        draw.line([(40, 58), (440, 58)], fill=(80, 0, 0), width=1)
        draw.text((40, 90), FLAG_5, fill=(0, 220, 80), font=font_large)
        draw.text((40, 170), "Property of Company Server", fill=(100, 100, 100), font=font_small)

        img.save(filepath)
    except ImportError:
        # Pillow not available; write a minimal placeholder
        with open(filepath, "wb") as f:
            f.write(b"FLAG: " + FLAG_5.encode() + b"\n")


def start_tftp():
    try:
        import tftpy
    except ImportError:
        return

    _create_tftp_files()
    server = tftpy.TftpServer(TFTP_DIR)
    server.listen("0.0.0.0", TFTP_PORT)


# ── BOT TRAFFIC ─────────────────────────────────────────────────────────

# Shared state: bots only run when their level is the current level
_current_level = 1
_level_lock = threading.Lock()
_game_started = threading.Event()


def set_current_level(lvl):
    global _current_level
    with _level_lock:
        _current_level = lvl


def _level_active(lvl):
    with _level_lock:
        return _current_level == lvl


def _bot_http_login():
    """Level 1: 2 failed logins + 1 correct, repeating."""
    _game_started.wait()
    import http.client
    attempts = [
        (HTTP_USER, "TrustNo1!"),
        (HTTP_USER, "trustn0one"),
        (HTTP_USER, FLAG_1),
    ]
    while True:
        if _level_active(1):
            for user, pwd in attempts:
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=5)
                    body = f"username={user}&password={pwd}"
                    conn.request("POST", "/login", body=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
                    conn.getresponse().read()
                    conn.close()
                except Exception:
                    pass
                time.sleep(random.uniform(1.5, 3))
        time.sleep(random.uniform(10, 18))


def _bot_http_basic_auth():
    """Level 2: periodic API calls with Basic Auth."""
    _game_started.wait()
    import http.client
    while True:
        if _level_active(2):
            try:
                cred = base64.b64encode(f"{API_USER}:{FLAG_2}".encode()).decode()
                conn = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=5)
                conn.request("GET", "/api/data",
                             headers={"Authorization": f"Basic {cred}"})
                conn.getresponse().read()
                conn.close()
            except Exception:
                pass
        time.sleep(random.uniform(3, 6))


def _bot_ftp_decoy():
    """Level 3: fake FTP logins with wrong credentials."""
    _game_started.wait()
    import ftplib
    while True:
        if _level_active(3):
            user, pwd = random.choice(FTP_DECOY_CREDS)
            try:
                ftp = ftplib.FTP()
                ftp.connect("127.0.0.1", FTP_PORT, timeout=5)
                try:
                    ftp.login(user, pwd)
                except Exception:
                    pass
                ftp.quit()
            except Exception:
                pass
        time.sleep(random.uniform(4, 10))


def _bot_ftp_real():
    """Level 3: real FTP login that succeeds (less frequent)."""
    _game_started.wait()
    import ftplib
    while True:
        if _level_active(3):
            try:
                ftp = ftplib.FTP()
                ftp.connect("127.0.0.1", FTP_PORT, timeout=5)
                ftp.login(FTP_REAL_USER, FLAG_3)
                ftp.retrlines("LIST", callback=lambda _: None)
                ftp.quit()
            except Exception:
                pass
        time.sleep(random.uniform(15, 30))


def _bot_tftp_download():
    """Level 5: periodic TFTP firmware download."""
    try:
        import tftpy
    except ImportError:
        return
    _game_started.wait()
    while True:
        if _level_active(5):
            try:
                client = tftpy.TftpClient("127.0.0.1", TFTP_PORT)
                tmpfile = os.path.join(tempfile.gettempdir(), "snifflab_fw.tmp")
                client.download("confidential.png", tmpfile)
                try:
                    os.unlink(tmpfile)
                except OSError:
                    pass
            except Exception:
                pass
        time.sleep(random.uniform(12, 25))


def start_bots():
    bots = [
        _bot_http_login,
        _bot_http_basic_auth,
        _bot_ftp_decoy,
        _bot_ftp_decoy,
        _bot_ftp_decoy,
        _bot_ftp_real,
        _bot_tftp_download,
    ]
    for fn in bots:
        threading.Thread(target=fn, daemon=True).start()


# ── LEVEL DEFINITIONS ───────────────────────────────────────────────────

LEVELS = {
    1: {
        "name": "The Login Sniffer",
        "proto": "HTTP",
        "desc": (
            "Someone is trying to log into the Company Portal.\n"
            "They keep mistyping their password, but eventually get it right.\n"
            "The login attempts repeat in the background every few seconds.\n"
            "\n"
            "[bold]Your task:[/bold]\n"
            "  1. Open Wireshark and start capturing on the loopback interface\n"
            "     [dim](Windows: select 'Adapter for loopback traffic capture'[/dim]\n"
            "     [dim] or 'Npcap Loopback Adapter'. Requires Npcap.)[/dim]\n"
            "  2. Find the HTTP login attempts in the capture\n"
            "  3. Two of them failed, one succeeded\n"
            "  4. Find the password from the [bold]successful[/bold] login\n"
            "\n"
            "[bold yellow]Submit:[/bold yellow] the password that worked  (e.g.  submit MyP@ss123)"
        ),
        "hint": (
            "Try this Wireshark display filter:\n"
            "  [bold]http.request.method == POST[/bold]\n"
            "Then right-click a packet and choose Follow > TCP Stream."
        ),
    },
    2: {
        "name": "The Hidden Header",
        "proto": "HTTP",
        "desc": (
            "An automated system on this machine is secretly calling an API.\n"
            "The credentials are NOT visible on any webpage. They are\n"
            "hidden inside an HTTP header, encoded in Base64.\n"
            "\n"
            "[bold]Your task:[/bold]\n"
            "  1. Make sure Wireshark is still capturing\n"
            "  2. Wait for the automated request to appear\n"
            "  3. Find the request and decode the hidden credentials\n"
            "\n"
            "[bold yellow]Submit:[/bold yellow] the decoded password  (e.g.  submit S3cretPwd)"
        ),
        "hint": (
            "Try this Wireshark display filter:\n"
            "  [bold]http contains \"Authorization\"[/bold]\n"
            "Then look at the HTTP headers in the packet details pane."
        ),
    },
    3: {
        "name": "Needle in a Haystack",
        "proto": "FTP",
        "desc": (
            "The FTP server is under attack. Bots are constantly trying\n"
            "to brute-force their way in with wrong passwords.\n"
            "But one attacker already knows the real password and gets in.\n"
            "\n"
            "[bold]Your task:[/bold]\n"
            "  1. Watch the FTP traffic in Wireshark\n"
            "  2. Among all the failed logins, find the ONE that succeeded\n"
            "  3. Read the password that was used for that successful login\n"
            "\n"
            "[bold yellow]Submit:[/bold yellow] the password of the successful login  (e.g.  submit r3alPwd)"
        ),
        "hint": (
            "Filter for FTP traffic and look at the server response codes.\n"
            "Most logins fail. One does not.\n"
            "What Wireshark filter could show only successful FTP logins?"
        ),
    },
    4: {
        "name": "The Vanishing Banner",
        "proto": "Telnet",
        "desc": (
            "Connect to the server via telnet and log in.\n"
            "After login, a system diagnostic will run. Somewhere in that\n"
            "output is a secret token, but the screen clears before\n"
            "you can read it. Only Wireshark remembers everything.\n"
            "\n"
            "[bold]Your task:[/bold]\n"
            "  1. Make sure Wireshark is capturing\n"
            "  2. Run:  [bold]telnet localhost[/bold]\n"
            "     [dim](Windows: enable Telnet Client in 'Turn Windows features on/off'[/dim]\n"
            "     [dim] or use PuTTY in Telnet mode)[/dim]\n"
            "  3. Login with  [bold]admin[/bold] / [bold]SniffLab[/bold]\n"
            "  4. Watch the diagnostic scroll by and the screen clear\n"
            "  5. Use Wireshark to find the secret token that was hidden\n"
            "\n"
            "[bold yellow]Submit:[/bold yellow] the token value that flashed on screen"
        ),
        "hint": (
            "Filter for telnet traffic by port number.\n"
            "Right-click a packet and use Follow > TCP Stream\n"
            "to reconstruct the full session output."
        ),
    },
    5: {
        "name": "The Secret File",
        "proto": "TFTP",
        "desc": (
            "A confidential file is being transferred over TFTP.\n"
            "You don't know the filename or what it contains.\n"
            "Use Wireshark to extract the file from the capture and open it.\n"
            "\n"
            "[bold]Your task:[/bold]\n"
            "  1. Make sure Wireshark is capturing\n"
            "  2. Wait for the TFTP transfer to appear\n"
            "  3. Extract the file directly from Wireshark\n"
            "  4. Open the file and read the flag\n"
            "\n"
            "[bold yellow]Submit:[/bold yellow] the text shown in the image  (e.g.  submit S3CR3T)"
        ),
        "hint": (
            "Wireshark can extract files transferred over certain protocols.\n"
            "Look in the File menu for an option related to exporting objects."
        ),
    },
}


# ── GAME INTERFACE ──────────────────────────────────────────────────────

def build_level_table(current_level, completed):
    table = Table(
        box=box.HEAVY_EDGE,
        show_header=False,
        pad_edge=True,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("Icon", width=3, justify="center")
    table.add_column("Level", width=7)
    table.add_column("Status", width=12)
    table.add_column("Name", min_width=24)
    table.add_column("Proto", width=8, justify="right")

    for lvl in range(1, 6):
        info = LEVELS[lvl]
        if lvl in completed:
            icon = "[green]*[/green]"
            status = "[green]COMPLETE[/green]"
            name = f"[green]{info['name']}[/green]"
        elif lvl == current_level:
            icon = "[yellow]>[/yellow]"
            status = "[yellow]CURRENT[/yellow]"
            name = f"[bold yellow]{info['name']}[/bold yellow]"
        else:
            icon = "[dim]o[/dim]"
            status = "[dim]LOCKED[/dim]"
            name = f"[dim]{info['name']}[/dim]"
        table.add_row(icon, f"Level {lvl}", status, name, f"[dim]\\[{info['proto']}][/dim]")

    return table


def display_dashboard(current_level, completed, clear=True):
    if clear:
        console.clear()
    title = Text("PROTOCOL SNIFFING CHALLENGE", style="bold cyan")
    console.print()
    console.print(Panel(title, border_style="cyan", expand=False), justify="center")
    console.print()
    console.print(build_level_table(current_level, completed))
    console.print()
    console.print(
        "  Commands:  [cyan]info[/cyan]  [cyan]hint[/cyan]  "
        "[cyan]submit <answer>[/cyan]  [cyan]status[/cyan]  [cyan]quit[/cyan]"
    )
    console.print()


def game_loop():
    current_level = 1
    completed = set()

    display_dashboard(current_level, completed)

    while True:
        try:
            cmd = console.input(
                f"  [bold]challenge[/bold] \\[[yellow]Level {current_level}[/yellow]]> "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break

        if not cmd:
            continue

        parts = cmd.split(None, 1)
        action = parts[0].lower()

        if action in ("quit", "exit"):
            break

        elif action == "status":
            display_dashboard(current_level, completed)

        elif action == "info":
            info = LEVELS[current_level]
            console.print()
            console.print(Panel(
                f"{info['desc']}",
                title=f"Level {current_level}: {info['name']} \\[{info['proto']}]",
                border_style="yellow",
                expand=False,
                padding=(1, 2),
            ))

        elif action == "hint":
            console.print()
            console.print(Panel(
                f"{LEVELS[current_level]['hint']}",
                title="Hint",
                border_style="yellow",
                expand=False,
                padding=(1, 2),
            ))

        elif action == "submit":
            if len(parts) < 2:
                console.print("  Usage: [cyan]submit <answer>[/cyan]")
                continue
            answer = parts[1]
            h = hashlib.sha256(answer.encode()).hexdigest()
            if h == ANSWER_HASHES.get(current_level):
                completed.add(current_level)
                if current_level < 5:
                    current_level += 1
                    set_current_level(current_level)
                    display_dashboard(current_level, completed)
                    nxt = LEVELS[current_level]
                    console.print(
                        f"  [green bold]Level {current_level - 1} complete![/green bold] "
                        f"Unlocked: [cyan]{nxt['name']}[/cyan]"
                    )
                    console.print(f"  Type [cyan]info[/cyan] to see the challenge.")
                else:
                    display_dashboard(current_level, completed)
                    console.print(Panel(
                        "[bold]You've mastered protocol sniffing![/bold]\n\n"
                        "Key takeaway: never send sensitive data\n"
                        "over unencrypted protocols.",
                        title="ALL LEVELS COMPLETE",
                        border_style="green",
                        expand=False,
                        padding=(1, 2),
                    ))
            else:
                console.print("\n  [red bold]Incorrect.[/red bold] Keep sniffing!\n")

        else:
            console.print(
                "  Commands:  [cyan]info[/cyan]  [cyan]hint[/cyan]  "
                "[cyan]submit <answer>[/cyan]  [cyan]status[/cyan]  [cyan]quit[/cyan]"
            )


# ── MAIN ────────────────────────────────────────────────────────────────

SERVERS = [
    ("HTTP",   start_http,   HTTP_PORT),
    ("FTP",    start_ftp,    FTP_PORT),
    ("Telnet", start_telnet, TELNET_PORT),
    ("TFTP",   start_tftp,   TFTP_PORT),
]


def main():
    console.clear()
    console.print()
    console.print("[bold]  Starting servers...[/bold]")

    for name, fn, port in SERVERS:
        t = threading.Thread(target=fn, daemon=True, name=name.lower())
        t.start()
        time.sleep(0.3)
        console.print(f"  [green]\\[+][/green] {name:<7} on port {port}")

    start_bots()
    console.print()
    console.print("  [dim]Background traffic active.[/dim]")
    console.print("  [yellow]Open Wireshark > capture on loopback > then play![/yellow]")
    console.print()
    console.input("  [dim]Press Enter to continue...[/dim]")
    _game_started.set()

    game_loop()

    console.print("\n  Shutting down. Goodbye!")
    sys.exit(0)


if __name__ == "__main__":
    main()
