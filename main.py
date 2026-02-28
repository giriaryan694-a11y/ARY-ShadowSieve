import socket
import threading
import select
import struct
import os
import fnmatch
import ipaddress
import datetime
import ssl
import logging
import traceback
import re
import queue
import time
from flask import Flask, request, render_template_string, redirect, session, jsonify, Response
import pyfiglet
from colorama import init, Fore, Style

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

init(autoreset=True)

# --- Configuration & State ---
AUTH_FILE = 'auth.txt'
LOG_FILE = 'server_logs.txt'
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'
CERT_CRT_FILE = 'cert.crt'
SETTINGS_FILE = 'settings.txt'

# List Files
FILE_PROXY_CLIENT_ALLOW = 'proxy_clients_allow.txt'
FILE_PROXY_CLIENT_BLOCK = 'proxy_clients_block.txt'
FILE_TARGET_ALLOW = 'targets_allow.txt'
FILE_TARGET_BLOCK = 'targets_block.txt'
FILE_WEB_CLIENT_ALLOW = 'web_clients_allow.txt'
FILE_WEB_CLIENT_BLOCK = 'web_clients_block.txt'

config = {
    'web_user': '', 'web_pass': '', 'proxy_user': '', 'proxy_pass': '',
    
    'proxy_client_allow': [], 'proxy_client_block': [],
    'target_allow': [], 'target_block': [],
    'web_client_allow': [], 'web_client_block': [],
    
    'use_proxy_client_allow': False,
    'use_target_allow': False,
    'use_target_block': True,
    'use_web_client_allow': False
}

web_logs = []
proxy_logs = []
MAX_LOGS = 150
seen_ips = set()
active_clients = {}
clients_lock = threading.Lock()

# --- Performance Enhancements (DNS Cache & Async Logging) ---
dns_cache = {}
dns_cache_ttl = 300
dns_lock = threading.Lock()
log_queue = queue.Queue()

def log_writer():
    while True:
        try:
            entry = log_queue.get()
            with open(LOG_FILE, 'a') as f:
                f.write(entry + '\n')
            log_queue.task_done()
        except:
            pass

threading.Thread(target=log_writer, daemon=True).start()

def resolve_domain(domain):
    now = time.time()
    with dns_lock:
        if domain in dns_cache:
            ip, expiry = dns_cache[domain]
            if now < expiry:
                return ip

    try:
        ip = socket.gethostbyname(domain)
    except:
        try:
            ip = socket.getaddrinfo(domain, None)[0][4][0]
        except:
            return "Unresolved"

    with dns_lock:
        dns_cache[domain] = (ip, now + dns_cache_ttl)

    return ip

# --- Security & TLS Setup ---
def generate_tls_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return CERT_FILE, KEY_FILE
        
    print(Fore.CYAN + "\n-> Generating new Self-Signed TLS Certificates for HTTPS...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"ARY-ShadowSieve Local")])
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        now_utc).not_valid_after(now_utc + datetime.timedelta(days=3650)).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
        critical=False).sign(private_key, hashes.SHA256())
    
    with open(KEY_FILE, "wb") as f: f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
    with open(CERT_FILE, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(CERT_CRT_FILE, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(Fore.YELLOW + Style.BRIGHT + f"-> [!] CERTIFICATE CREATED: '{CERT_CRT_FILE}'")
    print(Fore.YELLOW + f"-> [!] Please import '{CERT_CRT_FILE}' into your browser's Trusted Root Authorities to remove warnings.\n")
    return CERT_FILE, KEY_FILE

# --- Deep Packet Inspection Extractors ---
def extract_sni(data):
    try:
        if len(data) < 44 or data[0] != 0x16: return None
        session_id_length = data[43]
        idx = 44 + session_id_length
        if idx + 2 > len(data): return None
        cipher_len = struct.unpack(">H", data[idx:idx+2])[0]
        idx += 2 + cipher_len
        if idx + 1 > len(data): return None
        comp_len = data[idx]
        idx += 1 + comp_len
        if idx + 2 > len(data): return None
        ext_len = struct.unpack(">H", data[idx:idx+2])[0]
        idx += 2
        end = min(idx + ext_len, len(data))
        while idx + 4 <= end:
            ext_type = struct.unpack(">H", data[idx:idx+2])[0]
            ext_size = struct.unpack(">H", data[idx+2:idx+4])[0]
            idx += 4
            if ext_type == 0:
                if idx + 5 <= len(data):
                    sni_len = struct.unpack(">H", data[idx+3:idx+5])[0]
                    if idx + 5 + sni_len <= len(data):
                        return data[idx+5:idx+5+sni_len].decode('utf-8', errors='ignore')
            idx += ext_size
    except:
        return None
    return None

def extract_http_host(data):
    try:
        if data.startswith((b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ', b'CONNECT ', b'PATCH ')):
            match = re.search(b'\\r\\nHost: (.*?)\\r\\n', data, re.IGNORECASE)
            if match:
                return match.group(1).decode('utf-8', errors='ignore').split(':')[0]
    except:
        return None
    return None

# --- Helper Logic ---
def add_web_log(ip, action="logged into dashboard"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] IP: {ip} {action}"
    web_logs.insert(0, log_entry)
    if len(web_logs) > MAX_LOGS: web_logs.pop()
    log_queue.put(log_entry)

def add_proxy_log(ip, target, resolved_ip, status="requested"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if status == "requested":
        log_entry = f"[{timestamp}] Client {ip} → requested {target} Resolved to → {resolved_ip}"
    else:
        log_entry = f"[{timestamp}] Client {ip} → {status} {target} Resolved to → {resolved_ip}"
        
    proxy_logs.insert(0, log_entry)
    if len(proxy_logs) > MAX_LOGS: proxy_logs.pop()
    log_queue.put(log_entry)

def load_config():
    if not os.path.exists(AUTH_FILE):
        with open(AUTH_FILE, 'w') as f:
            f.write("# Web Control Pannel creds:\nuser : secure_admin\npass : secure_family@123\n\n#proxy creds if you enable auth for sock5 connection\nuser : proxy_needed\npass : secure123\n")
    with open(AUTH_FILE, 'r') as f:
        section = None
        for line in f:
            line = line.strip()
            if not line: continue
            if 'Web Control Pannel' in line: section = 'web'
            elif 'proxy creds' in line: section = 'proxy'
            elif ':' in line:
                key, val = [x.strip() for x in line.split(':', 1)]
                if section == 'web':
                    if key == 'user': config['web_user'] = val
                    if key == 'pass': config['web_pass'] = val
                elif section == 'proxy':
                    if key == 'user': config['proxy_user'] = val
                    if key == 'pass': config['proxy_pass'] = val

def load_list_file(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f: return [line.strip() for line in f if line.strip()]
    return []

def save_list_file(filename, data_string):
    with open(filename, 'w') as f: f.write(data_string)

def load_lists():
    config['proxy_client_allow'] = load_list_file(FILE_PROXY_CLIENT_ALLOW)
    config['proxy_client_block'] = load_list_file(FILE_PROXY_CLIENT_BLOCK)
    config['target_allow'] = load_list_file(FILE_TARGET_ALLOW)
    config['target_block'] = load_list_file(FILE_TARGET_BLOCK)
    config['web_client_allow'] = load_list_file(FILE_WEB_CLIENT_ALLOW)
    config['web_client_block'] = load_list_file(FILE_WEB_CLIENT_BLOCK)
            
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            for line in f:
                if '=' in line:
                    k, v = line.strip().split('=', 1)
                    if k in config and isinstance(config[k], bool):
                        config[k] = (v.lower() == 'true')
                    
    seen_ips.update(config['proxy_client_block'])
    seen_ips.update(config['proxy_client_allow'])

def save_settings():
    with open(SETTINGS_FILE, 'w') as f:
        f.write(f"use_proxy_client_allow={str(config['use_proxy_client_allow']).lower()}\n")
        f.write(f"use_target_allow={str(config['use_target_allow']).lower()}\n")
        f.write(f"use_target_block={str(config['use_target_block']).lower()}\n")
        f.write(f"use_web_client_allow={str(config['use_web_client_allow']).lower()}\n")

def is_match(target, pattern_list):
    for pattern in pattern_list:
        if fnmatch.fnmatch(target, pattern): return True
        if '/' in pattern:
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(pattern, strict=False): return True
            except ValueError: pass
    return False

# --- SOCKS5 Proxy Server ---
def handle_client(client_socket):
    try:
        client_ip = client_socket.getpeername()[0]
        seen_ips.add(client_ip)
    except Exception:
        client_socket.close(); return

    if config['use_proxy_client_allow'] and config['proxy_client_allow']:
        if client_ip not in config['proxy_client_allow']:
            client_socket.close(); return
    if client_ip in config['proxy_client_block']:
        client_socket.close(); return

    with clients_lock: active_clients[client_ip] = active_clients.get(client_ip, 0) + 1
    client_socket.settimeout(15.0) 
    
    try:
        version, nmethods = client_socket.recv(2)
        methods = client_socket.recv(nmethods)
        auth_required = bool(config['proxy_user'] and config['proxy_pass'])
        
        if auth_required and b'\x02' in methods:
            client_socket.sendall(b'\x05\x02')
            version, ulen = struct.unpack("!BB", client_socket.recv(2))
            username = client_socket.recv(ulen).decode()
            plen, = struct.unpack("!B", client_socket.recv(1))
            password = client_socket.recv(plen).decode()
            if username == config['proxy_user'] and password == config['proxy_pass']: client_socket.sendall(b'\x01\x00')
            else: client_socket.sendall(b'\x01\x01'); return
        elif not auth_required and b'\x00' in methods: client_socket.sendall(b'\x05\x00')
        else: client_socket.sendall(b'\x05\xFF'); return

        version, cmd, _, address_type = struct.unpack("!BBBB", client_socket.recv(4))
        if cmd != 1: return
            
        domain = ""
        resolved_ip = ""
        
        if address_type == 1: 
            domain = socket.inet_ntoa(client_socket.recv(4))
            resolved_ip = domain
        elif address_type == 3: 
            domain_length = client_socket.recv(1)[0]
            domain = client_socket.recv(domain_length).decode()
            resolved_ip = resolve_domain(domain)
        elif address_type == 4: 
            domain = socket.inet_ntop(socket.AF_INET6, client_socket.recv(16))
            resolved_ip = domain
            
        port = struct.unpack("!H", client_socket.recv(2))[0]

        # Stage 1 Checks
        if config['use_target_allow'] and config['target_allow']:
            if not is_match(domain, config['target_allow']):
                add_proxy_log(client_ip, domain, resolved_ip, "BLOCKED BY ALLOWLIST")
                client_socket.sendall(struct.pack("!BBBBIH", 5, 2, 0, 1, 0, 0)); return
                
        if config['use_target_block'] and config['target_block']:
            if is_match(domain, config['target_block']):
                add_proxy_log(client_ip, domain, resolved_ip, "BLOCKED")
                client_socket.sendall(struct.pack("!BBBBIH", 5, 2, 0, 1, 0, 0)); return

        remote = socket.create_connection((domain, port), timeout=15.0)
        client_socket.sendall(struct.pack("!BBBBIH", 5, 0, 0, 1, 0, 0))

        # --- Opportunistic Non-Blocking Deep Packet Inspection ---
        first_packet = None
        try:
            client_socket.setblocking(False)
            first_packet = client_socket.recv(16384)
            client_socket.setblocking(True)
        except Exception:
            client_socket.setblocking(True)

        detected_domain = None
        if first_packet:
            detected_domain = extract_sni(first_packet) or extract_http_host(first_packet)

        actual_target = detected_domain if detected_domain else domain

        # Stage 2 Checks (DPI verification)
        if detected_domain and detected_domain != domain:
            if config['use_target_allow'] and config['target_allow']:
                if not is_match(detected_domain, config['target_allow']):
                    add_proxy_log(client_ip, actual_target, resolved_ip, "BLOCKED (DPI) BY ALLOWLIST")
                    return
                    
            if config['use_target_block'] and config['target_block']:
                if is_match(detected_domain, config['target_block']):
                    add_proxy_log(client_ip, actual_target, resolved_ip, "BLOCKED (DPI)")
                    return

        add_proxy_log(client_ip, actual_target, resolved_ip, "requested")

        # Forward intercepted packet if any
        if first_packet:
            remote.sendall(first_packet)

        # High-Speed Relay Loop
        sockets = [client_socket, remote]
        while True:
            r, _, _ = select.select(sockets, [], [])
            for s in r:
                data = s.recv(16384)
                if not data: return
                if s is client_socket: remote.sendall(data)
                else: client_socket.sendall(data)

    except Exception: pass
    finally:
        with clients_lock:
            if client_ip in active_clients:
                active_clients[client_ip] -= 1
                if active_clients[client_ip] <= 0: del active_clients[client_ip]
        client_socket.close()

def run_socks5():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    server.bind(('0.0.0.0', 1080))
    server.listen(100)
    server.setblocking(False) 
    while True:
        try:
            r, _, _ = select.select([server], [], [], 1.0)
            if r:
                client, addr = server.accept()
                client.setblocking(True) 
                threading.Thread(target=handle_client, args=(client,), daemon=True).start()
        except Exception: pass

# --- Web Control Panel (Flask) ---
app = Flask(__name__)
app.secret_key = os.urandom(32).hex()
app.config['SESSION_COOKIE_HTTPONLY'] = True 
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

@app.before_request
def restrict_web_access():
    if request.path.startswith('/static'): return
    ip = request.remote_addr
    if ip in config['web_client_block']: return "403 Forbidden: Your IP is banned from the dashboard.", 403
    if config['use_web_client_allow'] and config['web_client_allow']:
        if ip not in config['web_client_allow']: return "403 Forbidden: Dashboard strict allowlist enabled.", 403

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

def generate_csrf_token():
    if '_csrf_token' not in session: session['_csrf_token'] = os.urandom(16).hex()
    return session['_csrf_token']
app.jinja_env.globals['csrf_token'] = generate_csrf_token

HTML_BASE = """
<!DOCTYPE html>
<html data-theme="dark">
<head>
    <title>ARY-ShadowSieve</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root[data-theme="dark"] { --bg: #0d1117; --container-bg: #161b22; --text: #c9d1d9; --border: #30363d; --primary: #58a6ff; --btn: #238636; --btn-hover: #2ea043; --input-bg: #010409; --card-bg: #21262d;}
        :root[data-theme="light"] { --bg: #f6f8fa; --container-bg: #ffffff; --text: #24292f; --border: #d0d7de; --primary: #0969da; --btn: #2da44e; --btn-hover: #2c974b; --input-bg: #f6f8fa; --card-bg: #f3f4f6;}
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background-color: var(--bg); color: var(--text); padding: 20px; transition: 0.3s; }
        .container { max-width: 1000px; margin: 0 auto; background: var(--container-bg); padding: 30px; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
        .banner { text-align: center; color: var(--primary); margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 10px;}
        .section-card { background: var(--card-bg); border: 1px solid var(--border); padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .section-card h3 { margin-top: 0; color: var(--primary); border-bottom: 1px solid var(--border); padding-bottom: 5px; display: flex; justify-content: space-between; align-items: center;}
        textarea { width: 100%; box-sizing: border-box; background: var(--input-bg); color: var(--text); border: 1px solid var(--border); padding: 10px; border-radius: 6px; height: 80px; font-family: monospace; resize: vertical; margin-bottom: 10px;}
        input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; background: var(--input-bg); color: var(--text); border: 1px solid var(--border); padding: 10px; border-radius: 6px; margin-bottom: 15px;}
        .log-box { height: 180px; overflow-y: scroll; background: var(--input-bg); border: 1px solid var(--border); padding: 10px; font-family: monospace; font-size: 0.85em; margin-bottom: 15px;}
        button, .dl-btn { background: var(--btn); color: white; border: none; padding: 10px 20px; cursor: pointer; border-radius: 6px; font-weight: bold; width: 100%; transition: 0.2s; text-decoration: none; text-align: center; box-sizing: border-box; display: inline-block;}
        button:hover, .dl-btn:hover { background: var(--btn-hover); }
        .btn-danger { background: #da3633; } .btn-danger:hover { background: #b32d2a; }
        .btn-warning { background: #d73a49; } .btn-warning:hover { background: #cb2431; }
        .btn-sm { padding: 4px 8px; font-size: 0.8em; width: auto; margin-left: 10px; }
        .grid { display: flex; gap: 15px; } .col { flex: 1; min-width: 0; }
        .toggle-label { display: block; margin-bottom: 10px; cursor: pointer; font-size: 0.9em; }
        .list-item { display: flex; justify-content: space-between; align-items: center; padding: 6px; border-bottom: 1px solid var(--border); background: var(--input-bg); margin-bottom: 2px;}
        @media (max-width: 750px) { .grid { flex-direction: column; } }
        .theme-toggle { position: absolute; top: 20px; right: 20px; width: auto; padding: 5px 10px; }
    </style>
    <script>
        window.onload = () => {
            const match = document.cookie.match(new RegExp('(^| )theme=([^;]+)'));
            if (match) document.documentElement.setAttribute('data-theme', match[2]);
            if (typeof initDashboard === 'function') initDashboard();
        };
        function toggleTheme() {
            const nextTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', nextTheme);
            document.cookie = "theme=" + nextTheme + "; path=/; max-age=31536000; Secure"; 
        }
    </script>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()">🌓 Theme</button>
    <div class="container">
        <div class="banner"><h1>ARY-ShadowSieve</h1></div>
        {% block content %}{% endblock %}
        <div style="text-align: center; color: gray; margin-top: 20px; font-size: 0.8em;">⚡ Made by Aryan Giri ⚡</div>
    </div>
</body>
</html>
"""

LOGIN_PAGE = HTML_BASE.replace('{% block content %}{% endblock %}', """
    <h3 style="text-align:center;">🔒 Web Panel Login</h3>
    {% if error %}<p style="color:red; text-align:center;">{{ error }}</p>{% endif %}
    <form method="POST" action="/login">
        <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
        <label>Username</label><input type="text" name="username" required>
        <label>Password</label><input type="password" name="password" required>
        <button type="submit">Access Dashboard</button>
    </form>
""")

DASHBOARD_PAGE = HTML_BASE.replace('{% block content %}{% endblock %}', """
    <div style="display:flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
        <h2 style="margin:0;">Dashboard <span id="sync" style="font-size:0.5em; color:gray;">(Syncing...)</span></h2>
        <div>
            <form action="/logout" method="POST" style="display:inline;"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><button type="submit" class="btn-danger" style="width:auto; padding: 5px 10px;">Logout</button></form>
        </div>
    </div>

    <div class="section-card">
        <h3>📱 1. Proxy Client Access (Who can connect)</h3>
        
        <div style="margin-bottom: 15px; border: 1px solid var(--primary); padding: 10px; border-radius: 6px;">
            <strong style="color: var(--primary);">📡 Discovered Devices (Network IPs)</strong>
            <div id="discovered-devices" style="max-height: 150px; overflow-y: auto; margin-top: 10px;">Loading...</div>
        </div>

        <form action="/update" method="POST" id="mainForm">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <label class="toggle-label"><input type="checkbox" name="use_proxy_client_allow" value="true" {% if config.use_proxy_client_allow %}checked{% endif %}> <strong>Enable Strict Allowlist</strong> (Drops any device IP not listed below)</label>
            <div class="grid">
                <div class="col"><label>✅ ALLOWED Client IPs</label><textarea name="proxy_client_allow" placeholder="10.58.45.177">{{ allowlist_text }}</textarea></div>
                <div class="col"><label>⛔ BANNED Client IPs</label><textarea name="proxy_client_block" id="proxy_client_block" placeholder="192.168.1.50">{{ bannedlist_text }}</textarea></div>
            </div>
    </div>

    <div class="section-card">
        <h3>🎯 2. Proxy Destinations (Where devices can go)</h3>
        <p style="font-size:0.8em; color:gray; margin-top:0;">Features Deep Packet Inspection (DPI) to block domains even if DNS is bypassed.</p>
        <div class="grid" style="margin-top:10px;">
            <div class="col">
                <label class="toggle-label"><input type="checkbox" name="use_target_allow" value="true" {% if config.use_target_allow %}checked{% endif %}> <strong>Enable Destination Allowlist</strong></label>
                <label>✅ ALLOWED Domains / IPs / Wildcards</label>
                <textarea name="target_allow" placeholder="github.com&#10;142.250.*.*">{{ '\n'.join(config.target_allow) }}</textarea>
            </div>
            <div class="col">
                <label class="toggle-label"><input type="checkbox" name="use_target_block" value="true" {% if config.use_target_block %}checked{% endif %}> <strong>Enable Destination Blocklist</strong></label>
                <label>⛔ BANNED Domains / IPs / Wildcards</label>
                <textarea name="target_block" placeholder="malicious.com&#10;*.cn&#10;104.26.0.0/16">{{ '\n'.join(config.target_block) }}</textarea>
            </div>
        </div>
    </div>

    <div class="section-card">
        <h3>💻 3. Web Dashboard Access</h3>
        <p style="font-size:0.8em; color:#d73a49; margin-top:0;">Warning: Do not block your own IP or you will lose access!</p>
        <label class="toggle-label"><input type="checkbox" name="use_web_client_allow" value="true" {% if config.use_web_client_allow %}checked{% endif %}> <strong>Enable Dashboard Allowlist</strong></label>
        <div class="grid">
            <div class="col"><label>✅ ALLOWED Dashboard IPs</label><textarea name="web_client_allow">{{ '\n'.join(config.web_client_allow) }}</textarea></div>
            <div class="col"><label>⛔ BANNED Dashboard IPs</label><textarea name="web_client_block">{{ '\n'.join(config.web_client_block) }}</textarea></div>
        </div>
    </div>

    <button type="submit" style="font-size: 1.1em; padding: 15px;">💾 Save All Security Rules & Settings</button>
    </form>
    
    <div class="grid" style="margin-top: 20px;">
        <div class="col" style="flex: 1.5;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h4 style="margin:0;">🛡️ Proxy Target Logs</h4>
                <a href="/download/proxy" class="dl-btn btn-sm">⬇️ Download CSV/Log</a>
            </div>
            <input type="text" id="log-filter" placeholder="🔍 Search Logs..." onkeyup="fetchLogs()" style="margin-top: 10px; padding: 8px; width: 100%; box-sizing: border-box; background: var(--input-bg); color: var(--text); border: 1px solid var(--border); border-radius: 6px;">
            <div class="log-box" id="proxy-logs" style="margin-top: 10px; height: 300px;">Loading...</div>
        </div>
        <div class="col" style="flex: 1;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h4 style="margin:0;">🌐 Web Panel Logs</h4>
                <a href="/download/web" class="dl-btn btn-sm">⬇️ Download</a>
            </div>
            <div class="log-box" id="web-logs" style="margin-top: 10px; height: 300px;">Loading...</div>
        </div>
    </div>
    <form action="/clear_logs" method="POST"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><button type="submit" class="btn-warning" style="width:auto; margin-top:10px;">🗑️ Clear Both Logs</button></form>

    <script>
        function manageClient(ip, action) {
            const formData = new FormData();
            formData.append('_csrf_token', '{{ csrf_token() }}');
            formData.append('ip', ip);
            formData.append('action', action);
            fetch('/manage_client', { method: 'POST', body: formData })
                .then(() => setTimeout(() => window.location.reload(), 300));
        }

        function fetchLogs() {
            fetch('/api/data').then(res => res.json()).then(data => {
                if(data.error) return window.location.reload();
                
                document.getElementById('web-logs').innerHTML = data.web.length ? data.web.join('<br>') : 'No web accesses yet.';
                
                let filterText = document.getElementById('log-filter') ? document.getElementById('log-filter').value.toLowerCase() : "";
                let filteredProxy = data.proxy.filter(log => log.toLowerCase().includes(filterText));
                
                let proxyHtml = filteredProxy.map(log => {
                    return `<div style="padding: 4px 0; border-bottom: 1px solid var(--border);"><span style="word-break: break-all;">${log}</span></div>`;
                }).join('');
                document.getElementById('proxy-logs').innerHTML = proxyHtml || 'No matching traffic yet.';
                
                let seenHtml = '';
                if (data.seen_ips.length === 0) {
                    seenHtml = '<div style="padding:10px; color:gray;">No devices detected yet.</div>';
                } else {
                    data.seen_ips.forEach(ip => {
                        let isBanned = data.blocked_clients.includes(ip);
                        if (isBanned) {
                            seenHtml += `<div class="list-item"><span style="color:#da3633; font-weight:bold;">${ip} (BANNED)</span> <button type="button" class="btn-sm" onclick="manageClient('${ip}', 'unblock')">Unblock</button></div>`;
                        } else {
                            seenHtml += `<div class="list-item"><span>${ip}</span> <button type="button" class="btn-danger btn-sm" onclick="manageClient('${ip}', 'block')">Block</button></div>`;
                        }
                    });
                }
                document.getElementById('discovered-devices').innerHTML = seenHtml;
            }).catch(() => {});
        }
        function initDashboard() { fetchLogs(); setInterval(fetchLogs, 3000); }
    </script>
""")

def verify_csrf():
    token = request.form.get('_csrf_token')
    if not token or token != session.get('_csrf_token'): return False
    return True

@app.route('/', methods=['GET'])
def index():
    if session.get('logged_in'):
        try: return render_template_string(
            DASHBOARD_PAGE, 
            allowlist_text='\n'.join(config['proxy_client_allow']),
            bannedlist_text='\n'.join(config['proxy_client_block']),
            config=config)
        except Exception as e:
            print(Fore.RED + f"\n[!] DASHBOARD RENDER ERROR: {e}\n{traceback.format_exc()}")
            return "Dashboard Template Error (Check Terminal)", 500
    return render_template_string(LOGIN_PAGE, error=None)

@app.route('/login', methods=['POST'])
def login():
    if not verify_csrf(): return "CSRF validation failed", 403
    if request.form.get('username') == config['web_user'] and request.form.get('password') == config['web_pass']:
        session.clear() 
        session['logged_in'] = True
        session['_csrf_token'] = os.urandom(16).hex() 
        client_ip = request.remote_addr
        seen_ips.add(client_ip)
        add_web_log(client_ip) 
        return redirect('/')
    return render_template_string(LOGIN_PAGE, error="Invalid Credentials")

@app.route('/api/data')
def api_data():
    if not session.get('logged_in'): return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"web": web_logs, "proxy": proxy_logs, "seen_ips": list(seen_ips), "blocked_clients": config['proxy_client_block']})

@app.route('/manage_client', methods=['POST'])
def manage_client():
    if not session.get('logged_in') or not verify_csrf(): return "Unauthorized", 403
    ip = request.form.get('ip')
    action = request.form.get('action')
    if ip:
        if action == 'block' and ip not in config['proxy_client_block']:
            config['proxy_client_block'].append(ip)
            add_web_log(ip, "was BANNED by Admin")
        elif action == 'unblock' and ip in config['proxy_client_block']:
            config['proxy_client_block'].remove(ip)
            add_web_log(ip, "was UNBANNED by Admin")
        save_list_file(FILE_PROXY_CLIENT_BLOCK, '\n'.join(config['proxy_client_block']))
        load_lists() 
    return jsonify({"success": True})

@app.route('/download/proxy')
def download_proxy():
    if not session.get('logged_in'): return "Unauthorized", 401
    return Response('\n'.join(proxy_logs), mimetype='text/plain', headers={"Content-disposition": "attachment; filename=proxy_logs.txt"})

@app.route('/download/web')
def download_web():
    if not session.get('logged_in'): return "Unauthorized", 401
    return Response('\n'.join(web_logs), mimetype='text/plain', headers={"Content-disposition": "attachment; filename=web_logs.txt"})

@app.route('/update', methods=['POST'])
def update_blocklist():
    if not session.get('logged_in') or not verify_csrf(): return "Unauthorized", 403
    
    save_list_file(FILE_PROXY_CLIENT_ALLOW, request.form.get('proxy_client_allow', ''))
    save_list_file(FILE_PROXY_CLIENT_BLOCK, request.form.get('proxy_client_block', ''))
    save_list_file(FILE_TARGET_ALLOW, request.form.get('target_allow', ''))
    save_list_file(FILE_TARGET_BLOCK, request.form.get('target_block', ''))
    save_list_file(FILE_WEB_CLIENT_ALLOW, request.form.get('web_client_allow', ''))
    save_list_file(FILE_WEB_CLIENT_BLOCK, request.form.get('web_client_block', ''))
    
    config['use_proxy_client_allow'] = request.form.get('use_proxy_client_allow') == 'true'
    config['use_target_allow'] = request.form.get('use_target_allow') == 'true'
    config['use_target_block'] = request.form.get('use_target_block') == 'true'
    config['use_web_client_allow'] = request.form.get('use_web_client_allow') == 'true'
    
    save_settings()
    load_lists()
    return redirect('/')

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    if not session.get('logged_in') or not verify_csrf(): return "Unauthorized", 403
    web_logs.clear(); proxy_logs.clear()
    return redirect('/')

@app.route('/logout', methods=['POST'])
def logout():
    if not verify_csrf(): return "Unauthorized", 403
    session.clear()
    return redirect('/')

def print_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(Fore.CYAN + pyfiglet.Figlet(font='slant').renderText('ARY - ShadowSieve'))
    print(Fore.YELLOW + Style.BRIGHT + " " * 15 + "⚡ Made by Aryan Giri ⚡\n")

if __name__ == '__main__':
    print_banner()
    load_config()
    load_lists()
    cert_path, key_path = generate_tls_cert()
    
    use_auth = input(Fore.WHITE + "Enable proxy authentication? (y/n): ").strip().lower()
    if use_auth == 'y': print(Fore.GREEN + "-> Proxy Auth Enabled (creds in auth.txt).\n")
    else: config['proxy_user'] = ''; config['proxy_pass'] = ''; print(Fore.RED + "-> Proxy Auth Disabled.\n")

    https_only = input(Fore.WHITE + "Run web panel in HTTPS-only mode? (y/n): ").strip().lower()
    if https_only == 'y': app.config['SESSION_COOKIE_SECURE'] = True
    else: app.config['SESSION_COOKIE_SECURE'] = False

    web_access = input(Fore.WHITE + "Access web panel from network devices? (y/n): ").strip().lower()
    web_host = '0.0.0.0' if web_access == 'y' else '127.0.0.1'

    # --- CLI Port Info ---
    print(Fore.CYAN + "\nStarting Services...")
    print(Fore.CYAN + Style.BRIGHT + "-> SOCKS5 Proxy Server is RUNNING on PORT 1080")
    threading.Thread(target=run_socks5, daemon=True).start()
    
    if https_only != 'y':
        print(Fore.YELLOW + f"-> Insecure Web Panel accessible at: http://{web_host if web_host != '0.0.0.0' else '127.0.0.1'}:5000")
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        threading.Thread(target=lambda: app.run(host=web_host, port=5000, debug=True, use_reloader=False, threaded=True), daemon=True).start()

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        print(Fore.GREEN + f"-> Secure Web Panel accessible at: https://{web_host if web_host != '0.0.0.0' else '127.0.0.1'}:8443\n")
        app.run(host=web_host, port=8443, debug=True, use_reloader=False, threaded=True, ssl_context=context)
    except Exception as e:
        print(Fore.RED + f"FAILED to start secure server: {e}")
