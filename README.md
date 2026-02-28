# 🛡️ ARY-ShadowSieve

> **Zero-Trust SOCKS5 Proxy + Secure Web Control Panel**

Welcome to **ARY-ShadowSieve** — a powerful, hacker-grade network control system built for precision traffic filtering, device governance, and secure proxy management.

⚡ Crafted with focus by **Aryan Giri** ⚡

---

## 🚀 Overview

ARY-ShadowSieve is a **Zero-Trust SOCKS5 Proxy Server** fused with a hardened **HTTPS Control Dashboard**.

Built for:

* Network visibility
* Device-level control
* Domain filtering
* Secure proxy deployment

Think of it as your personal **Network Command Center** 🧠

---

## ✨ Features

### 🧩 Core Proxy Engine

* ⚡ SOCKS5 Proxy on **Port 1080**
* 🔐 Optional authentication
* 🌍 IPv4 + IPv6 support

### 🖥️ Dual Dashboard Modes

* 🔒 Secure HTTPS Panel → **Port 8443**
* 🏠 Local HTTP Panel → **Port 5000**

### 🛡️ Zero-Trust Security

* Allow only specific client IPs
* Block / Allow:

  * Domains
  * IPs
  * Wildcards (e.g. `*.google.com`)
* Restrict dashboard access to admin IPs

### 📡 Live Device Monitoring

* Real-time IP discovery
* One-click **Ban System** 🚫

### 📜 Traffic Intelligence

* Full logging of proxy + dashboard activity
* Export logs as `.txt`

### 🔑 Auto TLS Generator

* Generates RSA certificates automatically
* Includes `.crt` for browser trust import

---

## 🛠️ Installation

### 📥 Clone Repository

```
git clone https://github.com/giriaryan694-a11y/ARY-ShadowSieve
cd ARY-ShadowSieve
```

---

## 🪟 Windows Setup

### 1️⃣ Create Virtual Environment

```
python -m venv venv
```

### 2️⃣ Activate

## For Windows
```
.\venv\Scripts\activate
```
## For Linux
'''
./venv/bin/activate
'''

### 3️⃣ Install Requirements

```
pip install -r requirements.txt
```

### 4️⃣ Run Server

```
python main.py
```

---

## 🐧 Linux Setup

### 1️⃣ Create Virtual Environment

```
python3 -m venv venv
```

### 2️⃣ Activate

```
source venv/bin/activate
```

### 3️⃣ Install Requirements

```
pip install -r requirements.txt
```

### 4️⃣ Run Server

```
python3 main.py
```

---

## 🌐 First Time Browser Setup

On first run, ShadowSieve generates:

```
cert.crt
```

Install it into:

👉 Trusted Root Certification Authorities

This removes HTTPS warnings.

---

## 🖥️ Access Dashboard

| Mode      | URL                                              |
| --------- | ------------------------------------------------ |
| 🔒 Secure | [https://127.0.0.1:8443](https://127.0.0.1:8443) |
| 🏠 Local  | [http://127.0.0.1:5000](http://127.0.0.1:5000)   |

---

## 🌍 Proxy Configuration

| Setting   | Value          |
| --------- | -------------- |
| Protocol  | SOCKS v5       |
| Host      | Your Device IP |
| Port      | 1080           |
| Proxy DNS | ENABLED        |

📌 Firefox Users:
Enable **Proxy DNS when using SOCKS v5**

---

## 📂 File Structure

| File                  | Purpose               |
| --------------------- | --------------------- |
| `main.py`             | Core engine           |
| `auth.txt`            | Encrypted credentials |
| `settings.txt`        | Feature toggles       |
| `proxy_clients_*.txt` | Allowed devices       |
| `targets_*.txt`       | Domain/IP rules       |
| `server_logs.txt`     | Activity history      |

---

## 🔐 Authentication Config

Auto-created on first run.

Manual format:

```
# Web Control Panel
user : secure_admin
pass : secure_family@123

# SOCKS5 Auth
user : proxy_needed
pass : secure123
```

---

## 🧭 Port Map

| Component        | Port | Protocol | Security                     |
| ---------------- | ---- | -------- | ---------------------------- |
| SOCKS5 Proxy     | 1080 | TCP      | Optional Auth + IP Allowlist |
| Secure Dashboard | 8443 | HTTPS    | TLS 1.3 + CSRF               |
| Basic Dashboard  | 5000 | HTTP     | Local Use Only               |

---

## ▶️ Quick Start

1. Add `requirements.txt`
2. Add `auth.txt`
OR it will generate default
3. Run:

```
python main.py
```

---

## 🔗 Repository

GitHub:

```
https://github.com/giriaryan694-a11y/ARY-ShadowSieve
```

---

## ⚙️ Use Cases

* Secure Home Network Control
* Research Lab Proxy Isolation
* Traffic Filtering
* Device-Level Monitoring
* Privacy-Oriented Routing

---

## 🧠 Philosophy

> "Trust nothing. Allow intentionally."
