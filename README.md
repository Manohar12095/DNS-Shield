# 🛡️ DNS Shield — DNS Tunneling Detection & Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.10%20--%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-5.4+-646CFF.svg)](https://vitejs.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4+-38B2AC.svg)](https://tailwindcss.com/)
[![Machine Learning](https://img.shields.io/badge/ML-XGBoost%20%2B%20SHAP-orange.svg)](https://xgboost.readthedocs.io/)

An enterprise-grade cybersecurity platform that detects, analyzes, and explains **DNS Tunneling**, **Data Exfiltration**, and **Covert C2 (Command & Control) Beaconing** using hybrid **Machine Learning (XGBoost + SHAP)**, **Deterministic Rule Heuristics**, and an **AI Threat Intelligence Co-Pilot**.

---

## 📑 Table of Contents
1. [What is DNS Tunneling & What is the Use of this Platform?](#1-what-is-dns-tunneling--what-is-the-use-of-this-platform)
2. [How It Finds DNS Tunneling (Detection Methodology & Science)](#2-how-it-finds-dns-tunneling-detection-methodology--science)
3. [System Architecture & Data Flow](#3-system-architecture--data-flow)
4. [How to Use the Website (Step-by-Step Guide)](#4-how-to-use-the-website-step-by-step-guide)
5. [Quick Start & Launching](#5-quick-start--launching)
6. [API Endpoints & Swagger Docs](#6-api-endpoints--swagger-docs)
7. [Troubleshooting & FAQ](#7-troubleshooting--faq)

---

## 1. What is DNS Tunneling & What is the Use of this Platform?

### What is DNS Tunneling?
**Domain Name System (DNS)** is the fundamental address book of the Internet. Because every workstation and server needs DNS to resolve domain names, firewalls, proxies, and captive portals almost universally allow outbound DNS traffic (**Port 53 UDP/TCP**) unrestricted without payload inspection.

Threat actors exploit this trust through **DNS Tunneling**:
* **Data Exfiltration**: Sensitive files, keystrokes, and credentials are sliced, encoded (Base64/Hex), and prepended as subdomains (e.g. `aGVsbG8gd29ybGQ.c2-server.com`). Recursive DNS resolvers forward the request until it hits the attacker's authoritative server, which reconstructs the data.
* **Command & Control (C2)**: Malware establishes an interactive shell or receives task commands via DNS response records (`TXT`, `NULL`, `CNAME`) without making direct HTTP/HTTPS connections.
* **Low-and-Slow Beaconing**: Advanced Persistent Threats (APTs) emit periodic low-frequency DNS queries (e.g., one query every 5 minutes with low variance) to maintain persistence while evading volume-based firewalls.

### What is the Use of this Website?
Traditional security controls fail to flag tunneling because individual queries appear syntactically valid.

**DNS Shield** provides complete defensive coverage:
1. **Instant Inspection**: Real-time evaluation of single domains, bulk CSV logs, and `.pcap` Wireshark packet captures.
2. **Transparent Explainability**: Every prediction explains **why** it was flagged with mathematical **SHAP values** and human-readable reasoning.
3. **AI Threat Intelligence Co-Pilot**: An integrated assistant that queries live DNS records, checks WHOIS registration history, and provides actionable risk reports.
4. **Audit & Compliance**: Generates downloadable executive security reports in standalone HTML format for incident response and SOC documentation.

---

## 2. How It Finds DNS Tunneling (Detection Methodology & Science)

The platform combines **Machine Learning** with **Deterministic Rule Heuristics** and **Temporal Traffic Modeling**:

```
                           Incoming DNS Query / Log
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
     [Feature Engineering]                         [Temporal Aggregates]
    • Shannon & N-gram Entropy                    • Query Rate (Bursts)
    • Subdomain & FQDN Length                     • Interval Std Dev (Beaconing)
    • Character Ratios (Digit/Hex/B64)            • Unique Subdomain Ratio
    • Query Types (TXT, NULL, etc.)                          │
               │                                             │
               ▼                                             │
      [XGBoost Classifier]                                   │
   (Non-linear decision trees)                               │
               │                                             │
               ▼                                             │
       Confidence Score                                      │
               │                                             │
               └──────────────────────┬──────────────────────┘
                                      ▼
                        [Rule Engine & Risk Scorer]
                           • Boost if Entropy > 3.5
                           • Boost if Base64 Pattern
                           • Boost if TXT/NULL Query
                           • Boost if Burst / Beaconing
                                      │
                                      ▼
                           [Final Risk Score (0-100)]
                           + SHAP Feature Breakdown
                           + Human-Readable Evidence
```

### A. Feature Extraction (13+ Distinct Metrics)

Every DNS query is analyzed across mathematical and behavioral dimensions:

1. **Shannon Entropy**:
   $$\text{Entropy} = -\sum_{i=1}^{n} p_i \log_2(p_i)$$
   * Normal dictionary domains (e.g. `google`, `github`) have low entropy ($1.5 - 2.5$).
   * Encrypted/encoded payloads (e.g. `aGVsbG93b3JsZHRlc3Q`) produce high entropy ($3.5 - 4.5+$).
2. **Normalized Entropy**: Entropy scaled by label length ($0.0 - 1.0$) to avoid skewing on short labels.
3. **Bigram & Trigram Entropy**: Measures unnatural character sequence transitions compared to standard English language patterns.
4. **Length Metrics**:
   * **FQDN Length**: Overall length of the domain (RFC limit: 253 characters).
   * **Subdomain Length**: Tunneling payloads cram large strings into individual labels (up to 63 characters per label).
5. **Label Count**: Number of dot-separated sub-elements (e.g., `payload.chunk1.segment2.attacker.com`).
6. **Character Composition**:
   * **Digit Ratio**: Proportion of numeric characters ($0-9$).
   * **Base64 / Hex Pattern Detection**: Regex identification of Base64 (`[A-Za-z0-9+/]{20,}`) and Hexadecimal strings (`[0-9a-f]{16,}`).
7. **Query Type Encoding**:
   * Standard web browsing utilizes `A` (IPv4) and `AAAA` (IPv6).
   * Tunneling utilities (`iodine`, `dnscat2`) prefer `TXT` and `NULL` records for maximum data capacity.
8. **Response Code**: `NXDOMAIN` vs `NOERROR`. Unusually high `NXDOMAIN` rates signal domain generation algorithms (DGA) or scanning.
9. **TTL (Time to Live)**: Near-zero TTLs ($0 - 10\text{ seconds}$) prevent DNS caching, forcing every query to the attacker's nameserver.

### B. Machine Learning (XGBoost + SHAP)
* **Model**: Gradient Boosted Decision Tree (XGBoost) trained on benign domain sets and tunneling tool captures.
* **SHAP (SHapley Additive exPlanations)**: Calculates exact feature contributions per inference (e.g., `+32% due to high entropy`, `+18% due to TXT record type`).

### C. Heuristic Session Analysis (CY-04 Standard)
* **High-Volume Bursts**: Flags sudden query bursts exceeding threshold (default: $>50\text{ queries/min}$).
* **Low-and-Slow Beaconing**: Measures interval standard deviation ($\sigma < 0.1\text{s}$ indicates automated heartbeats).
* **Unique Subdomain Ratio**: Flags traffic where nearly every subdomain label is unique (one-time exfiltration chunks).

---

## 3. System Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                       FRONTEND                              │
│       React 18 + Vite + Tailwind CSS + Zustand + Lucide     │
│                                                             │
│   [Dashboard]    [Analyze]    [AI Chat]   [History]  [Settings]
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP REST / Server-Sent Events (SSE)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND (FastAPI)                        │
│                                                             │
│  • /api/analyze/single   • /api/chat/sessions               │
│  • /api/analyze/batch    • /api/lookup/domain               │
│  • /api/dashboard        • /api/settings                    │
├─────────────────────────────────────────────────────────────┤
│  SERVICES:                                                  │
│  • ML Classifier (XGBoost + SHAP in memory cache)           │
│  • DNS Resolver (dnspython) + WHOIS Client (python-whois)   │
│  • OpenRouter LLM Gateway (SSE streaming)                   │
│  • Encryption Engine (Fernet AES-128-CBC)                   │
├─────────────────────────────────────────────────────────────┤
│  DATABASE: SQLite (scan_history, chat_sessions, settings)   │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. How to Use the Website (Step-by-Step Guide)

### 1. The Dashboard (`/`)
* **Live Threat Metrics**: Total scans, detected tunneling attempts, burst attacks, active beaconing channels, and average risk score.
* **Interactive Risk Gauge**: Visual speedometer gauge displaying global threat level.
* **Chronological Risk Chart**: 14-day timeline tracking query volume and risk spikes.
* **Top Offending Domains**: Identifies repeated adversary root domains.

### 2. The Analyze Page (`/analyze`)
* **Single Domain Inspection**:
  1. Input any domain (e.g., `aGVsbG93b3JsZHRlc3RkYXRh.evil-tunnel.net`).
  2. Select the query type (`A`, `TXT`, `NULL`, `CNAME`, `MX`, etc.).
  3. Click **Analyze Query**.
  4. Review **Risk Score (0–100)**, **Verdict (Clean vs Flagged)**, **Evidence Text**, and the **SHAP Feature Contribution Chart**.
* **Batch CSV Upload**:
  1. Upload a CSV containing DNS logs (`query_name`, `query_type`, `response_code`, `response_len`, `ttl`).
  2. Click **Analyze Batch**.
  3. View aggregated statistics and download flagged results.
* **PCAP File Upload**:
  1. Upload raw `.pcap` packet captures from Wireshark or tcpdump.
  2. The server extracts DNS packets, evaluates them, and returns flagged flows.

### 3. AI Threat Intelligence Co-Pilot (`/chat`)
* **Interactive Threat Analysis**: Enter any domain name to trigger automated investigation:
  * Resolves live DNS records (`A`, `AAAA`, `NS`, `MX`, `TXT`).
  * Queries WHOIS registration details (registrar, creation date, domain age).
  * Evaluates CY-04 criteria and displays a structured **Threat Card**.
* **Chat Session Management**:
  * **New Chat**: Click **+ New Chat** in sidebar.
  * **Rename & Delete**: Rename or delete threads directly from sidebar icons.
  * **Message Controls**: Hover over any chat bubble to delete individual messages.

### 4. Audit History & Reporting (`/history`)
* Search, filter, and inspect past scans.
* Toggle **"Show only flagged (tunneling) records"**.
* Click **Export Report (HTML)** to generate a self-contained executive security report.

### 5. Settings & Customization (`/settings`)
* **Themes**: Cyber Green, Midnight Blue, or High Contrast.
* **Custom Styling**: Adjust primary brand color and UI accents.
* **AI Configuration**: Enter your OpenRouter API key (encrypted with Fernet AES-128).
* **Detection Thresholds**: Customize Shannon Entropy threshold, Burst query threshold, and Beaconing variance.

---

## 5. Quick Start & Launching

### Method 1: One-Click Windows Launcher (Recommended)

Double-click `run.bat` or execute in terminal:
```cmd
run.bat
```
This launcher automatically:
1. Validates the Python virtual environment and installs dependencies.
2. Validates frontend Node modules.
3. Initializes the SQLite database.
4. Starts the FastAPI backend on `http://127.0.0.1:8000`.
5. Starts the Vite React frontend on `http://localhost:5173`.
6. Opens `http://localhost:5173` in your default browser.

To stop all services:
```cmd
stop.bat
```

---

### Method 2: Manual PowerShell / Command Line

#### Terminal 1 — Backend (FastAPI):
```powershell
cd backend
$env:PYTHONPATH="."
.\venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### Terminal 2 — Frontend (Vite):
```powershell
cd frontend
npm.cmd run dev
```

The application will be accessible at:
* **Frontend Web Application**: [http://localhost:5173](http://localhost:5173)
* **Backend API Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **Backend Health Check**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

---

### Method 3: Docker Compose

```bash
docker-compose up --build
```

---

## 6. API Endpoints & Swagger Docs

The backend provides interactive Swagger UI at **http://127.0.0.1:8000/docs**:

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | `GET` | Health check & ML model status |
| `/api/analyze/single` | `POST` | Real-time single domain tunneling analysis |
| `/api/analyze/batch` | `POST` | Batch CSV log file analysis |
| `/api/analyze/pcap` | `POST` | PCAP packet capture inspection |
| `/api/dashboard/summary`| `GET` | Aggregated dashboard security metrics |
| `/api/chat/sessions` | `GET`/`POST` | AI Threat Intel chat conversation management |
| `/api/chat/message` | `POST` | Send chat prompt with live streaming SSE |
| `/api/lookup/domain` | `GET` | Live DNS & WHOIS intelligence lookup |
| `/api/settings` | `GET`/`POST` | Thresholds & encrypted API key configuration |

---

## 7. Troubleshooting & FAQ

#### Q: How do I test a malicious sample?
* Navigate to **Analyze &rarr; Single Query**, enter `aGVsbG93b3JsZHRlc3RkYXRh.evil-tunnel.net` with query type `TXT`, and click **Analyze Query**. The platform will return a **100/100 Risk Score** with Base64 pattern and entropy flags.

#### Q: How do I test a clean benign sample?
* Enter `www.google.com` with query type `A`. The platform will return **Clean (Risk: ~0/100)**.

#### Q: How to configure the AI Chat Co-Pilot?
* Go to **Settings &rarr; AI Configuration**, paste your OpenRouter API key (format: `sk-or-v1-...`), and click **Save Settings**. The key is securely encrypted at rest.

#### Q: "Running scripts is disabled on this system" in PowerShell?
* Run `npm.cmd run dev` instead of `npm run dev`, or run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in PowerShell.

---

## 📄 License
This project is licensed under the MIT License.
