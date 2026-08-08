# 🛡️ PipeSecure — Client-Side DevSecOps Pipeline Security Scanner

> **Enterprise-Grade Data Pipeline Security & Vulnerability Scanner running 100% in your browser. Zero server uploads. Zero data leakage.**

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![React](https://img.shields.io/badge/React-18.x-61dafb.svg)
![Vite](https://img.shields.io/badge/Vite-5.x-646cff.svg)
![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client--Side-10b981.svg)
![Engine](https://img.shields.io/badge/Engine-Deterministic%20%2B%20Multi--Provider%20AI-8b5cf6.svg)

---

## 📋 Overview

**PipeSecure** is a lightweight, privacy-first DevSecOps security audit tool designed specifically for data engineering artifacts and infrastructure-as-code files (Airflow DAGs, dbt models, Terraform scripts, AWS/GCP/Azure policies, `.env` files, Python pipelines, SQL scripts, and package manifests).

PipeSecure operates under a **Strict Client-Side Privacy Model**: all file parsing, regular expression matching, dependency CVE checking, and threat density scoring execute entirely inside your local browser runtime. No source code or credentials are ever sent to an external server.

---

## ✨ Key Features

### 1. 🔒 100% Client-Side Architecture
- **Zero Server Uploads**: Code files are parsed using browser HTML5 File & Directory Entry APIs (`FileReader`, `webkitGetAsEntry`).
- **Complete Privacy**: Zero telemetry, zero analytics tracking, zero third-party remote code execution.

### 2. ⚡ Dual Security Scanning Engines
- **⚡ Fast Deterministic Engine (Sub-5ms, 100% Offline)**: High-speed regular expression matcher and policy enforcement engine. Instantly flags hardcoded API keys, exposed database credentials, IAM wildcard permissions, unencrypted storage buckets, and vulnerable package dependencies without needing an API key or internet connection.
- **🤖 AI-Enhanced Deep Analysis Engine**: Integrates with major LLM providers to perform deep contextual risk analysis, architectural blast radius assessment, and production-ready refactored code fixes.
  - **OpenAI** (`gpt-4o-mini`, `gpt-4o`)
  - **Anthropic Claude** (`claude-3-5-sonnet`, `claude-3-haiku`)
  - **Google Gemini** (`gemini-2.0-flash`, `gemini-1.5-pro`)
  - **Custom / Local LLMs** (Ollama `http://localhost:11434/v1`, DeepSeek, Groq, LM Studio)

### 3. 🔄 Zero-Downtime Fallback Architecture
- If AI mode is enabled but an API request fails (e.g. network offline, invalid API key, 404 endpoint error, or 429 quota rate limit), PipeSecure **silently catches the error** and falls back 100% to the Fast Deterministic Engine.
- Your security scan always completes instantly with full static threat findings and remediation code intact.

### 4. 🌐 Dynamic Live Model Fetching
- Queries the provider's `/models` endpoint dynamically (`api.openai.com/v1/models`, `generativelanguage.googleapis.com/v1beta/models`, or local Ollama `/v1/models`) to retrieve live active model IDs.
- Includes a live model selector dropdown featuring a green **`Live API List`** status badge.

### 5. 📊 Dynamic Executive Security Posture Dashboard
- **Security Health Grade**: Calculates a dynamic 0–100 threat penalty score and letter grade (**A / B / C / F**).
- **Category KPI Breakdown Cards**: Real-time counts for **Secrets**, **Storage & Access**, **Encryption**, and **Dependencies**.
- **Live Incident Stream**: Displays top critical findings with 1-click **Inspect** actions.
- **Pipeline Asset Risk Density**: Ranks scanned files by vulnerability density percentage.

### 6. 📁 Comprehensive Multi-Tab DevSecOps Workspace
- **⚡ Scan Engine & Upload Zone**: Single file pick, folder selection, or 1-click **Try Sample Pipeline** loader. Includes an API Connection Tester with active spinner and operation-blocking states.
- **🔑 Secrets & Vulnerabilities Tab**: Detailed threat cards with exact line numbers, code evidence snippets, category filter badges with count numbers, severity badges, and AI refactored code fixes.
- **🌳 File Tree Asset Navigator**: Visual directory tree showing vulnerability density badges per file.
- **🛠️ Remediation Hub**: Instant copy-paste fixed code snippets.

### 7. 🌓 Dark & Light Theme System
- Integrated header toggle button with Sun ☀️ and Moon 🌙 icons.
- Auto-detects OS `prefers-color-scheme` and persists user preference in `localStorage`.

### 8. 📥 Multi-Format Security Audit Exporter
- **Export Markdown Report (`.md`)**: Full human-readable security audit document.
- **Export JSON Report (`.json`)**: Machine-readable JSON manifest for CI/CD pipelines.
- **Export CSV Findings (`.csv`)**: Spreadsheet-compatible threat inventory.

---

## 🎯 Supported File Formats & Vulnerability Signatures

PipeSecure scans all common pipeline artifacts and infrastructure code:

| Category | File Extensions / Artifacts | Scanned Security Threats |
| :--- | :--- | :--- |
| **🔑 Secrets & Credentials** | `.py`, `.env`, `.yaml`, `.json`, `.tf`, `airflow.cfg` | Hardcoded AWS Access Keys (`AKIA...`), GCP JSON credentials, Database Connection URIs (`postgres://`, `mysql://`), OpenAI/Slack API keys, JWT tokens, RSA Private Keys. |
| **🪣 Storage & Access Control** | `.tf`, `main.tf`, `policy.json`, `.yaml` | S3 Buckets with Public Read/Write (`Principal: "*"`), IAM Wildcard Privileges (`Action: "*"`), Public S3 ACLs (`public-read`), Missing S3 Bucket Versioning. |
| **🔒 Encryption & Transport** | `.py`, `.tf`, `.env`, `.ini`, `.yaml` | Unencrypted DB Connections (`sslmode=disable`), HTTP URIs in production data transfers, Weak Hashing (`MD5`, `SHA1`), Disabled TLS verification (`verify=False`). |
| **📦 Dependencies (CVEs)** | `requirements.txt`, `Pipfile`, `package.json`, `pyproject.toml` | High & Critical CVEs matched against Google's OSV advisory database (PyPI & npm ecosystems). |

---

## 🚀 Quick Start & Installation

### Prerequisites
- **Node.js**: v18.0 or higher
- **npm**: v9.0 or higher

### 1. Clone & Install
```bash
git clone https://github.com/Vedant-303/PipeSecure.git
cd PipeSecure
npm install
```

### 2. Run Development Server
```bash
npm run dev
```

Open `http://localhost:5173/` in your browser.

---

## 🏗️ Project Architecture & Folder Structure

```
PipeSecure/
├── demo/                       # Sample vulnerable pipeline code for demo testing
│   ├── dags/                   # Sample Airflow DAGs with hardcoded secrets
│   ├── infra/                  # Sample Terraform configs with public S3 buckets
│   ├── requirements.txt        # Sample Python manifest with vulnerable dependencies
│   └── .env                    # Sample environment variables
├── src/
│   ├── components/             # React UI Components
│   │   ├── Header.jsx          # Header with Dark/Light mode toggle & report exporter
│   │   ├── Sidebar.jsx         # Navigation sidebar with tab switching
│   │   ├── FileUpload.jsx      # Folder/file drag & drop, AI engine selector, API connection tester
│   │   ├── TrendDashboard.jsx  # Executive posture dashboard, KPIs, incident stream
│   │   ├── FindingsList.jsx   # Threat findings list with category filter badges & AI fixes
│   │   ├── FileTree.jsx        # Interactive directory file tree asset navigator
│   │   └── Remediation.jsx     # Production remediation code fixes hub
│   ├── engine/                 # Core Security Engine & Utility Modules
│   │   ├── scanner.js          # Main scan orchestrator (Static rules + OSV API + AI enrichment)
│   │   ├── universalAIClient.js# Universal multi-provider AI client (OpenAI, Claude, Gemini, Ollama)
│   │   ├── aiConfigStore.js    # LocalStorage manager for AI engine settings
│   │   ├── historyStore.js     # Persistent scan history & posture score calculator
│   │   ├── rules.js            # Regular expression rules & threat signature definitions
│   │   ├── osvScanner.js       # Google OSV API dependency vulnerability query engine
│   │   ├── reportExporter.js   # Markdown & JSON audit report exporters
│   │   └── types.js            # Scannable extension checkers & helper functions
│   ├── App.jsx                 # Main application state orchestrator & scanning overlay
│   ├── main.jsx                # React entry point
│   └── index.css               # Design System, CSS tokens, Dark Theme, Animations
├── package.json
└── README.md
```

---

## 🔐 Security & Privacy Guarantee

- **No Remote Code Execution**: Scanning runs entirely in browser JavaScript.
- **Local Storage Isolation**: Your API keys (if using AI mode) are stored exclusively in your browser's `localStorage` or RAM and are only sent directly to your chosen provider's official endpoint over HTTPS.
- **Zero Third-Party Tracking**: PipeSecure contains no analytics scripts, cookies, or external trackers.

---

## 📄 License

This project is licensed under the **MIT License**.
