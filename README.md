# 🛡️ PrivacyGuard AI

> **Next-Generation Full-Stack Privacy Assessment, Hybrid PII Detection & Adaptive De-Identification Platform**

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Backend-Flask%203.1-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![Presidio](https://img.shields.io/badge/NER-Presidio%20%2B%20spaCy-blueviolet?style=flat-square)](https://github.com/microsoft/presidio)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

---

## 📌 Overview

**PrivacyGuard AI** is an end-to-end privacy engineering and de-identification system designed to identify, assess, and sanitize sensitive personal data (PII) before it is shared, published, or fed into Large Language Models (LLMs).

Combining Microsoft Presidio, spaCy NLP models, and custom pattern-recognition heuristics (including regional identifiers such as Indian Aadhaar, PAN, and IFSC), PrivacyGuard AI computes a composite **re-identification risk score**, executes **adaptive sanitization policies**, runs an **automated output leakage audit**, and generates auditable **PDF compliance reports**.

---

## ✨ Key Features

- 🔍 **Hybrid Multi-Engine Detection**:
  - **Presidio & spaCy NER**: Contextual detection of names, locations, organizations, and dates.
  - **Regex & Checksum Validators**: High-precision detection for emails, phone numbers, IP addresses, credit cards, Indian PAN numbers, IFSC codes, and Aadhaar patterns.
  - **Smart Merge & Conflict Resolution**: Deduplicates overlapping spans and prioritizes higher-confidence predictions.

- 📊 **Dynamic Privacy Risk Scoring Engine**:
  - Evaluates individual entity sensitivity weights ($0.0 - 1.0$).
  - Models **quasi-identifier combination risk** (e.g., Name + Location + Organization creates high re-identification potential).
  - Proximity-based risk multiplier for closely clustered sensitive tokens.
  - Categorizes risk into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

- 🎭 **Adaptive Sanitization Modes**:
  - **Masking**: Retains partial context while obscuring sensitive data (e.g., `p***@example.com`, `9876****10`).
  - **Redaction**: Explicit placeholder replacements (e.g., `[REDACTED_EMAIL_ADDRESS]`).
  - **Pseudonymization / Tokenization**: Replaces entities with consistent tokens (e.g., `<PERSON_1>`, `<LOCATION_1>`).
  - **Synthetic Replacement**: Generates surrogate data for realistic testing.

- 🛡️ **Zero-Leakage Output Auditor**:
  - Automatically re-scans sanitized text against all detection rules to verify zero residual PII leakage before data release.

- 📄 **Multi-Format Extraction & PDF Reporting**:
  - Extracts text from plain text, PDF (`pypdf`), and Word documents (`python-docx`).
  - Generates downloadable, audit-ready compliance PDF reports formatted with findings breakdowns and risk metrics using ReportLab.

- 🔐 **Secure Architecture**:
  - JWT authentication (`Flask-JWT-Extended`) and password hashing with `bcrypt`.
  - SQLite database managed via SQLAlchemy for scan histories and audit trails.
  - Interactive, responsive React dashboard built with Vite.

---

## 🏗️ Architecture

```
                       ┌─────────────────────────┐
                       │   React Web Client      │
                       │ (Dashboard / Analyzer)  │
                       └────────────┬────────────┘
                                    │ REST (JSON / Multipart)
                                    ▼
                       ┌─────────────────────────┐
                       │   Flask REST API        │
                       │ (Auth / JWT / Routes)   │
                       └────────────┬────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│ Document Parser  │       │  Hybrid Detector │       │ SQLite Database  │
│ (TXT, PDF, DOCX) │       │ (Presidio+spaCy) │       │  (Audit Trails)  │
└──────────────────┘       └────────┬─────────┘       └──────────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │   Privacy Risk Engine   │
                       │ (Sensitivity+Combos)    │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │ Adaptive Sanitizer      │
                       │ (Mask/Redact/Synthetic) │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │  Output Leakage Auditor │
                       │   & PDF Report Engine   │
                       └─────────────────────────┘
```

---

## 🚀 Quickstart Guide

### Prerequisites

- **Python**: 3.12+ (Python 3.12 recommended)
- **Node.js**: 18+ & `npm`
- **Git**

---

### Option A: Local Development Setup

#### 1. Clone the Repository
```bash
git clone https://github.com/D-GP/privacyguard.git
cd privacyguard
```

#### 2. Backend Setup
```powershell
cd backend

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # On Linux/macOS: source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download required spaCy models
python -m spacy download en_core_web_sm
python -m spacy download en_core_web_lg

# Initialize environment variables
cp .env.example .env

# Run the server
python run.py
```
> Backend will be running at: `http://localhost:5000`

#### 3. Frontend Setup
In a new terminal window:
```powershell
cd frontend

# Install packages
npm install

# Initialize environment variables
cp .env.example .env

# Start Vite dev server
npm run dev
```
> Frontend will be running at: `http://localhost:5173`

---

### Option B: Docker Compose

Spin up the entire stack with a single command:

```bash
docker compose up --build
```

- **Frontend**: `http://localhost:8080`
- **Backend API**: `http://localhost:5000`

---

## 📡 API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | Public | System health check |
| `POST` | `/api/auth/register` | Public | Register new user account |
| `POST` | `/api/auth/login` | Public | Authenticate user & receive JWT |
| `GET` | `/api/auth/me` | JWT | Get current user profile |
| `POST` | `/api/analyze` | JWT | Scan raw text or uploaded document |
| `POST` | `/api/scans/<id>/sanitize` | JWT | Apply de-identification policy |
| `GET` | `/api/scans` | JWT | List scan history |
| `GET` | `/api/scans/<id>` | JWT | Retrieve detailed scan & entity graph |
| `GET` | `/api/scans/<id>/report` | JWT | Download generated PDF audit report |
| `GET` | `/api/dashboard` | JWT | Aggregate statistics & risk distribution |
| `GET` | `/api/audit` | JWT | Fetch audit event log |

---

## 🏷️ Supported Identifiers & Recognizers

| Category | Identifier Types | Detection Method |
|---|---|---|
| **Direct PII** | Full Name, Email, Phone Numbers (`+91` & Intl) | Presidio / Regex |
| **Financial** | Credit Card Numbers, IFSC Codes | Presidio / Regex |
| **National IDs** | Indian PAN Card, Aadhaar-like numbers | Custom Regex Heuristics |
| **Network** | IPv4 Addresses, Domains | Regex Validation |
| **Quasi-Identifiers** | Location, Organization, Dates / Times | spaCy Statistical NER |

---

## 🧪 Testing with Sample Input

Once logged in, submit a sample paragraph to see the risk scoring and sanitization in action:

```text
Contact Dr. Priya Sharma at priya.sharma@example.com or +91 9876543210. 
She is registered under PAN ABCDE1234F and works at CyberTech Innovations in Bengaluru.
```

1. **Detection**: Identifies `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `PAN_IN`, `ORGANIZATION`, `LOCATION`.
2. **Risk Engine**: Identifies high combination sensitivity (`HIGH` / `CRITICAL` risk).
3. **Sanitization**: Select **Mask**, **Redact**, or **Pseudonymize** to inspect transformed outputs and audit leakage.
4. **Export**: Download the compliance summary PDF.

---

## 🛡️ Attribution & References

PrivacyGuard AI builds upon modern data privacy principles and leverages established open-source tools:
- [Microsoft Presidio](https://github.com/microsoft/presidio) — Core PII detection baseline (MIT License)
- [spaCy](https://spacy.io/) — Industrial-strength NLP (MIT License)
- [ZINK](https://github.com/deepanwadhwa/zink) & [pii-anon](https://github.com/subhash-holla/pii-anon) — Conceptual references for quasi-identifier modeling

---

## 📄 License

Distributed under the [MIT License](LICENSE).
