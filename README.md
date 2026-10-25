# 🛡️ PrivacyGuard AI

> **Enterprise-Grade Privacy Assessment, Hybrid Multi-Engine PII Detection & Adaptive De-Identification Platform**

[![Python 3.12](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Backend-Flask%203.1-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![Hugging Face](https://img.shields.io/badge/Transformers-BERT%20NER-FFD21E?style=flat-square&logo=huggingface&logoColor=black)](https://huggingface.co/dslim/bert-base-NER)
[![Presidio](https://img.shields.io/badge/NER-Presidio%20%2B%20spaCy-blueviolet?style=flat-square)](https://github.com/microsoft/presidio)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

---

## 📌 Overview

**PrivacyGuard AI** is an end-to-end privacy engineering, data governance, and automated de-identification system designed to identify, quantify, and sanitize personally identifiable information (PII) before it is shared across teams, stored in analytics warehouses, or fed into Large Language Models (LLMs).

Unlike traditional keyword filters or single-model detectors, PrivacyGuard AI combines **Hugging Face Transformer NER (`dslim/bert-base-NER`)**, **Microsoft Presidio & spaCy NLP**, and **deterministic algorithmic regex engines with checksum validation** (including regional identifiers such as Indian Aadhaar, PAN, IFSC, UPI IDs, and bank account numbers).

The platform models **quasi-identifier combination risks** and **spatial proximity clustering** to calculate a unified re-identification risk score, executes **adaptive sanitization policies**, runs an **automated zero-leakage output audit**, and generates auditable **PDF compliance reports**.

---

## ✨ Key Features

- 🔍 **Triple-Layer Hybrid Detection Engine**:
  - **Transformer NER**: Contextual entity classification powered by `dslim/bert-base-NER` for names, locations, and organizations.
  - **Presidio & spaCy Engine**: Enterprise-grade statistical NLP for entity discovery and contextual extraction.
  - **Deterministic Regex & Checksum Engine**: High-precision recognition with Luhn algorithm verification for credit cards, strict IPv4 octet bounds validation, and Indian financial identifiers (PAN, IFSC, UPI, Aadhaar, Vehicle RC, Bank Accounts).
  - **Context-Aware False Positive Suppression**: Disambiguates polysemous words (e.g., `"apple as fruit"` vs `"Apple the company"`, `"May as month"` vs `"May as person"`, `"rose as flower"` vs `"Rose as name"`) and suppresses accidental label detections (e.g. `IFSC:`, `UPI ID`).
  - **Span Deduplication & Conflict Resolution**: Merges overlapping detections, prioritizing structured checksum validators and longer spans with higher confidence.

- 📊 **Dynamic Privacy Risk Scoring Engine**:
  - Entity-level sensitivity weighting ($0.0 - 1.0$).
  - **Quasi-Identifier (QI) Linkage Modeling**: Evaluates the cumulative re-identification probability when multiple attributes (e.g., Name + Location + Organization + Phone) co-occur.
  - **Proximity Decay Multiplier**: Models spatial distance between entities in the document (`exp(-distance / 180)`), penalizing tightly clustered sensitive records.
  - Categorizes overall document posture into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

- 🎭 **Adaptive Sanitization & Transformation Modes**:
  - **Adaptive**: Context-aware anonymization matching the sensitivity level of each detected entity.
  - **Pseudonymization / Tokenization**: Replaces sensitive values with consistent semantic tokens (e.g., `<PERSON_1>`, `<EMAIL_ADDRESS_1>`).
  - **Redaction / Masking**: Uniform replacement with `[REDACTED]`.
  - **Cryptographic Hashing**: Deterministic SHA-256 truncation (`<HASH_xxxxxxxxxx>`) enabling referential integrity across analytical pipelines without revealing raw PII.
  - **Removal**: Total excision of sensitive tokens from downstream payloads.

- 🛡️ **Zero-Leakage Output Auditor & Quality Metrics**:
  - Automatically re-scans transformed text through all detection engines to guarantee zero residual PII leakage before data release.
  - Calculates post-sanitization **Utility Score** (text integrity preservation) and **Risk Reduction Index**.

- 🕸️ **Entity Proximity Relationship Graph**:
  - Automatically generates an entity interaction graph displaying connection weights between sensitive tokens that appear within close contextual proximity ($\le 220$ characters).

- 📄 **Multi-Format Document Ingestion & PDF Reporting**:
  - Direct file extraction support for plain text (`.txt`), Adobe PDF (`.pdf`), and Microsoft Word (`.docx`).
  - Generates downloadable, audit-ready compliance PDF reports built with ReportLab, complete with entity tables, risk metrics, and legal disclaimers.

- 🔐 **Enterprise Architecture & Audit Logging**:
  - JWT-based authentication (`Flask-JWT-Extended`) and password hashing via `bcrypt`.
  - Immutable audit logs capturing every analysis, sanitization, and report generation event with user and timestamp attribution.
  - Sleek, modern React 18 single-page dashboard with dark glassmorphic styling, real-time KPI metrics, and side-by-side diff viewers.

---

## 🏗️ System Architecture

```text
                           ┌───────────────────────────────┐
                           │       React Web Client        │
                           │  Dashboard / Analyzer / Audit │
                           └───────────────┬───────────────┘
                                           │ REST API (JSON / Multipart)
                                           ▼
                           ┌───────────────────────────────┐
                           │      Flask REST Backend       │
                           │  JWT Auth / Security / Routes │
                           └───────┬───────────────┬───────┘
                                   │               │
        ┌──────────────────────────┘               └──────────────────────────┐
        ▼                                                                     ▼
┌───────────────────────┐                                         ┌───────────────────────┐
│   Document Extractor  │                                         │    SQLite / SQLAlchemy│
│   (TXT, PDF, DOCX)    │                                         │    (Scans, Entities,  │
└──────────┬────────────┘                                         │       Audit Logs)     │
           │                                                      └───────────────────────┘
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Hybrid Detection Engine                     │
│  ┌────────────────────┬───────────────────┬──────────────────┐  │
│  │  Transformer NER   │  Microsoft        │ Regex + Checksum │  │
│  │ (dslim/bert-base)  │  Presidio + spaCy │  Validators      │  │
│  └─────────┬──────────┴─────────┬─────────┴─────────┬────────┘  │
│            └────────────────────┼───────────────────┘           │
│                                 ▼                               │
│                   Context Validation & Suppression              │
│                                 ▼                               │
│                   Priority Merge & Span Conflict Resolution     │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Privacy Risk Engine & Graph                  │
│   • Base Sensitivity Weights      • Proximity Multiplier        │
│   • Token Uniqueness Metrics     • Quasi-Identifier Combinations│
│   • Entity Relationship Graph (Contextual Proximity Clustered)  │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Adaptive Sanitization Engine                  │
│    [Adaptive]   |   [Pseudonymize]   |   [Mask]   |   [Hash]    │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│               Post-Transformation Leakage Auditor               │
│               & ReportLab PDF Export Generator                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🏷️ Supported Identifiers & Recognizers

| Category | Identifier Type | Label | Detection & Validation Mechanism | Sensitivity Weight |
|---|---|---|---|---|
| **Direct PII** | Full Name | `PERSON` | Transformer (`dslim/bert-base-NER`) + Presidio / spaCy | `0.55` |
| **Direct PII** | Email Address | `EMAIL_ADDRESS` | RFC-compliant Regex heuristic | `0.75` |
| **Direct PII** | Phone Number | `PHONE_NUMBER` | International & Indian format regex (`+91`, `6-9\d{9}`) | `0.85` |
| **Financial** | Credit Card | `CREDIT_CARD` | Formats (13–19 digits) + **Luhn Algorithm Checksum** | `0.95` |
| **Financial** | Indian PAN Card | `PAN_IN` | Statutory 10-char regex (`[A-Z]{5}[0-9]{4}[A-Z]`) | `0.90` |
| **Financial** | Bank Account | `BANK_ACCOUNT_IN` | Regex with keyword context matching (`a/c`, `account no`) | `0.90` |
| **Financial** | UPI ID | `UPI_ID` | Handle regex with strict domain disambiguation | `0.85` |
| **Financial** | Bank IFSC Code | `IFSC_IN` | RBI-compliant format regex (`[A-Z]{4}0[A-Z0-9]{6}`) | `0.60` |
| **Government** | Aadhaar Number | `AADHAAR_IN` | 12-digit standard and spaced pattern check | `0.95` |
| **Government** | Passport (IN) | `PASSPORT_IN` | Indian passport pattern regex (`[A-Z][0-9]{7}`) | `0.90` |
| **Transport** | Vehicle RC | `VEHICLE_REGISTRATION` | State-code motor vehicle format regex | `0.80` |
| **Network** | IPv4 Address | `IP_ADDRESS` | Four octets with strict numerical range check ($0-255$) | `0.65` |
| **Quasi-ID** | Geographic Location | `LOCATION` | Transformer NER + spaCy statistical model | `0.55` |
| **Quasi-ID** | Organization / Employer | `ORGANIZATION` | Transformer NER + spaCy statistical model | `0.45` |
| **Quasi-ID** | Date / Time | `DATE_TIME` | Presidio temporal entity recognizer | `0.25` |

---

## 📐 Privacy Risk Formulation

PrivacyGuard AI assesses risk not only by counting occurrences, but by modeling the mathematical probability that an unauthorized actor can achieve individual re-identification.

1. **Entity Uniqueness Factor ($U$)**:
   Frequent words are less unique; longer, rare tokens carry higher discriminating power:
   $$U(e, T) = \min\left(1.0, 0.35 + 0.25 \cdot \frac{1}{\text{freq}(e, T)} + 0.40 \cdot \frac{\text{len}(e)}{24}\right)$$

2. **Entity Risk Contribution ($R_e$)**:
   $$R_e = \min\left(1.0, S(e) \cdot (0.55 + 0.45 \cdot \text{conf}(e)) \cdot (0.60 + 0.40 \cdot U(e, T))\right)$$

3. **Quasi-Identifier Pairwise Proximity ($R_{pair}$)**:
   When two quasi-identifiers appear near each other, linkage risk escalates exponentially:
   $$\text{proximity}(a, b) = \exp\left(-\frac{|start_a - start_b|}{180}\right)$$
   $$R_{pair}(a, b) = \min\left(0.35, 0.30 \cdot S(a) \cdot S(b) \cdot \text{proximity}(a, b)\right)$$

4. **Composite Re-identification Score ($R_{total}$)**:
   $$R_{total} = 1 - \left(\prod_{e} (1 - R_e) \times \prod_{(a, b)} (1 - R_{pair}(a, b))\right)$$

| Score Range | Risk Classification | Recommended Action |
|---|---|---|
| **$0.75 - 1.00$** | `CRITICAL` | Block ingestion/export. Enforce mandatory pseudonymization or redaction. |
| **$0.55 - 0.74$** | `HIGH` | High linkage hazard. De-identification strongly advised. |
| **$0.30 - 0.54$** | `MEDIUM` | Moderate quasi-identifier presence. Apply selective masking. |
| **$0.00 - 0.29$** | `LOW` | Minimal sensitive data present. Safe for standard downstream processing. |

---

## 🚀 Quickstart Guide

### Prerequisites

- **Python**: 3.11+ (Python 3.12 recommended)
- **Node.js**: 18+ & `npm`
- **Git**

---

### Method 1: Local Development Setup

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

# Install dependencies (Flask, Presidio, spaCy, Transformers, PyTorch, ReportLab)
pip install -r requirements.txt

# Download required spaCy language models
python -m spacy download en_core_web_sm
python -m spacy download en_core_web_lg

# Set up local environment configuration
cp .env.example .env

# Run backend test suites
python test_detector.py
python test_false_positives.py

# Launch backend server
python run.py
```
> Backend API will be live at: `http://localhost:5000`

#### 3. Frontend Setup
In a new terminal window:
```powershell
cd frontend

# Install dependencies
npm install

# Set up frontend environment configuration
cp .env.example .env

# Start Vite dev server
npm run dev
```
> Frontend application will be live at: `http://localhost:5173`

---

### Method 2: Docker Compose Setup

Run the complete multi-container stack with a single command:

```bash
docker compose up --build
```

- **Frontend Web UI**: `http://localhost:8080`
- **Backend API**: `http://localhost:5000`

---

## 📡 API Reference

All protected endpoints require an `Authorization: Bearer <JWT>` header.

| Method | Endpoint | Access | Description | Payload / Params |
|---|---|---|---|---|
| `GET` | `/api/health` | Public | System status and service health | — |
| `POST` | `/api/auth/register` | Public | Register new user account | `{ "name", "email", "password" }` |
| `POST` | `/api/auth/login` | Public | Authenticate user & return JWT | `{ "email", "password" }` |
| `GET` | `/api/auth/me` | JWT | Get current user profile & role | — |
| `POST` | `/api/analyze` | JWT | Run detection & risk analysis on text or document | JSON `{ "text", "title" }` or multipart `file` (`.txt`, `.pdf`, `.docx`) |
| `POST` | `/api/scans/<id>/sanitize` | JWT | Apply de-identification & audit leakage | `{ "mode": "adaptive" \| "pseudonymize" \| "mask" \| "hash" \| "remove" }` |
| `GET` | `/api/scans` | JWT | List recent scans for authenticated user | Query limit: 50 |
| `GET` | `/api/scans/<id>` | JWT | Retrieve full scan details, entities, and risk breakdown | — |
| `GET` | `/api/scans/<id>/report` | JWT | Download audit-ready compliance PDF report | Returns `application/pdf` binary |
| `GET` | `/api/dashboard` | JWT | Aggregate metrics, scan volume, & risk distribution | — |
| `GET` | `/api/audit` | JWT | Retrieve immutable audit event history | Query limit: 100 |

---

## 🧪 Testing & Validation

PrivacyGuard AI comes with automated test suites covering detector accuracy, false positive suppression, and risk modeling:

```powershell
cd backend

# Run the 10-point hybrid detector test suite
python test_detector.py

# Run the contextual false positive diagnostic suite
python test_false_positives.py

# Run the 18-case advanced context & polysemy diagnostic suite
python test_advanced_context.py

# Run unit tests via pytest
pytest tests/
```

### Verified Test Cases Include:
- ✅ **Polysemy disambiguation**: Correctly ignores `"apple"` as a fruit, `"May"` as a calendar month, and `"rose"` as a flower while retaining them when used as person names or organizations.
- ✅ **Label suppression**: Ignores metadata labels like `"IFSC:"` or `"UPI ID"` without masking, while reliably detecting the actual credentials.
- ✅ **Indian PII formats**: 100% precision on PAN numbers (`ABCDE1234F`), IFSC codes (`SBIN0001234`), UPI addresses (`user@okaxis`), and mobile numbers (`+91 9876543210`).
- ✅ **Checksum verification**: Rejects invalid credit card numbers failing the Luhn check and rejects invalid IPv4 octets (e.g. `999.999.999.999`).

---

## 📂 Repository Structure

```text
privacyguard-ai/
├── README.md                      # Comprehensive project documentation
├── LICENSE                        # MIT License
├── docker-compose.yml             # Multi-service container orchestration
├── docs/
│   ├── api.md                     # Endpoint specifications
│   └── architecture.md            # Architectural deep-dive & research boundaries
├── backend/
│   ├── Dockerfile                 # Backend containerization file
│   ├── requirements.txt           # Python dependencies
│   ├── run.py                     # Flask entrypoint server script
│   ├── test_detector.py           # Comprehensive detector validation suite
│   ├── test_false_positives.py    # Contextual false positive diagnostics
│   ├── test_advanced_context.py   # 18-case advanced context & polysemy suite
│   ├── tests/
│   │   └── test_risk.py           # Risk calculation unit tests
│   └── app/
│       ├── __init__.py            # Flask app factory, SQLAlchemy & JWT initialization
│       ├── models.py              # User, Scan, Entity, and AuditLog DB models
│       ├── routes.py              # REST API controllers & route handlers
│       ├── detector.py            # HybridDetector combining regex, Presidio & transformer
│       ├── transformer_detector.py# Hugging Face BERT NER classification pipeline
│       ├── risk.py                # Privacy risk scoring, uniqueness & proximity logic
│       ├── sanitizer.py           # Adaptive, Pseudonymize, Mask, Hash transformations
│       ├── graph.py               # Entity relationship proximity graph generator
│       ├── extractor.py           # Text extraction from .txt, .pdf, .docx documents
│       ├── report.py              # ReportLab compliance PDF report generator
│       ├── audit.py               # Audit trail recorder
│       └── security.py            # Password hashing & verification utilities
└── frontend/
    ├── Dockerfile                 # Multi-stage Vite build + Nginx container
    ├── package.json               # Node.js dependencies & scripts
    ├── vite.config.js             # Vite configuration
    ├── index.html                 # HTML application template
    └── src/
        ├── main.jsx               # React 18 full-featured dashboard & analyzer application
        ├── services/
        │   └── api.js             # Frontend API client with auth interceptor
        └── styles/
            └── app.css            # Dark glassmorphic enterprise design system
```

---

## 🛡️ Attribution & Acknowledgements

PrivacyGuard AI builds upon modern data privacy standards and open-source machine learning:
- [Hugging Face Transformers](https://huggingface.co/transformers/) — Pre-trained NLP and `dslim/bert-base-NER` pipeline
- [Microsoft Presidio](https://github.com/microsoft/presidio) — Core PII detection baseline (MIT License)
- [spaCy](https://spacy.io/) — Industrial-strength Natural Language Processing (MIT License)
- [ReportLab](https://www.reportlab.com/) — Enterprise PDF generation engine
- [ZINK](https://github.com/deepanwadhwa/zink) & [pii-anon](https://github.com/subhash-holla/pii-anon) — Conceptual references for quasi-identifier modeling

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
