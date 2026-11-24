# RansomWatch — File Activity Early Warning System
## Backend & Authentication (Member A Deliverable)

RansomWatch is a real-time ransomware early detection and file monitoring system. This repository contains the complete foundation, authentication engine, role-based access control (RBAC), security audit logging service, and core API routers.

---

## 📌 Architecture & Technology Stack

- **Framework**: FastAPI (Python 3.12)
- **Database & ORM**: SQLite + SQLAlchemy 2.0 (declarative models)
- **Data Validation & Schemas**: Pydantic v2
- **Password Hashing**: `pwdlib` with **Argon2id** (memory-hard, resistant to GPU/ASIC cracking)
- **Session Tokens**: JSON Web Tokens (PyJWT) using **HMAC-SHA256 (HS256)**, 30-minute expiration
- **Authorization**: Server-side Role-Based Access Control (RBAC) supporting **Admin** and **Operator**
- **Audit Logging**: Append-only audit trail with automatic secret scrubbing (`[REDACTED]`)
- **Automated Testing**: `pytest` + FastAPI `TestClient` (44 comprehensive test cases)

---

## 📁 Project Structure

```
RansomWatch/
├── backend/
│   ├── main.py                  # FastAPI application entrypoint & router assembly
│   ├── database.py              # SQLite engine, SessionLocal, Base, get_db() dependency
│   ├── models.py                # 6 SQLAlchemy models (User, MonitoredFolder, FileEvent, Incident, AuditLog, Configuration)
│   ├── schemas.py               # Pydantic v2 validation models & DTOs
│   ├── auth.py                  # Password hashing, JWT creation/decoding, RBAC dependencies
│   ├── config.py                # Type-safe environment settings (Pydantic Settings)
│   │
│   ├── routers/
│   │   ├── auth_routes.py       # /auth (register, login, me, logout, admin-only)
│   │   ├── monitor_routes.py    # /monitor (folders, start, stop)
│   │   ├── event_routes.py      # /events (submit, list, get by id)
│   │   ├── incident_routes.py   # /incidents (create, list, get, status update)
│   │   ├── dashboard_routes.py  # /dashboard (stats, recent-events, severity)
│   │   ├── admin_routes.py      # /admin (users, configurations, audit-logs)
│   │   └── report_routes.py     # /reports (CSV & JSON sanitized report export)
│   │
│   └── services/
│       ├── audit_service.py     # Centralized, append-only audit logging & redaction
│       └── incident_service.py  # Incident management engine
│
├── tests/
│   ├── test_auth.py             # 8 authentication scenarios (Argon2, wrong password, expired token, etc.)
│   ├── test_rbac.py             # 4 RBAC & permission isolation tests
│   ├── test_api.py              # 26 end-to-end API tests across all routers
│   └── test_audit.py            # 6 audit logging, redaction & append-only security tests
│
├── docs/
│   └── test_matrix_and_user_roles.md  # Comprehensive test specifications & viva defense guide
├── .env                         # Secret keys & environment configuration
└── requirements.txt             # Locked Python dependencies
```

---

## 🚀 Quickstart Guide

### 1. Setup Virtual Environment
```powershell
cd D:\RansomWatch
python -m venv backend\venv
.\backend\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure Environment (`.env`)
Ensure `.env` exists in `D:\RansomWatch\.env`:
```ini
SECRET_KEY=1fd3865f14347267957eee3c5d7c73c513cec1cf6e6dc01c7785d1f8a171d384
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
DATABASE_URL=sqlite:///./ransomwatch.db
```

### 3. Start the Server
```powershell
cd D:\RansomWatch\backend
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
Interactive API documentation will be available at:
- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 👥 Role Permissions Matrix

| Feature | Endpoint | Administrator | Operator | Anonymous |
|---|---|:---:|:---:|:---:|
| User Registration | `POST /auth/register` | ✅ (Creates Operator) | ✅ (Creates Operator) | ✅ |
| User Login | `POST /auth/login` | ✅ | ✅ | ✅ |
| View Profile | `GET /auth/me` | ✅ | ✅ | ❌ (401) |
| Logout | `POST /auth/logout` | ✅ | ✅ | ❌ (401) |
| View Dashboard Stats | `GET /dashboard/*` | ✅ | ✅ | ❌ (401) |
| Manage Monitored Folders | `POST/GET /monitor/*` | ✅ | ✅ | ❌ (401) |
| Start/Stop Monitoring | `POST /monitor/start`, `stop` | ✅ | ✅ | ❌ (401) |
| Submit File Events | `POST /events` | ✅ | ✅ | ❌ (401) |
| View Events & Incidents | `GET /events`, `GET /incidents` | ✅ | ✅ | ❌ (401) |
| Update Incident Status | `PATCH /incidents/{id}` | ✅ | ✅ | ❌ (401) |
| Export Reports (CSV/JSON) | `GET /reports/export` | ✅ | ✅ | ❌ (401) |
| **Manage Users** | `GET/PATCH /admin/users/*` | ✅ | ❌ (403) | ❌ (401) |
| **Change Detection Thresholds** | `PATCH /admin/configurations/*` | ✅ | ❌ (403) | ❌ (401) |
| **View Audit Logs** | `GET /admin/audit-logs` | ✅ | ❌ (403) | ❌ (401) |

---

## 🤝 Member B Integration Guide (Security Engine Contract)

Member B is developing the detection modules in `security/`:
- `folder_monitor.py` (Watchdog file system watcher)
- `entropy.py` (Shannon entropy calculation)
- `canary.py` (Canary file tamper detection)
- `rules.py` (Threshold and heuristic rules)
- `anomaly.py` (Frequency and mass-modification analysis)

### Contract 1: Submitting a File Event (`POST /events`)

Whenever a detection module identifies suspicious activity, it submits a JSON payload to the backend:

**Endpoint:** `POST http://127.0.0.1:8000/events`  
**Headers:**
- `Content-Type: application/json`
- `Authorization: Bearer <OPERATOR_OR_ADMIN_JWT_TOKEN>`

**JSON Schema:**
```json
{
  "event_type": "file_modified",
  "file_name": "annual_financials.xlsx",
  "module": "entropy",
  "folder_id": 1,
  "severity": "HIGH",
  "risk_score": 85.5,
  "evidence": [
    "Shannon entropy 7.94 exceeds threshold 7.50",
    "142 modifications recorded in 8.2 seconds"
  ]
}
```

**Field Specifications:**
- `event_type` *(string, required)*: e.g. `"file_modified"`, `"file_created"`, `"file_deleted"`, `"file_renamed"`.
- `file_name` *(string, required)*: The name of the file affected.
- `module` *(string, optional)*: The detecting module: `"entropy"`, `"canary"`, `"anomaly"`, or `"process"`.
- `folder_id` *(integer, required)*: The database ID of the registered monitored folder.
- `severity` *(enum, required)*: Strictly `"LOW"`, `"MEDIUM"`, `"HIGH"`, or `"CRITICAL"`.
- `risk_score` *(float, required)*: Between `0.0` and `100.0`.
- `evidence` *(list of strings, optional)*: Technical findings supporting the alert.

**Response (`201 Created`):**
```json
{
  "id": 1,
  "event_id": "3b2e597c-9b11-47fa-80dc-6a3c3e8a7f1d",
  "event_type": "file_modified",
  "file_name": "annual_financials.xlsx",
  "module": "entropy",
  "severity": "HIGH",
  "risk_score": 85.5,
  "evidence": [
    "Shannon entropy 7.94 exceeds threshold 7.50",
    "142 modifications recorded in 8.2 seconds"
  ],
  "timestamp": "2026-11-24T20:30:00",
  "folder_id": 1,
  "incident_id": null
}
```

---

### Contract 2: Folder Monitoring Lifecycle

When an operator clicks "Start Monitoring" in the frontend:
1. Frontend calls `POST /monitor/start/{folder_id}`.
2. The folder's status transitions from `"stopped"` to `"active"`.
3. An audit log `MONITORING_STARTED` is recorded.
4. Member B's `folder_monitor.py` attaches a recursive filesystem observer to `folder.folder_path`.
5. When monitoring is stopped (`POST /monitor/stop/{folder_id}`), the observer unschedules and stops cleanly.

**Example Python Snippet for Member B to send an event:**
```python
import requests

def send_alert_to_backend(token, folder_id, file_name, severity, risk_score, evidence):
    url = "http://127.0.0.1:8000/events"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "event_type": "file_modified",
        "file_name": file_name,
        "module": "entropy",
        "folder_id": folder_id,
        "severity": severity,
        "risk_score": risk_score,
        "evidence": evidence
    }
    response = requests.post(url, json=payload, headers=headers)
    return response.json()
```

---

## 🧪 Automated Test Verification

Run all test suites across authentication, permissions, main APIs, and audit logging:

```powershell
.\backend\venv\Scripts\python.exe -m pytest tests\ -v
```

**Results:**
- `tests/test_auth.py`: **8 PASSED** (Password hashing, JWT claims, wrong password, user enumeration defense, expired tokens, account deactivation)
- `tests/test_rbac.py`: **4 PASSED** (Role separation, operator vs admin, 403 enforcement, audit logging of violations)
- `tests/test_api.py`: **26 PASSED** (Folder monitoring, file events, incidents, dashboard analytics, admin actions, CSV/JSON report exports)
- `tests/test_audit.py`: **6 PASSED** (Secret scrubbing, credential redaction, append-only security, event tracking)
- **Total: 44 tests, 0 failures.**
