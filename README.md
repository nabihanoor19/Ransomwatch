# RansomWatch — File Activity Early Warning System

RansomWatch is a full-stack, real-time ransomware early-detection and file-monitoring system built as a group information security project. It combines a FastAPI backend with a React/Vite frontend and an ML-powered security detection engine.

---

## 👥 Team Contributions

| Member | Role | Deliverables |
|--------|------|-------------|
| **Member A** | Backend & Auth | FastAPI REST API, SQLite/SQLAlchemy models, Argon2id password hashing, JWT RBAC, audit logging |
| **Member B** | Security Engine | Watchdog file monitor, Shannon entropy analysis, canary decoy detection, IsolationForest anomaly detection, rule engine |
| **Member C** | Frontend | React + Vite SPA — 7 pages, JWT auth flow, role-based UI controls, real-time dashboard, all API integrations |

---

## 📌 Architecture & Technology Stack

### Backend (Member A)
- **Framework**: FastAPI (Python 3.12)
- **Database & ORM**: SQLite + SQLAlchemy 2.0
- **Data Validation**: Pydantic v2
- **Password Hashing**: `pwdlib` with **Argon2id** (memory-hard, GPU-resistant)
- **Session Tokens**: JWT (PyJWT, HS256), 30-minute expiration
- **Authorization**: Server-side RBAC — `admin` and `operator` roles
- **Audit Logging**: Append-only trail with automatic secret scrubbing (`[REDACTED]`)
- **Tests**: `pytest` + FastAPI `TestClient` (44 test cases, 0 failures)

### Security Engine (Member B)
- **File Monitoring**: `watchdog` Watchdog observer with sandbox boundary validation
- **Entropy Analysis**: Shannon entropy + SHA-256 baseline delta detection
- **Canary Detection**: Decoy file tamper detection with CRITICAL alerts
- **Rule Engine**: Configurable sliding-window heuristics (rapid modification, bulk rename, mass delete, suspicious extensions)
- **Anomaly Detection**: IsolationForest behavioral model with fallback scoring

### Frontend (Member C)
- **Framework**: React 18 + Vite 6
- **HTTP Client**: Axios with Bearer token injection & 401 auto-logout
- **Routing**: React Router v7 with protected and admin-only routes
- **State**: React Context (AuthContext) + localStorage JWT persistence

---

## 📁 Project Structure

```
RansomWatch/
├── backend/
│   ├── main.py                   # FastAPI entrypoint & router assembly
│   ├── database.py               # SQLite engine, SessionLocal, Base
│   ├── models.py                 # 6 SQLAlchemy models
│   ├── schemas.py                # Pydantic v2 DTOs
│   ├── auth.py                   # Argon2 hashing, JWT, RBAC dependencies
│   ├── config.py                 # Pydantic Settings (.env loader)
│   ├── routers/
│   │   ├── auth_routes.py        # /auth  (register, login, me, logout)
│   │   ├── monitor_routes.py     # /monitor (folders, start, stop, scan)
│   │   ├── event_routes.py       # /events (submit, list, get)
│   │   ├── incident_routes.py    # /incidents (list, get, patch status)
│   │   ├── dashboard_routes.py   # /dashboard (stats, recent-events, severity)
│   │   ├── admin_routes.py       # /admin (users, configurations, audit-logs)
│   │   └── report_routes.py      # /reports (CSV & JSON export)
│   ├── security/
│   │   ├── entropy.py            # Shannon entropy & SHA-256 baseline
│   │   ├── canary.py             # Canary decoy deployment & tamper detection
│   │   ├── rules.py              # Sliding-window deterministic rule engine
│   │   ├── anomaly.py            # IsolationForest behavioral detector
│   │   └── pipeline.py           # End-to-end detection orchestrator
│   ├── monitor/
│   │   └── folder_monitor.py     # Watchdog observer & sandbox boundary validation
│   └── services/
│       ├── audit_service.py      # Append-only audit logging & redaction
│       └── incident_service.py   # Incident correlation & lifecycle
│
├── frontend/                     # Member C — React/Vite SPA
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json
│   ├── .env.example              # Set VITE_API_BASE_URL here
│   ├── src/
│   │   ├── main.jsx              # React entry point
│   │   ├── App.jsx               # Route definitions
│   │   ├── index.css             # Dark-theme design system (CSS variables)
│   │   ├── api/
│   │   │   ├── client.js         # Axios instance, token injection, 401 handler
│   │   │   └── services.js       # Typed wrappers for all backend endpoints
│   │   ├── context/
│   │   │   └── AuthContext.jsx   # Auth state, login/logout, role helpers
│   │   ├── components/
│   │   │   ├── Layout.jsx        # Sidebar + topbar shell, /health indicator
│   │   │   ├── Modal.jsx         # Reusable modal dialog
│   │   │   └── ProtectedRoute.jsx # Auth & admin route guards
│   │   ├── pages/
│   │   │   ├── LoginPage.jsx     # OAuth2 form-urlencoded login
│   │   │   ├── RegisterPage.jsx  # Operator self-registration
│   │   │   ├── DashboardPage.jsx # KPIs, severity breakdown, recent feed
│   │   │   ├── MonitorPage.jsx   # Register folders, start/stop, canary scan
│   │   │   ├── EventsPage.jsx    # File events table + evidence modal
│   │   │   ├── IncidentsPage.jsx # Incident timeline + status transitions
│   │   │   ├── ReportsPage.jsx   # Sanitized CSV/JSON export
│   │   │   └── AdminPage.jsx     # Users, thresholds, audit log (admin only)
│   │   └── utils/
│   │       └── formatters.js     # Timestamps, severity badges, risk colours
│   └── README.md                 # Frontend-specific setup guide
│
├── tests/
│   ├── test_auth.py              # 8 auth tests
│   ├── test_rbac.py              # 4 RBAC tests
│   ├── test_api.py               # 26 end-to-end API tests
│   ├── test_audit.py             # 6 audit logging tests
│   └── ...
│
├── docs/
│   ├── test_matrix_and_user_roles.md
│   ├── threat_model.md
│   └── architecture.png
├── requirements.txt              # Python dependencies
└── .gitignore
```

---

## 🚀 Quickstart — Run Locally (Full Stack)

### 1. Backend Setup

```powershell
cd RansomWatch
python -m venv backend\venv
.\backend\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create `backend\.env` (or project root `.env`):
```ini
SECRET_KEY=1fd3865f14347267957eee3c5d7c73c513cec1cf6e6dc01c7785d1f8a171d384
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
DATABASE_URL=sqlite:///./ransomwatch.db
```

Start FastAPI:
```powershell
cd backend
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

- **Swagger UI**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc

### 2. Frontend Setup

```powershell
cd frontend
npm install
npm run dev
```

App runs at **http://localhost:5173**

> The frontend is pre-configured to call `http://127.0.0.1:8000`. To use a different backend URL, copy `.env.example` to `.env` and set `VITE_API_BASE_URL`.

### 3. First Login

1. Open http://localhost:5173/register and create an operator account.
2. Sign in at http://localhost:5173/login.
3. To promote an account to **admin** (run once in PowerShell):
```powershell
# Replace 'yourusername' with your registered username
backend\venv\Scripts\python.exe -c @"
import sqlite3
c = sqlite3.connect(r'backend\ransomwatch.db')
c.execute('UPDATE users SET role = ? WHERE username = ?', ('admin', 'yourusername'))
c.commit()
print('Done:', c.execute('SELECT username, role FROM users').fetchall())
"@
```
Then sign out and sign back in to gain Admin Console access.

---

## 👥 Role Permissions Matrix

| Feature | Endpoint | Administrator | Operator | Anonymous |
|---|---|:---:|:---:|:---:|
| Register | `POST /auth/register` | ✅ | ✅ | ✅ |
| Login | `POST /auth/login` | ✅ | ✅ | ✅ |
| View Profile | `GET /auth/me` | ✅ | ✅ | ❌ 401 |
| Dashboard Stats | `GET /dashboard/*` | ✅ | ✅ | ❌ 401 |
| Manage Folders | `POST/GET /monitor/*` | ✅ | ✅ | ❌ 401 |
| Start/Stop Monitoring | `POST /monitor/start,stop` | ✅ | ✅ | ❌ 401 |
| View Events & Incidents | `GET /events`, `/incidents` | ✅ | ✅ | ❌ 401 |
| Update Incident Status | `PATCH /incidents/{id}` | ✅ | ✅ | ❌ 401 |
| Export Reports (CSV/JSON) | `GET /reports/export` | ✅ | ✅ | ❌ 401 |
| **Manage Users** | `GET/PATCH /admin/users/*` | ✅ | ❌ 403 | ❌ 401 |
| **Change Detection Thresholds** | `PATCH /admin/configurations/*` | ✅ | ❌ 403 | ❌ 401 |
| **View Audit Logs** | `GET /admin/audit-logs` | ✅ | ❌ 403 | ❌ 401 |

---

## 🧪 Automated Test Verification

```powershell
.\backend\venv\Scripts\python.exe -m pytest tests\ -v
```

| Suite | Tests | Status |
|---|---|---|
| `test_auth.py` | 8 | ✅ PASSED |
| `test_rbac.py` | 4 | ✅ PASSED |
| `test_api.py` | 26 | ✅ PASSED |
| `test_audit.py` | 6 | ✅ PASSED |
| **Total** | **44** | **0 failures** |

---

## 🛡️ Security Design Highlights

- **Argon2id** password hashing — memory-hard, GPU/ASIC-resistant
- **JWT (HS256)** with 30-minute expiration; server-side `is_active` check on every request
- **Mass assignment prevention** — `role` field ignored on registration, always forced to `operator`
- **Canary decoy files** — 3 synthetic files deployed per sandbox; any tamper triggers CRITICAL alert
- **Shannon entropy** baseline delta analysis — detects encryption-in-progress
- **IsolationForest** anomaly detection — catches statistically unusual file-activity bursts
- **Append-only audit trail** — no DELETE or PATCH route exists for audit logs; all actions recorded
- **Secret scrubbing** — passwords and tokens automatically `[REDACTED]` before audit storage
- **CORS** locked to `localhost:5173`, `localhost:3000`, `localhost:8080` only
