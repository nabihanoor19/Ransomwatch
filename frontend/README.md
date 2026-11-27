# RansomWatch Frontend (Member C)

React + Vite web interface for the **RansomWatch File-Activity Early Warning System**.

## Prerequisites

- Node.js 20+ and npm
- Running RansomWatch FastAPI backend (default `http://127.0.0.1:8000`)

## Setup & Local Development

```powershell
cd frontend
npm install
npm run dev
```

The app runs at `http://localhost:5173`.

### Custom Backend URL (Optional)

Copy `.env.example` to `.env` and override `VITE_API_BASE_URL` if the backend runs on a different host or port:

```ini
VITE_API_BASE_URL=http://127.0.0.1:8000
```

## Production Build

```powershell
cd frontend
npm run build
```

## Implemented Pages & Capabilities

- **Authentication (`/login`, `/register`):** Operator registration, OAuth2 form-urlencoded login, JWT bearer session persistence, `/auth/me` profile hydration, and logout audit recording.
- **Dashboard (`/`):** Live KPI cards, incident severity breakdown, active/open/investigating/resolved counts, recent file activity feed, and auto-refresh toggle.
- **Folder Monitoring (`/monitor`):** Register sandbox paths, start/stop Watchdog observers (with confirmation before stopping), inspect live observer status, run on-demand canary integrity scans, and review per-folder activity.
- **File Events (`/events`):** Filter events by severity and folder, inspect risk scores, detection modules, supporting evidence, and recommended remediation actions.
- **Incident Timeline (`/incidents`):** Filter incidents by severity, status, detection module, and UTC date range; inspect full evidence; transition status (`open` → `investigating` → `resolved`) with confirmation on resolution.
- **Reports (`/reports`):** Preview sanitized incident reports and download CSV or JSON exports.
- **Admin Console (`/admin`, `admin` role only):** Manage user roles and active status, tune rule engine thresholds (`entropy_threshold`, `entropy_delta_threshold`, `rapid_mod_count`, `bulk_rename_count`, `mass_delete_count`, `window_seconds`), and inspect the append-only security audit trail.
